"""UBIFS carver.

UBIFS sits on the UBI volume layer and is the usual choice for larger raw NAND
parts. Like the other log based designs it writes new nodes out of place and
leaves superseded ones behind until garbage collection reclaims their erase
blocks, so a raw dump of the flash holds current and stale nodes side by side.

Every node carries a CRC and a global sequence number. The carver validates
each node, collects inode, data, and directory entry nodes, and rebuilds files
per inode. The newest sequence number wins for each 4 KiB block, older copies
of a block are reported as obsolete, and blocks past the size recorded in the
newest inode node are treated as truncated remnants. A directory entry whose
target inode is zero marks an unlink, and an inode whose newest node has a
link count of zero is deleted.

The on flash index tree is not rebuilt, so live against obsolete is decided
from sequence numbers rather than from the index. That is a stated
simplification. It still recovers content, which is the point of the tool.
"""

from __future__ import annotations

import struct
import zlib
from datetime import datetime, timezone
from typing import Iterator, Optional

from ..models import Artifact, ArtifactState, Confidence, ScanStats
from ..security import BoundedReader, Limits, inflate_bounded
from .base import FilesystemCarver

_MAGIC = 0x06101831
_MAGIC_LE = b"\x31\x18\x10\x06"
_INO, _DATA, _DENT = 0, 1, 2
_BLOCK = 4096
_ROOT = 1

try:
    import lzo as _lzo  # type: ignore
except Exception:
    _lzo = None
try:
    import zstandard as _zstd  # type: ignore
except Exception:
    _zstd = None


def _ucrc(data) -> int:
    """UBIFS CRC, seeded with all ones and left without the final inversion."""
    return zlib.crc32(data) ^ 0xFFFFFFFF


def _crc_ok(data, stored: int) -> bool:
    return stored in (_ucrc(data), zlib.crc32(data) & 0xFFFFFFFF)


class UBIFSCarver(FilesystemCarver):
    name = "ubifs"
    maturity = "CRC checked node scan, live status from sequence numbers rather than the index"

    def detect(self, reader: BoundedReader) -> bool:
        head = reader.read_at(0, min(len(reader), 2 * 1024 * 1024))
        valid, pos = 0, head.find(_MAGIC_LE)
        while pos != -1 and valid < 2:
            if pos % 8 == 0 and self._valid(head, pos):
                valid += 1
            pos = head.find(_MAGIC_LE, pos + 1)
        return valid >= 2

    def _valid(self, buf, off: int) -> bool:
        if off + 24 > len(buf):
            return False
        _, crc, _, length = struct.unpack_from("<IIQI", buf, off)
        if length < 24 or length > 64 * 1024 or off + length > len(buf):
            return False
        return _crc_ok(bytes(buf[off + 8:off + length]), crc)

    def carve(self, reader: BoundedReader, stats: ScanStats) -> Iterator[Artifact]:
        buf = reader.haystack()
        n = len(buf)
        inos, datas, dents = [], [], []
        pos, seen = 0, 0
        while True:
            hit = buf.find(_MAGIC_LE, pos)
            if hit == -1 or hit + 24 > n:
                break
            if hit % 8 or not self._valid(buf, hit):
                if hit % 8 == 0:
                    stats.false_positive_guard += 1
                pos = hit + 1
                continue
            _, _, sqnum, length, ntype = struct.unpack_from("<IIQIB", buf, hit)
            if ntype == _DATA and length >= 48:
                inum = struct.unpack_from("<I", buf, hit + 24)[0]
                block = struct.unpack_from("<I", buf, hit + 28)[0] & 0x1FFFFFFF
                size, compr = struct.unpack_from("<IH", buf, hit + 40)
                data = self._decompress(bytes(buf[hit + 48:hit + length]), compr, min(size, _BLOCK))
                datas.append((inum, block, sqnum, data, hit, data is not None))
            elif ntype == _DENT and length >= 56:
                parent = struct.unpack_from("<I", buf, hit + 24)[0]
                inum = struct.unpack_from("<Q", buf, hit + 40)[0]
                dtype = buf[hit + 49]
                nlen = struct.unpack_from("<H", buf, hit + 50)[0]
                name = bytes(buf[hit + 56:hit + 56 + min(nlen, 255)]).decode("utf-8", "replace")
                dents.append((parent, name, inum, sqnum, dtype))
            elif ntype == _INO and length >= 160:
                inum = struct.unpack_from("<I", buf, hit + 24)[0]
                isize = struct.unpack_from("<Q", buf, hit + 48)[0]
                mtime = struct.unpack_from("<Q", buf, hit + 72)[0]
                nlink = struct.unpack_from("<I", buf, hit + 92)[0]
                inos.append((inum, sqnum, isize, nlink, mtime))
            seen += 1
            stats.records_seen += 1
            if seen > Limits.MAX_RECORDS:
                break
            pos = hit + ((length + 7) & ~7)
        yield from self._rebuild(inos, datas, dents)

    def _decompress(self, body: bytes, compr: int, size: int) -> Optional[bytes]:
        if compr == 0:
            return body[:size]
        if compr == 2:
            out = inflate_bounded(body, -15, size)
            return out if out is not None else inflate_bounded(body, 15, size)
        if compr == 1 and _lzo is not None:
            try:
                return _lzo.decompress(body, False, size)[:size]
            except Exception:
                return None
        if compr == 3 and _zstd is not None:
            try:
                return _zstd.ZstdDecompressor().decompress(body, max_output_size=size)[:size]
            except Exception:
                return None
        return None

    def _rebuild(self, inos, datas, dents) -> Iterator[Artifact]:
        latest_dent: dict[tuple, tuple] = {}
        for d in dents:
            key = (d[0], d[1])
            if key not in latest_dent or d[3] > latest_dent[key][3]:
                latest_dent[key] = d
        live_link, historic = {}, {}
        for (parent, name), d in latest_dent.items():
            if d[2]:
                live_link.setdefault(d[2], (parent, name))
        for d in dents:
            if d[2] and (d[2] not in historic or d[3] > historic[d[2]][2]):
                historic[d[2]] = (d[0], d[1], d[3])
        latest_ino: dict[int, tuple] = {}
        linked_ino: dict[int, tuple] = {}
        for rec in inos:
            if rec[0] not in latest_ino or rec[1] > latest_ino[rec[0]][1]:
                latest_ino[rec[0]] = rec
            if rec[3] and (rec[0] not in linked_ino or rec[1] > linked_ino[rec[0]][1]):
                linked_ino[rec[0]] = rec

        def path_of(inum: int) -> str:
            parts, cur = [], inum
            for _ in range(Limits.MAX_PARSE_DEPTH):
                if cur == _ROOT:
                    return "/" + "/".join(reversed(parts))
                link = live_link.get(cur) or (historic[cur][:2] if cur in historic else None)
                if link is None:
                    break
                parts.append(link[1])
                cur = link[0]
            return "?/" + "/".join(reversed(parts))

        by_inode: dict[int, list] = {}
        for rec in datas:
            by_inode.setdefault(rec[0], []).append(rec)

        count = 0
        for inum in sorted(by_inode):
            best: dict[int, tuple] = {}
            stale: list = []
            for rec in sorted(by_inode[inum], key=lambda r: r[2]):
                if rec[1] in best:
                    stale.append(best[rec[1]])
                best[rec[1]] = rec
            ino = latest_ino.get(inum)
            extent = max(b * _BLOCK + len(r[3] or b"") for b, r in best.items())
            # A deleted inode's last node may record size zero, so size comes from
            # the newest node that still had a link.
            sized = linked_ino.get(inum) if (ino and ino[3] == 0) else ino
            size = min(sized[2] if sized else extent, Limits.MAX_ARTIFACT_BYTES)
            buf = bytearray(size)
            for b, rec in best.items():
                start = b * _BLOCK
                if start >= size:
                    stale.append(rec)
                    continue
                piece = (rec[3] or b"")[:size - start]
                buf[start:start + len(piece)] = piece
            unlinked = ino is not None and ino[3] == 0
            if inum in live_link and not unlinked:
                state, note = ArtifactState.LIVE, "rebuilt from the newest data nodes"
            elif inum in historic or unlinked:
                state, note = ArtifactState.DELETED, "unlinked, its data nodes remain on flash"
            else:
                state, note = ArtifactState.ORPHANED, "data nodes with no surviving name"
            path = path_of(inum) if (inum in live_link or inum in historic) else f"inode_{inum}"
            name = path.rsplit("/", 1)[-1] or f"inode_{inum}"
            broken = sum(1 for r in best.values() if not r[5])
            if broken:
                note += f", {broken} blocks used a compressor that is not installed"
            mtime = datetime.fromtimestamp(ino[4], timezone.utc).isoformat() if ino else None
            if buf:
                count += 1
                yield Artifact(name=name, filesystem="ubifs", state=state,
                               confidence=Confidence.LOW if broken else Confidence.MEDIUM,
                               offset=min(r[4] for r in best.values()), size=len(buf), data=bytes(buf),
                               path=path, inode=inum, mtime=mtime, note=note)
            for rec in stale[:Limits.MAX_VERSIONS_PER_FILE]:
                if not rec[3]:
                    continue
                count += 1
                yield Artifact(name=f"{name}.blk{rec[1]}.sq{rec[2]}", filesystem="ubifs",
                               state=ArtifactState.OBSOLETE, confidence=Confidence.MEDIUM,
                               offset=rec[4], size=len(rec[3]), data=rec[3], path=path, inode=inum,
                               note="an older copy of this block, replaced by a newer write or cut by truncation")
            if not self._guard_count(count):
                return
