"""JFFS2 carver.

JFFS2 is a log structured filesystem for raw flash. Every change is a new node
appended to the log, and older nodes are only marked obsolete rather than
erased straight away, so the log holds a trail of past states until garbage
collection reclaims the space.

The carver scans for node headers, validates each one with the kernel's CRC
convention, and rebuilds every inode by replaying its data nodes in version
order. Replaying rather than simply stacking nodes matters, because a later
node can truncate a file, and a naive merge would leak stale bytes into the
live content. Whenever a write overwrites or truncates earlier content, the
state just before that write is kept as an obsolete version. A directory entry
pointing at inode zero is an unlink, and data belonging to an inode with no
remaining name is reported as deleted. On NOR flash the kernel also clears a
bit in the header of nodes it has obsoleted, and those nodes are read too.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator, Optional

from ..models import Artifact, ArtifactState, Confidence, ScanStats
from ..security import BoundedReader, Limits, inflate_bounded
from .base import FilesystemCarver

_MAGIC = 0x1985
_ACCURATE = 0x2000
_DIRENT = 0xE001
_INODE = 0xE002
_ROOT_INO = 1

_COMPR_NONE, _COMPR_ZERO, _COMPR_RTIME, _COMPR_ZLIB, _COMPR_LZO = 0, 1, 2, 6, 7

try:
    import lzo as _lzo  # type: ignore
except Exception:
    _lzo = None


def _jcrc(data) -> int:
    """The kernel CRC for JFFS2, a zero seed with no final inversion."""
    return zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF


def _crc_ok(data, stored: int) -> bool:
    # The plain zlib form is accepted too, so an image from a tool using the
    # other convention is still read instead of silently dropped.
    return stored in (_jcrc(data), zlib.crc32(data) & 0xFFFFFFFF)


@dataclass
class _Dirent:
    pino: int
    version: int
    ino: int
    ftype: int
    name: str
    offset: int
    marked: bool
    ok: bool


@dataclass
class _Node:
    ino: int
    version: int
    doff: int
    isize: int
    data: bytes
    offset: int
    mtime: int
    ok: bool
    marked: bool
    compr: int


def _rtime(raw: bytes, dsize: int) -> bytes:
    """The small run length decoder JFFS2 calls rtime, bounded at every step."""
    out = bytearray()
    positions = [0] * 256
    ip = 0
    while ip + 1 < len(raw) and len(out) < dsize:
        value = raw[ip]
        repeat = raw[ip + 1]
        ip += 2
        out.append(value)
        back = positions[value]
        positions[value] = len(out)
        for _ in range(repeat):
            if back >= len(out) or len(out) >= dsize:
                break
            out.append(out[back])
            back += 1
    return bytes(out[:dsize])


def _supersedes(extents: list, nd: _Node) -> bool:
    wend = nd.doff + len(nd.data)
    for s, e, _, _ in extents:
        if e > nd.isize or (nd.data and s < wend and e > nd.doff):
            return True
    return False


def _apply(extents: list, nd: _Node) -> None:
    """Apply one data node to the extent list, truncating to its recorded size."""
    size = nd.isize
    wstart, wend = nd.doff, nd.doff + len(nd.data)
    out = []
    for s, e, src, ss in extents:
        if s >= size:
            continue
        e = min(e, size)
        if nd.data and s < wend and e > wstart:
            if s < wstart:
                out.append([s, wstart, src, ss])
            if e > wend:
                out.append([wend, e, src, ss + (wend - s)])
            continue
        out.append([s, e, src, ss])
    if nd.data and wstart < size:
        out.append([wstart, min(wend, size), nd, 0])
    out.sort(key=lambda x: x[0])
    extents[:] = out


def _materialise(extents: list, size: int) -> bytes:
    size = max(0, min(size, Limits.MAX_ARTIFACT_BYTES))
    buf = bytearray(size)
    for s, e, src, ss in extents:
        if s < size:
            e = min(e, size)
            buf[s:e] = src.data[ss:ss + (e - s)]
    return bytes(buf)


def replay_versions(nodes: list[_Node]):
    """Replay nodes in version order and keep each state a later write changed."""
    extents: list = []
    snapshots: list = []
    size, last_version = 0, None
    for nd in sorted(nodes, key=lambda d: d.version):
        if extents and _supersedes(extents, nd) and len(snapshots) < Limits.MAX_VERSIONS_PER_FILE:
            snapshots.append((last_version, _materialise(extents, size)))
        _apply(extents, nd)
        size, last_version = nd.isize, nd.version
    return _materialise(extents, size), snapshots


class JFFS2Carver(FilesystemCarver):
    name = "jffs2"
    maturity = "CRC checked node scan with ordered replay, validate on nandsim images"

    def detect(self, reader: BoundedReader) -> bool:
        head = reader.read_at(0, min(len(reader), 1024 * 1024))
        for endian, magic in (("<", b"\x85\x19"), (">", b"\x19\x85")):
            valid, pos = 0, head.find(magic)
            while pos != -1 and valid < 2:
                if pos % 4 == 0 and pos + 12 <= len(head):
                    _, ntype, totlen, hcrc = struct.unpack_from(endian + "HHII", head, pos)
                    if _crc_ok(struct.pack(endian + "HHI", _MAGIC, ntype | _ACCURATE, totlen), hcrc):
                        valid += 1
                pos = head.find(magic, pos + 1)
            if valid >= 2:
                return True
        return False

    def carve(self, reader: BoundedReader, stats: ScanStats) -> Iterator[Artifact]:
        buf = reader.haystack()
        n = len(buf)
        head = reader.read_at(0, min(n, 16 * 1024 * 1024))
        big = head.count(b"\x19\x85") > head.count(b"\x85\x19")
        endian = ">" if big else "<"
        magic = b"\x19\x85" if big else b"\x85\x19"
        dirents, nodes = [], []
        pos, seen = 0, 0
        while True:
            hit = buf.find(magic, pos)
            if hit == -1 or hit + 12 > n:
                break
            parsed = self._parse(buf, hit, endian, stats)
            if parsed is None:
                pos = hit + 1
                continue
            kind, obj, totlen = parsed
            (dirents if kind == "dirent" else nodes).append(obj)
            seen += 1
            stats.records_seen += 1
            if seen > Limits.MAX_RECORDS:
                break
            pos = hit + max(4, (totlen + 3) & ~3)
        yield from self._rebuild(dirents, nodes)

    def _parse(self, buf, off: int, endian: str, stats: ScanStats):
        if off % 4:
            return None
        _, ntype, totlen, hcrc = struct.unpack_from(endian + "HHII", buf, off)
        full = ntype | _ACCURATE
        if not _crc_ok(struct.pack(endian + "HHI", _MAGIC, full, totlen), hcrc):
            stats.false_positive_guard += 1
            return None
        if totlen < 12 or off + totlen > len(buf):
            return None
        marked = not (ntype & _ACCURATE)
        fixed = struct.pack(endian + "H", full)
        if full == _DIRENT and totlen >= 40:
            pino, version, ino, _, nsize, ftype = struct.unpack_from(endian + "IIIIBB", buf, off + 12)
            node_crc, name_crc = struct.unpack_from(endian + "II", buf, off + 32)
            name = bytes(buf[off + 40:off + 40 + nsize])
            head = bytearray(buf[off:off + 32])
            head[2:4] = fixed
            ok = _crc_ok(bytes(head), node_crc) and _crc_ok(name, name_crc)
            return "dirent", _Dirent(pino, version, ino, ftype, name.decode("utf-8", "replace"),
                                     off, marked, ok), totlen
        if full == _INODE and totlen >= 68:
            (ino, version, _, _, _, isize, _, mtime, _, doff, csize, dsize, compr, _, _,
             data_crc, node_crc) = struct.unpack_from(endian + "IIIHHIIIIIIIBBHII", buf, off + 12)
            head = bytearray(buf[off:off + 60])
            head[2:4] = fixed
            raw = bytes(buf[off + 68:off + 68 + min(csize, Limits.MAX_NODE_OUTPUT)])
            ok = _crc_ok(bytes(head), node_crc) and _crc_ok(raw, data_crc)
            data = self._decompress(raw, compr, min(dsize, Limits.MAX_NODE_OUTPUT))
            if data is None:
                ok, data = False, b""
            return "inode", _Node(ino, version, doff, isize, data, off, mtime, ok, marked, compr), totlen
        return None

    def _decompress(self, raw: bytes, compr: int, dsize: int) -> Optional[bytes]:
        if compr == _COMPR_NONE:
            return raw[:dsize]
        if compr == _COMPR_ZERO:
            return b"\x00" * dsize
        if compr == _COMPR_ZLIB:
            out = inflate_bounded(raw, 15, dsize)
            return out if out is not None else inflate_bounded(raw, -15, dsize)
        if compr == _COMPR_RTIME:
            return _rtime(raw, dsize)
        if compr == _COMPR_LZO and _lzo is not None:
            try:
                return _lzo.decompress(raw, False, dsize)[:dsize]
            except Exception:
                return None
        return None

    def _rebuild(self, dirents: list[_Dirent], nodes: list[_Node]) -> Iterator[Artifact]:
        latest: dict[tuple, _Dirent] = {}
        for de in dirents:
            key = (de.pino, de.name)
            if key not in latest or de.version > latest[key].version:
                latest[key] = de
        live_link: dict[int, tuple] = {}
        for (pino, name), de in latest.items():
            if de.ino:
                live_link.setdefault(de.ino, (pino, name))
        historic: dict[int, tuple] = {}
        for de in dirents:
            if de.ino and (de.ino not in historic or de.version > historic[de.ino][2]):
                historic[de.ino] = (de.pino, de.name, de.version)

        def path_of(ino: int) -> str:
            parts, cur = [], ino
            for _ in range(Limits.MAX_PARSE_DEPTH):
                if cur == _ROOT_INO:
                    return "/" + "/".join(reversed(parts))
                link = live_link.get(cur) or (historic[cur][:2] if cur in historic else None)
                if link is None:
                    break
                parts.append(link[1])
                cur = link[0]
            return "?/" + "/".join(reversed(parts))

        by_ino: dict[int, list[_Node]] = {}
        for nd in nodes:
            by_ino.setdefault(nd.ino, []).append(nd)

        count = 0
        for ino in sorted(by_ino):
            group = by_ino[ino]
            final, snapshots = replay_versions(group)
            if ino in live_link:
                state, path, note = ArtifactState.LIVE, path_of(ino), "rebuilt from the node log"
            elif ino in historic:
                state, path = ArtifactState.DELETED, path_of(ino)
                note = "every name for this inode was unlinked, its data nodes remain"
            else:
                state, path = ArtifactState.ORPHANED, f"inode_{ino}"
                note = "data nodes with no surviving directory entry"
            damaged = [nd for nd in group if not nd.ok]
            if damaged:
                note += f", {len(damaged)} nodes failed a CRC or used an unsupported compressor"
            if any(nd.marked for nd in group):
                note += ", some nodes carry the kernel obsolete mark"
            conf = Confidence.LOW if damaged else (Confidence.MEDIUM if state == ArtifactState.ORPHANED
                                                    else Confidence.HIGH)
            name = path.rsplit("/", 1)[-1] or f"inode_{ino}"
            mtime = datetime.fromtimestamp(max(nd.mtime for nd in group), timezone.utc).isoformat()
            if final:
                count += 1
                yield Artifact(name=name, filesystem="jffs2", state=state, confidence=conf,
                               offset=min(nd.offset for nd in group), size=len(final), data=final,
                               path=path, inode=ino, mtime=mtime, note=note)
            seen = {final}
            for version, data in snapshots:
                if not data or data in seen:
                    continue
                seen.add(data)
                count += 1
                yield Artifact(name=f"{name}.v{version}", filesystem="jffs2",
                               state=ArtifactState.OBSOLETE,
                               confidence=Confidence.MEDIUM if not damaged else Confidence.LOW,
                               offset=min(nd.offset for nd in group if nd.version <= version),
                               size=len(data), data=data, path=path, inode=ino,
                               note=f"the file as it stood at version {version}, before a later write changed it")
            if not self._guard_count(count):
                return
