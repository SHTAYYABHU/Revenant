"""SPIFFS carver.

SPIFFS is a small filesystem for SPI NOR flash, common on ESP class devices.
Every page opens with a five byte header holding an object id, a span index,
and a flags byte whose bits are cleared as the page moves from free to used to
deleted. Deleting a file clears the deleted bit in place and leaves the bytes
alone, so the name and the content stay readable until garbage collection
erases the block.

The page and block sizes are chosen at build time and are not stored in the
image, so the carver tries the common geometries and keeps the one that yields
the most valid object index headers. Files are rebuilt from their data pages by
span index, which avoids depending on the index table layout. Live pages are
preferred, older deleted copies of a span are reported as obsolete fragments,
and a file whose index header carries the deleted bit is reported as deleted.
"""

from __future__ import annotations

import struct
from typing import Iterator

from ..models import Artifact, ArtifactState, Confidence, ScanStats
from ..security import BoundedReader, Limits
from .base import FilesystemCarver

_IX_BIT = 0x8000
_F_USED, _F_INDEX, _F_IXDELE, _F_DELET = 0x01, 0x04, 0x40, 0x80
_HDR = 5
_GEOMETRIES = ((256, 4096), (256, 8192), (512, 4096), (128, 4096), (256, 65536), (512, 8192), (1024, 4096))


def _plausible(name: bytes) -> bool:
    return 2 <= len(name) < 32 and all(32 <= b < 127 for b in name) and any(chr(b).isalnum() for b in name)


class SPIFFSCarver(FilesystemCarver):
    name = "spiffs"
    maturity = "page header parse with span reassembly, checked against spiffsgen images"

    def detect(self, reader: BoundedReader) -> bool:
        head = reader.read_at(0, min(len(reader), 1024 * 1024))
        return self._choose(head)[2] >= 1

    def _choose(self, buf):
        best = (256, 4096, 0, 13)
        for page, block in _GEOMETRIES:
            if len(buf) < block:
                continue
            for name_off in (13, 10):
                score = sum(1 for _ in self._headers(buf, page, block, name_off))
                if score > best[2]:
                    best = (page, block, score, name_off)
        return best

    def _pages(self, buf, page: int, block: int):
        lookup = max(1, ((block // page) * 2) // page)
        for bstart in range(0, len(buf) - block + 1, block):
            for p in range(lookup, block // page):
                off = bstart + p * page
                obj_id, span, flags = struct.unpack_from("<HHB", buf, off)
                if obj_id == 0xFFFF or not (obj_id & 0x7FFF) or flags & _F_USED:
                    continue
                yield off, obj_id, span, flags

    def _headers(self, buf, page: int, block: int, name_off: int):
        for off, obj_id, span, flags in self._pages(buf, page, block):
            if not (obj_id & _IX_BIT) or span != 0 or flags & _F_INDEX:
                continue
            size, otype = struct.unpack_from("<IB", buf, off + name_off - 5)
            name = bytes(buf[off + name_off:off + name_off + 32]).split(b"\x00", 1)[0]
            if not _plausible(name):
                continue
            deleted = not (flags & _F_DELET) or not (flags & _F_IXDELE)
            yield off, obj_id & 0x7FFF, name.decode("ascii"), size, deleted

    def carve(self, reader: BoundedReader, stats: ScanStats) -> Iterator[Artifact]:
        buf = reader.haystack()
        page, block, _, name_off = self._choose(reader.read_at(0, min(len(reader), 1024 * 1024)))
        payload = page - _HDR
        headers: dict[int, list] = {}
        for off, obj_id, name, size, deleted in self._headers(buf, page, block, name_off):
            headers.setdefault(obj_id, []).append((off, name, size, deleted))
        spans: dict[int, dict[int, list]] = {}
        for off, obj_id, span, flags in self._pages(buf, page, block):
            if obj_id & _IX_BIT or not (flags & _F_INDEX):
                continue
            spans.setdefault(obj_id, {}).setdefault(span, []).append((off, not (flags & _F_DELET)))
            stats.records_seen += 1

        def piece(off: int) -> bytes:
            return bytes(buf[off + _HDR:off + page])

        count = 0
        for obj_id in sorted(set(headers) | set(spans)):
            by_span = spans.get(obj_id, {})
            used: set[int] = set()
            hdrs = headers.get(obj_id, [])
            live = [h for h in hdrs if not h[3]]
            groups = []
            if live:
                groups.append((live[0], ArtifactState.LIVE, False))
            for h in hdrs:
                if h[3] and (not live or h[1] != live[0][1]) and all(h[1] != g[0][1] for g in groups):
                    groups.append((h, ArtifactState.DELETED, True))
            for (hoff, name, size, _), state, want_deleted in groups:
                known = 0 < size < 0xFFFFFFFF
                total = -(-size // payload) if known else (max(by_span) + 1 if by_span else 0)
                total = min(total, Limits.MAX_ARTIFACT_BYTES // payload)
                out, ambiguous, missing = bytearray(), False, 0
                for s in range(total):
                    cands = [c for c in by_span.get(s, []) if c[0] not in used]
                    pref = [c for c in cands if c[1] == want_deleted] or cands
                    if not pref:
                        out += b"\x00" * payload
                        missing += 1
                        continue
                    ambiguous |= len(pref) > 1
                    used.add(pref[0][0])
                    out += piece(pref[0][0])
                data = bytes(out[:size]) if known else bytes(out).rstrip(b"\xff")
                note = "live object" if state == ArtifactState.LIVE else "index header carries the deleted flag"
                conf = Confidence.HIGH
                if missing:
                    conf, note = Confidence.LOW, note + f", {missing} spans missing"
                elif ambiguous:
                    conf, note = Confidence.MEDIUM, note + ", several copies of a span existed"
                count += 1
                yield Artifact(name=name.rsplit("/", 1)[-1] or name, filesystem="spiffs", state=state,
                               confidence=conf, offset=hoff, size=len(data), data=data, path=name,
                               inode=obj_id, note=f"{note}, page {page} block {block}")
            label = groups[0][0][1] if groups else f"object_{obj_id}"
            leftovers = [(s, off) for s, lst in by_span.items() for off, _ in lst if off not in used]
            for s, off in sorted(leftovers)[:Limits.MAX_VERSIONS_PER_FILE]:
                data = piece(off).rstrip(b"\xff")
                if not data:
                    continue
                state = ArtifactState.OBSOLETE if groups else ArtifactState.ORPHANED
                count += 1
                yield Artifact(name=f"{label.rsplit('/', 1)[-1]}.span{s}", filesystem="spiffs", state=state,
                               confidence=Confidence.MEDIUM, offset=off, size=len(data), data=data,
                               path=label, inode=obj_id,
                               note="a data page no current index uses, likely from an earlier version")
            if not self._guard_count(count):
                return
