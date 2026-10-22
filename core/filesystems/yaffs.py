"""YAFFS carver.

YAFFS2 keeps an object header chunk for every file and directory, while the
tags that tie data chunks to their objects normally live in the spare area of
each NAND page. An image captured without that spare area loses the tags, so
data chunks cannot be tied back to files with any certainty. The object
headers survive either way, and they carry the name, the type, the parent, the
recorded size, and the modification time.

This carver recovers what it can stand behind. It reads object headers on
chunk boundaries, with and without spare bytes in the layout. When a file is
unlinked, YAFFS rewrites its header under the unlinked or deleted pseudo
directories, and those headers are reported as deleted. Content is left to the
signature carver instead of being guessed, which keeps the output honest.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Iterator, Optional

from ..models import Artifact, ArtifactState, Confidence, ScanStats
from ..security import BoundedReader
from .base import FilesystemCarver

_TYPES = {1: "file", 2: "symlink", 3: "directory", 4: "hardlink", 5: "special"}
_UNLINKED, _DELETED_DIR = 3, 4
_CHUNKS = (2048, 2112, 512, 528, 4096, 4224, 1024, 1056)
_NAME_OFF, _NAME_LEN = 10, 256
_MTIME_OFF, _SIZE_OFF, _ALIAS_OFF = 284, 292, 300


def _header(buf, off: int) -> Optional[tuple]:
    if off + 460 > len(buf):
        return None
    otype, parent = struct.unpack_from("<II", buf, off)
    if otype not in _TYPES or parent == 0 or parent > 0x3FFFF:
        return None
    raw = bytes(buf[off + _NAME_OFF:off + _NAME_OFF + _NAME_LEN])
    name = raw.split(b"\x00", 1)[0]
    if not name or len(name) >= _NAME_LEN or any(b < 32 or b == 127 for b in name):
        return None
    mtime, size = struct.unpack_from("<II", buf, off + _MTIME_OFF)[0], struct.unpack_from("<I", buf, off + _SIZE_OFF)[0]
    alias = b""
    if otype == 2:
        alias = bytes(buf[off + _ALIAS_OFF:off + _ALIAS_OFF + 160]).split(b"\x00", 1)[0]
    return otype, parent, name.decode("utf-8", "replace"), mtime, size, alias


class YAFFSCarver(FilesystemCarver):
    name = "yaffs"
    maturity = "object header recovery, data reassembly needs the spare area tags"

    def _best_chunk(self, buf) -> tuple[int, int]:
        best = (2048, 0)
        for chunk in _CHUNKS:
            hits = sum(1 for off in range(0, len(buf) - chunk + 1, chunk) if _header(buf, off))
            if hits > best[1]:
                best = (chunk, hits)
        return best

    def detect(self, reader: BoundedReader) -> bool:
        return self._best_chunk(reader.read_at(0, min(len(reader), 512 * 1024)))[1] >= 2

    def carve(self, reader: BoundedReader, stats: ScanStats) -> Iterator[Artifact]:
        buf = reader.haystack()
        chunk, _ = self._best_chunk(reader.read_at(0, min(len(reader), 4 * 1024 * 1024)))
        count = 0
        for off in range(0, len(buf) - chunk + 1, chunk):
            hdr = _header(buf, off)
            if hdr is None:
                continue
            otype, parent, name, mtime, size, alias = hdr
            stats.records_seen += 1
            note = f"yaffs {_TYPES[otype]} header, parent object {parent}"
            if otype == 1:
                note += f", recorded size {size}"
            if parent in (_UNLINKED, _DELETED_DIR):
                state = ArtifactState.DELETED
                note += ", filed under the unlinked or deleted pseudo directory"
            else:
                state = ArtifactState.CARVED
            stamp = None
            if 946684800 <= mtime <= 4102444800:  # between 2000 and 2100
                stamp = datetime.fromtimestamp(mtime, timezone.utc).isoformat()
            count += 1
            yield Artifact(name=name, filesystem="yaffs", state=state, confidence=Confidence.LOW,
                           offset=off, size=len(alias), data=alias, path=name, mtime=stamp, note=note)
            if not self._guard_count(count):
                return
