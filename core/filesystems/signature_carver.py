"""A universal carver that finds known file types by their signatures.

This carver ignores filesystems entirely. It searches the raw image for the
magic bytes of common formats and then works out where each file really ends,
which is exactly what you want for content left in regions the filesystem has
forgotten. Finding the end properly is most of the job. PNG chunks and JPEG
markers are walked, ZIP archives are closed with their end record, compressed
streams are decoded to their trailer, and SQLite and ELF sizes come from their
headers. A find whose structure validates end to end is marked high, one whose
end came from a footer or a size field is marked medium, and a bounded slice
with no reliable end is marked low.

The search runs in native code through the image's own find method, so a large
image is scanned in seconds rather than minutes, and every payload is bounded.
"""

from __future__ import annotations

import bz2
import lzma
import re
import struct
import zlib
from typing import Iterator, Optional

from ..models import Artifact, ArtifactState, Confidence, ScanStats
from ..security import BoundedReader, Limits
from .base import FilesystemCarver

_FALLBACK = 256 * 1024
_NOT_TEXT = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\xff]")


def _png(buf, pos, limit):
    end_limit = min(len(buf), pos + limit)
    p = pos + 8
    while p + 12 <= end_limit:
        length = int.from_bytes(buf[p:p + 4], "big")
        ctype = bytes(buf[p + 4:p + 8])
        if not ctype.isalpha() or length > limit:
            return None
        p += 12 + length
        if ctype == b"IEND":
            return (p, Confidence.HIGH) if p <= end_limit else None
    return None


def _jpeg(buf, pos, limit):
    if not (0xC0 <= buf[pos + 3] <= 0xFE):
        return None
    end = min(len(buf), pos + limit)
    p = pos + 2
    while p + 4 <= end:
        if buf[p] != 0xFF:
            return None
        marker = buf[p + 1]
        if marker == 0xFF:
            p += 1
            continue
        if marker == 0xD9:
            return p + 2, Confidence.HIGH
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            p += 2
            continue
        seglen = int.from_bytes(buf[p + 2:p + 4], "big")
        if seglen < 2:
            return None
        p += 2 + seglen
        if marker == 0xDA:
            while True:
                q = buf.find(b"\xff", p, end)
                if q == -1 or q + 1 >= end:
                    return None
                nxt = buf[q + 1]
                if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:
                    p = q + 2
                elif nxt == 0xFF:
                    p = q + 1
                else:
                    p = q
                    break
    return None


def _footer(footer: bytes, skip: int, conf=Confidence.MEDIUM):
    def measure(buf, pos, limit):
        q = buf.find(footer, pos + skip, min(len(buf), pos + limit))
        return (q + len(footer), conf) if q != -1 else None
    return measure


def _zip(buf, pos, limit):
    q = buf.find(b"PK\x05\x06", pos, min(len(buf), pos + limit))
    if q == -1 or q + 22 > len(buf):
        return None
    cd_size, cd_off, comment = struct.unpack_from("<IIH", buf, q + 12)
    conf = Confidence.HIGH if cd_off + cd_size == q - pos else Confidence.MEDIUM
    return q + 22 + comment, conf


def _gzip(buf, pos, limit):
    if buf[pos + 3] & 0xE0:
        return None
    d = zlib.decompressobj(31)
    end_limit = min(len(buf), pos + limit)
    p, produced = pos, 0
    while p < end_limit and not d.eof:
        data = bytes(buf[p:min(p + 65536, end_limit)])
        p += len(data)
        while data and not d.eof:
            try:
                produced += len(d.decompress(data, 1 << 20))
            except zlib.error:
                return None
            if produced > Limits.MAX_ARTIFACT_BYTES:
                return None
            data = d.unconsumed_tail
    return (p - len(d.unused_data), Confidence.HIGH) if d.eof else None


def _stream(factory, check=None):
    def measure(buf, pos, limit):
        if check and not check(buf, pos):
            return None
        d = factory()
        end_limit = min(len(buf), pos + limit)
        p, produced = pos, 0
        for _ in range(limit // 65536 + Limits.MAX_ARTIFACT_BYTES // (1 << 20) + 16):
            if d.eof:
                return p - len(d.unused_data), Confidence.HIGH
            data = b""
            if d.needs_input:
                if p >= end_limit:
                    return None
                data = bytes(buf[p:min(p + 65536, end_limit)])
                p += len(data)
            try:
                produced += len(d.decompress(data, 1 << 20))
            except (lzma.LZMAError, OSError, EOFError, ValueError):
                return None
            if produced > Limits.MAX_ARTIFACT_BYTES:
                return None
        return None
    return measure


def _bz2_check(buf, pos):
    return buf[pos + 3] in b"123456789" and bytes(buf[pos + 4:pos + 10]) == b"1AY&SY"


def _sqlite(buf, pos, limit):
    if pos + 100 > len(buf):
        return None
    page = int.from_bytes(buf[pos + 16:pos + 18], "big")
    page = 65536 if page == 1 else page
    if page < 512 or page & (page - 1):
        return None
    change = int.from_bytes(buf[pos + 24:pos + 28], "big")
    count = int.from_bytes(buf[pos + 28:pos + 32], "big")
    valid_for = int.from_bytes(buf[pos + 92:pos + 96], "big")
    if count == 0 or page * count > limit:
        return None
    return pos + page * count, Confidence.HIGH if valid_for == change else Confidence.MEDIUM


def _elf(buf, pos, limit):
    cls, enc, ver = buf[pos + 4], buf[pos + 5], buf[pos + 6]
    if cls not in (1, 2) or enc not in (1, 2) or ver != 1:
        return None
    e = "<" if enc == 1 else ">"
    if cls == 1:
        phoff, shoff = struct.unpack_from(e + "II", buf, pos + 28)
        phent, phnum, shent, shnum = struct.unpack_from(e + "HHHH", buf, pos + 42)
    else:
        phoff, shoff = struct.unpack_from(e + "QQ", buf, pos + 32)
        phent, phnum, shent, shnum = struct.unpack_from(e + "HHHH", buf, pos + 54)
    end = max(shoff + shent * shnum, phoff + phent * phnum)
    for i in range(min(phnum, 256)):
        ph = pos + phoff + i * phent
        if ph + phent > len(buf):
            break
        if cls == 1:
            p_off, p_size = struct.unpack_from(e + "I", buf, ph + 4)[0], struct.unpack_from(e + "I", buf, ph + 16)[0]
        else:
            p_off, p_size = struct.unpack_from(e + "Q", buf, ph + 8)[0], struct.unpack_from(e + "Q", buf, ph + 32)[0]
        end = max(end, p_off + p_size)
    if end <= 52 or end > limit:
        return None
    return pos + end, Confidence.MEDIUM


def _riff(buf, pos, limit):
    size = int.from_bytes(buf[pos + 4:pos + 8], "little")
    form = bytes(buf[pos + 8:pos + 12])
    if not form.replace(b" ", b"").isalnum() or size < 4 or 8 + size > limit:
        return None
    return pos + 8 + size + (size & 1), Confidence.MEDIUM


def _pem(buf, pos, limit):
    end_limit = min(len(buf), pos + limit)
    line_end = buf.find(b"-----", pos + 11, min(end_limit, pos + 80))
    if line_end == -1:
        return None
    label = bytes(buf[pos + 11:line_end])
    if not label or not all(65 <= c <= 90 or 48 <= c <= 57 or c == 32 for c in label):
        return None
    footer = b"-----END " + label + b"-----"
    q = buf.find(footer, line_end, end_limit)
    if q == -1:
        return None
    end = q + len(footer)
    if bytes(buf[end:end + 2]) == b"\r\n":
        end += 2
    elif bytes(buf[end:end + 1]) == b"\n":
        end += 1
    return end, Confidence.HIGH


def _text(buf, pos, limit):
    end_limit = min(len(buf), pos + limit)
    p = pos
    while p < end_limit:
        chunk = bytes(buf[p:min(p + 65536, end_limit)])
        m = _NOT_TEXT.search(chunk)
        if m:
            p += m.start()
            break
        p += len(chunk)
    last = buf.rfind(b">", pos, p)
    if last == -1:
        return None
    return last + 1, Confidence.LOW if p >= end_limit else Confidence.MEDIUM


class _Sig:
    __slots__ = ("ext", "magic", "max_len", "measure", "desc", "strong")

    def __init__(self, ext, magic, max_len, measure, desc, strong=True):
        self.ext, self.magic, self.max_len = ext, magic, max_len
        self.measure, self.desc, self.strong = measure, desc, strong


MB = 1024 * 1024
SIGNATURES = [
    _Sig("png", b"\x89PNG\r\n\x1a\n", 64 * MB, _png, "PNG image"),
    _Sig("jpg", b"\xff\xd8\xff", 32 * MB, _jpeg, "JPEG image", strong=False),
    _Sig("gif", b"GIF89a", 16 * MB, _footer(b"\x00\x3b", 13), "GIF image"),
    _Sig("gif", b"GIF87a", 16 * MB, _footer(b"\x00\x3b", 13), "GIF image"),
    _Sig("pdf", b"%PDF-", 64 * MB, _footer(b"%%EOF", 8), "PDF document"),
    _Sig("zip", b"PK\x03\x04", 128 * MB, _zip, "ZIP or ZIP based archive"),
    _Sig("gz", b"\x1f\x8b\x08", 64 * MB, _gzip, "gzip stream", strong=False),
    _Sig("xz", b"\xfd7zXZ\x00", 64 * MB, _stream(lzma.LZMADecompressor), "xz stream"),
    _Sig("bz2", b"BZh", 64 * MB, _stream(bz2.BZ2Decompressor, _bz2_check), "bzip2 stream", strong=False),
    _Sig("sqlite", b"SQLite format 3\x00", 256 * MB, _sqlite, "SQLite database"),
    _Sig("xml", b"<?xml", 8 * MB, _text, "XML document"),
    _Sig("elf", b"\x7fELF", 64 * MB, _elf, "ELF binary"),
    _Sig("riff", b"RIFF", 64 * MB, _riff, "RIFF media"),
    _Sig("pem", b"-----BEGIN ", 64 * 1024, _pem, "PEM key or certificate"),
]

_HOW = {
    Confidence.HIGH: "structure validated end to end",
    Confidence.MEDIUM: "end located from a footer or a size field",
    Confidence.LOW: "no reliable end, bounded slice kept",
}


def _mostly_blank(data: bytes) -> bool:
    return data.count(b"\xff") + data.count(b"\x00") >= 0.9 * len(data)


class SignatureCarver(FilesystemCarver):
    name = "signatures"
    maturity = "stable"

    def detect(self, reader: BoundedReader) -> bool:
        return True

    def carve(self, reader: BoundedReader, stats: ScanStats) -> Iterator[Artifact]:
        buf = reader.haystack()
        n = len(buf)
        hits = []
        for sig in SIGNATURES:
            start = 0
            while len(hits) < Limits.MAX_RECORDS:
                i = buf.find(sig.magic, start)
                if i == -1:
                    break
                hits.append((i, sig))
                start = i + 1
        hits.sort(key=lambda h: h[0])
        covered, count = -1, 0
        for pos, sig in hits:
            if pos < covered:
                continue
            art = self._extract(buf, pos, sig, n)
            if art is None:
                stats.false_positive_guard += 1
                continue
            stats.records_seen += 1
            if art.confidence == Confidence.HIGH:
                covered = pos + art.size
            count += 1
            yield art
            if not self._guard_count(count):
                return

    def _extract(self, buf, pos: int, sig: _Sig, n: int) -> Optional[Artifact]:
        try:
            res = sig.measure(buf, pos, sig.max_len) if pos + 16 <= n else None
        except (IndexError, ValueError, struct.error):
            res = None
        if res is None:
            if not sig.strong:
                return None
            end, conf = min(n, pos + _FALLBACK), Confidence.LOW
        else:
            end, conf = res
        end = min(end, n, pos + Limits.MAX_ARTIFACT_BYTES)
        payload = bytes(buf[pos:end])
        if len(payload) < 16 or (conf != Confidence.HIGH and _mostly_blank(payload)):
            return None
        return Artifact(name=f"carved_{pos:08x}.{sig.ext}", filesystem="signatures",
                        state=ArtifactState.CARVED, confidence=conf, offset=pos,
                        size=len(payload), data=payload, note=f"{sig.desc}, {_HOW[conf]}")
