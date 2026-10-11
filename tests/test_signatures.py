"""Signature carving must find the true end of each file, not a guess."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import random
import sqlite3
import struct
import zipfile
import zlib

import pytest

from revenant.core.evidence import Evidence
from revenant.core.filesystems.signature_carver import SignatureCarver
from revenant.core.models import Confidence, ScanStats


def _embed(payload: bytes, lead: int = 3000, tail: int = 5000) -> tuple[bytes, int]:
    rng = random.Random(1)
    head = bytes(rng.getrandbits(8) for _ in range(lead)).replace(b"\xff", b"\x00")
    return head + payload + b"\xff" * tail, lead


def _carve(raw: bytes):
    ev = Evidence.from_bytes(raw)
    return list(SignatureCarver().carve(ev.reader, ScanStats()))


def _png() -> bytes:
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    rows = b"".join(b"\x00" + bytes(range(16)) * 3 for _ in range(16))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 16, 16, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("notes.txt", "meeting at 10 " * 50)
        z.writestr("keys/id.txt", "k=1")
    return buf.getvalue()


def _sqlite(tmp_path) -> bytes:
    db = tmp_path / "t.db"
    con = sqlite3.connect(db)
    con.execute("create table t (a text)")
    con.executemany("insert into t values (?)", [(f"row {i}",) for i in range(200)])
    con.commit()
    con.close()
    return db.read_bytes()


def _pem() -> bytes:
    return (b"-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ3Jvc3NjaGVja2VkLWZvci1yZXZlbmFudDAK\n"
            b"BggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjUwMTAx\n-----END CERTIFICATE-----\n")


def _elf() -> bytes:
    body = bytearray(400)
    body[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", body, 16, 2, 62, 1, 0x400000, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", body, 64, 1, 5, 0, 0x400000, 0x400000, 400, 400, 0x1000)
    body[120:400] = bytes((i * 7) % 251 for i in range(280))
    return bytes(body)


CASES = {
    "png": (_png, Confidence.HIGH),
    "zip": (_zip, Confidence.HIGH),
    "gz": (lambda: gzip.compress(b"log line with detail\n" * 400), Confidence.HIGH),
    "xz": (lambda: lzma.compress(b"telemetry sample " * 300), Confidence.HIGH),
    "bz2": (lambda: bz2.compress(b"backup chunk " * 300), Confidence.HIGH),
    "pem": (_pem, Confidence.HIGH),
    "elf": (_elf, Confidence.MEDIUM),
}


@pytest.mark.parametrize("ext", sorted(CASES))
def test_exact_extraction(ext):
    make, conf = CASES[ext]
    payload = make()
    raw, at = _embed(payload)
    hits = [a for a in _carve(raw) if a.offset == at]
    assert hits, f"{ext} not found"
    assert hits[0].data == payload and hits[0].confidence == conf


def test_sqlite_exact(tmp_path):
    payload = _sqlite(tmp_path)
    raw, at = _embed(payload)
    hit = next(a for a in _carve(raw) if a.offset == at)
    assert hit.data == payload and hit.confidence == Confidence.HIGH


def test_jpeg_exact():
    pil = pytest.importorskip("PIL.Image")
    img = pil.new("RGB", (40, 30), (200, 80, 20))
    buf = io.BytesIO()
    img.save(buf, "JPEG")
    payload = buf.getvalue()
    raw, at = _embed(payload)
    hit = next(a for a in _carve(raw) if a.offset == at)
    assert hit.data == payload and hit.confidence == Confidence.HIGH


def test_junk_behind_a_magic_is_rejected():
    raw = b"\xff" * 4096 + b"\xff\xd8\xff\xe0" + b"\x00" * 64 + b"\xff" * 4096 + b"PK\x03\x04" + b"\xff" * 9000
    assert _carve(raw) == []


def test_nested_hits_inside_a_validated_file_are_skipped():
    inner = gzip.compress(b"nested " * 100)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("inner.gz", inner)
    raw, at = _embed(buf.getvalue())
    arts = _carve(raw)
    assert [a.offset for a in arts] == [at]
