"""The guardrails that keep hostile evidence from harming the examiner's machine."""

from __future__ import annotations

import hashlib
import mmap
import os
import zlib
from pathlib import Path

import pytest

from revenant.core.evidence import Evidence
from revenant.core.security import (
    AuditLog, BoundedReader, SecurityError, clean_display_name, csv_safe, inflate_bounded,
    safe_output_path, sanitise_filename, validate_source_path,
)


@pytest.mark.parametrize("name,expected", [
    ("../../etc/passwd", "passwd"),
    ("..\\..\\windows\\system32\\cmd.exe", "cmd.exe"),
    ("CON", "_CON"),
    ("", "recovered.bin"),
    ("rep ort<1>.txt", "rep_ort_1_.txt"),
])
def test_sanitise_filename(name, expected):
    assert sanitise_filename(name) == expected


def test_safe_output_path_never_clobbers(tmp_path):
    first = safe_output_path(tmp_path, "a.txt")
    first.write_text("x")
    second = safe_output_path(tmp_path, "a.txt")
    assert second != first and second.parent == tmp_path.resolve()


def test_display_names_lose_control_characters():
    assert clean_display_name("bad\x1b[31mname\n") == "bad?[31mname?"
    assert len(clean_display_name("x" * 5000)) == 255


def test_csv_formula_injection_is_neutralised():
    assert csv_safe("=HYPERLINK(\"http://x\")").startswith("'=")
    assert csv_safe("normal.txt") == "normal.txt"


def test_decompression_bomb_is_capped():
    bomb = zlib.compress(b"\x00" * (64 * 1024 * 1024))
    out = inflate_bounded(bomb, 15, 1024 * 1024)
    assert out is not None and len(out) <= 1024 * 1024


def test_reader_bounds_and_read_only_haystack(tmp_path):
    img = tmp_path / "e.img"
    img.write_bytes(b"\xab" * 8192)
    with Evidence.from_image(str(img)) as ev:
        with pytest.raises(SecurityError):
            ev.reader.read_at(9000, 4)
        assert ev.reader.read_at(8190, 100) == b"\xab\xab"
        hay = ev.reader.haystack()
        assert isinstance(hay, (bytes, mmap.mmap))
        with pytest.raises(TypeError):
            hay[0] = 1


def test_scanning_never_changes_the_evidence(samples):
    from revenant.core.engine import ScanEngine

    img = samples / "jffs2_demo.img"
    before = (hashlib.sha256(img.read_bytes()).hexdigest(), os.stat(img).st_mtime_ns)
    ScanEngine().scan_image(str(img))
    assert (hashlib.sha256(img.read_bytes()).hexdigest(), os.stat(img).st_mtime_ns) == before


def test_source_validation(tmp_path):
    with pytest.raises(SecurityError):
        validate_source_path(str(tmp_path / "missing.img"))
    empty = tmp_path / "empty.img"
    empty.write_bytes(b"")
    with pytest.raises(SecurityError):
        validate_source_path(str(empty))


def test_audit_log_is_append_only_and_cleans_detail():
    log = AuditLog()
    log.record("open", "a\x07b")
    entries = log.entries()
    entries.clear()
    assert log.entries()[0]["detail"] == "a?b"
