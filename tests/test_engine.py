"""Engine behaviour, outputs, acquisition, and cancellation."""

from __future__ import annotations

import csv
import json
import threading

from revenant.core.engine import ScanEngine, merge_duplicates
from revenant.core.evidence import acquire_device
from revenant.core.export import export_artifacts
from revenant.core.models import Artifact, ArtifactState, CaseInfo, Confidence
from revenant.core.report import build_report


def test_progress_reaches_the_end(samples):
    seen = []
    ScanEngine().scan_image(str(samples / "littlefs_demo.img"), progress=lambda m, f: seen.append(f))
    assert seen[-1] == 1.0 and seen == sorted(seen)


def test_cancel_before_start_returns_an_empty_partial_result(samples):
    stop = threading.Event()
    stop.set()
    result = ScanEngine().scan_image(str(samples / "littlefs_demo.img"), cancel=stop)
    assert result.stats.cancelled and result.artifacts == []


def test_duplicate_merge_keeps_the_named_copy():
    named = Artifact("a.jpg", "littlefs", ArtifactState.DELETED, Confidence.MEDIUM, 0, 5, b"hello world").finalise()
    carved = Artifact("c.jpg", "signatures", ArtifactState.CARVED, Confidence.HIGH, 9, 5, b"world").finalise()
    other = Artifact("d.png", "signatures", ArtifactState.CARVED, Confidence.HIGH, 30, 5, b"other").finalise()
    kept, merged = merge_duplicates([named, carved, other])
    assert merged == 1 and kept == [named, other]


def test_json_manifest_and_report(samples, tmp_path):
    engine = ScanEngine()
    result = engine.scan_image(str(samples / "jffs2_demo.img"),
                               case=CaseInfo(case_name="Case <1>", examiner="Tester", notes="a & b"))
    doc = json.loads(json.dumps(result.to_dict()))
    assert doc["schema"] and len(doc["artifacts"]) == len(result.artifacts)
    assert all("data" not in a for a in doc["artifacts"])
    pdf = build_report(result, str(tmp_path), audit_entries=engine.audit.entries())
    assert pdf.read_bytes()[:4] == b"%PDF" and pdf.stat().st_size > 3000


def test_export_writes_verified_files_and_a_safe_manifest(tmp_path):
    arts = [Artifact("=cmd|' /C calc'!A0", "jffs2", ArtifactState.DELETED, Confidence.HIGH, 16, 4, b"data").finalise(),
            Artifact("empty", "jffs2", ArtifactState.DELETED, Confidence.LOW, 0, 0, b"")]
    summary = export_artifacts(arts, tmp_path / "out")
    assert summary.written == 1 and summary.skipped == 1
    rows = list(csv.DictReader(open(summary.manifest, encoding="utf-8")))
    assert rows[0]["verified_after_write"] == "yes"
    assert rows[0]["original_name"].startswith("'=")


def test_acquisition_from_a_device_like_file_is_verified(samples, tmp_path):
    source = samples / "spiffs_demo.img"
    image = tmp_path / "acquired.img"
    result = ScanEngine().scan_disk(str(source), str(image), length=source.stat().st_size)
    assert result.evidence.verified is True
    assert image.read_bytes() == source.read_bytes()
    assert "spiffs" in result.detected_filesystems


def test_acquisition_refuses_to_overwrite(samples, tmp_path):
    image = tmp_path / "exists.img"
    image.write_bytes(b"keep me")
    try:
        acquire_device(str(samples / "jffs2_demo.img"), str(image))
    except FileExistsError:
        pass
    assert image.read_bytes() == b"keep me"


def test_cancelled_acquisition_leaves_no_partial_image(samples, tmp_path):
    stop = threading.Event()
    stop.set()
    image = tmp_path / "partial.img"
    try:
        acquire_device(str(samples / "littlefs_demo.img"), str(image), cancel=stop)
    except Exception:
        pass
    assert not image.exists()
