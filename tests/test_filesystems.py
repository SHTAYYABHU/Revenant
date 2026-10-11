"""Filesystem carvers scored against ground truth, plus targeted format checks."""

from __future__ import annotations

import hashlib
import struct

import pytest

from conftest import DEMOS, load_truth
from revenant.core.engine import ScanEngine
from revenant.core.evidence import Evidence
from revenant.core.filesystems.jffs2 import JFFS2Carver, _Node, replay_versions
from revenant.core.filesystems.littlefs import LittleFSCarver, walk_commits
from revenant.core.filesystems.ubifs import UBIFSCarver
from revenant.core.filesystems.yaffs import YAFFSCarver
from revenant.core.models import ArtifactState, Confidence, ScanStats
from tools.workload import JFFS2Writer, UBIFSWriter


def _carve(carver, raw: bytes):
    ev = Evidence.from_bytes(raw)
    stats = ScanStats()
    arts = [a.finalise() for a in carver.carve(ev.reader, stats)] if carver.detect(ev.reader) else []
    return arts, stats


@pytest.mark.parametrize("name", DEMOS)
def test_demo_truth_recovered_with_state_and_exact_bytes(samples, name):
    truth = load_truth(name)
    result = ScanEngine().scan_image(str(samples / name))
    assert truth["filesystem"] in result.detected_filesystems
    for item in truth["items"]:
        if not item["survives"]:
            continue
        hits = [a for a in result.artifacts if item["token"].encode() in a.data]
        assert any(a.state.value == item["state"] for a in hits), f"{item['path']} not found as {item['state']}"
        assert any(a.sha256 == item["sha256"] for a in hits), f"{item['path']} not byte exact"


def test_littlefs_rejects_a_commit_with_a_bad_crc(samples):
    raw = bytearray((samples / "littlefs_demo.img").read_bytes())
    block = bytes(raw[4096:8192])
    tags, commits = walk_commits(block)
    assert commits >= 2
    first_data = tags[0][1]
    corrupted = bytearray(block)
    corrupted[first_data] ^= 0x40
    _, after = walk_commits(bytes(corrupted))
    assert after < commits


def test_littlefs_realistic_workload_has_full_recall():
    pytest.importorskip("littlefs")
    from tools.run_benchmark import evaluate
    from tools.workload import littlefs_workload

    raw, tracker, _ = littlefs_workload(3, ops=60, churn=0)
    truth = tracker.truth("t.img", "littlefs", "test")
    score = evaluate(ScanEngine().scan_bytes(raw), truth, raw)
    for state in ("deleted", "obsolete", "live"):
        rec = score["states"][state]
        assert rec["found"] == rec["survived"] == rec["total"]
        assert rec["labelled"] == rec["found"] and rec["exact"] == rec["found"]
    assert score["unattributed"] == 0


def test_littlefs_orphaned_chains_are_recovered_after_churn():
    pytest.importorskip("littlefs")
    from tools.run_benchmark import evaluate
    from tools.workload import littlefs_workload

    raw, tracker, _ = littlefs_workload(5, ops=60, churn=200)
    truth = tracker.truth("t.img", "littlefs", "test")
    result = ScanEngine().scan_bytes(raw)
    score = evaluate(result, truth, raw)
    for state in ("deleted", "obsolete"):
        assert score["states"][state]["found"] == score["states"][state]["survived"]
    assert any(a.state == ArtifactState.ORPHANED for a in result.artifacts)


def test_littlefs_high_confidence_is_always_exact():
    pytest.importorskip("littlefs")
    from tools.workload import littlefs_workload

    raw, tracker, _ = littlefs_workload(8, ops=60, churn=800)
    hashes = {hashlib.sha256(v.content).hexdigest() for v in tracker.versions}
    result = ScanEngine().scan_bytes(raw)
    high = [a for a in result.artifacts if a.filesystem == "littlefs" and a.confidence == Confidence.HIGH]
    assert high and all(a.sha256 in hashes for a in high)


def test_jffs2_replay_respects_truncation_and_holes():
    nodes = [
        _Node(5, 1, 0, 10, b"AAAAAAAAAA", 0, 0, True, False, 0),
        _Node(5, 2, 0, 4, b"", 0, 0, True, False, 0),
        _Node(5, 3, 8, 12, b"BBBB", 0, 0, True, False, 0),
    ]
    final, snapshots = replay_versions(nodes)
    assert final == b"AAAA\x00\x00\x00\x00BBBB"
    assert snapshots == [(1, b"AAAAAAAAAA")]


def test_jffs2_node_with_bad_header_crc_is_skipped():
    w = JFFS2Writer()
    ino = w.new_ino()
    first = w.inode(ino, b"payload that should vanish", 0, 26)
    w.dirent(1, ino, "a.txt")
    keep = w.new_ino()
    w.write_file(keep, b"payload that must survive")
    w.dirent(1, keep, "b.txt")
    raw = bytearray(w.image())
    raw[first + 8] ^= 0xFF  # damage only the first node's header CRC
    arts, stats = _carve(JFFS2Carver(), bytes(raw))
    assert stats.false_positive_guard >= 1
    assert not any(b"payload that should vanish" in a.data for a in arts)
    assert any(a.data == b"payload that must survive" for a in arts)


def test_jffs2_big_endian_images_are_read():
    w = JFFS2Writer()
    ino = w.new_ino()
    w.write_file(ino, b"little endian only")
    w.dirent(1, ino, "x")
    assert _carve(JFFS2Carver(), w.image())[0]


def test_ubifs_truncation_leaves_a_stale_block():
    w = UBIFSWriter()
    w.ino(1, 0, nlink=2, mode=0o040755)
    body = bytes(range(256)) * 24  # 6144 bytes, two blocks
    w.ino(70, len(body))
    w.data(70, 0, body[:4096])
    w.data(70, 1, body[4096:])
    w.dent(1, "trunc.bin", 70)
    w.ino(70, 100)
    arts, _ = _carve(UBIFSCarver(), w.image())
    live = [a for a in arts if a.state == ArtifactState.LIVE]
    stale = [a for a in arts if a.state == ArtifactState.OBSOLETE]
    assert live and live[0].data == body[:100]
    assert stale and stale[0].data == body[4096:]


def _yaffs_header(otype: int, parent: int, name: str, size: int = 0) -> bytes:
    hdr = bytearray(b"\xff" * 2048)
    struct.pack_into("<II", hdr, 0, otype, parent)
    struct.pack_into("<H", hdr, 8, 0xFFFF)
    nb = name.encode()
    hdr[10:10 + 256] = nb + b"\x00" * (256 - len(nb))
    struct.pack_into("<I", hdr, 284, 1_750_000_000)
    struct.pack_into("<I", hdr, 292, size)
    return bytes(hdr)


def test_yaffs_headers_and_deletion_markers():
    raw = (_yaffs_header(3, 1, "etc") + _yaffs_header(1, 257, "shadow", 120)
           + _yaffs_header(1, 3, "deleted_note.txt", 44) + b"\xff" * 2048)
    arts, _ = _carve(YAFFSCarver(), raw)
    states = {a.name: a.state for a in arts}
    assert states["deleted_note.txt"] == ArtifactState.DELETED
    assert states["shadow"] == ArtifactState.CARVED
    assert all(a.mtime and a.mtime.startswith("2025") for a in arts)


def test_blank_and_random_images_produce_no_filesystem_items():
    import random

    rng = random.Random(4)
    for raw in (b"\xff" * 65536, bytes(rng.getrandbits(8) for _ in range(65536))):
        result = ScanEngine().scan_bytes(raw)
        assert result.detected_filesystems == []
        assert not [a for a in result.artifacts if a.filesystem != "signatures"]
