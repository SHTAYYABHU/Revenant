"""A small benchmark run end to end, so the harness itself stays honest."""

from __future__ import annotations

import pytest

from tools import run_benchmark


def test_small_benchmark_writes_outputs(tmp_path):
    pytest.importorskip("littlefs")
    rows = run_benchmark.littlefs_suite(range(2), 40, [0, 100]) + run_benchmark.jffs2_suite(range(2), 40)
    summary = run_benchmark.aggregate(rows)
    for s in summary.values():
        assert s["recall_of_surviving"] == 1.0
        assert s["baseline_recall_of_surviving"] in (0.0, None)
    assert summary["littlefs|0"]["exact_rate"] == 1.0
    files = run_benchmark.write_outputs(rows, summary, tmp_path, plot=False)
    assert {f.name for f in files} == {"results.csv", "summary.json", "summary.md"}


def test_demo_samples_score_perfectly(samples):
    rows = run_benchmark.external_suite(samples, "samples")
    s = run_benchmark.aggregate(rows)["samples|0"]
    assert s["recall_of_surviving"] == 1.0 and s["exact_rate"] == 1.0 and s["unattributed_items"] == 0
