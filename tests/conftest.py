"""Shared fixtures. The demo images ship in samples and are rebuilt if missing."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
DEMOS = ["littlefs_demo.img", "jffs2_demo.img", "ubifs_demo.img", "spiffs_demo.img"]
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def samples() -> Path:
    missing = [n for n in DEMOS if not (SAMPLES / n).exists() or not (SAMPLES / f"{n}.truth.json").exists()]
    if missing:
        try:
            from tools import make_test_images
            make_test_images.main()
        except ImportError as exc:  # littlefs-python is a development dependency
            pytest.skip(f"demo images missing and cannot be rebuilt: {exc}")
    return SAMPLES


def load_truth(name: str) -> dict:
    return json.loads((SAMPLES / f"{name}.truth.json").read_text())
