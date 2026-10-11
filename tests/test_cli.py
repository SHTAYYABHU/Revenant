"""The command line drives the same engine and outputs."""

from __future__ import annotations

import json

from revenant.cli import main


def test_scan_with_every_output(samples, tmp_path, capsys):
    rc = main(["scan", str(samples / "ubifs_demo.img"), "-q", "--case", "CLI",
               "--json", str(tmp_path / "r.json"), "--report", str(tmp_path),
               "--export", str(tmp_path / "exp")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "ubifs" in out and "deleted" in out
    assert json.loads((tmp_path / "r.json").read_text())["artifacts"]
    assert (tmp_path / "revenant_report.pdf").exists()
    assert (tmp_path / "exp" / "revenant_manifest.csv").exists()


def test_missing_image_is_a_clean_error(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "nope.img"), "-q"]) == 2
    assert "error" in capsys.readouterr().err


def test_disks_command_runs():
    assert main(["disks"]) == 0
