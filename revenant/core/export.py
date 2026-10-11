"""Write recovered items to disk together with a manifest.

Each item is written under a sanitised name inside the chosen folder, read back,
and hashed again, so the manifest records not only what was exported but that
the bytes on disk match the bytes that were recovered. Strings in the manifest
are neutralised against spreadsheet formula injection, since recovered names
are attacker controlled.
"""

from __future__ import annotations

import csv
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from .models import Artifact
from .security import AuditLog, csv_safe, safe_output_path

MANIFEST_FIELDS = [
    "exported_file", "original_name", "path", "filesystem", "state", "confidence",
    "offset_hex", "size", "sha256", "verified_after_write", "note",
]


@dataclass
class ExportSummary:
    written: int
    skipped: int
    manifest: Optional[Path]
    folder: Path


def export_artifacts(artifacts: Iterable[Artifact], folder, audit: Optional[AuditLog] = None) -> ExportSummary:
    folder = Path(folder)
    rows = []
    written = skipped = 0
    for art in artifacts:
        if not art.data:
            skipped += 1
            continue
        art.finalise()
        target = safe_output_path(folder, f"{art.state.value}_{art.name}")
        with open(target, "xb") as fh:
            fh.write(art.data)
        check = hashlib.sha256(target.read_bytes()).hexdigest()
        rows.append({
            "exported_file": target.name,
            "original_name": csv_safe(art.name),
            "path": csv_safe(art.path or ""),
            "filesystem": art.filesystem,
            "state": art.state.value,
            "confidence": art.confidence.value,
            "offset_hex": f"0x{art.offset:x}",
            "size": len(art.data),
            "sha256": check,
            "verified_after_write": "yes" if check == art.sha256 else "NO",
            "note": csv_safe(art.note or ""),
        })
        written += 1
        if audit:
            audit.record("export", f"{target.name} {len(art.data)} bytes sha256 {check}")
    manifest = None
    if rows:
        manifest = safe_output_path(folder, "revenant_manifest.csv")
        with open(manifest, "x", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=MANIFEST_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        if audit:
            audit.record("manifest", manifest.name)
    return ExportSummary(written, skipped, manifest, folder)
