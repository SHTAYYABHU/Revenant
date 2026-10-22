"""Data models shared by the engine, the interface, the command line, and the report.

Everything the engine produces is a plain dataclass, which keeps results easy
to serialise, test, and pass to the interface without hidden state.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from ..version import CASE_SCHEMA


class ArtifactState(str, Enum):
    """Where a recovered item stood at the moment the image was taken."""

    LIVE = "live"            # still part of the active filesystem
    OBSOLETE = "obsolete"    # an older version that a later write superseded
    DELETED = "deleted"      # removed from the active filesystem
    ORPHANED = "orphaned"    # parent is gone, so the path is partial
    CARVED = "carved"        # found by raw signature with no filesystem context


class Confidence(str, Enum):
    """How much trust to place in a single recovered item."""

    HIGH = "high"            # structure and checksums line up
    MEDIUM = "medium"        # looks complete but part of it is unverified
    LOW = "low"              # partial, damaged, or possibly overwritten


@dataclass
class Artifact:
    """One recovered thing, with enough provenance to defend it later."""

    name: str
    filesystem: str
    state: ArtifactState
    confidence: Confidence
    offset: int
    size: int
    data: bytes = field(default=b"", repr=False)
    path: Optional[str] = None
    inode: Optional[int] = None
    mtime: Optional[str] = None
    sha256: Optional[str] = None
    note: Optional[str] = None

    def finalise(self) -> "Artifact":
        """Fill in the hash once the payload is known. Safe to call twice."""
        if self.data and not self.sha256:
            self.sha256 = hashlib.sha256(self.data).hexdigest()
        if self.size == 0 and self.data:
            self.size = len(self.data)
        return self

    def preview_text(self, limit: int = 240) -> str:
        """A short printable preview, with anything unprintable shown as a dot."""
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in self.data[:limit])
        if len(self.data) > limit:
            text += " ..."
        return text

    def hex_preview(self, limit: int = 512) -> str:
        """A classic offset, hex, and text dump of the first bytes."""
        lines = []
        chunk = self.data[:limit]
        for i in range(0, len(chunk), 16):
            row = chunk[i:i + 16]
            hexpart = " ".join(f"{b:02x}" for b in row)
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
            lines.append(f"{i:08x}  {hexpart:<47}  {text}")
        if len(self.data) > limit:
            lines.append(f"... {len(self.data) - limit:,} more bytes")
        return "\n".join(lines)

    def to_row(self) -> dict:
        """A flat dict for tables and manifests, without the raw bytes."""
        d = asdict(self)
        d.pop("data", None)
        d["state"] = self.state.value
        d["confidence"] = self.confidence.value
        return d


@dataclass
class ScanStats:
    """Counters gathered during a scan, shown in the summary and the report."""

    bytes_scanned: int = 0
    records_seen: int = 0
    live_count: int = 0
    recovered_count: int = 0
    false_positive_guard: int = 0      # candidate records rejected by validation
    merged_duplicates: int = 0         # carved copies of content already recovered
    duration_seconds: float = 0.0
    cancelled: bool = False

    def register(self, art: Artifact) -> None:
        if art.state == ArtifactState.LIVE:
            self.live_count += 1
        else:
            self.recovered_count += 1


@dataclass
class EvidenceInfo:
    """Identity and integrity record for the source under examination."""

    source_kind: str                    # "image" or "disk"
    source_path: str
    size_bytes: int
    sha256: Optional[str] = None
    md5: Optional[str] = None
    acquired_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    read_only: bool = True
    device_path: Optional[str] = None   # set when the image came from an attached device
    acquired_image: Optional[str] = None
    verified: Optional[bool] = None     # acquisition hash matched a fresh hash of the image


@dataclass
class CaseInfo:
    """The human context around a scan, all optional free text."""

    case_name: str = "Untitled Case"
    examiner: str = ""
    reference: str = ""
    notes: str = ""
    created_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ScanResult:
    """The complete output of one scan, ready for the report writer."""

    case: CaseInfo
    evidence: EvidenceInfo
    detected_filesystems: list[str] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    engine_version: str = ""

    def recovered(self) -> list[Artifact]:
        return [a for a in self.artifacts if a.state != ArtifactState.LIVE]

    def to_dict(self) -> dict:
        """A JSON friendly manifest of the whole result, without payload bytes."""
        return {
            "schema": CASE_SCHEMA,
            "engine_version": self.engine_version,
            "case": asdict(self.case),
            "evidence": asdict(self.evidence),
            "detected_filesystems": list(self.detected_filesystems),
            "stats": asdict(self.stats),
            "artifacts": [a.to_row() for a in self.artifacts],
        }
