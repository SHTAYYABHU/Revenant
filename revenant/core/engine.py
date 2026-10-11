"""The scan engine, which drives an examination from evidence to result.

The engine stays thin on purpose. It opens the evidence read only, asks the
detector which carvers apply, runs each one inside the shared limits, and
gathers everything into one result for the interface, the command line, and
the report. It writes the audit trail as it goes, so the chain of custody is
captured while the work happens rather than pieced together afterwards.
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Optional

from .evidence import Evidence, acquire_device
from .filesystems.detect import select_carvers
from .models import Artifact, ArtifactState, CaseInfo, ScanResult, ScanStats
from .security import AuditLog, Limits, SecurityError, clean_display_name
from ..version import __version__

log = logging.getLogger("revenant.engine")

ProgressFn = Callable[[str, float], None]

# Beyond this many pairwise checks the duplicate merge relies on hashes alone.
_CONTAINMENT_BUDGET = 2_000_000


def merge_duplicates(artifacts: list[Artifact]) -> tuple[list[Artifact], int]:
    """Drop signature carves whose bytes a filesystem carver already recovered.

    The signature carver sees raw bytes with no idea that a parser has already
    placed them in a file, so the same content can surface twice. Keeping the
    filesystem result is better because it carries a name, a path, and a state.
    """
    structured = [a for a in artifacts if a.filesystem != "signatures" and a.data]
    carved = [a for a in artifacts if a.filesystem == "signatures" and a.data]
    if not structured or not carved:
        return artifacts, 0
    hashes = {a.sha256 for a in structured if a.sha256}
    use_contains = len(structured) * len(carved) <= _CONTAINMENT_BUDGET
    kept, merged = [], 0
    for art in artifacts:
        if art.filesystem == "signatures" and art.data:
            if art.sha256 in hashes or (use_contains and any(
                    len(s.data) >= len(art.data) and art.data in s.data for s in structured)):
                merged += 1
                continue
        kept.append(art)
    return kept, merged


class ScanEngine:
    """Runs one examination and returns a ScanResult."""

    def __init__(self, audit: Optional[AuditLog] = None):
        self.audit = audit or AuditLog()

    def scan_image(self, path, case: Optional[CaseInfo] = None, progress: Optional[ProgressFn] = None,
                   compute_hash: bool = True, cancel=None) -> ScanResult:
        case = case or CaseInfo()
        self.audit.record("open_image", str(path))
        with Evidence.from_image(str(path), compute_hash=compute_hash) as ev:
            if ev.info.sha256:
                self.audit.record("hash_image", f"sha256 {ev.info.sha256}")
            return self._run(ev, case, progress, cancel)

    def scan_bytes(self, data: bytes, case: Optional[CaseInfo] = None, progress: Optional[ProgressFn] = None,
                   label: str = "in-memory", cancel=None) -> ScanResult:
        case = case or CaseInfo()
        self.audit.record("open_bytes", f"{label} ({len(data)} bytes)")
        with Evidence.from_bytes(data, label=label) as ev:
            return self._run(ev, case, progress, cancel)

    def scan_disk(self, device_path: str, image_path: str, length: Optional[int] = None,
                  case: Optional[CaseInfo] = None, progress: Optional[ProgressFn] = None,
                  cancel=None) -> ScanResult:
        """Acquire a device into an image file, verify the copy, then scan it."""
        case = case or CaseInfo()
        self.audit.record("acquire_start", f"{device_path} into {image_path}")

        def acq_progress(frac: float) -> None:
            if progress:
                progress("Acquiring the device into an image file", 0.45 * frac)

        acq = acquire_device(device_path, image_path, length=length, progress=acq_progress, cancel=cancel)
        self.audit.record("acquire_done", f"{acq['bytes']} bytes, sha256 {acq['sha256']}")

        def scan_progress(msg: str, frac: float) -> None:
            if progress:
                progress(msg, 0.5 + 0.5 * frac)

        with Evidence.from_image(str(image_path), compute_hash=True) as ev:
            verified = ev.info.sha256 == acq["sha256"]
            self.audit.record("acquire_verify", "hash match" if verified else "hash MISMATCH")
            ev.info.source_kind = "disk"
            ev.info.device_path = device_path
            ev.info.acquired_image = str(image_path)
            ev.info.verified = verified
            return self._run(ev, case, scan_progress, cancel)

    def _run(self, ev: Evidence, case: CaseInfo, progress: Optional[ProgressFn], cancel) -> ScanResult:
        started = time.time()
        reader = ev.reader

        def tick(msg: str, frac: float) -> None:
            if progress:
                try:
                    progress(msg, max(0.0, min(1.0, frac)))
                except Exception:
                    pass

        def cancelled() -> bool:
            return cancel is not None and cancel.is_set()

        tick("Detecting filesystems", 0.02)
        carvers, names = select_carvers(reader)
        self.audit.record("detect", ", ".join(names) if names else "none by structure")

        result = ScanResult(case=case, evidence=ev.info, detected_filesystems=names,
                            engine_version=__version__)
        stats = ScanStats(bytes_scanned=len(reader))
        total = max(1, len(carvers))
        for i, carver in enumerate(carvers):
            if cancelled():
                stats.cancelled = True
                break
            tick(f"Scanning with {carver.name}", 0.05 + 0.9 * i / total)
            self.audit.record("carve_start", carver.name)
            produced = 0
            try:
                for art in carver.carve(reader, stats):
                    if cancelled():
                        stats.cancelled = True
                        break
                    art.name = clean_display_name(art.name)
                    if art.path:
                        art.path = clean_display_name(art.path, limit=4096)
                    art.finalise()
                    result.artifacts.append(art)
                    produced += 1
                    if len(result.artifacts) >= Limits.MAX_ARTIFACTS:
                        self.audit.record("limit", "artifact ceiling reached")
                        break
            except SecurityError as exc:
                # A guardrail stopped this carver. Record it and carry on with the rest.
                log.warning("security guard in %s: %s", carver.name, exc)
                self.audit.record("carve_guard", f"{carver.name}: {exc}")
            except Exception as exc:
                log.exception("carver %s failed", carver.name)
                self.audit.record("carve_error", f"{carver.name}: {exc}")
            self.audit.record("carve_done", f"{carver.name}: {produced} artifacts")
            if len(result.artifacts) >= Limits.MAX_ARTIFACTS:
                break

        result.artifacts, merged = merge_duplicates(result.artifacts)
        stats.merged_duplicates = merged
        if merged:
            self.audit.record("merge", f"{merged} carved copies of already recovered content merged")
        stats.live_count = sum(1 for a in result.artifacts if a.state == ArtifactState.LIVE)
        stats.recovered_count = len(result.artifacts) - stats.live_count
        stats.duration_seconds = time.time() - started
        result.stats = stats
        if stats.cancelled:
            self.audit.record("scan_cancelled", "partial result kept")
        self.audit.record("scan_complete",
                          f"{len(result.artifacts)} artifacts, {stats.recovered_count} recovered")
        tick("Done", 1.0)
        return result
