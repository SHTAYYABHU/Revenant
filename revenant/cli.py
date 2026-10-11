"""Command line interface for headless and scripted use.

The desktop interface is the main way in, but an examiner often needs the same
engine inside a script, on a machine without a display, or under sudo to reach
a raw device. The command line covers those cases. It lists attached disks,
acquires a device into a verified image, and scans an image with optional
report, JSON manifest, and export outputs.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .core.disks import list_disks
from .core.engine import ScanEngine
from .core.evidence import acquire_device
from .core.export import export_artifacts
from .core.models import ArtifactState, CaseInfo
from .core.report import build_report
from .core.security import OperationCancelled, SecurityError, have_admin_rights, safe_output_path
from .version import APP_NAME, __version__

_LOGO = Path(__file__).resolve().parent / "assets" / "revenant_logo_square.png"


def _case(args) -> CaseInfo:
    return CaseInfo(case_name=args.case or "Untitled Case", examiner=args.examiner or "",
                    reference=args.reference or "", notes=args.notes or "")


def _progress(quiet: bool):
    last = [-1]

    def report(message: str, frac: float) -> None:
        pct = int(frac * 100)
        if not quiet and pct != last[0] and (pct % 10 == 0 or pct == 100):
            last[0] = pct
            print(f"  {pct:3d}%  {message}", file=sys.stderr)
    return report


def _print_result(result, limit: int) -> None:
    st = result.stats
    found = ", ".join(result.detected_filesystems) or "none by structure"
    print(f"\nDetected filesystems: {found}")
    print(f"Artifacts: {len(result.artifacts)} ({st.live_count} live, {st.recovered_count} recovered), "
          f"merged duplicates {st.merged_duplicates}, {st.duration_seconds:.2f} s")
    if result.evidence.sha256:
        print(f"Evidence SHA-256: {result.evidence.sha256}")
    order = {ArtifactState.DELETED: 0, ArtifactState.OBSOLETE: 1, ArtifactState.ORPHANED: 2,
             ArtifactState.CARVED: 3, ArtifactState.LIVE: 4}
    rows = sorted(result.artifacts, key=lambda a: (order[a.state], a.offset))
    print(f"\n{'STATE':9} {'CONF':6} {'FS':10} {'SIZE':>9} {'OFFSET':>12}  PATH OR NAME")
    for a in rows[:limit]:
        print(f"{a.state.value:9} {a.confidence.value:6} {a.filesystem:10} {a.size:>9,} {a.offset:>#12x}  {a.path or a.name}")
    if len(rows) > limit:
        print(f"... and {len(rows) - limit} more, raise --limit or use --json for the full list")


def _outputs(engine: ScanEngine, result, args) -> int:
    if args.export:
        items = result.artifacts if args.export_all else result.recovered()
        summary = export_artifacts(items, args.export, audit=engine.audit)
        print(f"Exported {summary.written} items to {summary.folder}, manifest {summary.manifest}")
    if args.json:
        path = Path(args.json)
        target = safe_output_path(path.parent, path.name)
        target.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        print(f"JSON manifest: {target}")
    if args.report:
        pdf = build_report(result, args.report, audit_entries=engine.audit.entries(),
                           logo_path=str(_LOGO) if _LOGO.exists() else None)
        print(f"PDF report: {pdf}")
    return 0


def _cmd_disks(args) -> int:
    disks = list_disks()
    if not disks:
        print("No disks found. Listing raw devices can need administrator or root rights.")
    for d in disks:
        print(f"{d.path:28} {d.human_size():>10}  {d.model} {'removable' if d.removable else ''} {d.note}".rstrip())
    if not have_admin_rights():
        print("\nReading a raw device needs administrator or root rights. Run the acquire command elevated.")
    return 0


def _cmd_scan(args) -> int:
    engine = ScanEngine()
    result = engine.scan_image(args.image, case=_case(args), progress=_progress(args.quiet),
                               compute_hash=not args.no_hash)
    _print_result(result, args.limit)
    return _outputs(engine, result, args)


def _cmd_acquire(args) -> int:
    length = args.length
    if length is None:
        length = next((d.size_bytes for d in list_disks() if d.path == args.device and d.size_bytes), None)
    if args.scan:
        engine = ScanEngine()
        result = engine.scan_disk(args.device, args.output, length=length, case=_case(args),
                                  progress=_progress(args.quiet))
        verdict = "verified" if result.evidence.verified else "HASH MISMATCH"
        print(f"Acquired {result.evidence.size_bytes:,} bytes into {args.output}, {verdict}")
        _print_result(result, args.limit)
        return _outputs(engine, result, args)
    info = acquire_device(args.device, args.output, length=length,
                          progress=None if args.quiet else (lambda f: None))
    print(f"Acquired {info['bytes']:,} bytes into {info['image']}")
    print(f"SHA-256 {info['sha256']}\nMD5     {info['md5']}")
    return 0


def _add_common(p) -> None:
    p.add_argument("--case", help="case name for the report")
    p.add_argument("--examiner")
    p.add_argument("--reference")
    p.add_argument("--notes")
    p.add_argument("--report", metavar="FOLDER", help="write a PDF report into this folder")
    p.add_argument("--json", metavar="FILE", help="write a JSON manifest of every artifact")
    p.add_argument("--export", metavar="FOLDER", help="export recovered items with a hashed manifest")
    p.add_argument("--export-all", action="store_true", help="export live files too")
    p.add_argument("--limit", type=int, default=40, help="rows to print in the result table")
    p.add_argument("-q", "--quiet", action="store_true", help="hide progress lines")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="revenant-cli",
        description=f"{APP_NAME} {__version__} recovers deleted and superseded data from raw flash images.")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="show engine log messages")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("disks", help="list attached disks")
    p.set_defaults(func=_cmd_disks)

    p = sub.add_parser("scan", help="scan an image file")
    p.add_argument("image")
    p.add_argument("--no-hash", action="store_true", help="skip hashing the image before the scan")
    _add_common(p)
    p.set_defaults(func=_cmd_scan)

    p = sub.add_parser("acquire", help="copy a device into a new image file with hashes")
    p.add_argument("device", help="for example /dev/sdb, /dev/mtd0 or \\\\.\\PhysicalDrive1")
    p.add_argument("output", help="new image file, never overwritten")
    p.add_argument("--length", type=int, help="bytes to copy, defaults to the device size when known")
    p.add_argument("--scan", action="store_true", help="scan the verified image straight away")
    _add_common(p)
    p.set_defaults(func=_cmd_acquire)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s %(message)s")
    try:
        return args.func(args)
    except (SecurityError, OperationCancelled, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted, any partial image was removed", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
