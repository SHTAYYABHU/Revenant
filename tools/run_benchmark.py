"""Benchmark harness for Revenant, scored against exact ground truth.

Two suites run by default. The LittleFS suite drives the reference
implementation through randomised workloads followed by several amounts of
later write activity, then compares Revenant with a baseline that mounts each
image and reads the live tree, which is all a conventional extractor returns.
The JFFS2 suite checks the parser on synthetic node logs where nothing was
erased, so it measures parsing rather than survival. Any folder of images with
truth files, such as the output of the nandsim script on a Linux host, can be
added with --images.

Recovery is scored by tokens. Every version of every file starts with a unique
token, a version counts as found when its token appears in a recovered item of
the right kind, as labelled when that item also carries the right state, and
as exact when the item's hash equals the hash of the original bytes. Survival
is measured separately by searching the raw image for each token, so a version
the flash already erased is never held against the tool.

Results go to bench_results by default: results.csv with one row per image,
summary.json and summary.md with totals, and survival_vs_churn.png.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from revenant.core.engine import ScanEngine  # noqa: E402

STATES = ("deleted", "obsolete", "live")
COUNTS = ("total", "survived", "found", "labelled", "exact", "baseline", "path_seen", "path_ok")


def evaluate(result, truth: dict, raw: bytes, baseline: dict | None = None) -> dict:
    """Score one scan result against its truth file."""
    all_survive = truth.get("survival") == "all"
    # With compression on, a raw token search cannot prove survival, so anything
    # the tool found is counted as surviving. Survival is then a lower bound.
    unknown = truth.get("survival") == "unknown"
    arts = result.artifacts
    tokens = [(item, item["token"].encode()) for item in truth["items"]]
    states = {s: dict.fromkeys(COUNTS, 0) for s in STATES}
    main = dict.fromkeys(("total", "survived", "found", "baseline"), 0)
    for item, tok in tokens:
        st = item["state"]
        if st not in states:
            continue
        rec = states[st]
        rec["total"] += 1
        hits = [a for a in arts if tok in a.data]
        hits = [a for a in hits if (a.state.value == "live") == (st == "live")]
        survived = all_survive or raw.find(tok) != -1 or (unknown and bool(hits))
        in_base = baseline is not None and any(tok in data for data in baseline.values())
        rec["survived"] += survived
        rec["baseline"] += in_base
        if hits:
            rec["found"] += 1
            rec["labelled"] += any(a.state.value == st for a in hits)
            rec["exact"] += any(a.sha256 == item["sha256"] for a in hits)
            # Metadata accuracy. A remnant with a recovered path is scored on
            # whether that path matches the truth path. Orphaned remnants whose
            # parent was erased carry no path, so they are not counted as named,
            # which keeps path accuracy honest about what was recoverable at all.
            truth_path = item.get("path")
            rec["path_seen"] += any(a.path for a in hits)
            rec["path_ok"] += any(a.path == truth_path for a in hits)
        if st != "live" and item.get("phase", "main") == "main":
            main["total"] += 1
            main["survived"] += survived
            main["found"] += bool(hits)
            main["baseline"] += in_base
    unattributed = sum(
        1 for a in arts
        if a.filesystem != "signatures" and a.state.value != "live"
        and not any(tok in a.data for _, tok in tokens))
    return {"states": states, "main": main, "unattributed": unattributed, "artifacts": len(arts)}


def _row(suite: str, image: str, fs: str, seed, churn, score: dict, ms: float) -> dict:
    row = {"suite": suite, "image": image, "filesystem": fs, "seed": seed, "churn": churn,
           "artifacts": score["artifacts"], "unattributed": score["unattributed"], "scan_ms": round(ms, 1)}
    for st, rec in score["states"].items():
        for k, v in rec.items():
            row[f"{st}_{k}"] = v
    for k, v in score["main"].items():
        row[f"main_{k}"] = v
    return row


def _scan(raw: bytes, label: str):
    started = time.perf_counter()
    result = ScanEngine().scan_bytes(raw, label=label)
    return result, (time.perf_counter() - started) * 1000


def littlefs_suite(seeds, ops, churns, keep_dir=None):
    from tools.workload import littlefs_live_view, littlefs_workload

    rows = []
    for churn in churns:
        for seed in seeds:
            raw, tracker, cfg = littlefs_workload(seed, ops=ops, churn=churn)
            name = f"littlefs_s{seed}_c{churn}.img"
            truth = tracker.truth(name, "littlefs", "littlefs-python reference implementation",
                                  seed=seed, churn=churn, config=cfg)
            result, ms = _scan(raw, name)
            score = evaluate(result, truth, raw, baseline=littlefs_live_view(raw, cfg))
            rows.append(_row("littlefs", name, "littlefs", seed, churn, score, ms))
            if keep_dir:
                keep_dir.mkdir(parents=True, exist_ok=True)
                (keep_dir / name).write_bytes(raw)
                (keep_dir / f"{name}.truth.json").write_text(json.dumps(truth, indent=2))
    return rows


def jffs2_suite(seeds, ops, keep_dir=None):
    from tools.workload import jffs2_workload

    rows = []
    for seed in seeds:
        raw, tracker = jffs2_workload(seed, ops=ops)
        name = f"jffs2_s{seed}.img"
        truth = tracker.truth(name, "jffs2", "synthetic node log, no garbage collection", seed=seed)
        truth["survival"] = "all"
        result, ms = _scan(raw, name)
        rows.append(_row("jffs2", name, "jffs2", seed, 0, evaluate(result, truth, raw), ms))
        if keep_dir:
            keep_dir.mkdir(parents=True, exist_ok=True)
            (keep_dir / name).write_bytes(raw)
            (keep_dir / f"{name}.truth.json").write_text(json.dumps(truth, indent=2))
    return rows


def external_suite(folder: Path, suite: str = "external"):
    rows = []
    for img in sorted(folder.glob("*.img")):
        truth_path = img.with_name(img.name + ".truth.json")
        if not truth_path.exists():
            continue
        truth = json.loads(truth_path.read_text())
        raw = img.read_bytes()
        result, ms = _scan(raw, img.name)
        rows.append(_row(suite, img.name, truth.get("filesystem", "?"), truth.get("seed"),
                         truth.get("churn", 0), evaluate(result, truth, raw), ms))
    return rows


def _rate(num: int, den: int):
    return round(num / den, 4) if den else None


def aggregate(rows: list[dict]) -> dict:
    out = {}
    for key in sorted({(r["suite"], r["churn"]) for r in rows}, key=lambda k: (k[0], k[1] or 0)):
        group = [r for r in rows if (r["suite"], r["churn"]) == key]
        tot = {k: sum(r[k] for r in group) for k in group[0] if isinstance(group[0][k], int) and k not in ("seed", "churn")}
        rem = {c: tot.get(f"deleted_{c}", 0) + tot.get(f"obsolete_{c}", 0) for c in COUNTS}
        out[f"{key[0]}|{key[1]}"] = {
            "suite": key[0], "churn": key[1], "images": len(group),
            "remnant_versions": rem["total"],
            "survival_rate": _rate(rem["survived"], rem["total"]),
            "recall_of_surviving": _rate(rem["found"], rem["survived"]),
            "label_accuracy": _rate(rem["labelled"], rem["found"]),
            "exact_rate": _rate(rem["exact"], rem["found"]),
            "metadata_accuracy": _rate(rem["path_ok"], rem["found"]),
            "path_accuracy_where_named": _rate(rem["path_ok"], rem["path_seen"]),
            "baseline_recall_of_surviving": _rate(rem["baseline"], rem["survived"]),
            "live_recall": _rate(tot.get("live_found", 0), tot.get("live_total", 0)),
            "live_exact_rate": _rate(tot.get("live_exact", 0), tot.get("live_found", 0)),
            "unattributed_items": tot.get("unattributed", 0),
            "deleted": {c: tot.get(f"deleted_{c}", 0) for c in COUNTS},
            "obsolete": {c: tot.get(f"obsolete_{c}", 0) for c in COUNTS},
            "main_phase_survival": _rate(tot.get("main_survived", 0), tot.get("main_total", 0)),
            "median_scan_ms": round(statistics.median(r["scan_ms"] for r in group), 1),
        }
    return out


def _pct(v):
    return "n/a" if v is None else f"{100 * v:.1f}%"


def write_outputs(rows: list[dict], summary: dict, out: Path, plot: bool = True) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    written = []
    csv_path = out / "results.csv"
    fields = list(rows[0].keys())
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    written.append(csv_path)
    json_path = out / "summary.json"
    json_path.write_text(json.dumps(summary, indent=2))
    written.append(json_path)

    lines = ["# Revenant Benchmark Summary", "",
             "Rates for deleted and superseded versions. Recall and baseline recall count only",
             "versions whose bytes still existed in the image, since erased data cannot be recovered",
             "by any tool.", "",
             "| Suite | Later writes | Images | Versions | Still on flash | Recall | Labelled right | Byte exact | Path correct | Live mount baseline | Unattributed |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for s in summary.values():
        lines.append(f"| {s['suite']} | {s['churn']} | {s['images']} | {s['remnant_versions']} | "
                     f"{_pct(s['survival_rate'])} | {_pct(s['recall_of_surviving'])} | "
                     f"{_pct(s['label_accuracy'])} | {_pct(s['exact_rate'])} | "
                     f"{_pct(s['metadata_accuracy'])} | "
                     f"{_pct(s['baseline_recall_of_surviving'])} | {s['unattributed_items']} |")
    lines += ["", "Live files", "", "| Suite | Later writes | Live recall | Live byte exact | Median scan ms |",
              "|---|---|---|---|---|"]
    for s in summary.values():
        lines.append(f"| {s['suite']} | {s['churn']} | {_pct(s['live_recall'])} | "
                     f"{_pct(s['live_exact_rate'])} | {s['median_scan_ms']} |")
    md_path = out / "summary.md"
    md_path.write_text("\n".join(lines) + "\n")
    written.append(md_path)

    lfs = [r for r in rows if r["suite"] == "littlefs"]
    if plot and lfs:
        try:
            written.append(_plot(lfs, out / "survival_vs_churn.png"))
        except Exception as exc:  # plotting is optional, the numbers are not
            print(f"plot skipped: {exc}")
    return written


def _plot(rows: list[dict], path: Path) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    churns = sorted({r["churn"] for r in rows})
    xs = list(range(len(churns)))  # evenly spaced, the levels are not linear

    def series(fn):
        means, lows, highs = [], [], []
        for c in churns:
            vals = [v for v in (fn(r) for r in rows if r["churn"] == c) if v is not None]
            m = statistics.mean(vals) if vals else 0.0
            sd = statistics.pstdev(vals) if len(vals) > 1 else 0.0
            means.append(m)
            lows.append(max(0.0, m - sd))
            highs.append(min(1.0, m + sd))
        return means, lows, highs

    def rem(r, key):
        tot = r["deleted_total"] + r["obsolete_total"]
        return (r[f"deleted_{key}"] + r[f"obsolete_{key}"]) / tot if tot else None

    fig, ax = plt.subplots(figsize=(7.4, 4.4), dpi=150)
    m, lo, hi = series(lambda r: rem(r, "survived"))
    ax.plot(xs, m, color="#2f6f9f", linewidth=7, alpha=0.3, solid_capstyle="round", label="Still On Flash")
    ax.fill_between(xs, lo, hi, color="#2f6f9f", alpha=0.10, linewidth=0)
    m, _, _ = series(lambda r: rem(r, "found"))
    ax.plot(xs, m, color="#c0392b", linewidth=1.8, linestyle="--", marker="s", label="Recovered By Revenant")
    m, _, _ = series(lambda r: r["main_survived"] / r["main_total"] if r["main_total"] else None)
    ax.plot(xs, m, color="#5b8c5a", linewidth=1.6, linestyle=":", marker="o",
            label="Original Activity Still On Flash")
    m, _, _ = series(lambda r: rem(r, "baseline"))
    ax.plot(xs, m, color="#7f8c8d", linewidth=1.6, marker="^", label="Recovered By Live Mount")
    ax.set_title("Remnant Survival And Recovery In LittleFS As Writes Continue")
    ax.set_xlabel("Write Operations After The Tracked Activity")
    ax.set_ylabel("Share Of Deleted And Superseded Versions")
    ax.set_xticks(xs)
    ax.set_xticklabels([str(c) for c in churns])
    ax.set_ylim(-0.03, 1.05)
    ax.grid(alpha=0.25)
    ax.legend(frameon=False, loc="center left", bbox_to_anchor=(0.01, 0.4))
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Score Revenant against ground truth workloads.")
    ap.add_argument("--seeds", type=int, default=10, help="workload seeds per setting")
    ap.add_argument("--ops", type=int, default=60, help="tracked operations per workload")
    ap.add_argument("--churn", type=int, nargs="+", default=[0, 50, 200, 800],
                    help="later write operations applied after the tracked activity")
    ap.add_argument("--images", type=Path, help="also score every image with a truth file in this folder")
    ap.add_argument("--samples", action="store_true", help="also score the demo images in samples")
    ap.add_argument("--skip-synthetic", action="store_true", help="run only external or sample images")
    ap.add_argument("--quick", action="store_true", help="three seeds and two churn levels")
    ap.add_argument("--keep-images", action="store_true", help="save generated images and truth files")
    ap.add_argument("--no-plot", action="store_true")
    ap.add_argument("--out", type=Path, default=ROOT / "bench_results")
    args = ap.parse_args(argv)

    seeds = range(3 if args.quick else args.seeds)
    churns = [0, 200] if args.quick else args.churn
    keep = args.out / "images" if args.keep_images else None
    started = time.time()
    rows = []
    if not args.skip_synthetic:
        print(f"LittleFS suite, {len(seeds)} seeds x churn {churns}")
        rows += littlefs_suite(seeds, args.ops, churns, keep)
        print(f"JFFS2 suite, {len(seeds)} seeds")
        rows += jffs2_suite(seeds, args.ops, keep)
    if args.samples:
        rows += external_suite(ROOT / "samples", "samples")
    if args.images:
        rows += external_suite(args.images, "external")
    if not rows:
        print("Nothing to score.")
        return 1
    summary = aggregate(rows)
    files = write_outputs(rows, summary, args.out, plot=not args.no_plot)
    print()
    print(f"{'suite':10} {'writes':>6} {'imgs':>5} {'versions':>9} {'on flash':>9} {'recall':>8} "
          f"{'labelled':>9} {'exact':>7} {'path':>7} {'baseline':>9} {'unattr':>7}")
    for s in summary.values():
        print(f"{s['suite']:10} {s['churn']:>6} {s['images']:>5} {s['remnant_versions']:>9} "
              f"{_pct(s['survival_rate']):>9} {_pct(s['recall_of_surviving']):>8} "
              f"{_pct(s['label_accuracy']):>9} {_pct(s['exact_rate']):>7} "
              f"{_pct(s['metadata_accuracy']):>7} "
              f"{_pct(s['baseline_recall_of_surviving']):>9} {s['unattributed_items']:>7}")
    print(f"\nFinished in {time.time() - started:.1f} s. Files written:")
    for f in files:
        print(f"  {f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
