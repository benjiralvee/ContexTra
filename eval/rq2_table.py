"""
rq2_table.py — Reproduce RQ2 cross-model table on the Python 250 sample.

Computes per-model metrics: TP Precision/Recall/F1, NA prediction count,
median iterations, and latency (median/max).

Usage:
    python rq2_table.py \\
        --gt data/ground_truth/python_sample_250_proportional_GT.json \\
        --results results/python/results_claude_proportional_250.json "Claude Sonnet 4.5" \\
        --results results/python/results_contextra_llama33_70b_prop250.json "Llama 3.3 70B" \\
        --results results/python/results_contextra_qwen25coder_32b_prop250.json "Qwen2.5-Coder 32B"
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

CLASSES = ["TP", "FP", "NON_ACTIONABLE"]
DISPLAY = {"TP": "TP", "FP": "FP", "NON_ACTIONABLE": "NA"}


def normalize_label(raw: str) -> str:
    raw = raw.strip().upper()
    if raw in ("NA", "NON_ACTIONABLE", "NON-ACTIONABLE"):
        return "NON_ACTIONABLE"
    return raw


def load_gt(path: Path) -> Dict[str, str]:
    """Load ground truth, return {str(id): label}."""
    with open(path) as f:
        data = json.load(f)

    gt = {}
    if isinstance(data, list):
        for entry in data:
            if "sample_id" in entry:
                key = str(entry["sample_id"])
            elif "id" in entry:
                key = str(entry["id"])
            else:
                continue
            gt[key] = normalize_label(entry["label"])
            if "source_id" in entry:
                gt[str(entry["source_id"])] = normalize_label(entry["label"])
    elif isinstance(data, dict):
        for key, val in data.items():
            label = val.get("label", val.get("classification", ""))
            gt[str(key)] = normalize_label(label)
    return gt


def load_predictions(path: Path) -> List[Dict]:
    """Load result JSON, return list of dicts."""
    with open(path) as f:
        data = json.load(f)

    entries = []
    for entry in data:
        issue_id = str(entry["issue_id"])

        if "classification" in entry:
            raw = entry["classification"]
        elif "llm_analysis" in entry and isinstance(entry["llm_analysis"], dict):
            raw = entry["llm_analysis"].get("classification", "UNKNOWN")
        else:
            raw = "UNKNOWN"

        entries.append({
            "issue_id": issue_id,
            "classification": normalize_label(raw),
            "num_iterations": entry.get("num_iterations", 0),
            "processing_time_sec": entry.get("processing_time_sec", 0.0),
        })
    return entries


def compute_metrics(gt, pred_entries):
    """Compute all RQ2 metrics for one model."""
    matrix = Counter()
    matched = 0
    iterations = []
    latencies = []

    for entry in pred_entries:
        iid = entry["issue_id"]
        if iid not in gt:
            continue
        gt_label = gt[iid]
        pred_label = entry["classification"]
        if pred_label not in CLASSES or gt_label not in CLASSES:
            continue

        matrix[(pred_label, gt_label)] += 1
        matched += 1
        iterations.append(entry["num_iterations"])
        latencies.append(entry["processing_time_sec"])

    tp_correct = matrix.get(("TP", "TP"), 0)
    pred_tp_total = sum(matrix.get(("TP", g), 0) for g in CLASSES)
    gt_tp_total = sum(matrix.get((p, "TP"), 0) for p in CLASSES)

    tp_p = tp_correct / pred_tp_total if pred_tp_total else 0.0
    tp_r = tp_correct / gt_tp_total if gt_tp_total else 0.0
    tp_f1 = 2 * tp_p * tp_r / (tp_p + tp_r) if (tp_p + tp_r) else 0.0

    na_pred_count = sum(matrix.get(("NON_ACTIONABLE", g), 0) for g in CLASSES)

    iterations.sort()
    latencies.sort()
    n = len(iterations)
    iter_med = iterations[n // 2] if n else 0
    lat_med = latencies[n // 2] if n else 0.0
    lat_max = latencies[-1] if n else 0.0

    gt_counts = {}
    for cls in CLASSES:
        gt_counts[cls] = sum(matrix.get((p, cls), 0) for p in CLASSES)

    return {
        "matched": matched,
        "tp_p": tp_p, "tp_r": tp_r, "tp_f1": tp_f1,
        "na_pred_count": na_pred_count,
        "iter_med": iter_med,
        "lat_med": lat_med,
        "lat_max": lat_max,
        "gt_counts": gt_counts,
        "matrix": dict(matrix),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Compute RQ2 cross-model table (TP P/R/F1, NA pred, Iter, Latency)."
    )
    parser.add_argument("--gt", required=True, type=Path, help="Path to ground truth JSON")
    parser.add_argument(
        "--results", nargs=2, action="append", metavar=("PATH", "NAME"),
        help="Result JSON path and display name (can repeat)"
    )
    args = parser.parse_args()

    if not args.results:
        print("Error: provide at least one --results PATH NAME", file=sys.stderr)
        sys.exit(1)

    gt = load_gt(args.gt)

    all_results = []
    for result_path_str, name in args.results:
        pred_entries = load_predictions(Path(result_path_str))
        metrics = compute_metrics(gt, pred_entries)
        all_results.append((name, metrics))

    first_m = all_results[0][1]
    print(f"Ground truth (n={first_m['matched']}): "
          f"TP={first_m['gt_counts']['TP']}, "
          f"FP={first_m['gt_counts']['FP']}, "
          f"NA={first_m['gt_counts']['NON_ACTIONABLE']}")

    # Confusion matrices
    for name, m in all_results:
        print(f"\n  {name} (n={m['matched']})")
        header = f"  {'Pred':<6}"
        for cls in CLASSES:
            header += f"  {'GT-'+DISPLAY[cls]:>6}"
        header += f"  {'Total':>6}"
        print(header)
        for pred in CLASSES:
            row = f"  {DISPLAY[pred]:<6}"
            row_total = 0
            for gt_cls in CLASSES:
                val = m["matrix"].get((pred, gt_cls), 0)
                row += f"  {val:>6}"
                row_total += val
            row += f"  {row_total:>6}"
            print(row)

    # Metrics table
    print(f"\n  {'Model':<22} {'P%':>6} {'R%':>6} {'F1%':>6} {'NA pred':>8} {'Iter':>5} {'Lat med/max':>14}")
    print(f"  {'-'*22} {'-'*6} {'-'*6} {'-'*6} {'-'*8} {'-'*5} {'-'*14}")

    for name, m in all_results:
        lat_str = f"{m['lat_med']:.0f} / {m['lat_max']:.0f}"
        print(
            f"  {name:<22} "
            f"{m['tp_p']*100:>5.1f} "
            f"{m['tp_r']*100:>5.1f} "
            f"{m['tp_f1']*100:>5.1f} "
            f"{m['na_pred_count']:>8} "
            f"{m['iter_med']:>5} "
            f"{lat_str:>14}"
        )
    print()


if __name__ == "__main__":
    main()
