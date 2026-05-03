"""
rq4_table.py — Reproduce RQ4 tool-ablation table on the pilot 50 alerts.

Computes per-config metrics: Accuracy, TP Precision/Recall, Misclassifications,
average tool calls per alert, and latency (median/max).

Note: per-alert API cost is not stored in result JSONs. It was measured by
recording Anthropic account balance before and after each 50-alert experiment
run, then dividing the difference by 50.

Usage:
    python rq4_table.py \\
        --gt data/ground_truth/pilot1_50_GT.json \\
        --results results/ablation/pilot1_t0_9tool.json "9-tool" \\
        --results results/ablation/pilot1_t0_9tool_searchcap.json "9-tool + SEARCH cap" \\
        --results results/ablation/pilot1_t0_8tool.json "8-tool" \\
        --results results/ablation/pilot1_t0_7tool_nosast.json "7-tool (no SAST)" \\
        --results results/ablation/pilot1_t0_6tool.json "6-tool"
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

CLASSES = ["TP", "FP", "NON_ACTIONABLE"]
DISPLAY = {"TP": "TP", "FP": "FP", "NON_ACTIONABLE": "NA"}

# Per-alert API cost in USD, measured from Anthropic account balance
# before/after each 50-alert run: cost = (balance_before - balance_after) / 50.
# Not derivable from result JSONs.
COST_PER_ALERT = {
    "9-tool":              0.30,
    "9-tool + SEARCH cap": 0.28,
    "8-tool":              0.31,
    "7-tool (no SAST)":    0.31,
    "6-tool":              0.40,
}


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
            if isinstance(val, dict):
                label = val.get("label", "")
                gt[str(key)] = normalize_label(label)
                if "source_id" in val:
                    gt[str(val["source_id"])] = normalize_label(label)
            else:
                gt[str(key)] = normalize_label(val)
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

        tool_counts = entry.get("tool_call_counts", {})
        total_calls = sum(tool_counts.values()) if isinstance(tool_counts, dict) else 0

        entries.append({
            "issue_id": issue_id,
            "classification": normalize_label(raw),
            "num_iterations": entry.get("num_iterations", 0),
            "processing_time_sec": entry.get("processing_time_sec", 0.0),
            "total_tool_calls": total_calls,
        })
    return entries


def compute_metrics(gt, pred_entries):
    """Compute all RQ4 metrics for one config."""
    matrix = Counter()
    matched = 0
    iterations = []
    latencies = []
    tool_calls = []

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
        tool_calls.append(entry["total_tool_calls"])

    correct = sum(matrix.get((c, c), 0) for c in CLASSES)
    accuracy = correct / matched if matched else 0.0
    misc = matched - correct

    tp_correct = matrix.get(("TP", "TP"), 0)
    pred_tp_total = sum(matrix.get(("TP", g), 0) for g in CLASSES)
    gt_tp_total = sum(matrix.get((p, "TP"), 0) for p in CLASSES)

    tp_p = tp_correct / pred_tp_total if pred_tp_total else 0.0
    tp_r = tp_correct / gt_tp_total if gt_tp_total else 0.0

    avg_calls = sum(tool_calls) / len(tool_calls) if tool_calls else 0.0

    latencies.sort()
    n = len(latencies)
    lat_med = latencies[n // 2] if n else 0.0
    lat_max = latencies[-1] if n else 0.0

    gt_counts = {}
    for cls in CLASSES:
        gt_counts[cls] = sum(matrix.get((p, cls), 0) for p in CLASSES)

    return {
        "matched": matched,
        "accuracy": accuracy,
        "tp_p": tp_p, "tp_r": tp_r,
        "misc": misc,
        "avg_calls": avg_calls,
        "lat_med": lat_med,
        "lat_max": lat_max,
        "gt_counts": gt_counts,
        "matrix": dict(matrix),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Compute RQ4 ablation table (Acc, TP P/R, Misc, Calls, Latency)."
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
    print(f"\n  {'Config':<24} {'Acc':>6} {'TP P%':>6} {'TP R%':>6} {'Misc':>5} {'Calls':>6} {'Lat med/max':>14} {'Cost':>6}")
    print(f"  {'-'*24} {'-'*6} {'-'*6} {'-'*6} {'-'*5} {'-'*6} {'-'*14} {'-'*6}")

    for name, m in all_results:
        lat_str = f"{m['lat_med']:.0f} / {m['lat_max']:.0f}"
        cost = COST_PER_ALERT.get(name, None)
        cost_str = f"${cost:.2f}" if cost is not None else "  N/A"
        print(
            f"  {name:<24} "
            f"{m['accuracy']*100:>4.0f}% "
            f"{m['tp_p']*100:>5.1f} "
            f"{m['tp_r']*100:>5.1f} "
            f"{m['misc']:>5} "
            f"{m['avg_calls']:>5.1f} "
            f"{lat_str:>14} "
            f"{cost_str:>6}"
        )
    print()
    print("  Cost = (Anthropic balance before run - balance after) / 50 alerts.")
    print()


if __name__ == "__main__":
    main()
