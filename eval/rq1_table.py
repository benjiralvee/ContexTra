"""
rq1_table.py — Reproduce RQ1 confusion matrix and aggregate metrics table.

Computes per-method 3x3 confusion matrices (Pred rows x GT columns) and
aggregate metrics: Accuracy, TP Precision, TP Recall, Filter rate, Misc count.

Supports three result formats:
  - ContexTra:  top-level "classification" field
  - Baselines:  nested "llm_analysis.classification" field
  - Either may use "issue_id" (int or str)

GT formats supported:
  - Python GT:  "sample_id" as the join key, "source_id" as fallback
  - Java GT:    "id" as the join key

Usage:
    python rq1_table.py \\
        --gt data/ground_truth/python_sample_250_proportional_GT.json \\
        --results results/python/results_b1_claude_prop250.json "B1 Minimal" \\
        --results results/python/results_b2_claude_prop250.json "B2 Guided" \\
        --results results/python/results_claude_proportional_250.json "ContexTra"

    python rq1_table.py \\
        --gt data/ground_truth/java_279_GT.json \\
        --results results/java/results_claude_java_279.json "ContexTra Java"
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
    if raw in ("TP", "FP", "UNKNOWN"):
        return raw
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


def load_predictions(path: Path) -> Dict[str, str]:
    """Load predictions, return {str(issue_id): classification}."""
    with open(path) as f:
        data = json.load(f)

    preds = {}
    for entry in data:
        issue_id = str(entry["issue_id"])

        if "classification" in entry:
            raw = entry["classification"]
        elif "llm_analysis" in entry and isinstance(entry["llm_analysis"], dict):
            raw = entry["llm_analysis"].get("classification", "UNKNOWN")
        else:
            raw = "UNKNOWN"

        preds[issue_id] = normalize_label(raw)

    return preds


def build_confusion(
    gt: Dict[str, str], preds: Dict[str, str]
) -> Tuple[Dict[Tuple[str, str], int], int]:
    """Build 3x3 confusion matrix {(pred, gt_class): count} over matched IDs."""
    matrix = Counter()
    matched = 0

    for issue_id, pred_label in preds.items():
        if issue_id not in gt:
            continue
        gt_label = gt[issue_id]
        if pred_label not in CLASSES or gt_label not in CLASSES:
            continue
        matrix[(pred_label, gt_label)] += 1
        matched += 1

    return dict(matrix), matched


def compute_metrics(matrix: Dict[Tuple[str, str], int], matched: int) -> Dict:
    gt_counts = {}
    for cls in CLASSES:
        gt_counts[cls] = sum(matrix.get((p, cls), 0) for p in CLASSES)

    correct = sum(matrix.get((c, c), 0) for c in CLASSES)
    accuracy = correct / matched if matched else 0

    pred_tp_total = sum(matrix.get(("TP", g), 0) for g in CLASSES)
    tp_precision = matrix.get(("TP", "TP"), 0) / pred_tp_total if pred_tp_total else 0
    tp_recall = matrix.get(("TP", "TP"), 0) / gt_counts["TP"] if gt_counts["TP"] else 0

    gt_non_tp = gt_counts["FP"] + gt_counts["NON_ACTIONABLE"]
    false_alarms_as_tp = matrix.get(("TP", "FP"), 0) + matrix.get(("TP", "NON_ACTIONABLE"), 0)
    filtered = gt_non_tp - false_alarms_as_tp
    filter_rate = filtered / gt_non_tp if gt_non_tp else 0

    misc = matched - correct

    return {
        "matched": matched,
        "correct": correct,
        "accuracy": accuracy,
        "tp_precision": tp_precision,
        "tp_recall": tp_recall,
        "filter_rate": filter_rate,
        "filter_num": filtered,
        "filter_denom": gt_non_tp,
        "misc": misc,
        "gt_counts": gt_counts,
    }


def print_confusion(name: str, matrix: Dict[Tuple[str, str], int]):
    print(f"\n  {name}")
    header = f"  {'Pred':<6}"
    for cls in CLASSES:
        header += f"  {'GT-'+DISPLAY[cls]:>6}"
    header += f"  {'Total':>6}"
    print(header)

    for pred in CLASSES:
        row = f"  {DISPLAY[pred]:<6}"
        row_total = 0
        for gt_cls in CLASSES:
            val = matrix.get((pred, gt_cls), 0)
            row += f"  {val:>6}"
            row_total += val
        row += f"  {row_total:>6}"
        print(row)


def print_metrics_table(results: List[Tuple[str, Dict]]):
    print(f"\n  {'Method':<20} {'Acc':>7} {'TPP':>7} {'TPR':>7} {'Filt':>12} {'Misc':>5}")
    print(f"  {'-'*20} {'-'*7} {'-'*7} {'-'*7} {'-'*12} {'-'*5}")

    for name, m in results:
        filt_str = f"{m['filter_num']}/{m['filter_denom']}"
        print(
            f"  {name:<20} "
            f"{m['accuracy']*100:>6.1f}% "
            f"{m['tp_precision']*100:>6.1f}% "
            f"{m['tp_recall']*100:>6.1f}% "
            f"{m['filter_rate']*100:>5.1f}% ({filt_str}) "
            f"{m['misc']:>4}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Compute RQ1 confusion matrix and metrics table."
    )
    parser.add_argument(
        "--gt", required=True, type=Path,
        help="Path to ground truth JSON"
    )
    parser.add_argument(
        "--results", nargs=2, action="append", metavar=("PATH", "NAME"),
        help="Result JSON path and display name (can repeat)"
    )
    args = parser.parse_args()

    if not args.results:
        print("Error: provide at least one --results PATH NAME", file=sys.stderr)
        sys.exit(1)

    gt = load_gt(args.gt)
    print(f"Ground truth: {len(gt)} entries from {args.gt.name}")

    gt_label_counts = Counter(gt.values())
    for cls in CLASSES:
        print(f"  GT {DISPLAY[cls]}: {gt_label_counts.get(cls, 0)}")

    all_results = []

    for result_path_str, name in args.results:
        result_path = Path(result_path_str)
        preds = load_predictions(result_path)
        matrix, matched = build_confusion(gt, preds)
        metrics = compute_metrics(matrix, matched)

        print_confusion(name, matrix)
        all_results.append((name, metrics))

    print_metrics_table(all_results)
    print()


if __name__ == "__main__":
    main()
