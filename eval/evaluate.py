"""
evaluate.py — ContexTra classifier evaluation

Reads a run's result JSON + ground-truth labels JSON, computes classifier
metrics (accuracy, TP precision/recall, non-TP filtering rate), writes a
ground-truth-vs-LLM bar chart, and saves metrics to disk.

Usage:
    python evaluate.py RESULTS.json GROUND_TRUTH.json \
        --config-name "9-Tool + Prompt Caching" \
        --subtitle "Claude Sonnet 4.5, n = 50, Pilot 1, temp = 0.0" \
        --out-dir ./evaluation_output

Inputs
------
results.json
    A JSON list of objects, each at minimum containing:
        {
            "issue_id": str,
            "classification": "TP" | "FP" | "NON_ACTIONABLE" | "NA" | "UNKNOWN"
        }

ground_truth.json
    A JSON object mapping issue_id (str) -> { "label": "TP" | "FP" | "NA" | "NON_ACTIONABLE", ... }

Outputs (written to --out-dir)
------------------------------
    chart.pdf, chart.png : classifier performance chart
    metrics.json         : all computed metrics
    confusion.csv        : 3x3 confusion matrix

CCS 2026 submission
"""

import argparse
import csv
import json
import os
import sys
from collections import Counter
from typing import Dict, List, Tuple

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.ticker import MultipleLocator
import numpy as np


# =============================================================================
# Constants — colors and canonical class names
# =============================================================================

C_TP        = "#C0392B"   # red
C_FP        = "#2471A3"   # blue
C_NA        = "#7D8C8E"   # gray
C_TP_LIGHT  = "#E6B0AA"
C_FP_LIGHT  = "#AED6F1"
C_NA_LIGHT  = "#C4CDCE"
EDGE        = "#333333"

LIGHT_MAP = {"TP": C_TP_LIGHT, "FP": C_FP_LIGHT, "NA": C_NA_LIGHT}
DARK_MAP  = {"TP": C_TP,       "FP": C_FP,       "NA": C_NA}

CATEGORIES = ["TP", "FP", "NA"]
CAT_LABELS = {
    "TP": "True Positive",
    "FP": "False Positive",
    "NA": "Non-Actionable",
}

# How raw labels in the JSON map to our canonical 3-class system.
LLM_LABEL_MAP = {
    "TP":             "TP",
    "FP":             "FP",
    "NA":             "NA",
    "NON_ACTIONABLE": "NA",
    "UNKNOWN":        "UNK",
}
GT_LABEL_MAP = {
    "TP":             "TP",
    "FP":             "FP",
    "NA":             "NA",
    "NON_ACTIONABLE": "NA",
}


# =============================================================================
# Scoring
# =============================================================================

def score_run(
    run: List[Dict],
    gt_all: Dict[str, Dict],
) -> Tuple[Dict, Dict, List, List]:
    """
    Build the confusion matrix for one run.

    Returns
    -------
    confusion : {predicted: {actual: count}} for {TP,FP,NA} x {TP,FP,NA}
    gt_counts : Counter of actual-class counts (over scored items only)
    unknowns  : list of (issue_id, gt_class) skipped because LLM said UNKNOWN
    missing   : list of issue_ids that had no ground-truth entry
    """
    confusion = {p: {a: 0 for a in CATEGORIES} for p in CATEGORIES}
    gt_counts = Counter()
    unknowns, missing = [], []

    for item in run:
        iid = str(item["issue_id"])
        llm_raw = item.get("classification") or item.get("llm_analysis", {}).get("classification", "UNKNOWN")

        if llm_raw not in LLM_LABEL_MAP:
            raise ValueError(
                f"Unexpected LLM classification '{llm_raw}' on issue {iid}. "
                f"Expected one of {list(LLM_LABEL_MAP)}."
            )
        llm = LLM_LABEL_MAP[llm_raw]

        if iid not in gt_all:
            missing.append(iid)
            continue

        gt_raw = gt_all[iid]["label"]
        if gt_raw not in GT_LABEL_MAP:
            raise ValueError(
                f"Unexpected GT label '{gt_raw}' on issue {iid}. "
                f"Expected one of {list(GT_LABEL_MAP)}."
            )
        gt = GT_LABEL_MAP[gt_raw]

        if llm == "UNK":
            unknowns.append((iid, gt))
            continue

        gt_counts[gt] += 1
        confusion[llm][gt] += 1

    return confusion, gt_counts, unknowns, missing


def compute_metrics(confusion: Dict, gt_counts: Counter) -> Dict:
    """Derive the metrics the chart and any paper tables will need."""
    total   = sum(sum(row.values()) for row in confusion.values())
    correct = sum(confusion[c][c] for c in CATEGORIES)

    tp_pred = sum(confusion["TP"].values())   # LLM's TP column total
    tp_true = confusion["TP"]["TP"]           # TP predictions that were actually TP
    tp_gt   = gt_counts["TP"]                 # all true TPs

    # "Non-TP filtering" = of all actual FP+NA issues, how many did the LLM
    # correctly NOT classify as TP (i.e., put into FP or NA bucket)?
    non_tp_gt = gt_counts["FP"] + gt_counts["NA"]
    non_tp_filtered = (confusion["FP"]["FP"] + confusion["FP"]["NA"]
                     + confusion["NA"]["FP"] + confusion["NA"]["NA"])

    def safe_div(a, b): return (a / b) if b else 0.0

    return {
        "n_total":           total,
        "n_correct":         correct,
        "n_misclassified":   total - correct,
        "accuracy":          safe_div(correct, total),
        "tp_precision":      safe_div(tp_true, tp_pred),
        "tp_recall":         safe_div(tp_true, tp_gt),
        "non_tp_filter_rate": safe_div(non_tp_filtered, non_tp_gt),
        "non_tp_filtered":   non_tp_filtered,
        "non_tp_total":      non_tp_gt,
        "gt_counts":         dict(gt_counts),
        "llm_counts": {
            p: sum(confusion[p].values()) for p in CATEGORIES
        },
        "confusion":         confusion,
    }


# =============================================================================
# Plotting (style matches the pilot-1/pilot-2 paper figures)
# =============================================================================

def plot_chart(
    confusion: Dict,
    gt_counts: Counter,
    metrics: Dict,
    config_name: str,
    subtitle: str,
    ax=None,
    pred_label: str = "ContexTra",
):
    """Draw the GT-vs-LLM bar chart onto `ax` (or a new figure)."""
    standalone = ax is None
    if standalone:
        fig, ax = plt.subplots(figsize=(9.0, 5.4))

    x = np.array([0.0, 2.0, 4.0])
    bar_w, gap = 0.48, 0.08

    max_val = max(
        max(gt_counts.values()) if gt_counts else 1,
        max(sum(confusion[p].values()) for p in CATEGORIES) if confusion else 1,
    )
    y_ceil = int(np.ceil((max_val + 5) / 10) * 10)
    y_major = max(5, int(np.ceil(y_ceil / 8 / 5) * 5))

    # --- GT bars (solid dark) ---
    for i, cat in enumerate(CATEGORIES):
        xpos = x[i] - bar_w / 2 - gap / 2
        ax.bar(xpos, gt_counts[cat], width=bar_w,
               color=DARK_MAP[cat], edgecolor=EDGE, linewidth=0.8,
               zorder=2, label=f"GT" if i == 0 else None)
        ax.text(xpos, gt_counts[cat] + max_val * 0.02, str(gt_counts[cat]),
                ha="center", va="bottom",
                fontsize=11, fontweight="bold", color="#333", zorder=6)

    # --- LLM bars (correct solid + misclassified hatch stacked on top) ---
    for i, pred in enumerate(CATEGORIES):
        xpos = x[i] + bar_w / 2 + gap / 2
        row = confusion[pred]
        correct = row[pred]
        mis_parts = [(a, c) for a, c in row.items() if a != pred and c > 0]

        bottom = 0
        if correct > 0:
            ax.bar(xpos, correct, width=bar_w, bottom=bottom,
                   color=DARK_MAP[pred], edgecolor=EDGE, linewidth=0.8, zorder=2)
            ax.text(xpos, bottom + correct / 2, str(correct),
                    ha="center", va="center",
                    fontsize=11, fontweight="bold", color="white")
            bottom += correct

        for actual_cls, cnt in mis_parts:
            ax.bar(xpos, cnt, width=bar_w, bottom=bottom,
                   color=LIGHT_MAP[actual_cls],
                   edgecolor=DARK_MAP[actual_cls], linewidth=1.0,
                   hatch="///", zorder=2)
            bottom += cnt

        total = sum(row.values())
        ax.text(xpos, total + max_val * 0.02, str(total),
                ha="center", va="bottom",
                fontsize=11, fontweight="bold", color="#333", zorder=6)

        y_cursor = correct
        callout_positions = []
        for actual_cls, cnt in mis_parts:
            mid_y = y_cursor + cnt / 2
            callout_positions.append((actual_cls, cnt, mid_y))
            y_cursor += cnt

        # Space callouts vertically to avoid overlap
        min_gap_y = max_val * 0.06
        for j in range(1, len(callout_positions)):
            prev_y = callout_positions[j - 1][2]
            curr_y = callout_positions[j][2]
            if curr_y - prev_y < min_gap_y:
                cls, cnt, _ = callout_positions[j]
                callout_positions[j] = (cls, cnt, prev_y + min_gap_y)

        for actual_cls, cnt, mid_y in callout_positions:
            ax.annotate(
                f"{cnt} {actual_cls}",
                xy=(xpos + bar_w / 2, mid_y),
                xytext=(xpos + 0.65, mid_y),
                fontsize=9.5, color=DARK_MAP[actual_cls],
                fontweight="bold", ha="left", va="center",
                arrowprops=dict(arrowstyle="->", color=DARK_MAP[actual_cls],
                                lw=0.8, shrinkA=0, shrinkB=2),
                zorder=5,
            )

    # --- Right-side non-TP filter bracket ---
    bracket_x = x[2] + bar_w + gap + 1.35
    # Leave headroom at the bottom so the metrics box doesn't collide with the bracket tick.
    y_bot, y_top = y_ceil * 0.20, y_ceil * 0.92
    tick = 0.12
    ax.plot([bracket_x, bracket_x], [y_bot, y_top],
            color="#1A5276", lw=1.2, zorder=3, clip_on=False)
    ax.plot([bracket_x - tick, bracket_x], [y_top, y_top],
            color="#1A5276", lw=1.2, zorder=3, clip_on=False)
    ax.plot([bracket_x - tick, bracket_x], [y_bot, y_bot],
            color="#1A5276", lw=1.2, zorder=3, clip_on=False)
    mid_y = (y_top + y_bot) / 2
    ax.plot([bracket_x, bracket_x + tick], [mid_y, mid_y],
            color="#1A5276", lw=1.2, zorder=3, clip_on=False)

    ax.text(bracket_x + tick + 0.10, mid_y + y_ceil * 0.06,
            f"{metrics['non_tp_filter_rate']*100:.1f}%",
            fontsize=15, fontweight="bold", color="#1A5276",
            ha="left", va="center", clip_on=False)
    ax.text(bracket_x + tick + 0.10, mid_y - y_ceil * 0.01,
            "non-TP\nfiltered",
            fontsize=9, fontweight="bold", color="#1A5276",
            ha="left", va="center", clip_on=False)
    ax.text(bracket_x + tick + 0.10, mid_y - y_ceil * 0.08,
            f"{metrics['non_tp_filtered']} of {metrics['non_tp_total']}",
            fontsize=8.5, color="#888",
            ha="left", va="center", clip_on=False)

    # --- Metrics box (inside chart, top-left area) ---
    metrics_text = (
        f"Accuracy {metrics['accuracy']*100:.0f}% ({metrics['n_correct']}/{metrics['n_total']})\n"
        f"TP Prec. {metrics['tp_precision']*100:.1f}%\n"
        f"TP Recall {_fmt_pct(metrics['tp_recall'])}\n"
        f"Misclass. {metrics['n_misclassified']}"
    )
    ax.text(0.18, 0.88, metrics_text,
            transform=ax.transAxes,
            fontsize=10, fontweight="bold",
            color="#1A1A1A", va="top", ha="left",
            bbox=dict(boxstyle="round,pad=0.4",
                      facecolor="white", edgecolor="#444444",
                      linewidth=1.2, alpha=0.9),
            zorder=4)

    # --- Legend (top center) ---
    patches = [
        mpatches.Patch(facecolor=C_TP, edgecolor=EDGE, label="TP"),
        mpatches.Patch(facecolor=C_FP, edgecolor=EDGE, label="FP"),
        mpatches.Patch(facecolor=C_NA, edgecolor=EDGE, label="NA"),
        mpatches.Patch(facecolor="white", edgecolor="#333",
                       hatch="///", label="Misclassified"),
    ]
    ax.legend(handles=patches, loc="lower center", ncol=4,
              bbox_to_anchor=(0.42, 1.0), frameon=True,
              fontsize=9, handlelength=1.6, columnspacing=1.4)

    # --- X-axis: bar labels directly under bars, category name below ---
    bar_label_y = -0.03
    cat_label_y = -0.09
    ax.set_xticks(x)
    ax.set_xticklabels([""] * len(x))

    for i, cat in enumerate(CATEGORIES):
        cx = x[i]
        gt_x = cx - bar_w / 2 - gap / 2
        llm_x = cx + bar_w / 2 + gap / 2
        ax.text(gt_x, bar_label_y, "GT",
                ha="center", va="top", fontsize=9, fontweight="bold",
                color="#222", transform=ax.get_xaxis_transform())
        ax.text(llm_x, bar_label_y, pred_label,
                ha="center", va="top", fontsize=9, fontweight="bold",
                color="#222", transform=ax.get_xaxis_transform())
        ax.text(cx, cat_label_y, CAT_LABELS[cat],
                ha="center", va="top", fontsize=10.5, fontweight="bold",
                color="#111", transform=ax.get_xaxis_transform())

    # --- Y-axis ---
    ax.set_ylim(0, y_ceil)
    ax.yaxis.set_major_locator(MultipleLocator(y_major))
    ax.set_ylabel("Number of Issues", fontsize=10.5, labelpad=8)
    ax.tick_params(axis="y", labelsize=9)
    ax.tick_params(axis="x", length=0, pad=6)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", linestyle=":", linewidth=0.5, alpha=0.6, zorder=1)
    ax.set_axisbelow(True)
    ax.set_xlim(-0.8, bracket_x + 1.45)

    # --- Title (two lines: config on top, subtitle below) ---
    main_title = f"Ground Truth vs. {pred_label} — {config_name}"
    if subtitle:
        main_title += f"\n{subtitle}"
    ax.set_title(main_title, fontsize=12, fontweight="bold", pad=28)

    if standalone:
        fig.subplots_adjust(top=0.86, right=0.86, left=0.08, bottom=0.15)
        return fig


def _fmt_pct(x: float) -> str:
    """Format 1.0 as '100%', otherwise one decimal."""
    return "100%" if abs(x - 1.0) < 1e-9 else f"{x*100:.1f}%"


# =============================================================================
# Output writers
# =============================================================================

def write_metrics_json(metrics: Dict, path: str):
    """metrics.json is the canonical machine-readable output."""
    # Round floats for readability; keep raw counts intact.
    out = dict(metrics)
    for k in ("accuracy", "tp_precision", "tp_recall", "non_tp_filter_rate"):
        out[k] = round(out[k], 4)
    with open(path, "w") as f:
        json.dump(out, f, indent=2)


def write_confusion_csv(confusion: Dict, path: str):
    """3x3 confusion matrix, rows=predicted, cols=actual."""
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["predicted \\ actual"] + CATEGORIES)
        for p in CATEGORIES:
            w.writerow([p] + [confusion[p][a] for a in CATEGORIES])


# =============================================================================
# CLI
# =============================================================================

def main():
    ap = argparse.ArgumentParser(
        description="Evaluate a ContexTra run and produce chart + metrics.")
    ap.add_argument("results", help="Path to run results JSON (list of items).")
    ap.add_argument("ground_truth",
                    help="Path to manual labels JSON (dict: id -> {label: ...}).")
    ap.add_argument("--config-name", required=True,
                    help="Name shown in chart title, e.g. '9-Tool + Prompt Caching'.")
    ap.add_argument("--subtitle", default="",
                    help="Optional subtitle, e.g. 'Claude Sonnet 4.5, n = 50, Pilot 1, temp = 0.0'.")
    ap.add_argument("--out-dir", default="./evaluation_output",
                    help="Directory to write chart and metrics into.")
    ap.add_argument("--dpi", type=int, default=200,
                    help="PNG DPI (default 200).")
    ap.add_argument("--pred-label", default="ContexTra",
                    help="Label for the predicted bars (default 'ContexTra').")
    args = ap.parse_args()

    with open(args.results) as f:
        run = json.load(f)
    with open(args.ground_truth) as f:
        gt_raw = json.load(f)

    if not isinstance(run, list):
        sys.exit(f"Expected {args.results} to be a JSON list, got {type(run).__name__}.")

    # Accept either a dict {id -> {label:...}} or a list [{uid/sample_id, label, ...}]
    if isinstance(gt_raw, list):
        def _gt_key(g):
            return str(g["uid"]) if "uid" in g else str(g["sample_id"])
        gt_all = {_gt_key(g): g for g in gt_raw}
    elif isinstance(gt_raw, dict):
        gt_all = gt_raw
    else:
        sys.exit(f"Expected {args.ground_truth} to be a JSON object or list, got {type(gt_raw).__name__}.")

    confusion, gt_counts, unknowns, missing = score_run(run, gt_all)
    metrics = compute_metrics(confusion, gt_counts)

    # Terminal summary
    print(f"Scored {metrics['n_total']} items "
          f"(unknowns skipped: {len(unknowns)}, missing GT skipped: {len(missing)})")
    print(f"  Accuracy   : {metrics['accuracy']*100:.1f}% "
          f"({metrics['n_correct']}/{metrics['n_total']})")
    print(f"  TP Prec    : {metrics['tp_precision']*100:.2f}%")
    print(f"  TP Recall  : {metrics['tp_recall']*100:.2f}%")
    print(f"  Non-TP filt: {metrics['non_tp_filter_rate']*100:.2f}% "
          f"({metrics['non_tp_filtered']}/{metrics['non_tp_total']})")
    print(f"  Misclass   : {metrics['n_misclassified']}")
    if missing:
        print(f"  WARNING: no ground truth for {len(missing)} issue(s): "
              f"{missing[:5]}{'...' if len(missing) > 5 else ''}")
    if unknowns:
        print(f"  WARNING: LLM returned UNKNOWN for {len(unknowns)} issue(s).")

    # Outputs
    os.makedirs(args.out_dir, exist_ok=True)

    fig = plot_chart(confusion, gt_counts, metrics,
                     config_name=args.config_name,
                     subtitle=args.subtitle,
                     pred_label=args.pred_label)
    fig.savefig(os.path.join(args.out_dir, "chart.pdf"), bbox_inches="tight")
    fig.savefig(os.path.join(args.out_dir, "chart.png"),
                bbox_inches="tight", dpi=args.dpi)
    plt.close(fig)

    write_metrics_json(metrics, os.path.join(args.out_dir, "metrics.json"))
    write_confusion_csv(confusion, os.path.join(args.out_dir, "confusion.csv"))

    print(f"\nWrote: {args.out_dir}/chart.pdf, chart.png, metrics.json, confusion.csv")


if __name__ == "__main__":
    main()
