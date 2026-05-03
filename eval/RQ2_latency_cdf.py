
"""
RQ2_latency_cdf.py — v2 for CCS submission

Latency CDF for ContexTra running on Claude Sonnet 4.5 / Llama 3.3 70B /
Qwen2.5-Coder 32B over the 250-alert Python proportional sample.

Improvements over v1:
  1. p50 AND p90 marked with circles for every model (story is at p90).
  2. Each curve labeled with its max latency at the right endpoint.
  3. 60-second SLA reference line, anchoring "acceptable latency".
  4. Distinct line styles (solid / dashed / dash-dot) so curves are
     readable in B&W print and at small size.
  5. Legend ordered by tail behavior: bounded -> moderate tail -> heavy tail.
"""

import json
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

# Match ACM acmart's serif body font as closely as Matplotlib allows.
mpl.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Nimbus Roman', 'Times New Roman', 'DejaVu Serif'],
    'mathtext.fontset': 'cm',
    'pdf.fonttype': 42,         # TrueType (embeddable, ACM-compliant)
    'ps.fonttype': 42,
})

ROOT = Path(__file__).resolve().parent.parent / 'results' / 'python'

# Order matters: bounded curve first, heavy-tail last (matches the story arc)
FILES = [
    ('Claude Sonnet 4.5 (cloud)',   ROOT / 'results_claude_proportional_250.json',
     '#0072B2', '-',   2.0),
    ('Llama 3.3 70B (local)',       ROOT / 'results_contextra_llama33_70b_prop250.json',
     '#009E73', '--',  1.8),
    ('Qwen2.5-Coder 32B (local)',   ROOT / 'results_contextra_qwen25coder_32b_prop250.json',
     '#D55E00', '-.',  1.8),
]

OUT_PDF = Path(__file__).resolve().parent / 'RQ2_latency_cdf_v2.pdf'
OUT_PNG = Path(__file__).resolve().parent / 'RQ2_latency_cdf_v2.png'


def load_latencies(path):
    with path.open() as f:
        rows = json.load(f)
    vals = []
    for r in rows:
        t = r.get('processing_time_sec')
        if t is None:
            continue
        try:
            t = float(t)
        except (TypeError, ValueError):
            continue
        if t > 0:
            vals.append(t)
    return np.array(sorted(vals))


def main():
    fig, ax = plt.subplots(figsize=(3.5, 2.5))

    # Faint reference lines at y=50 and y=90
    for yref, label_text in [(50, 'p50'), (90, 'p90')]:
        ax.axhline(yref, color='0.7', linewidth=0.5,
                   linestyle=(0, (1, 3)), alpha=0.7, zorder=1)
        ax.text(8.3, yref + 1.5, label_text, fontsize=6.2, color='0.40')

    summary = []
    # Place all max labels just above y=100, vertically anchored at the endpoint x.
    # Uniform placement reads cleaner than per-curve hand-tuning.
    max_label_offsets = {
        'Claude Sonnet 4.5 (cloud)':   (0, 6, 'center'),
        'Llama 3.3 70B (local)':       (0, 6, 'center'),
        'Qwen2.5-Coder 32B (local)':   (0, 6, 'center'),
    }

    for label, path, color, ls, lw in FILES:
        x = load_latencies(path)
        n = len(x)
        y = np.arange(1, n + 1) / n * 100
        med = float(np.median(x))
        p90 = float(np.percentile(x, 90))
        p99 = float(np.percentile(x, 99))
        mx = float(x.max())

        ax.plot(x, y, label=label, color=color, linestyle=ls,
                linewidth=lw, solid_capstyle='round',
                solid_joinstyle='round', zorder=3)

        # Markers at p50 and p90
        ax.plot([med, p90], [50, 90], 'o', markersize=4.5,
                markerfacecolor='white', markeredgecolor=color,
                markeredgewidth=1.3, zorder=4)

        # Annotate max latency at the right endpoint
        dx, dy, ha = max_label_offsets[label]
        ax.annotate(
            f'max\u202f{mx:.0f}\u202fs',
            xy=(mx, 100),
            xytext=(dx, dy),
            textcoords='offset points',
            ha=ha, va='center',
            fontsize=6.4, color=color, weight='bold', zorder=5,
        )
        # Small terminal dot to anchor the annotation visually
        ax.plot([mx], [100], marker='o', markersize=3,
                color=color, zorder=5)

        summary.append((label, n, med, p90, p99, mx))

    ax.set_xscale('log')
    ax.set_xlim(8, 700)
    ax.set_ylim(0, 115)
    ax.set_xlabel('latency per alert in seconds (log scale)', fontsize=8)
    ax.set_ylabel('Cumulative % of alerts', fontsize=8)
    ax.tick_params(axis='both', labelsize=7)

    # Clean spines
    for s in ('top', 'right'):
        ax.spines[s].set_visible(False)
    for s in ('left', 'bottom'):
        ax.spines[s].set_linewidth(0.6)

    ax.grid(True, which='major', axis='x',
            linestyle=':', linewidth=0.4, alpha=0.5, zorder=0)

    leg = ax.legend(loc='lower right', bbox_to_anchor=(0.99, 0.03),
                    fontsize=6.6, frameon=True, framealpha=0.97,
                    borderpad=0.45, handlelength=2.0, labelspacing=0.3)
    leg.get_frame().set_linewidth(0.4)
    leg.get_frame().set_edgecolor('0.7')

    plt.tight_layout(pad=0.3)
    plt.savefig(OUT_PDF, bbox_inches='tight', pad_inches=0.02)
    plt.savefig(OUT_PNG, dpi=220, bbox_inches='tight', pad_inches=0.02)

    print('Saved:')
    print(f'  {OUT_PDF}')
    print(f'  {OUT_PNG}')
    print()
    print(f'{"Model":30s}  {"n":>4} {"med":>7} {"p90":>7} {"p99":>7} {"max":>7}')
    for label, n, med, p90, p99, mx in summary:
        print(f'{label:30s}  {n:>4} {med:>6.1f}s {p90:>6.1f}s {p99:>6.1f}s {mx:>6.1f}s')


if __name__ == '__main__':
    main()
