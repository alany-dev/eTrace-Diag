"""Time-RCD base vs improved final model — comparison figures.

Generates paper-style (arXiv:2509.21190) comparison figures from dumped
per-timestep scores and the module-matrix JSONs:

    1. fig_score_curves.png  — per-machine anomaly score timeline, base vs
       combo, ground-truth anomaly spans shaded (paper Fig.5 style).
    2. fig_metrics_bars.png  — grouped bars: point F1 / seg F1 / VUS-PR per
       machine, base vs combo (paper Fig.6 style).
    3. fig_score_dist.png    — score distribution, normal vs anomalous points,
       base vs combo (discrimination quality).
    4. fig_pr_curves.png     — per-machine precision-recall curves for both
       models (the surface under VUS-PR).

Run:  uv run --with matplotlib python -m experiments.baselines.plot_time_rcd_compare \
         --base-dump results/time_rcd/figures-data/base \
         --combo-dump results/time_rcd/figures-data/combo-fusion03-med5 \
         --results-dir results/time_rcd --out-dir results/time_rcd/figures
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

MACHINES = ["machine-1-1", "machine-1-2", "machine-1-3"]
MODEL_LABELS = {"base": "Time-RCD base (zero-shot)", "combo": "Time-RCD combo-fusion03-med5"}
COLORS = {"base": "#2b6cb0", "combo": "#c05621"}
FONT = {"family": "WenQuanYi Zen Hei"}


def load_dump(base_dir: Path, combo_dir: Path, machine: str) -> dict:
    b = np.load(base_dir / f"base_{machine}.npz")
    c = np.load(combo_dir / f"combo-fusion03-med5_{machine}.npz")
    return {
        "base": {"scores": b["scores"], "pred": b["pred"]},
        "combo": {"scores": c["scores"], "pred": c["pred"]},
        "labels": b["labels"].astype(bool),
    }


def _anomaly_spans(labels: np.ndarray) -> list[tuple[int, int]]:
    spans, start = [], None
    for i, v in enumerate(labels):
        if v and start is None:
            start = i
        elif not v and start is not None:
            spans.append((start, i - 1))
            start = None
    if start is not None:
        spans.append((start, len(labels) - 1))
    return spans


def fig_score_curves(base_dir, combo_dir, out: Path):
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(3, 2, figsize=(15, 9), sharex="col", constrained_layout=True)
    for row, machine in enumerate(MACHINES):
        d = load_dump(base_dir, combo_dir, machine)
        spans = _anomaly_spans(d["labels"])
        for col, model in enumerate(("base", "combo")):
            ax = axes[row, col]
            scores = d[model]["scores"]
            for a, b in spans:
                ax.axvspan(a, b, color="#e53e3e", alpha=0.18, lw=0)
            ax.plot(scores, color=COLORS[model], lw=0.6, alpha=0.9)
            thr = 0.5
            ax.axhline(thr, color="gray", lw=0.8, ls="--", label="threshold 0.5")
            ax.set_ylim(-0.05, 1.05)
            if row == 0:
                ax.set_title(MODEL_LABELS[model], fontsize=11, **FONT)
            if col == 0:
                ax.set_ylabel(machine, fontsize=10, **FONT)
    axes[2, 0].set_xlabel("timestep", **FONT)
    axes[2, 1].set_xlabel("timestep", **FONT)
    fig.suptitle(
        "SMD per-machine anomaly scores — Time-RCD base vs combo-fusion03-med5 "
        "(red spans = ground-truth anomalies)",
        fontsize=12,
        **FONT,
    )
    fig.savefig(out, dpi=150)
    print("wrote", out)


def fig_metrics_bars(results_dir: Path, out: Path):
    import matplotlib.pyplot as plt

    data = {}
    for model, fname in (("base", "base.json"), ("combo", "combo-fusion03-med5.json")):
        j = json.loads((results_dir / fname).read_text())
        data[model] = {r["machine"]: r for r in j["machine_rows"]}

    metrics = [("point_f1", "point F1"), ("seg_f1", "seg F1"), ("vus_pr", "VUS-PR")]
    x = np.arange(len(MACHINES))
    width = 0.36
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.6), constrained_layout=True)
    for i, (key, label) in enumerate(metrics):
        ax = axes[i]
        base_vals = [data["base"][m][key] for m in MACHINES]
        combo_vals = [data["combo"][m][key] for m in MACHINES]
        ax.bar(x - width / 2, base_vals, width, color=COLORS["base"], label=MODEL_LABELS["base"])
        ax.bar(x + width / 2, combo_vals, width, color=COLORS["combo"], label=MODEL_LABELS["combo"])
        for j, v in enumerate(base_vals):
            ax.text(x[j] - width / 2, v, f"{v:.3f}", ha="center", va="bottom", fontsize=8)
        for j, v in enumerate(combo_vals):
            ax.text(x[j] + width / 2, v, f"{v:.3f}", ha="center", va="bottom", fontsize=8)
        ax.set_xticks(x)
        ax.set_xticklabels(MACHINES, rotation=15, fontsize=9)
        ax.set_title(label, fontsize=11, **FONT)
        ax.set_ylim(0, 1.08)
        if i == 0:
            ax.set_ylabel("score", **FONT)
            ax.legend(fontsize=8)
    fig.suptitle(
        "Time-RCD base vs combo-fusion03-med5 — SMD 3-machine metrics", fontsize=12, **FONT
    )
    fig.savefig(out, dpi=150)
    print("wrote", out)


def fig_score_dist(base_dir, combo_dir, out: Path):
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2), constrained_layout=True)
    bins = np.linspace(0, 1, 51)
    for col, model in enumerate(("base", "combo")):
        ax = axes[col]
        normal_scores, anom_scores = [], []
        for machine in MACHINES:
            d = load_dump(base_dir, combo_dir, machine)
            s = d[model]["scores"]
            normal_scores.append(s[~d["labels"]])
            anom_scores.append(s[d["labels"]])
        normal = np.concatenate(normal_scores)
        anom = np.concatenate(anom_scores)
        ax.hist(normal, bins, alpha=0.7, color="#48bb78", label=f"normal (n={len(normal)})")
        ax.hist(anom, bins, alpha=0.7, color="#e53e3e", label=f"anomalous (n={len(anom)})")
        ax.set_title(MODEL_LABELS[model], fontsize=11, **FONT)
        ax.set_xlabel("anomaly score", **FONT)
        ax.set_ylabel("count", **FONT)
        ax.legend(fontsize=8)
    fig.suptitle("Score distribution: normal vs anomalous points", fontsize=12, **FONT)
    fig.savefig(out, dpi=150)
    print("wrote", out)


def fig_pr_curves(base_dir, combo_dir, out: Path):
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.6), constrained_layout=True)
    for i, machine in enumerate(MACHINES):
        ax = axes[i]
        d = load_dump(base_dir, combo_dir, machine)
        y = d["labels"]
        for model in ("base", "combo"):
            s = d[model]["scores"]
            # descending thresholds, only at observed score values (log-spaced)
            thrs = np.unique(np.round(np.quantile(s, np.linspace(0, 1, 200)[::-1]), 6))
            precs, recs = [], []
            for thr in thrs:
                pred = s >= thr
                tp = int((pred & y).sum())
                fp = int((pred & ~y).sum())
                fn = int((~pred & y).sum())
                precs.append(tp / (tp + fp) if tp + fp else 1.0)
                recs.append(tp / (tp + fn) if tp + fn else 0.0)
            ax.plot(recs, precs, color=COLORS[model], lw=1.4, label=MODEL_LABELS[model])
        ax.set_title(machine, fontsize=11, **FONT)
        ax.set_xlabel("recall", **FONT)
        ax.set_ylabel("precision", **FONT)
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        if i == 0:
            ax.legend(fontsize=8)
    fig.suptitle("Per-machine precision-recall curves (VUS-PR surface)", fontsize=12, **FONT)
    fig.savefig(out, dpi=150)
    print("wrote", out)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="experiments.baselines.plot_time_rcd_compare")
    p.add_argument("--base-dump", required=True)
    p.add_argument("--combo-dump", required=True)
    p.add_argument("--results-dir", required=True)
    p.add_argument("--out-dir", required=True)
    args = p.parse_args(argv)

    base_dir = Path(args.base_dump)
    combo_dir = Path(args.combo_dump)
    results_dir = Path(args.results_dir)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    fig_score_curves(base_dir, combo_dir, out / "fig_score_curves.png")
    fig_metrics_bars(results_dir, out / "fig_metrics_bars.png")
    fig_score_dist(base_dir, combo_dir, out / "fig_score_dist.png")
    fig_pr_curves(base_dir, combo_dir, out / "fig_pr_curves.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
