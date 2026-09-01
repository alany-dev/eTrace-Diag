"""TORAI faithful vs improved (RCA task) — paper-style comparison figures.

Generates figures for RCAeval RE1/RE2/RE3 and AIOps Challenge 2020 from the
measured result JSONs (`results/rcaeval/*.json`, `results/aiops/*.json`),
mirroring TORAI (arXiv:2604.13522) / RCAEval presentation forms: grouped bars
for AC@k / Avg@5, per-fault and per-system breakdowns, rank distribution,
and latency speedup.

Run:
    uv run --with matplotlib python -m experiments.baselines.plot_torai_rca \
        --rcaeval-dir results/rcaeval --aiops-dir results/aiops \
        --out-dir docs/research/assets/torai-rca
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import matplotlib

matplotlib.rcParams["font.family"] = "WenQuanYi Zen Hei"
matplotlib.rcParams["axes.unicode_minus"] = False



import numpy as np

SUITES = ["RE1", "RE2", "RE3", "AIOps"]
VARIANT_CN = {"faithful": "TORAI 基准版 faithful", "improved": "TORAI 改进版 improved"}
COLORS = {"faithful": "#2b6cb0", "improved": "#c05621"}
FONT = {"family": "WenQuanYi Zen Hei"}


def load_rcaeval(d: Path) -> dict:
    out = {}
    for suite in ("RE1", "RE2", "RE3"):
        for var in ("faithful", "improved"):
            agg = json.loads((d / f"{suite}-{var}.json").read_text())
            cases = json.loads((d / f"{suite}-{var}-cases.json").read_text())
            out[(suite, var)] = {"agg": agg, "cases": cases}
    return out


def load_aiops(d: Path) -> dict:
    out = {}
    for var in ("faithful", "improved"):
        out[var] = json.loads((d / f"{var}.json").read_text())
    return out


def fig_avg5(rcaeval: dict, aiops: dict, out: Path):
    import matplotlib.pyplot as plt

    vals = {v: [] for v in ("faithful", "improved")}
    for suite in ("RE1", "RE2", "RE3"):
        for var in ("faithful", "improved"):
            vals[var].append(rcaeval[(suite, var)]["agg"]["avg@5"])
    for var in ("faithful", "improved"):
        vals[var].append(aiops[var]["avg@5"])

    x = np.arange(len(SUITES))
    w = 0.36
    fig, ax = plt.subplots(figsize=(8.5, 4.6), constrained_layout=True)
    for i, var in enumerate(("faithful", "improved")):
        bars = ax.bar(x + (i - 0.5) * w, vals[var], w, color=COLORS[var], label=VARIANT_CN[var])
        for b, v in zip(bars, vals[var]):
            ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.3f}", ha="center", va="bottom", fontsize=9)
    ax.set_xticks(x)
    ax.set_xticklabels([f"RCAeval {s}" for s in SUITES[:3]] + ["AIOps 2020"], fontsize=10)
    ax.set_ylabel("Avg@5", fontsize=11, **FONT)
    ax.set_ylim(0, 1.08)
    ax.set_title("Avg@5 per dataset — faithful vs improved", fontsize=12, **FONT)
    ax.legend(fontsize=9)
    fig.savefig(out, dpi=150)
    print("wrote", out)


def fig_ack(rcaeval: dict, aiops: dict, out: Path):
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.4), constrained_layout=True)
    for i, metric in enumerate(("ac@1", "ac@3", "ac@5")):
        ax = axes[i]
        x = np.arange(len(SUITES))
        w = 0.36
        for j, var in enumerate(("faithful", "improved")):
            vals = [rcaeval[(s, var)]["agg"][metric] for s in ("RE1", "RE2", "RE3")]
            vals.append(aiops[var][metric])
            bars = ax.bar(x + (j - 0.5) * w, vals, w, color=COLORS[var], label=VARIANT_CN[var])
            for b, v in zip(bars, vals):
                ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.2f}", ha="center", va="bottom", fontsize=8)
        ax.set_xticks(x)
        ax.set_xticklabels([f"RE1", "RE2", "RE3", "AIOps"], fontsize=9)
        ax.set_ylim(0, 1.1)
        ax.set_title(f"{metric.upper()}", fontsize=11)
        if i == 0:
            ax.set_ylabel("accuracy", **FONT)
            ax.legend(fontsize=8)
    fig.suptitle("AC@k per dataset — faithful vs improved", fontsize=12, **FONT)
    fig.savefig(out, dpi=150)
    print("wrote", out)


def fig_byfault(rcaeval: dict, aiops: dict, out: Path):
    import matplotlib.pyplot as plt

    fault_orders = {
        "RE1": ["cpu", "mem", "delay", "disk", "loss"],
        "RE2": ["cpu", "mem", "delay", "disk", "loss", "socket"],
        "RE3": ["f1", "f2", "f3", "f4", "f5"],
    }
    fig, axes = plt.subplots(2, 2, figsize=(13, 8.5), constrained_layout=True)
    for k, suite in enumerate(("RE1", "RE2", "RE3")):
        ax = axes[k // 2, k % 2]
        faults = fault_orders[suite]
        x = np.arange(len(faults))
        w = 0.36
        for j, var in enumerate(("faithful", "improved")):
            by_fault = rcaeval[(suite, var)]["agg"]["by_fault"]
            vals = [by_fault[f]["avg@5"] if f in by_fault else 0.0 for f in faults]
            ax.bar(x + (j - 0.5) * w, vals, w, color=COLORS[var], label=VARIANT_CN[var])
        ax.set_xticks(x)
        ax.set_xticklabels(faults, fontsize=9)
        ax.set_ylim(0, 1.08)
        ax.set_title(f"RCAeval {suite} — per-fault Avg@5", fontsize=11, **FONT)
        if suite == "RE1":
            ax.legend(fontsize=8)
    # AIOps by-object (computed from per_case; faithful evaluable os subset differs)
    ax = axes[1, 1]
    objs = ["db", "docker", "os"]
    x = np.arange(len(objs))
    w = 0.36
    for j, var in enumerate(("faithful", "improved")):
        per_case = aiops[var]["per_case"]
        vals = []
        for o in objs:
            n = h1 = h3 = h5 = 0
            for c in per_case.values():
                if "rank" not in c or not c["root_enc"].startswith(o):
                    continue
                n += 1
                r = c["rank"]
                h1 += r == 1
                h3 += 0 < r <= 3
                h5 += 0 < r <= 5
            vals.append((h1 + h3 + h5) / 3 / n if n else 0.0)
        bars = ax.bar(x + (j - 0.5) * w, vals, w, color=COLORS[var], label=VARIANT_CN[var])
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.3f}", ha="center", va="bottom", fontsize=8)
    ax.set_xticks(x)
    ax.set_xticklabels(objs, fontsize=9)
    ax.set_ylim(0, 1.08)
    ax.set_title("AIOps 2020 — per-object Avg@5", fontsize=11, **FONT)
    fig.suptitle("Per-fault / per-object Avg@5", fontsize=12, **FONT)
    fig.savefig(out, dpi=150)
    print("wrote", out)


def fig_bysystem(rcaeval: dict, out: Path):
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.4), constrained_layout=True)
    for i, suite in enumerate(("RE1", "RE2", "RE3")):
        ax = axes[i]
        systems = ["ob", "ss", "tt"]
        x = np.arange(len(systems))
        w = 0.36
        for j, var in enumerate(("faithful", "improved")):
            by_sys = rcaeval[(suite, var)]["agg"]["by_system"]
            vals = [by_sys[s]["avg@5"] if s in by_sys else 0.0 for s in systems]
            ax.bar(x + (j - 0.5) * w, vals, w, color=COLORS[var], label=VARIANT_CN[var])
        ax.set_xticks(x)
        ax.set_xticklabels(["Online Boutique", "Sock Shop", "Train Ticket"], fontsize=9, rotation=10)
        ax.set_ylim(0, 1.08)
        ax.set_title(f"RCAeval {suite} — per-system Avg@5", fontsize=11, **FONT)
        if i == 0:
            ax.legend(fontsize=8)
    fig.suptitle("Per-system Avg@5", fontsize=12, **FONT)
    fig.savefig(out, dpi=150)
    print("wrote", out)


def fig_rankdist(rcaeval: dict, aiops: dict, out: Path):
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4), constrained_layout=True)
    bins = np.arange(1, 8) - 0.5  # rank 1..6+, last bin = >5

    # RCAeval: rank distribution pooled over RE1-RE3
    ax = axes[0]
    for var, color in COLORS.items():
        ranks = []
        for suite in ("RE1", "RE2", "RE3"):
            for c in rcaeval[(suite, var)]["cases"].values():
                if "rank" in c:
                    ranks.append(min(c["rank"], 6))
        counts, _ = np.histogram(ranks, bins=bins)
        ax.bar(np.arange(1, 7) + (0.4 if var == "improved" else -0.4), counts,
               width=0.4, color=color, label=VARIANT_CN[var])
    ax.set_xticks(np.arange(1, 7))
    ax.set_xticklabels(["1", "2", "3", "4", "5", ">5"], fontsize=9)
    ax.set_xlabel("root-cause rank", **FONT)
    ax.set_ylabel("cases", **FONT)
    ax.set_title("RCAeval RE1-3 rank distribution (733 cases)", fontsize=11, **FONT)
    ax.legend(fontsize=8)

    # AIOps rank distribution
    ax = axes[1]
    for var, color in COLORS.items():
        ranks = [min(c["rank"], 6) for c in aiops[var]["per_case"].values() if "rank" in c]
        counts, _ = np.histogram(ranks, bins=bins)
        ax.bar(np.arange(1, 7) + (0.4 if var == "improved" else -0.4), counts,
               width=0.4, color=color, label=VARIANT_CN[var])
    ax.set_xticks(np.arange(1, 7))
    ax.set_xticklabels(["1", "2", "3", "4", "5", ">5"], fontsize=9)
    ax.set_xlabel("root-cause rank", **FONT)
    ax.set_title("AIOps 2020 rank distribution", fontsize=11, **FONT)
    ax.legend(fontsize=8)
    fig.suptitle("Root-cause rank distribution (faithful vs improved)", fontsize=12, **FONT)
    fig.savefig(out, dpi=150)
    print("wrote", out)


def fig_speedup(rcaeval: dict, aiops: dict, out: Path):
    import matplotlib.pyplot as plt

    labels = ["RE1", "RE2", "RE3", "AIOps"]
    f_vals = [rcaeval[(s, "faithful")]["agg"]["total_s"] for s in ("RE1", "RE2", "RE3")]
    f_vals.append(aiops["faithful"]["total_s"])
    i_vals = [rcaeval[(s, "improved")]["agg"]["total_s"] for s in ("RE1", "RE2", "RE3")]
    i_vals.append(aiops["improved"]["total_s"])

    x = np.arange(len(labels))
    w = 0.36
    fig, ax = plt.subplots(figsize=(8.5, 4.4), constrained_layout=True)
    ax.bar(x - w / 2, f_vals, w, color=COLORS["faithful"], label=VARIANT_CN["faithful"])
    ax.bar(x + w / 2, i_vals, w, color=COLORS["improved"], label=VARIANT_CN["improved"])
    for xi, fv, iv in zip(x, f_vals, i_vals):
        ax.text(xi - w / 2, fv, f"{fv:.0f}s", ha="center", va="bottom", fontsize=8)
        ax.text(xi + w / 2, iv, f"{iv:.0f}s", ha="center", va="bottom", fontsize=8)
        sp = fv / iv if iv else float("nan")
        ax.text(xi, max(fv, iv) * 1.06, f"{sp:.2f}x" if sp >= 1 else f"{-1/sp:.2f}x", ha="center", fontsize=9, color="#e53e3e")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("total wall time (s)", **FONT)
    ax.set_title("Latency — faithful vs improved (speedup annotation)", fontsize=12, **FONT)
    ax.legend(fontsize=9)
    fig.savefig(out, dpi=150)
    print("wrote", out)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="experiments.baselines.plot_torai_rca")
    p.add_argument("--rcaeval-dir", required=True)
    p.add_argument("--aiops-dir", required=True)
    p.add_argument("--out-dir", required=True)
    args = p.parse_args(argv)

    rcaeval = load_rcaeval(Path(args.rcaeval_dir))
    aiops = load_aiops(Path(args.aiops_dir))
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    fig_avg5(rcaeval, aiops, out / "fig_rca_avg5.png")
    fig_ack(rcaeval, aiops, out / "fig_rca_ack.png")
    fig_byfault(rcaeval, aiops, out / "fig_rca_byfault.png")
    fig_bysystem(rcaeval, out / "fig_rca_bysystem.png")
    fig_rankdist(rcaeval, aiops, out / "fig_rca_rankdist.png")
    fig_speedup(rcaeval, aiops, out / "fig_rca_speedup.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
