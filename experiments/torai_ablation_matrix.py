#!/usr/bin/env python3
"""TORAI ablation matrix: canonical module parser, screen/confirm case split,
cold recomputation of ``matrix.csv`` + ``summary.json`` from per-run JSONs.

Canonical module contract (single source of truth):
- order: ``tail,guided,onset,consensus``
- mapping: tail -> severity_method=empirical_tail, guided -> guided_ci=True,
  onset -> temporal_precedence=True, consensus -> rcd_consensus=True
- input to ``parse_modules``: comma-separated canonical names or empty/"none"
- canonical label: ``"+".join(names)`` or ``"none"``

Runners import ``parse_modules``/``canonical_label`` and pass ONLY the parsed
config to ``ToraiRCA``; the matrix never trusts a run JSON's metric fields and
recomputes everything from per-case ranks (bad JSON/missing fields survive as
``status=failed`` rows).

Usage:
    uv run python -m experiments.torai_ablation_matrix \
        --input-dir results/torai_ablation/screen \
        --output-dir results/torai_ablation/screen-summary [--select-confirmation]
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

CANONICAL_ORDER = ("tail", "guided", "onset", "consensus")
_MODULE_CONFIG: dict[str, dict[str, Any]] = {
    "tail": {"severity_method": "empirical_tail"},
    "guided": {"guided_ci": True},
    "onset": {"temporal_precedence": True},
    "consensus": {"rcd_consensus": True},
}
# the four evaluation suites (AIOps pinned to object=docker)
SUITES = ("RE1", "RE2", "RE3", "AIOPS")


# ---------------------------------------------------------------- canonical parser

def parse_modules(spec: str) -> dict[str, Any]:
    """Parse a comma-separated canonical module list into ToraiConfig overrides.

    Raises ValueError on unknown names, duplicates, out-of-order lists, or
    empty segments. Empty string and ``"none"`` both map to ``{}``.
    """
    spec = (spec or "").strip()
    if spec == "" or spec.lower() == "none":
        return {}
    names = [t.strip() for t in spec.split(",")]
    if any(not t for t in names):
        raise ValueError(f"empty module segment in --modules {spec!r}")
    order = {name: i for i, name in enumerate(CANONICAL_ORDER)}
    idx = []
    seen: set[str] = set()
    for t in names:
        if t not in order:
            raise ValueError(
                f"unknown module {t!r}; canonical names are {','.join(CANONICAL_ORDER)}"
            )
        if t in seen:
            raise ValueError(f"duplicate module {t!r} in {spec!r}")
        seen.add(t)
        idx.append(order[t])
    if idx != sorted(idx):
        raise ValueError(
            f"modules out of canonical order {','.join(CANONICAL_ORDER)}: {spec!r}"
        )
    cfg: dict[str, Any] = {}
    for t in names:
        cfg.update(_MODULE_CONFIG[t])
    return cfg


def canonical_label(names: Iterable[str]) -> str:
    """``"+".join(names)`` or ``"none"`` (canonical, fixed order)."""
    parts = [n for n in CANONICAL_ORDER if n in list(names)]
    return "+".join(parts) if parts else "none"

def canonical_label_from_spec(spec: str) -> str:
    """Validate a ``--modules`` spec and return its canonical label.
    Shares all validation with :func:`parse_modules` (unknown/duplicate/
    out-of-order/empty-segment all raise)."""
    spec = (spec or "").strip()
    if spec == "" or spec.lower() == "none":
        return "none"
    names = [t.strip() for t in spec.split(",")]
    parse_modules(spec)  # validate
    return "+".join(names)


def module_masks() -> list[str]:
    """The 16 full-factorial masks in canonical order (none .. full)."""
    masks: list[list[str]] = [[]]
    for m in CANONICAL_ORDER:
        masks += [s + [m] for s in masks]
    return [canonical_label(s) for s in masks]


def screen_confirm_split(groups: dict[tuple, list[str]]) -> tuple[set[str], set[str]]:
    """Fixed metadata-only split: per group, case ids sorted; first
    ``ceil(0.2*n)`` are screen, the rest confirmation. Disjoint by
    construction (ids are globally unique within a suite)."""
    screen: set[str] = set()
    confirm: set[str] = set()
    for key in sorted(groups):
        ids = sorted(set(groups[key]))
        n = max(1, math.ceil(0.2 * len(ids))) if ids else 0
        screen |= set(ids[:n])
        confirm |= set(ids[n:])
    return screen, confirm


# ---------------------------------------------------------------- run loading

def _fnum(value: Any, default: float | None = None) -> float | None:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def load_runs(input_dir: Path) -> list[dict]:
    """Read every JSON in ``input_dir`` (one file = one run). Bad JSON or
    missing required fields become ``{"status": "failed", ...}`` rows."""
    runs: list[dict] = []
    files = sorted(input_dir.glob("*.json")) if input_dir.is_dir() else []
    for f in files:
        try:
            rec = json.loads(f.read_text())
        except Exception as e:  # noqa: BLE001
            runs.append(
                {"status": "failed", "path": f.name, "reason": f"{type(e).__name__}: {e}"}
            )
            continue
        required = ("suite", "stage", "modules", "variant", "seed", "cases", "failures")
        if not all(k in rec for k in required):
            runs.append(
                {
                    "status": "failed",
                    "path": f.name,
                    "reason": "missing required fields: " + ",".join(required),
                }
            )
            continue
        rec["status"] = "ok"
        runs.append(rec)
    return runs


# ---------------------------------------------------------------- metrics

def _case_metrics(cases: list[dict]) -> dict[str, Any]:
    """Native-denominator metrics from per-case ranks (rank key present =
    evaluable; rank==-1 still counts as evaluated-but-missed)."""
    evaluable = [c for c in cases if "rank" in c]
    n = len(evaluable)
    if n == 0:
        return {"n": 0, "ac1": None, "ac3": None, "ac5": None, "avg5": None}
    hits = {k: sum(1 for c in evaluable if 0 < c["rank"] <= k) for k in (1, 3, 5)}
    ac = {k: hits[k] / n for k in (1, 3, 5)}
    return {
        "n": n,
        "ac1": ac[1],
        "ac3": ac[3],
        "ac5": ac[5],
        "avg5": (ac[1] + ac[3] + ac[5]) / 3,
    }


def paired_metrics(cand_cases: list[dict], base_cases: list[dict]) -> dict[str, Any]:
    """Paired denominator: cases evaluated (rank key present) in BOTH runs.
    Deltas only over that intersection; coverage gain reported separately."""
    cand_eval = {c["case"]: c for c in cand_cases if "rank" in c}
    base_eval = {c["case"]: c for c in base_cases if "rank" in c}
    paired_ids = sorted(set(cand_eval) & set(base_eval))
    if not paired_ids:
        return {
            "paired_n": 0,
            "paired_avg5_delta": None,
            "paired_ac1_delta": None,
            "paired_avg5": None,
        }
    c = _case_metrics([cand_eval[i] for i in paired_ids])
    b = _case_metrics([base_eval[i] for i in paired_ids])
    return {
        "paired_n": len(paired_ids),
        "paired_avg5_delta": c["avg5"] - b["avg5"],
        "paired_ac1_delta": c["ac1"] - b["ac1"],
        "paired_avg5": c["avg5"],
        "paired_ac1": c["ac1"],
        "paired_base_avg5": b["avg5"],
        "paired_base_ac1": b["ac1"],
    }


CSV_COLUMNS = [
    "suite", "stage", "modules", "variant", "seed",
    "n_total", "n_evaluable", "paired_n",
    "ac@1", "ac@3", "ac@5", "avg@5",
    "paired_avg5_delta", "paired_ac1_delta",
    "p50_s", "p95_s", "total_s", "peak_rss_mb", "failure_count",
    "status",
]


def build_rows(runs: list[dict], baseline_variant: str = "improved") -> list[dict]:
    """One CSV row per run; paired deltas vs the ``{modules=none, variant=
    baseline_variant}`` base of the same (suite, stage, seed)."""
    # index base runs: (suite, stage, seed) -> cases of the selected baseline
    base_index: dict[tuple, list[dict]] = {}
    for r in runs:
        if r.get("status") != "ok":
            continue
        if r["modules"] == "none" and r["variant"] == baseline_variant:
            base_index.setdefault((r["suite"], r["stage"], r["seed"]), r["cases"])
    rows: list[dict] = []
    for r in runs:
        if r.get("status") != "ok":
            rows.append(
                {c: "" for c in CSV_COLUMNS}
                | {
                    "status": "failed",
                    "path": r.get("path", ""),
                    "reason": r.get("reason", ""),
                }
            )
            continue
        cases = r["cases"]
        n_total = r.get("n_total", len(cases) + len(r["failures"]))
        native = _case_metrics(cases)
        base_cases = base_index.get((r["suite"], r["stage"], r["seed"]), [])
        paired = (
            paired_metrics(cases, base_cases)
            if base_cases or r["modules"] == "none"
            else {"paired_n": 0, "paired_avg5_delta": None, "paired_ac1_delta": None}
        )
        latencies = [c.get("latency_s") for c in cases if c.get("latency_s") is not None]
        p50 = p95 = None
        if latencies:
            slat = sorted(latencies)
            p50 = slat[len(slat) // 2]
            p95 = slat[min(len(slat) - 1, int(math.ceil(0.95 * len(slat)) - 1))]
        row = {
            "suite": r["suite"],
            "stage": r["stage"],
            "modules": r["modules"],
            "variant": r["variant"],
            "seed": r["seed"],
            "n_total": n_total,
            "n_evaluable": native["n"],
            "paired_n": paired["paired_n"],
            "ac@1": native["ac1"],
            "ac@3": native["ac3"],
            "ac@5": native["ac5"],
            "avg@5": native["avg5"],
            "paired_avg5": paired.get("paired_avg5"),
            "paired_ac1": paired.get("paired_ac1"),
            "paired_avg5_delta": paired["paired_avg5_delta"],
            "paired_ac1_delta": paired["paired_ac1_delta"],
            "p50_s": _fnum(r.get("p50_s"), p50),
            "p95_s": _fnum(r.get("p95_s"), p95),
            "total_s": _fnum(r.get("total_s")),
            "peak_rss_mb": _fnum(r.get("peak_rss_mb")),
            "failure_count": len(r["failures"]),
            "status": "ok",
        }
        rows.append(row)
    return rows


def _round(v: float | None, nd: int = 4) -> float | None:
    return round(v, nd) if v is not None else None


def _fmt(v: Any, nd: int = 4) -> str:
    if v is None:
        return ""
    if isinstance(v, (int, float)):
        return f"{v:.{nd}f}"
    return str(v)


def write_matrix_csv(rows: list[dict], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=CSV_COLUMNS + ["path", "reason"], extrasaction="ignore"
        )
        writer.writeheader()
        for r in rows:
            writer.writerow({k: _fmt(v) for k, v in r.items()})


# ---------------------------------------------------------------- screen selection

def select_confirmation(runs: list[dict]) -> dict[str, Any]:
    """Rank non-none screen combos by macro paired Avg@5 over the suites
    (ties: paired AC@1, coverage, canonical label), take the top 3, always
    add full + none, dedupe (<= 5)."""
    rows = [r for r in build_rows(runs) if r.get("status") == "ok"]
    screen_rows = [r for r in rows if r["stage"] == "screen"]
    by_combo: dict[str, list[dict]] = defaultdict(list)
    for r in screen_rows:
        by_combo[r["modules"]].append(r)

    def macro_avg5(combo_rows: list[dict]) -> float | None:
        vals = [r["paired_avg5"] for r in combo_rows if r["paired_avg5"] is not None]
        return sum(vals) / len(vals) if vals else None

    def macro_paired_ac1(combo_rows: list[dict]) -> float | None:
        vals = [r["paired_ac1"] for r in combo_rows if r["paired_ac1"] is not None]
        return sum(vals) / len(vals) if vals else None

    def coverage(combo_rows: list[dict]) -> float:
        tot = sum(r["n_total"] for r in combo_rows)
        ev = sum(r["n_evaluable"] for r in combo_rows)
        return ev / tot if tot else 0.0

    ranking: list[tuple[str, float, float, float]] = []
    for label, combo_rows in sorted(by_combo.items()):
        if label == "none":
            continue
        a5 = macro_avg5(combo_rows)
        if a5 is None:
            continue  # unsuccessful combo (no paired cases anywhere)
        ranking.append((label, a5, macro_paired_ac1(combo_rows) or 0.0, coverage(combo_rows)))

    # ties resolved in priority order; final tie-break is canonical label (lex)
    ranking.sort(key=lambda t: (-t[1], -t[2], -t[3], t[0]))
    if len(ranking) >= 3:
        chosen = [t[0] for t in ranking[:3]]
    else:
        chosen = [t[0] for t in ranking]  # fewer than 3 successful -> all of them
    full = canonical_label(CANONICAL_ORDER)
    combos: list[str] = []
    for label in chosen + [full, "none"]:
        if label not in combos:
            combos.append(label)
    return {
        "selection_ranking": [
            {"modules": label, "macro_paired_avg5": _round(a5), "macro_paired_ac1": _round(a1),
             "coverage": _round(cov)}
            for label, a5, a1, cov in ranking
        ],
        "combos": combos,
    }


# ---------------------------------------------------------------- summary

def build_summary(
    runs: list[dict],
    rows: list[dict],
    selection: dict[str, Any] | None,
    baseline_variant: str = "improved",
) -> dict[str, Any]:
    ok = [r for r in rows if r.get("status") == "ok"]
    suites = sorted({r["suite"] for r in ok})
    stages = sorted({r["stage"] for r in ok})
    by_key: dict[tuple, list[dict]] = defaultdict(list)
    for r in ok:
        by_key[(r["suite"], r["stage"], r["modules"], r["variant"])].append(r)

    strata: dict[str, Any] = {}
    for key, grp in sorted(by_key.items()):
        suite, stage, modules, variant = key
        # seed mean/std across the seeds present
        seeds = sorted({g["seed"] for g in grp})
        seed_vals = {s: [] for s in seeds}
        for g in grp:
            if g["avg@5"] is not None:
                seed_vals[g["seed"]].append(g["avg@5"])
        seed_mean = seed_std = None
        all_vals = [v for vals in seed_vals.values() for v in vals]
        if all_vals:
            seed_mean = sum(all_vals) / len(all_vals)
            var = sum((v - seed_mean) ** 2 for v in all_vals) / len(all_vals)
            seed_std = math.sqrt(var)
        deltas = [g["paired_avg5_delta"] for g in grp if g["paired_avg5_delta"] is not None]
        ac1_deltas = [g["paired_ac1_delta"] for g in grp if g["paired_ac1_delta"] is not None]
        tot = sum(g["n_total"] for g in grp)
        ev = sum(g["n_evaluable"] for g in grp)
        strata[f"{suite}|{stage}|{modules}|{variant}"] = {
            "suite": suite, "stage": stage, "modules": modules, "variant": variant,
            "seeds": seeds,
            "n_total": tot,
            "n_evaluable": ev,
            "coverage": round(ev / tot, 4) if tot else 0.0,
            "ac@1": _round(sum(g["ac@1"] for g in grp if g["ac@1"] is not None) / max(1, sum(1 for g in grp if g["ac@1"] is not None))),
            "avg@5": _round(seed_mean),
            "seed_avg5_mean": _round(seed_mean),
            "seed_avg5_std": _round(seed_std),
            "paired_n": sum(g["paired_n"] for g in grp),
            "paired_avg5_delta_mean": _round(sum(deltas) / len(deltas)) if deltas else None,
            "paired_ac1_delta_mean": _round(sum(ac1_deltas) / len(ac1_deltas)) if ac1_deltas else None,
            "p95_s_max": max((g["p95_s"] for g in grp if g["p95_s"] is not None), default=None),
            "total_s_mean": _round(sum(g["total_s"] for g in grp if g["total_s"] is not None) / max(1, sum(1 for g in grp if g["total_s"] is not None)), 1),
            "failure_count": sum(g["failure_count"] for g in grp),
        }

    # candidate-improvement determination (confirm stage only, vs the
    # user-selected baseline: faithful+none = original TORAI or improved+none)
    candidates: list[dict] = []
    confirm_groups = [(k, v) for k, v in by_key.items() if k[1] == "confirm"]
    for key, grp in confirm_groups:
        suite, stage, modules, variant = key
        if variant != "improved" or modules == "none":
            continue
        base = by_key.get((suite, stage, "none", baseline_variant))
        if not base:
            continue
        base_delta = {
            "avg5_delta": sum(g["paired_avg5_delta"] for g in grp if g["paired_avg5_delta"] is not None)
            / max(1, sum(1 for g in grp if g["paired_avg5_delta"] is not None)),
            "ac1_delta": sum(g["paired_ac1_delta"] for g in grp if g["paired_ac1_delta"] is not None)
            / max(1, sum(1 for g in grp if g["paired_ac1_delta"] is not None)),
            "p95_s": max((g["p95_s"] for g in grp if g["p95_s"] is not None), default=None),
            "total_s": sum(g["total_s"] for g in grp if g["total_s"] is not None),
            "base_total_s": sum(g["total_s"] for g in base if g["total_s"] is not None),
        }
        candidates.append({"suite": suite, "modules": modules, **{k: _round(v) if isinstance(v, float) else v for k, v in base_delta.items()}})

    # global verdict: >=2 suites with paired avg5 delta >= +0.01, macro paired
    # AC@1 not lower, every suite p95 <= 30 s, per-suite total <= 1.5x base
    verdict: dict[str, Any] = {}
    for key, grp in confirm_groups:
        suite, stage, modules, variant = key
        if variant != "improved" or modules == "none":
            continue
        v = next((c for c in candidates if c["suite"] == suite and c["modules"] == modules), None)
        verdict.setdefault(modules, {"suites": {}})
        verdict[modules]["suites"][suite] = {
            "avg5_delta": v["avg5_delta"] if v else None,
            "ac1_delta": v["ac1_delta"] if v else None,
            "p95_s": v["p95_s"] if v else None,
            "total_s": v["total_s"] if v else None,
            "base_total_s": v["base_total_s"] if v else None,
        }
    improvements: list[str] = []
    for modules, v in verdict.items():
        suites = v["suites"]
        if len(suites) < 2:
            continue
        gains = [s for s, d in suites.items() if d["avg5_delta"] is not None and d["avg5_delta"] >= 0.01]
        if len(gains) < 2:
            continue
        ac1_ok = all(
            d["ac1_delta"] is None or d["ac1_delta"] >= 0.0
            for d in suites.values()
        )
        p95_ok = all(
            d["p95_s"] is None or d["p95_s"] <= 30.0
            for d in suites.values()
        )
        time_ok = all(
            d["total_s"] is None or d["base_total_s"] is None
            or d["base_total_s"] <= 0
            or d["total_s"] <= 1.5 * d["base_total_s"]
            for d in suites.values()
        )
        if ac1_ok and p95_ok and time_ok:
            improvements.append(modules)
    return {
        "input_files": len(runs),
        "failed_files": sum(1 for r in runs if r.get("status") == "failed"),
        "baseline_variant": baseline_variant,
        "suites": suites,
        "stages": stages,
        "strata": strata,
        "selection": selection,
        "candidate_improvements": improvements,
        "verdict": verdict,
    }


# ---------------------------------------------------------------- CLI

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-dir", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--select-confirmation", action="store_true")
    p.add_argument("--baseline-variant", default="improved",
                   choices=["improved", "faithful"],
                   help="paired-delta baseline: none@<variant> (faithful = original TORAI)")
    args = p.parse_args(argv)

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    runs = load_runs(input_dir)
    rows = build_rows(runs, baseline_variant=args.baseline_variant)
    write_matrix_csv(rows, output_dir / "matrix.csv")

    input_dir = Path(args.input_dir)
    selection = None
    if args.select_confirmation:
        selection = select_confirmation(runs)
        manifest = {
            "suites": list(SUITES),
            "seeds": [7, 11, 19],
            "combinations": [{"modules": label, "variant": "improved"} for label in selection["combos"]]
            + [{"modules": "none", "variant": "faithful"}],
            "baselines": [
                {"modules": "none", "variant": "improved"},
                {"modules": "none", "variant": "faithful"},
            ],
            "selection": selection["selection_ranking"],
        }
        (output_dir / "confirmation.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"confirmation manifest -> {output_dir / 'confirmation.json'}")
        print("selected combos:", selection["combos"])

    summary = build_summary(runs, rows, selection, baseline_variant=args.baseline_variant)
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"matrix.csv + summary.json -> {output_dir}")
    print(json.dumps({"candidate_improvements": summary["candidate_improvements"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
