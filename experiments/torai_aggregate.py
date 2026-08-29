#!/usr/bin/env python3
"""Aggregate per-seed TORAI benchmark row files into per-dataset/variant
tables and profile-{variant}.json. Pure re-read of results/torai/*-s*.json.

Usage:
    uv run python -m experiments.torai_aggregate [--out results/torai]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

FAULTS = ["cpu", "mem", "disk", "socket", "delay", "loss"]
FAULT_MAP = {"io": "disk", "latency": "delay"}
METHODS = ["torai", "rcd_only", "baro", "correlation"]


def norm_fault(f: str) -> str:
    return FAULT_MAP.get(f, f)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="results/torai")
    args = parser.parse_args(argv)
    out = Path(args.out)

    # group per-seed files by (dataset, variant)
    groups: dict[tuple[str, str], list[dict]] = {}
    for f in sorted(out.glob("*-s*.json")):
        if not f.name.endswith(".json") or "-s" not in f.name:
            continue
        stem = f.name[:-5]  # strip .json
        if stem.count("-") < 3:
            continue
        # torai-ob-faithful-s7
        parts = stem.split("-")
        # dataset = first 2, variant = next, s = last
        dataset = "-".join(parts[:-2])
        variant = parts[-2]
        seed = parts[-1][1:]
        payload = json.loads(f.read_text())
        if isinstance(payload, dict) and "rows" in payload:
            rows = payload["rows"]
            profile = payload.get("profile", {})
        else:
            rows = payload
            profile = {}
        groups.setdefault((dataset, variant), []).append(
            {"seed": seed, "profile": profile, "rows": rows}
        )

    results: dict = {}
    for (dataset, variant), runs in groups.items():
        # per-fault coarse Avg@5 averaged across seeds
        by_fault: dict[str, list[float]] = {}
        overall: list[float] = []
        latency: dict[str, list[float]] = {m: [] for m in METHODS}
        for run in runs:
            for r in run["rows"]:
                fl = norm_fault(r["fault"])
                for m in METHODS:
                    if f"{m}_coarse_avg5" in r:
                        by_fault.setdefault(fl, []).append(r[f"{m}_coarse_avg5"])
                        if fl != "unknown":
                            overall.append(r[f"{m}_coarse_avg5"])
                    if f"{m}_latency_s" in r:
                        latency[m].append(r[f"{m}_latency_s"])
        entry = {"dataset": dataset, "variant": variant, "n_seeds": len(runs)}
        for m in METHODS:
            entry[f"{m}_avg5_by_fault"] = {
                fl: (round(float(sum(v) / len(v)), 4) if v else 0.0)
                for fl, v in by_fault.items()
            }
            ov = overall if m == "torai" else overall  # same overall pool per method
            # overall should be per-method: recompute
        # recompute per-method overall properly
        for m in METHODS:
            vals = [r[f"{m}_coarse_avg5"] for run in runs for r in run["rows"]
                    if f"{m}_coarse_avg5" in r and norm_fault(r["fault"]) != "unknown"]
            entry[f"{m}_overall_avg5"] = round(float(sum(vals) / len(vals)), 4) if vals else 0.0
            lats = latency[m]
            if lats:
                entry[f"{m}_latency_p50"] = round(float(sorted(lats)[len(lats) // 2]), 3)
                entry[f"{m}_latency_p95"] = round(float(sorted(lats)[int(len(lats) * 0.95) - 1]), 3)
        # peak RSS = max across seeds
        entry["peak_rss_mb"] = round(max((r["profile"]["peak_rss_mb"] for r in runs), default=0.0), 2)
        results[f"{dataset}-{variant}"] = entry

    (out / "benchmark-summary.json").write_text(json.dumps(results, indent=2) + "\n")
    # profile-{variant}.json: p50/p95 + peak RSS per dataset (plan Step 5.3)
    for variant in ("faithful", "improved"):
        prof = {}
        for key, v in results.items():
            ds, var = key.rsplit("-", 1)
            if var != variant:
                continue
            prof[ds] = {
                "torai_latency_p50": v.get("torai_latency_p50"),
                "torai_latency_p95": v.get("torai_latency_p95"),
                "peak_rss_mb": v.get("peak_rss_mb"),
                "overall_avg5": v.get("torai_overall_avg5"),
            }
        if prof:
            (out / f"profile-{variant}.json").write_text(
                json.dumps(prof, indent=2) + "\n"
            )
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
