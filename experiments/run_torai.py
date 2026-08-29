#!/usr/bin/env python3
"""TORAI benchmark runner + baselines.

Usage:
    uv run python -m experiments.run_torai --dataset torai-ob --variant faithful --limit 10
    uv run python -m experiments.run_torai --dataset torai-ob --variant improved \\
        --seeds 7,11,19 --methods torai,rcd_only,baro,correlation
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import time
from pathlib import Path

import numpy as np
import pandas as pd


from alg_models.causal.torai import ToraiRCA


def _peak_rss_mb() -> float:
    import resource

    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0

FAULTS = ["cpu", "mem", "disk", "socket", "delay", "loss"]
FAULT_LABEL_MAP = {"disk": "disk", "io": "disk", "latency": "delay", "socket": "socket"}


def load_case(data_dir: Path, length: int = 20) -> dict:
    """Load one case, window to ±length/2 min around inject_time."""
    with open(data_dir / "inject_time.txt") as f:
        inject_time = int(f.read().strip())
    data = pd.read_csv(data_dir / "simple_metrics.csv")
    data = data.loc[:, ~data.columns.str.endswith("_latency-50")]
    if "torai-TT" in str(data_dir):
        time_col = data["time"]
        data = data.loc[:, data.columns.str.startswith("ts-")]
        data["time"] = time_col
    data = data.replace([np.inf, -np.inf], np.nan).ffill().fillna(0)
    data = data.rename(columns={c: c.replace("_latency-90", "_latency") for c in data.columns})
    half = length * 60 // 2
    normal_df = data[data["time"] < inject_time].tail(half)
    anomal_df = data[data["time"] >= inject_time].head(half)
    data = pd.concat([normal_df, anomal_df], ignore_index=True)

    logts = pd.read_csv(data_dir / "logts.csv")
    ll = length * 4 // 2
    a = logts[logts["time"] < inject_time].tail(ll)
    b = logts[logts["time"] >= inject_time].head(ll)
    logts = pd.concat([a, b], ignore_index=True)

    traces_err = traces_lat = None
    for name in ("tracets_err.csv", "tracets_lat.csv"):
        p = data_dir / name
        if p.exists():
            df = pd.read_csv(p)
            a = df[df["time"] < inject_time].tail(ll)
            b = df[df["time"] >= inject_time].head(ll)
            m = pd.concat([a, b], ignore_index=True)
            if name == "tracets_err.csv":
                traces_err = m
            else:
                traces_lat = m

    parts = data_dir.parent.name.split("_")
    service, fault = parts[0], "_".join(parts[1:])
    return {
        "metric": data,
        "logts": logts,
        "tracets_err": traces_err,
        "tracets_lat": traces_lat,
        "inject_time": inject_time,
        "service": service,
        "fault": fault,
    }


def evaluate(ranks: list[str], answer_service: str, answer_fault: str) -> dict:
    """Coarse (service) + fine (service_fault) AC@k/Avg@5."""
    s_ranks = []
    for x in ranks:
        svc = x.split("_")[0].replace("-db", "")
        if svc not in s_ranks:
            s_ranks.append(svc)
    f_ranks = []
    for x in ranks:
        parts = x.split("_")
        svc = parts[0]
        metric = parts[1] if len(parts) > 1 and parts[1] != "A" else "unknown"
        if (svc, metric) not in f_ranks:
            f_ranks.append((svc, metric))
    ac = {}
    for k in (1, 3, 5):
        ac[f"coarse_{k}"] = int(answer_service in s_ranks[:k])
        ac[f"fine_{k}"] = int(
            any(s == answer_service and m in (answer_fault, "unknown") for s, m in f_ranks[:k])
        )
    ac["coarse_avg5"] = sum(ac[f"coarse_{k}"] for k in (1, 3, 5)) / 3
    ac["fine_avg5"] = sum(ac[f"fine_{k}"] for k in (1, 3, 5)) / 3
    return ac


def _normalize_fault_label(fault: str) -> str:
    return FAULT_LABEL_MAP.get(fault, fault)


def run_method(method: str, case: dict, rca: ToraiRCA, variant: str) -> list[str]:
    inj = case["inject_time"]
    if method == "torai":
        return rca.analyze_tables(
            case["metric"], case["logts"],
            case["tracets_err"], case["tracets_lat"],
            inject_ns=inj * 1_000_000_000, variant=variant,
        )["service_ranks"]
    if method == "rcd_only":
        return rca.analyze_tables(
            case["metric"], case["logts"],
            None, None, inject_ns=inj * 1_000_000_000, variant=variant,
        )["service_ranks"]
    if method == "baro":
        return baseline_baro(case["metric"], inj)
    if method == "correlation":
        return baseline_correlation(case["metric"], inj)
    raise ValueError(method)


def baseline_baro(metric: pd.DataFrame, inject_time: int) -> list[str]:
    normal = metric[metric["time"] < inject_time]
    anomal = metric[metric["time"] >= inject_time]
    normal = normal.loc[:, (normal != normal.iloc[0]).any()]
    cols = [c for c in normal.columns if c != "time"]
    rows = []
    for c in cols:
        a = normal[c].to_numpy()
        b = anomal[c].to_numpy()
        if a.size == 0:
            continue
        med = np.median(a)
        q25, q75 = np.percentile(a, [25, 75])
        iqr = (q75 - q25) or 1.0
        z = (b - med) / iqr
        rows.append((c, float(np.max(np.abs(z)))))
    rows.sort(key=lambda x: x[1], reverse=True)
    return [c for c, _ in rows]


def baseline_correlation(metric: pd.DataFrame, inject_time: int) -> list[str]:
    cols = [c for c in metric.columns if c != "time"]
    t = metric["time"].to_numpy()
    y = (t >= inject_time).astype(float)
    rows = []
    for c in cols:
        x = metric[c].to_numpy(dtype=np.float64)
        if np.std(x) == 0:
            continue
        r = float(np.corrcoef(x, y)[0, 1])
        rows.append((c, abs(r)))
    rows.sort(key=lambda x: x[1], reverse=True)
    return [c for c, _ in rows]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default="data/torai")
    parser.add_argument("--dataset", choices=["torai-ob", "torai-ss", "torai-tt"], required=True)
    parser.add_argument("--variant", choices=["faithful", "improved"], default="faithful")
    parser.add_argument("--methods", default="torai")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--length", type=int, default=20)
    parser.add_argument("--seeds", default="7,11,19")
    parser.add_argument("--output", default="results/torai")
    args = parser.parse_args(argv)

    root = Path(args.data)
    dataset_dir = root / ("torai-" + args.dataset.split("-")[1].upper())
    if not dataset_dir.is_dir():
        candidates = sorted(root.glob(f"torai-{args.dataset.split('-')[1].upper()}"))
        dataset_dir = candidates[0] if candidates else dataset_dir
    csv_paths = sorted(glob.glob(str(dataset_dir / "*" / "*" / "simple_metrics.csv"), recursive=True))
    if not csv_paths:
        print(f"no cases under {dataset_dir}", file=os.sys.stderr)
        return 2
    if args.limit:
        csv_paths = csv_paths[: args.limit]

    seeds = [int(s) for s in args.seeds.split(",")]
    methods = [m.strip() for m in args.methods.split(",")]
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    # aggregate across seeds for the per-fault table
    fault_agg: dict[tuple[int, str, str], list[float]] = {}

    for seed in seeds:
        seed_label = f"s{seed}"
        rca = ToraiRCA({"torai": {"variant": args.variant, "random_state": 0}}, seed=seed)
        rows: list[dict] = []
        for i, path in enumerate(csv_paths, 1):
            case = load_case(Path(path).parent, args.length)
            key = f"{case['service']}_{case['fault']}/{Path(path).parent.name}"
            row = {"case": key, "service": case["service"], "fault": case["fault"]}
            for method in methods:
                t0 = time.perf_counter()
                ranks = run_method(method, case, rca, args.variant)
                elapsed = time.perf_counter() - t0
                row[f"{method}_latency_s"] = round(elapsed, 4)
                ev = evaluate(ranks, case["service"], case["fault"])
                for k, v in ev.items():
                    row[f"{method}_{k}"] = round(v, 4) if isinstance(v, float) else v
            rows.append(row)
            if i % 10 == 0 or i == len(csv_paths):
                print(
                    f"  [{args.dataset} {args.variant} {seed_label}] {i}/{len(csv_paths)} "
                    f"cases done (last: {key})",
                    flush=True,
                )
            # accumulate for fault aggregation
            fl = _normalize_fault_label(case["fault"])
            for method in methods:
                key = (seed, method, fl)
                fault_agg.setdefault(key, []).append(row[f"{method}_coarse_avg5"])

        # write per-seed row-level JSON with a profile summary (latency + RSS)
        seed_path = out_dir / f"{args.dataset}-{args.variant}-{seed_label}.json"
        profile_summary: dict = {"dataset": args.dataset, "variant": args.variant,
                                 "seed": seed, "n_cases": len(rows),
                                 "peak_rss_mb": round(_peak_rss_mb(), 2)}
        for method in methods:
            lats = [r[f"{method}_latency_s"] for r in rows]
            if lats:
                profile_summary[f"{method}_latency_p50"] = round(float(np.median(lats)), 3)
                profile_summary[f"{method}_latency_p95"] = round(float(np.percentile(lats, 95)), 3)
        seed_payload = {"profile": profile_summary, "rows": rows}
        seed_path.write_text(json.dumps(seed_payload, indent=2) + "\n")

    # --- per-fault table ---
    print(f"Dataset: {args.dataset}  Variant: {args.variant}  Seeds: {args.seeds}")
    print(f"Methods: {','.join(methods)}  Cases: {len(csv_paths)}")
    print()
    for method in methods:
        print(f"== {method} ==")
        header = ("Fault",) + tuple(f.upper() for f in FAULTS) + ("AVERAGE",)
        print("{:<12}".format(header[0]) + "".join(f"{h:>10}" for h in header[1:]))
        row_vals = {}
        for flabel in FAULTS:
            vals = []
            for seed in seeds:
                key = (seed, method, flabel)
                if key in fault_agg:
                    vals.extend(fault_agg[key])
            row_vals[flabel] = float(np.mean(vals)) if vals else 0.0
        all_vals = [v for flabel in FAULTS for v in
                     (fault_agg.get((seed, method, flabel), [])
                      for seed in seeds)]
        all_flat = [v for seed in seeds for flabel in FAULTS
                     for v in fault_agg.get((seed, method, flabel), [])]
        avg = float(np.mean(all_flat)) if all_flat else 0.0
        line = f"{'Avg@5':<12}"
        for flabel in FAULTS:
            line += f"{row_vals.get(flabel, 0.0):>10.4f}"
        line += f"{avg:>10.4f}"
        print(line)
        print()

    # also write aggregated JSON
    agg: dict = {"dataset": args.dataset, "variant": args.variant,
                  "seeds": args.seeds, "n_cases": len(csv_paths)}
    for method in methods:
        by_fault: dict[str, float] = {}
        for flabel in FAULTS:
            vals = []
            for seed in seeds:
                vals.extend(fault_agg.get((seed, method, flabel), []))
            by_fault[flabel] = round(float(np.mean(vals)), 4) if vals else 0.0
        all_flat = [v for seed in seeds for flabel in FAULTS
                     for v in fault_agg.get((seed, method, flabel), [])]
        by_fault["overall"] = round(float(np.mean(all_flat)), 4) if all_flat else 0.0
        agg[f"{method}_avg5_by_fault"] = by_fault
        # latency
        lats = []
        for seed in seeds:
            sp = out_dir / f"{args.dataset}-{args.variant}-s{seed}.json"
            if sp.exists():
                payload = json.loads(sp.read_text())
                rows_here = payload["rows"] if isinstance(payload, dict) else payload
                for r in rows_here:
                    lats.append(r.get(f"{method}_latency_s", 0))
        if lats:
            agg[f"{method}_latency_p50"] = round(float(np.median(lats)), 3)
            agg[f"{method}_latency_p95"] = round(float(np.percentile(lats, 95)), 3)

    # aggregate file only when multiple seeds ran in one invocation; per-seed
    # row-level files are always written so parallel single-seed runs compose
    if len(seeds) > 1:
        agg_path = out_dir / f"{args.dataset}-{args.variant}.json"
        agg_path.write_text(json.dumps(agg, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())