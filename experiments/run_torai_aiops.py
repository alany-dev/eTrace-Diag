#!/usr/bin/env python3
"""Run TORAI on the AIOps Challenge 2020 dataset (instance-level RCA).

AIOps metrics are `{metric} rows per (cmdb_id, timestamp)` in per-day zips;
TORAI needs `{service}_{metric}` columns + a `time` column + an inject split.
This adapter pivots the daily platform CSVs (dcos_docker / os_linux /
db_oracle_11g) into that layout and calls
`ToraiRCA.analyze_tables` per fault, evaluating against the catalog root
instance (`name`).

Clock domains: catalog `log_time` is LOCAL time (UTC+8); metric `timestamp`
is UTC epoch millis. inject_ns is converted to UTC epoch seconds so the
`time < inject` split lands in the metric clock domain.

Instance ids contain `_` (docker_003), which collides with TORAI's service
prefix convention (`split("_")[0]`). The adapter encodes each instance id by
removing `_` (docker_003 -> docker003) and uses the same encoding on the
ground-truth name when scoring.

Usage:
    uv run python -m experiments.run_torai_aiops \
        --archive data/AIOps挑战赛2020预赛数据.zip [--object docker] [--variant faithful|improved]
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import sys
import time
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

from alg_models.causal.torai import ToraiRCA

UTC_OFFSET_H = 8  # catalog log_time is local (UTC+8)


def _encode_instance(cid: str) -> str:
    """docker_003 -> docker003 (TORAI service tokens must not contain '_')."""
    return cid.replace("_", "")


def _inject_utc_sec(log_time: str) -> int:
    """'2020/4/11 0:05' (local UTC+8) -> UTC epoch seconds."""
    # local naive datetime
    local = dt.datetime.strptime(log_time.strip(), "%Y/%m/%d %H:%M")
    local_epoch = local.replace(tzinfo=dt.timezone.utc).timestamp()
    return int(local_epoch) - UTC_OFFSET_H * 3600


OBJECT_CSV = {
    "docker": "dcos_docker.csv",
    "os": "os_linux.csv",
    "db": "db_oracle_11g.csv",
}


def _load_metric_table(inner_zip, csv_suffix: str) -> pd.DataFrame:
    """Pivot the daily platform-metric CSV into {service}_{metric} columns +
    time (sec). Sparse per-(metric,instance) timestamps produce NaN gaps,
    filled like RCAEval main.py preprocess (ffill + 0)."""
    csv_member = next((n for n in inner_zip.namelist() if n.endswith(csv_suffix)), None)
    if csv_member is None:
        return pd.DataFrame(columns=["time"])
    rows = list(csv.DictReader(io.StringIO(inner_zip.read(csv_member).decode("utf-8", "replace"))))
    # pivot: (time_sec, col) -> value
    acc: dict[tuple[int, str], float] = {}
    for r in rows:
        cid = _encode_instance(r["cmdb_id"])
        t = int(r["timestamp"]) // 1000
        col = f"{cid}_{r['name']}"
        acc[(t, col)] = float(r["value"])
    if not acc:
        return pd.DataFrame(columns=["time"])
    keys = sorted(acc.keys())
    time_sec = [k[0] for k in keys]
    cols = sorted({k[1] for k in keys})
    rows_out = {"time": time_sec}
    for c in cols:
        rows_out[c] = [acc.get((t, c), np.nan) for t in time_sec]
    df = pd.DataFrame(rows_out)
    # sparse per-(metric,instance) timestamps produce NaN gaps; RCAEval main.py
    # preprocesses metrics with ffill + fillna(0) before TORAI
    return df.ffill().fillna(0.0)


def run(args) -> dict:
    from experiments.torai_ablation_matrix import (
        canonical_label_from_spec,
        parse_modules,
        screen_confirm_split,
    )

    module_cfg = parse_modules(args.modules)
    modules_label = canonical_label_from_spec(args.modules)

    z = zipfile.ZipFile(args.archive)
    cat = z.read("故障整理（预赛）.csv").decode("utf-8", "replace")
    faults = list(csv.DictReader(io.StringIO(cat)))
    if args.object and args.object != "all":
        faults = [f for f in faults if f["object"] == args.object]

    # ---- metadata-only screen/confirm split (per object group) ----
    groups: dict[tuple, list[str]] = {}
    for f in faults:
        groups.setdefault((f["object"],), []).append(f["index"])
    screen_ids, confirm_ids = screen_confirm_split(groups)
    if args.stage == "screen":
        faults = [f for f in faults if f["index"] in screen_ids]
    elif args.stage == "confirm":
        faults = [f for f in faults if f["index"] in confirm_ids]
    if args.limit:
        faults = faults[: args.limit]

    rca = ToraiRCA({"torai": {**module_cfg, "variant": args.variant}}, seed=args.seed)
    case_records: list[dict] = []
    failures: list[dict] = []
    latencies: list[float] = []
    t0 = time.time()
    for fi, f in enumerate(faults, 1):
        day = f["log_time"].split(" ")[0].split("/")
        day_zip_name = f"AIOps挑战赛数据/{day[0]}_{int(day[1]):02d}_{int(day[2]):02d}.zip"
        idx = f["index"]
        if day_zip_name not in z.namelist():
            failures.append({"case": idx, "root": f["name"],
                             "reason": f"missing {day_zip_name}"})
            continue
        inner = zipfile.ZipFile(io.BytesIO(z.read(day_zip_name)))
        csv_suffix = OBJECT_CSV.get(f["object"])
        if csv_suffix is None:
            failures.append({"case": idx, "root": f["name"],
                             "reason": f"no csv for object {f['object']}"})
            continue
        metric = _load_metric_table(inner, csv_suffix)
        # bound RCD cost: keep top-N columns by variance when the pivot expands
        if args.max_cols and len(metric.columns) - 1 > args.max_cols:
            var = metric.drop(columns=["time"]).var()
            keep = var.nlargest(args.max_cols).index.tolist()
            metric = metric[["time"] + keep]
        if len(metric) <= 2:
            failures.append({"case": idx, "root": f["name"], "reason": "no docker metrics"})
            continue
        inject_utc = _inject_utc_sec(f["log_time"])
        # daily zip covers only the local 00:00-06:00 window; faults outside it
        # have no metric coverage for the anomalous segment -> record, skip
        if (metric["time"] < inject_utc).sum() == 0 or (metric["time"] >= inject_utc).sum() == 0:
            failures.append({"case": idx, "root": f["name"],
                             "reason": "fault time outside metric window"})
            continue
        t_start = time.perf_counter()
        try:
            res = rca.analyze_tables(
                metric, pd.DataFrame(columns=["time"]), None, None,
                inject_ns=inject_utc * 1_000_000_000,
                variant=args.variant,
            )
            lat = time.perf_counter() - t_start
            ranks = [r[:-2] if r.endswith("_A") else r for r in res["service_ranks"]]
        except Exception as e:  # noqa: BLE001 - per-case robustness for survey
            failures.append({"case": idx, "root": f["name"],
                             "reason": f"{type(e).__name__}: {e}"})
            continue
        root = _encode_instance(f["name"])
        rank = (ranks.index(root) + 1) if root in ranks else -1
        case_records.append({
            "case": idx,
            "object": f["object"],
            "root": f["name"],
            "root_enc": root,
            "rank": rank,
            "top3": ranks[:3],
            "top5": ranks[:5],
            "hit1": int(rank == 1),
            "hit3": int(0 < rank <= 3),
            "hit5": int(0 < rank <= 5),
            "latency_s": round(lat, 4),
            "module_evidence": res["module_evidence"],
        })
        latencies.append(lat)
        print(f"  [{fi}/{len(faults)}] {f['name']} rank={rank}", file=sys.stderr, flush=True)

    import math
    import resource
    peak_rss_mb = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 1)
    n_eval = len(case_records)
    n_total = n_eval + len(failures)
    hits = {k: sum(c[f"hit{k}"] for c in case_records) for k in (1, 3, 5)}
    ac = {k: round(hits[k] / n_eval, 4) if n_eval else None for k in (1, 3, 5)}
    avg5 = round((ac[1] + ac[3] + ac[5]) / 3, 4) if n_eval else None
    p50 = p95 = None
    if latencies:
        slat = sorted(latencies)
        p50 = round(slat[len(slat) // 2], 2)
        p95 = round(slat[min(len(slat) - 1, int(math.ceil(0.95 * len(slat)) - 1))], 2)

    by_object: dict[str, dict] = {}
    for c in case_records:
        e = by_object.setdefault(c["object"], {"n": 0, "hit1": 0, "hit3": 0, "hit5": 0})
        e["n"] += 1
        e["hit1"] += c["hit1"]; e["hit3"] += c["hit3"]; e["hit5"] += c["hit5"]
    for g, e in by_object.items():
        e.update({"ac@1": round(e["hit1"] / e["n"], 4),
                  "ac@3": round(e["hit3"] / e["n"], 4),
                  "ac@5": round(e["hit5"] / e["n"], 4),
                  "avg@5": round((e["hit1"] + e["hit3"] + e["hit5"]) / 3 / e["n"], 4)})

    return {
        "suite": "AIOPS",
        "object": args.object,
        "stage": args.stage,
        "modules": modules_label,
        "variant": args.variant,
        "seed": args.seed,
        "torai_config": {"variant": args.variant,
                         **{k: getattr(rca.cfg, k) for k in rca.cfg.__dataclass_fields__}},
        "n_total": n_total,
        "n_evaluable": n_eval,
        "n_failed": len(failures),
        "coverage": round(n_eval / n_total, 4) if n_total else None,
        "ac@1": ac[1], "ac@3": ac[3], "ac@5": ac[5], "avg@5": avg5,
        "p50_s": p50, "p95_s": p95,
        "total_s": round(time.time() - t0, 1),
        "peak_rss_mb": peak_rss_mb,
        "cases": case_records,
        "failures": failures,
        "by_object": by_object,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", required=True)
    p.add_argument("--object", default="docker", help="docker|os|db|all")
    p.add_argument("--max-cols", type=int, default=50,
                   help="cap metric columns by variance (os/db expand to 600-1100 cols; RCD explodes)")
    p.add_argument("--variant", default="faithful", choices=["faithful", "improved"])
    p.add_argument("--modules", default="none",
                   help="comma-separated canonical modules tail,guided,onset,consensus "
                        "(fixed order; empty or 'none' = baseline)")
    p.add_argument("--stage", default="all", choices=["all", "screen", "confirm"],
                   help="case selection: metadata-defined screen/confirm split")
    p.add_argument("--output", default="", help="write the run JSON here")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--seed", type=int, default=7)
    args = p.parse_args(argv)
    out = run(args)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(out, indent=2, ensure_ascii=False))
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

