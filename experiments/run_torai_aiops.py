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
    z = zipfile.ZipFile(args.archive)
    cat = z.read("故障整理（预赛）.csv").decode("utf-8", "replace")
    faults = list(csv.DictReader(io.StringIO(cat)))
    if args.object and args.object != "all":
        faults = [f for f in faults if f["object"] == args.object]
    if args.limit:
        faults = faults[: args.limit]

    rca = ToraiRCA({"torai": {"variant": args.variant}}, seed=args.seed)
    per_case: dict[str, dict] = {}
    t0 = time.time()
    for fi, f in enumerate(faults, 1):
        day = f["log_time"].split(" ")[0].split("/")
        day_zip_name = f"AIOps挑战赛数据/{day[0]}_{int(day[1]):02d}_{int(day[2]):02d}.zip"
        idx = f["index"]
        if day_zip_name not in z.namelist():
            per_case[idx] = {"root": f["name"], "reason": f"missing {day_zip_name}"}
            continue
        inner = zipfile.ZipFile(io.BytesIO(z.read(day_zip_name)))
        csv_suffix = OBJECT_CSV.get(f["object"])
        if csv_suffix is None:
            per_case[idx] = {"root": f["name"], "reason": f"no csv for object {f['object']}"}
            continue
        metric = _load_metric_table(inner, csv_suffix)
        # bound RCD cost: keep top-N columns by variance when the pivot expands
        if args.max_cols and len(metric.columns) - 1 > args.max_cols:
            var = metric.drop(columns=["time"]).var()
            keep = var.nlargest(args.max_cols).index.tolist()
            metric = metric[["time"] + keep]
        if len(metric) <= 2:
            per_case[idx] = {"root": f["name"], "reason": "no docker metrics"}
            continue
        inject_utc = _inject_utc_sec(f["log_time"])
        # daily zip covers only the local 00:00-06:00 window; faults outside it
        # have no metric coverage for the anomalous segment -> record, skip
        if (metric["time"] < inject_utc).sum() == 0 or (metric["time"] >= inject_utc).sum() == 0:
            per_case[idx] = {"root": f["name"], "reason": "fault time outside metric window"}
            continue
        try:
            res = rca.analyze_tables(
                metric, pd.DataFrame(columns=["time"]), None, None,
                inject_ns=inject_utc * 1_000_000_000,
                variant=args.variant,
            )
            ranks = [r[:-2] if r.endswith("_A") else r for r in res["service_ranks"]]
        except Exception as e:  # noqa: BLE001 - per-case robustness for survey
            per_case[idx] = {"root": f["name"], "reason": f"{type(e).__name__}: {e}"}
            continue
        root = _encode_instance(f["name"])
        per_case[idx] = {
            "root": f["name"],
            "root_enc": root,
            "top3": ranks[:3],
            "top5": ranks[:5],
            "rank": (ranks.index(root) + 1) if root in ranks else -1,
        }
        print(f"  [{fi}/{len(faults)}] {f['name']} rank={per_case[idx]['rank']}", file=sys.stderr, flush=True)

    elapsed = time.time() - t0
    n = sum(1 for c in per_case.values() if "rank" in c)
    if n == 0:
        return {"object": args.object, "variant": args.variant, "n_cases": 0,
                "note": "no case had metric coverage"}
    hit1 = sum(1 for c in per_case.values() if c.get("rank") == 1)
    hit3 = sum(1 for c in per_case.values() if 0 < c.get("rank", 0) <= 3)
    hit5 = sum(1 for c in per_case.values() if 0 < c.get("rank", 0) <= 5)
    # RCAEval-style Avg@5 = (AC@1 + AC@3 + AC@5) / 3
    avg5 = (hit1 + hit3 + hit5) / 3 / n
    return {
        "object": args.object,
        "variant": args.variant,
        "n_cases": n,
        "ac@1": round(hit1 / n, 4),
        "ac@3": round(hit3 / n, 4),
        "ac@5": round(hit5 / n, 4),
        "avg@5": round(avg5, 4),
        "total_s": round(elapsed, 1),
        "per_case": per_case,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", required=True)
    p.add_argument("--object", default="docker", help="docker|os|db|all")
    p.add_argument("--max-cols", type=int, default=200,
                   help="cap metric columns by variance (os/db expand to 600-1100 cols; RCD explodes)")
    p.add_argument("--variant", default="faithful", choices=["faithful", "improved"])
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--seed", type=int, default=7)
    args = p.parse_args(argv)
    out = run(args)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
