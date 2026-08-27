"""AIOps Challenge 2020 (preliminary round) instance-level fault attribution.

Reads the fault catalog (`故障整理（预赛）.csv`) and the daily metric zips
(`平台指标/dcos_docker.csv` for docker faults). For each fault, ranks instances
by the deviation of the fault's KPI metric around the fault segment and checks
whether the catalog `name` (root instance) is the top hit.

    uv run python -m experiments.aiops2020 \
        --archive data/AIOps挑战赛2020预赛数据.zip --limit 11 --top-k 3

License note: AIOps 2020 requires a non-commercial research license — recorded
in docs/research/data-matrix.md; use the user-provided archive only under that
license. Catalog `log_time` and metric `timestamp` are in different clock
domains (the Challenge's offset), so attribution uses per-instance deviation
rank within the corresponding daily archive rather than exact wall-clock.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import zipfile
from pathlib import Path

import numpy as np


def _day_zip(date_str: str) -> str:
    # "2020/4/11" -> "2020_04_11"
    y, m, d = date_str.split("/")
    d = d.split(" ")[0]
    return f"{y}_{int(m):02d}_{int(d):02d}"


def _metric_for(object_: str, fault: str) -> str:
    if object_ == "docker":
        return "container_cpu_used" if "CPU" in fault else "container_net_io"
    if object_ == "db":
        return "Sess_Connect"  # fallback; catalog gives kpi(s) per fault
    return "cpu_used"


def _series_by_instance(csv_bytes: bytes, metric: str) -> dict[str, np.ndarray]:
    rows = list(csv.DictReader(io.StringIO(csv_bytes.decode("utf-8", "replace"))))
    by: dict[str, list[float]] = {}
    for r in rows:
        if r["name"] == metric:
            by.setdefault(r["cmdb_id"], []).append(max(0.0, float(r["value"])))
    return {k: np.asarray(v) for k, v in by.items() if len(v) > 10}


def _deviation_rank(series: dict[str, np.ndarray]) -> list[tuple[str, float]]:
    dev: list[tuple[str, float]] = []
    for k, v in series.items():
        med = float(np.median(v))
        mad = float(np.median(np.abs(v - med))) + 1e-9
        dev.append((k, float(np.max(np.abs(v - med)) / (1.4826 * mad))))
    dev.sort(key=lambda x: -x[1])
    return dev


def run(args) -> dict:
    z = zipfile.ZipFile(args.archive)
    cat = z.read("故障整理（预赛）.csv").decode("utf-8", "replace")
    faults = list(csv.DictReader(io.StringIO(cat)))
    if args.object:
        faults = [f for f in faults if f["object"] == args.object]
    faults = faults[: args.limit] if args.limit else faults

    hits, per_case = [], {}
    for f in faults:
        day = _day_zip(f["log_time"])
        member = f"AIOps挑战赛数据/{day}.zip"
        if member not in z.namelist():
            per_case[f["index"]] = {"root": f["name"], "hit@1": False, "reason": f"missing {day}.zip"}
            continue
        inner = zipfile.ZipFile(io.BytesIO(z.read(member)))
        kpi = f["kpi"].split(";")[0] if f["kpi"] else _metric_for(f["object"], f["fault_desrcibtion"])
        csv_member = next((n for n in inner.namelist() if n.endswith("dcos_docker.csv")), None)
        if csv_member is None:
            per_case[f["index"]] = {"root": f["name"], "hit@1": False, "reason": "no docker.csv"}
            continue
        series = _series_by_instance(inner.read(csv_member), kpi)
        rank = _deviation_rank(series)
        top = [k for k, _ in rank[: args.top_k]]
        hit = f["name"] in top
        hits.append(hit)
        per_case[f["index"]] = {"root": f["name"], "top": top[:3], "rank": next((i for i, (k, _) in enumerate(rank) if k == f["name"]), -1) + 1, "hit@1": f["name"] == top[0] if top else False}

    n = max(1, len(hits))
    return {
        "object": args.object or "all",
        "n_faults": len(per_case),
        f"hit@{args.top_k}": round(sum(hits) / n, 4),
        "hit@1": round(sum(1 for c in per_case.values() if c.get("hit@1")) / max(1, len(per_case)), 4),
        "per_case": per_case,
        "license": "non-commercial research; see docs/research/data-matrix.md",
        "note": "catalog log_time and metric timestamp are offset clocks; "
                "attribution = per-instance KPI deviation rank within the daily archive",
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--archive", required=True)
    p.add_argument("--object", default=None, help="docker/db/os (None = all)")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--top-k", type=int, default=3)
    p.add_argument("--output", default=None)
    args = p.parse_args(argv)
    r = run(args)
    print(json.dumps(r, indent=2))
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(r, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())