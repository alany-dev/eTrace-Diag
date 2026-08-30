#!/usr/bin/env python3
"""Run TORAI on the OFFICIAL RCAEval RE1/RE2/RE3 datasets (direct parquet).

Reads each case's `metrics.parquet` / `logs.parquet` / `traces.parquet`
directly from `data/rcaeval/<case>/` and the ground truth from
`cases.parquet` (root_cause_service + inject_time). No derived dataset is
written. Windowing follows RCAEval main.py `--length 20` (±10 min around
inject). Metric columns are already `{service}_{metric}` in the official
layout, matching TORAI's convention.

Usage:
    uv run python -m experiments.run_torai_rcaeval --suite RE1 [--limit 10]
    uv run python -m experiments.run_torai_rcaeval --suite RE2 [--logs --traces]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

from alg_models.causal.torai import ToraiRCA

BIN_S = 15
HALF_SEC = 10 * 60  # ±10 min around inject (main.py length=20)
LOG_TAIL = 40  # 15s bins per half (main.py logts_length = length*4//2)

_VAR_TOKEN = re.compile(
    r"^\s*(?:<.*>|[-\+]?\d+(?:\.\d+)?(?:[eE][-\+]?\d+)?|[0-9a-fA-F]{6,}(?::[0-9a-fA-F]{1,4})?|"
    r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?|0x[0-9a-fA-F]+|[-_\w]*\d[-_\w]*)$"
)
_SPLIT = re.compile(r"([^\w\s]|_)")


class _Drain:
    """Compact classic Drain (LogPAI-style): fixed-depth prefix + similarity
    merge, bounding the template count per service (tens, not thousands)."""

    def __init__(self, depth: int = 3, sim_th: float = 0.5, max_groups: int = 500):
        self.depth, self.sim_th, self.max_groups = depth, sim_th, max_groups
        self._prefix: dict[tuple, list[int]] = {}
        self._templates: list[str] = []

    def _tokens(self, message: str) -> list[str]:
        return [
            ("<*>" if _VAR_TOKEN.match(t) else t)
            for t in _SPLIT.sub(" ", str(message)).split()
            if t
        ]

    def match(self, message: str) -> int:
        tokens = self._tokens(message) or ["<*>"]
        prefix = tuple(tokens[: self.depth]) if len(tokens) >= self.depth else tuple(tokens)
        for idx in self._prefix.get(prefix, []):
            gt = self._templates[idx].split()
            if len(gt) != len(tokens):
                continue
            same = sum(1 for x, y in zip(gt, tokens) if x == y)
            if same / len(tokens) >= self.sim_th:
                merged = [g if g == t else "<*>" for g, t in zip(gt, tokens)]
                if merged != gt:
                    self._templates[idx] = " ".join(merged)
                return idx
        if len(self._templates) >= self.max_groups:
            self._prefix.setdefault(prefix, []).append(len(self._templates) - 1)
            return len(self._templates) - 1
        idx = len(self._templates)
        self._templates.append(" ".join(tokens))
        self._prefix.setdefault(prefix, []).append(idx)
        return idx


def load_case(case_dir: Path, inject_time: int, use_logs: bool, use_traces: bool) -> dict:
    """Build TORAI tables for one official case, windowed ±10 min around inject."""
    metrics = pd.read_parquet(case_dir / "metrics.parquet")
    metrics = metrics.replace([np.inf, -np.inf], np.nan).ffill().fillna(0)
    normal = metrics[metrics["time"] < inject_time].tail(HALF_SEC)
    anomal = metrics[metrics["time"] >= inject_time].head(HALF_SEC)
    metric = pd.concat([normal, anomal], ignore_index=True)

    logts = pd.DataFrame(columns=["time"])
    if use_logs and (case_dir / "logs.parquet").exists():
        logs = pd.read_parquet(case_dir / "logs.parquet")
        if len(logs):
            logts = _build_logts(logs, inject_time)

    tracets_err = tracets_lat = None
    if use_traces and (case_dir / "traces.parquet").exists():
        traces = pd.read_parquet(case_dir / "traces.parquet")
        if len(traces):
            tracets_err, tracets_lat = _build_traces(traces, inject_time)

    return {"metric": metric, "logts": logts, "tracets_err": tracets_err, "tracets_lat": tracets_lat}


def _build_logts(logs: pd.DataFrame, inject_time: int) -> pd.DataFrame:
    rows: list[dict] = []
    for svc in sorted(logs["container_name"].astype(str).unique()):
        sub = logs[logs["container_name"] == svc]
        drain = _Drain()
        bins = (sub["timestamp"].astype("int64") // BIN_S) * BIN_S
        for b, msg in zip(bins.tolist(), sub["message"].astype(str).tolist()):
            rows.append({"bin": int(b), "col": f"{svc}_{drain.match(msg):04d}"})
    counts = pd.DataFrame(rows).groupby(["bin", "col"]).size().unstack(fill_value=0)
    counts.index.name = "time"
    counts = counts.reset_index()
    a = counts[counts["time"] < inject_time].tail(LOG_TAIL)
    b = counts[counts["time"] >= inject_time].head(LOG_TAIL)
    return pd.concat([a, b], ignore_index=True)


def _build_traces(traces: pd.DataFrame, inject_time: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    df = traces.copy()
    df["bin"] = (df["startTimeMillis"].astype("int64") // (BIN_S * 1000)) * BIN_S
    err = (
        df.assign(is_err=(pd.to_numeric(df["statusCode"], errors="coerce").fillna(0) != 200).astype(int))
        .groupby(["bin", "serviceName"])["is_err"]
        .sum()
        .unstack(fill_value=0)
    )
    err.columns = [f"{c}_errors" for c in err.columns]
    lat = df.groupby(["bin", "serviceName"])["duration"].mean().unstack()
    lat.columns = [f"{c}_latency" for c in lat.columns]
    for tbl in (err, lat):
        tbl.index.name = "time"
        tbl.reset_index(inplace=True)
        a = tbl[tbl["time"] < inject_time].tail(LOG_TAIL)
        b = tbl[tbl["time"] >= inject_time].head(LOG_TAIL)
    err_out = pd.concat([err[err["time"] < inject_time].tail(LOG_TAIL),
                         err[err["time"] >= inject_time].head(LOG_TAIL)], ignore_index=True)
    lat_out = pd.concat([lat[lat["time"] < inject_time].tail(LOG_TAIL),
                         lat[lat["time"] >= inject_time].head(LOG_TAIL)], ignore_index=True)
    return err_out, lat_out


def evaluate(ranks: list[str], answer_service: str) -> dict:
    s_ranks = []
    for x in ranks:
        svc = x.split("_")[0].replace("-db", "")
        if svc not in s_ranks:
            s_ranks.append(svc)
    return {k: int(answer_service in s_ranks[:k]) for k in (1, 3, 5)}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", default="data/rcaeval")
    p.add_argument("--suite", default="RE1", choices=["RE1", "RE2", "RE3"])
    p.add_argument("--variant", default="faithful", choices=["faithful", "improved"])
    p.add_argument("--seeds", default="7")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--start", type=int, default=0, help="skip first N cases (resume)")
    p.add_argument("--logs", action="store_true", help="include logs modality (RE2/RE3)")
    p.add_argument("--traces", action="store_true", help="include traces modality (RE2/RE3 OB/TT)")
    args = p.parse_args(argv)

    root = Path(args.data)
    cases = pd.read_parquet(root / "cases.parquet")
    suite = cases[cases["suite"] == args.suite]
    if args.start:
        suite = suite.iloc[args.start:]
    if args.limit:
        suite = suite.head(args.limit)

    seeds = [int(s) for s in args.seeds.split(",")]
    rca = ToraiRCA({"torai": {"variant": args.variant}}, seed=seeds[0])
    hits = {k: [] for k in (1, 3, 5)}
    per_case: dict[str, dict] = {}
    t0 = time.time()
    for _, row in suite.iterrows():
        case_dir = root / row["case"]
        inj = int(row["inject_time"])
        try:
            tables = load_case(case_dir, inj, args.logs, args.traces)
            res = rca.analyze_tables(
                tables["metric"], tables["logts"],
                tables["tracets_err"], tables["tracets_lat"],
                inject_ns=inj * 1_000_000_000, variant=args.variant,
            )
            ranks = [r[:-2] if r.endswith("_A") else r for r in res["service_ranks"]]
            if not ranks:
                per_case[row["case"]] = {"root": row["root_cause_service"],
                                         "reason": "empty severity matrix (no signal)"}
                continue
        except Exception as e:  # noqa: BLE001
            per_case[row["case"]] = {"root": row["root_cause_service"], "reason": f"{type(e).__name__}: {e}"}
            continue
        ev = evaluate(ranks, row["root_cause_service"])
        for k in (1, 3, 5):
            hits[k].append(ev[k])
        per_case[row["case"]] = {"root": row["root_cause_service"], "top3": ranks[:3],
                                 "rank": (ranks.index(row["root_cause_service"]) + 1
                                          if row["root_cause_service"] in ranks else -1)}
        if len(hits[1]) % 10 == 0:
            print(f"  [{len(hits[1])}/{len(suite)}] {row['case']} rank={per_case[row['case']]['rank']}",
                  file=sys.stderr, flush=True)

    n = len(hits[1]) or 1
    ac = {k: round(sum(v) / n, 4) for k, v in hits.items()}
    avg5 = round((ac[1] + ac[3] + ac[5]) / 3, 4)
    out = {
        "suite": args.suite, "variant": args.variant, "seeds": args.seeds,
        "n_cases": n, "total": len(suite),
        "ac@1": ac[1], "ac@3": ac[3], "ac@5": ac[5], "avg@5": avg5,
        "total_s": round(time.time() - t0, 1),
        "modalities": "metric" + ("+log" if args.logs else "") + ("+trace" if args.traces else ""),
        "failures": [{"case": c, **v} for c, v in per_case.items() if "reason" in v],
    }
    print(json.dumps({k: v for k, v in out.items() if k != "per_case"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
