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
import math
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
    p.add_argument("--modules", default="none",
                   help="comma-separated canonical modules tail,guided,onset,consensus "
                        "(fixed order; empty or 'none' = baseline)")
    p.add_argument("--seed", type=int, default=7, help="single seed per process")
    p.add_argument("--stage", default="all", choices=["all", "screen", "confirm"],
                   help="case selection: metadata-defined screen/confirm split")
    p.add_argument("--output", default="", help="write the run JSON here")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--start", type=int, default=0, help="skip first N cases (resume)")
    p.add_argument("--out-cases", default="", help="write per-case results JSON here")
    p.add_argument("--logs", action="store_true", help="include logs modality (RE2/RE3)")
    p.add_argument("--traces", action="store_true", help="include traces modality (RE2/RE3 OB/TT)")
    args = p.parse_args(argv)

    from experiments.torai_ablation_matrix import (
        canonical_label_from_spec,
        parse_modules,
        screen_confirm_split,
    )

    module_cfg = parse_modules(args.modules)
    modules_label = canonical_label_from_spec(args.modules)

    root = Path(args.data)
    cases = pd.read_parquet(root / "cases.parquet")
    suite = cases[cases["suite"] == args.suite]

    # ---- metadata-only screen/confirm split (per (system, fault) group) ----
    groups: dict[tuple, list[str]] = {}
    for _, row in suite.iterrows():
        groups.setdefault((row["system"], row["fault"]), []).append(row["case"])
    screen_ids, confirm_ids = screen_confirm_split(groups)
    if args.stage == "screen":
        suite = suite[suite["case"].isin(screen_ids)]
    elif args.stage == "confirm":
        suite = suite[suite["case"].isin(confirm_ids)]
    if args.start:
        suite = suite.iloc[args.start:]
    if args.limit:
        suite = suite.head(args.limit)

    rca = ToraiRCA({"torai": {**module_cfg, "variant": args.variant}}, seed=args.seed)
    row_map = {r["case"]: r for _, r in suite.iterrows()}
    case_records: list[dict] = []
    failures: list[dict] = []
    latencies: list[float] = []
    t0 = time.time()
    for _, row in suite.iterrows():
        case_dir = root / row["case"]
        inj = int(row["inject_time"])
        t_start = time.perf_counter()
        try:
            tables = load_case(case_dir, inj, args.logs, args.traces)
            res = rca.analyze_tables(
                tables["metric"], tables["logts"],
                tables["tracets_err"], tables["tracets_lat"],
                inject_ns=inj * 1_000_000_000, variant=args.variant,
            )
            lat = time.perf_counter() - t_start
            ranks = [r[:-2] if r.endswith("_A") else r for r in res["service_ranks"]]
            if not ranks:
                failures.append({"case": row["case"], "root": row["root_cause_service"],
                                 "reason": "empty severity matrix (no signal)"})
                continue
        except Exception as e:  # noqa: BLE001
            lat = time.perf_counter() - t_start
            failures.append({"case": row["case"], "root": row["root_cause_service"],
                             "reason": f"{type(e).__name__}: {e}"})
            continue
        ev = evaluate(ranks, row["root_cause_service"])
        rank = (ranks.index(row["root_cause_service"]) + 1
                if row["root_cause_service"] in ranks else -1)
        case_records.append({
            "case": row["case"],
            "root": row["root_cause_service"],
            "system": row["system"],
            "fault": row["fault"],
            "rank": rank,
            "top3": ranks[:3],
            "hit1": ev[1], "hit3": ev[3], "hit5": ev[5],
            "latency_s": round(lat, 4),
            "module_evidence": res["module_evidence"],
        })
        latencies.append(lat)
        if len(case_records) % 10 == 0:
            print(f"  [{len(case_records)}/{len(suite)}] {row['case']} rank={rank}",
                  file=sys.stderr, flush=True)

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

    def _agg(key):
        groups_out: dict = {}
        for c in case_records:
            g = row_map.get(c["case"], {}).get(key, "?")
            e = groups_out.setdefault(g, {"n": 0, "hit1": 0, "hit3": 0, "hit5": 0})
            e["n"] += 1
            e["hit1"] += c["hit1"]; e["hit3"] += c["hit3"]; e["hit5"] += c["hit5"]
        out = {}
        for g, e in groups_out.items():
            out[g] = {"n": e["n"],
                      "ac@1": round(e["hit1"] / e["n"], 4),
                      "ac@3": round(e["hit3"] / e["n"], 4),
                      "ac@5": round(e["hit5"] / e["n"], 4),
                      "avg@5": round((e["hit1"] + e["hit3"] + e["hit5"]) / 3 / e["n"], 4)}
        return out

    out = {
        "suite": args.suite,
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
        "by_fault": _agg("fault"),
        "by_system": _agg("system"),
        "modalities": "metric" + ("+log" if args.logs else "") + ("+trace" if args.traces else ""),
    }
    if args.out_cases:
        per_case = {}
        for c in case_records:
            per_case[c["case"]] = {"root": c["root"], "top3": c["top3"], "rank": c["rank"],
                                   "system": c["system"], "fault": c["fault"],
                                   "hit1": c["hit1"], "hit3": c["hit3"], "hit5": c["hit5"]}
        for f in failures:
            per_case[f["case"]] = {"root": f["root"], "reason": f["reason"]}
        Path(args.out_cases).write_text(json.dumps(per_case, indent=2))
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
