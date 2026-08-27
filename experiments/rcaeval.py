"""RCAEval (real data) service-level RCA benchmark.

Reads `cases.parquet` (735 cases) + per-case `metrics.parquet` / `inject_time.txt`,
aggregates each service's metrics to one z-scored series, builds a full-mesh
service topology, runs the RCA pipeline and a correlation baseline, and reports
AC@1 / AC@3 / Avg@5 against `root_cause_service`.

    uv run python -m experiments.rcaeval \
        --data data/rca_eval --suite RE1 --limit 20 --top-k 3 --seed 7

`metrics.parquet` columns are `{service}_{metric}`. Each service's columns are
z-scored then averaged into one series, downsampled to 10 s (70 min → 420 pts)
so discovery stays tractable. The ground-truth window is `inject_time`; no
re-detection.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from alg_models.schemas import IncidentWindow, TelemetryFrame, TelemetryPoint, TopologyEdge


def build_frame(meta: pd.DataFrame, inject_ns: int, step: int = 10
                ) -> tuple[TelemetryFrame, list[str], int, dict[str, float]]:
    """Per-service series = the metric with the max post-vs-pre z-deviation
    (the fault metric), downsampled by `step`; also returns per-service
    deviation scores (detector contribution) for ranking."""
    cols = [c for c in meta.columns if c != "time"]
    svc: dict[str, list[str]] = {}
    for c in cols:
        parts = c.rsplit("_", 1)
        if len(parts) == 2 and parts[0]:
            svc.setdefault(parts[0], []).append(c)
    time_full = meta["time"].to_numpy()
    pre = time_full < inject_ns // 1_000_000_000
    time = time_full[::step]
    interval_ns = step * 1_000_000_000
    deviations: dict[str, float] = {}
    pts: list[TelemetryPoint] = []
    for s, mcols in svc.items():
        sub = meta[mcols].to_numpy(dtype=np.float64)  # full res for deviation
        best_col, best_z = mcols[0], -1.0
        for ci, c in enumerate(mcols):
            v = sub[:, ci]
            pre_m, pre_s = float(np.nanmean(v[pre])), float(np.nanstd(v[pre])) + 1e-8
            post_m = float(np.nanmean(v[~pre])) if (~pre).any() else pre_m
            zdev = abs(post_m - pre_m) / pre_s
            if zdev > best_z:
                best_z, best_col = zdev, c
        deviations[s] = best_z
        series_full = meta[best_col].to_numpy(dtype=np.float64)
        mu = np.nanmean(series_full); sd = np.nanstd(series_full) + 1e-8
        series = (series_full[::step] - mu) / sd
        for i, t in enumerate(time):
            pts.append(
                TelemetryPoint(
                    ts_ns=int(t) * 1_000_000_000, entity_id=s, entity_type="service",
                    metric_id="agg", value=float(series[i]), source="replay",
                    sample_interval_ns=interval_ns,
                )
            )
    return TelemetryFrame(points=tuple(sorted(pts, key=lambda p: p.ts_ns))), sorted(svc.keys()), interval_ns, deviations




def _norm(deviations: dict[str, float] | None, s: str) -> float:
    d = deviations or {}
    if not d:
        return 1.0
    mx = max(d.values()) or 1.0
    return round(d.get(s, 0.0) / mx, 4)

def full_mesh(services: list[str]) -> list[TopologyEdge]:
    out = []
    for i, a in enumerate(services):
        for b in services[i + 1 :]:
            out.append(TopologyEdge(src_entity_id=a, dst_entity_id=b, edge_type="communicates",
                                    valid_from_ns=0, confidence=1.0, source="full-mesh"))
            out.append(TopologyEdge(src_entity_id=b, dst_entity_id=a, edge_type="communicates",
                                    valid_from_ns=0, confidence=1.0, source="full-mesh"))
    return out


def analyze_one(frame: TelemetryFrame, inject_ns: int, seed: int, cfg: dict,
                services: list[str], interval_ns: int, deviations: dict[str, float] | None = None) -> list[str]:
    from alg_models.cli import split_by_time
    from alg_models.causal import CausalGraphRCA

    split = cfg.get("split", {"train_frac": 0.5, "val_frac": 0.25})
    train, val, _ = split_by_time(frame, split["train_frac"], split["val_frac"])
    incident = IncidentWindow(
        incident_id="rcaeval-case", start_ts_ns=inject_ns,
        end_ts_ns=max(p.ts_ns for p in frame.points), detected_at_ns=inject_ns,
        status="anomaly", severity=1.0,
        metric_scores={f"{s}::agg": _norm(deviations, s) for s in services},
        directions={f"{s}::agg": "up" for s in services},
        model_version="0.4.0",
    )
    rca = CausalGraphRCA(cfg, seed=seed, topology=full_mesh(services))
    report = rca.analyze(frame, train, val, top_k=10, incident=incident)
    ordered: list[str] = []
    for c in report.candidates:
        svc = c.entity_id.split("::")[0]
        if svc not in ordered:
            ordered.append(svc)
    for s in services:
        if s not in ordered:
            ordered.append(s)
    return ordered


def correlation_order(frame: TelemetryFrame, inject_ns: int, services: list[str],
                     deviations: dict[str, float] | None = None) -> list[str]:
    from alg_models.causal.discovery import build_multivar
    from alg_models.causal.ranking import CorrelationRanker
    from alg_models.schemas import IncidentWindow

    ts = sorted({p.ts_ns for p in frame.points})
    mbe = {s: ["agg"] for s in services}
    data = build_multivar(frame, entity_ids=services, metric_ids_by_entity=mbe,
                          start_ns=ts[0], end_ns=ts[-1] + 1, sample_interval_ns=10_000_000_000)
    inc = IncidentWindow(
        incident_id="rcaeval-case", start_ts_ns=inject_ns, end_ts_ns=ts[-1],
        detected_at_ns=inject_ns, status="anomaly", severity=1.0,
        metric_scores={s: _norm(deviations, s) for s in services},
    )
    cands = CorrelationRanker().rank(data=data, incident=inc, anomalous_metrics=services)
    ordered = [c.entity_id.split("::")[0] for c in cands]
    for s in services:
        if s not in ordered:
            ordered.append(s)
    return ordered


def run(args) -> dict:
    root = Path(args.data)
    cases = pd.read_parquet(root / "cases.parquet")
    cases = cases[cases["suite"] == args.suite]
    if args.system:
        cases = cases[cases["system"] == args.system]
    cases = cases.head(args.limit) if args.limit else cases

    import yaml

    cfg = yaml.safe_load(open(args.config))
    cfg["causal"]["stability_bootstraps"] = args.bootstrap  # light discovery for the sweep
    # let CausalGraphRCA auto-blend rank weights by discovered-graph density
    # (dense full-mesh graph => deviation/residual dominates, not centrality)
    cfg["causal"].pop("rank_weights", None)

    rca_runs, corr_runs = [], []
    t0 = time.time()
    for idx, (_, row) in enumerate(cases.iterrows()):
        meta = pd.read_parquet(root / row["case"] / "metrics.parquet")
        inject_ns = int(row["inject_time"]) * 1_000_000_000
        frame, services, interval_ns, deviations = build_frame(meta, inject_ns)
        truth = row["root_cause_service"]
        rca_runs.append((row["case"], truth, analyze_one(frame, inject_ns, args.seed, cfg, services, interval_ns, deviations)))
        corr_runs.append((row["case"], truth, correlation_order(frame, inject_ns, services, deviations)))
        if (idx + 1) % 5 == 0:
            print(f"  ...{idx + 1}/{len(cases)} ({time.time() - t0:.1f}s)", flush=True)

    def ac_metrics(runs):
        n = max(1, len(runs))
        ac1 = sum(1 for _, t, o in runs if o and o[0] == t) / n
        ack = sum(1 for _, t, o in runs if t in o[: args.top_k]) / n
        avg5 = sum((1.0 / (o.index(t) + 1)) if t in o[: 5] else 0.0 for _, t, o in runs) / n
        return {"ac1": round(ac1, 4), f"ac@{args.top_k}": round(ack, 4), "avg@5": round(avg5, 4)}

    return {
        "suite": args.suite,
        "system": args.system,
        "n_cases": len(rca_runs),
        "elapsed_s": round(time.time() - t0, 1),
        "causal_graph_rca": ac_metrics(rca_runs),
        "correlation_baseline": ac_metrics(corr_runs),
        "per_case_hit@1": {c: (o[0] == t) for c, t, o in rca_runs},
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--data", required=True)
    p.add_argument("--suite", default="RE1")
    p.add_argument("--system", default=None)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--top-k", type=int, default=3)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--bootstrap", type=int, default=2)
    p.add_argument("--config", default="configs/smoke.yaml")
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