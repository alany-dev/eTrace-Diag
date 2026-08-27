"""HTTP API (FastAPI). API-first interaction surface; no browser frontend.

Endpoints:
- POST /v1/score          TelemetryPoint[] -> IncidentWindow[]
- POST /v1/causal/analyze incident window + joint series + topology + config
                          -> CausalReport
- POST /v1/feedback       FeedbackEvent -> new model_version + audit id
- POST /v1/what-if        dry-run effect estimate / CI / identifiability
- GET  /v1/incidents/{id} full evidence chain + versions

The what-if endpoint is DRY-RUN ONLY: it never executes kill, rate-limiting,
or rollback. All responses use the contract models.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException

from .data.replay import TelemetryFrame
from .detection import DETECTOR_REGISTRY
from .interactive.controller import IncidentController, VersionedStore
from .schemas import (
    CausalReport,
    FeedbackEvent,
    IncidentWindow,
    TelemetryPoint,
    TopologyEdge,
)
from .interactive.explainer import EvidenceNarrator

app = FastAPI(title="alg-models", version="0.1.0")
store = VersionedStore()
controller = IncidentController(store)
narrator = EvidenceNarrator()

DEFAULT_CONFIG = {
    "detector": {
        "name": "edge_cascade",
        "window_ns": 60_000_000_000,
        "stride_ns": 30_000_000_000,
        "low_freq": 3,
        "n_fft": 16,
    },
    "split": {"train_frac": 0.6, "val_frac": 0.2},
    "causal": {"tau_max_s": 5, "alpha_level": 0.05, "min_edge_stability": 0.6},
}


def _merge_config(config: dict | None) -> dict:
    merged = {}
    for k, v in DEFAULT_CONFIG.items():
        merged[k] = dict(v)
    if config:
        for k, v in config.items():
            if isinstance(v, dict) and isinstance(merged.get(k), dict):
                merged[k].update(v)
            else:
                merged[k] = v
    return merged


def _detector_for(config: dict):
    det_cfg = dict(config.get("detector", {}))
    name = det_cfg.pop("name", "edge_cascade")
    if name not in DETECTOR_REGISTRY:
        raise HTTPException(400, f"unknown detector {name!r}")
    import inspect

    sig = inspect.signature(DETECTOR_REGISTRY[name].__init__)
    det_cfg = {k: v for k, v in det_cfg.items() if k in sig.parameters}
    return DETECTOR_REGISTRY[name](**det_cfg)


def _split(frame: TelemetryFrame, cfg: dict):
    from .cli import split_by_time

    split = cfg.get("split", {"train_frac": 0.6, "val_frac": 0.2})
    return split_by_time(frame, split["train_frac"], split["val_frac"])


@app.post("/v1/score")
def v1_score(payload: dict) -> dict:
    points = [TelemetryPoint.model_validate(p) for p in payload.get("points", [])]
    if not points:
        raise HTTPException(400, "empty points array")
    frame = TelemetryFrame(points=tuple(sorted(points, key=lambda p: p.ts_ns)))
    cfg = _merge_config(payload.get("config"))
    train, val, _ = _split(frame, cfg)
    det = controller.detector_for(cfg, seed=payload.get("seed", 7))
    if det is None:
        det = _detector_for(cfg)
        det.fit(train, val, seed=payload.get("seed", 7))
        dcfg = cfg.get("detector", {})
        controller.attach_detector(
            det,
            signature=(dcfg.get("name", "edge_cascade"), dcfg.get("window_ns"), dcfg.get("stride_ns")),
        )
    incidents = det.score(frame)
    for inc in incidents:
        store.put_incident(inc)
    return {
        "incidents": [i.model_dump() for i in incidents],
        "model_version": det.model_version,
    }


@app.post("/v1/causal/analyze")
def v1_causal(payload: dict) -> dict:
    from .causal import CausalGraphRCA

    points = [TelemetryPoint.model_validate(p) for p in payload.get("points", [])]
    if not points:
        raise HTTPException(400, "empty points array")
    frame = TelemetryFrame(points=tuple(sorted(points, key=lambda p: p.ts_ns)))
    cfg = _merge_config(payload.get("config"))
    train, val, _ = _split(frame, cfg)
    incident = None
    if payload.get("incident"):
        incident = IncidentWindow.model_validate(payload["incident"])
    topology = None
    if payload.get("topology"):
        topology = [TopologyEdge.model_validate(t) for t in payload["topology"]]
    rca = CausalGraphRCA(cfg, seed=payload.get("seed", 7), topology=topology)
    report = rca.analyze(frame, train, val, top_k=payload.get("top_k", 3), incident=incident)
    store.put_incident(report.window)
    store.put_report(report)
    # retain analysis context for what-if (never raw telemetry beyond the frame)
    store.store_causal_context(report.incident_id, {
        "data": _build_context_data(frame, report, cfg, train, val, topology, payload.get("seed", 7)),
        "edges": report.edges,
        "outcome_entity": _context_outcome(report),
        "sample_interval_ns": _context_interval(frame),
        "tau_max_samples": max(1, int(round(cfg.get("causal", {}).get("tau_max_s", 5) * 1e9 / _context_interval(frame)))),
        "alpha_level": cfg.get("causal", {}).get("alpha_level", 0.05),
        "seed": payload.get("seed", 7),
    })
    return report.model_dump()


def _context_interval(frame: TelemetryFrame) -> int:
    from collections import Counter

    ts = sorted({p.ts_ns for p in frame.points})
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b > a]
    return Counter(gaps).most_common(1)[0][0] if gaps else 1_000_000_000


def _context_outcome(report: CausalReport) -> str | None:
    """Mirror graph_rca's outcome rule: deepest ANOMALOUS metric with an
    incoming directed-lagged edge."""
    depth: dict[str, int] = {}
    for _ in range(len(report.anomalous_metrics) + 2):
        for e in report.edges:
            if e.edge_mark != "directed" or e.lag_ns <= 0:
                continue
            depth[e.dst_entity_id] = max(
                depth.get(e.dst_entity_id, 0), depth.get(e.src_entity_id, 0) + 1
            )
    candidates = {
        nid for nid in depth
        if nid.split("::")[1] in report.anomalous_metrics and depth.get(nid, 0) > 0
    }
    if not candidates:
        return None
    return max(candidates, key=lambda nid: depth.get(nid, 0))


def _build_context_data(frame, report, cfg, train, val, topology, seed):
    from .causal.discovery import build_multivar
    from .causal.graph_rca import CausalGraphRCA

    rca = CausalGraphRCA(cfg, seed=seed, topology=topology)
    interval = _context_interval(frame)
    entities = sorted({p.entity_id for p in frame.points})
    mbe: dict[str, set] = {}
    for p in frame.points:
        mbe.setdefault(p.entity_id, set()).add(p.metric_id)
    mbe = {e: sorted(m) for e, m in mbe.items()}
    w = report.window
    start_ns = max(min(p.ts_ns for p in frame.points), w.start_ts_ns - 60_000_000_000)
    end_ns = min(max(p.ts_ns for p in frame.points) + 1, w.end_ts_ns + 60_000_000_000)
    return build_multivar(frame, entity_ids=entities, metric_ids_by_entity=mbe,
                          start_ns=start_ns, end_ns=end_ns, sample_interval_ns=interval)


@app.post("/v1/feedback")
def v1_feedback(payload: dict) -> dict:
    feedback = FeedbackEvent.model_validate(payload.get("feedback", payload))
    try:
        return controller.process_feedback(feedback)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/v1/what-if")
def v1_what_if(payload: dict) -> dict:
    incident_id = payload.get("incident_id")
    candidate = payload.get("candidate_id")
    if not incident_id or not candidate:
        raise HTTPException(400, "incident_id and candidate_id required")
    dry_run = bool(payload.get("dry_run", True))
    try:
        return controller.what_if(
            incident_id, candidate,
            float(payload.get("baseline", 0.0)),
            float(payload.get("high", 1.0)),
            dry_run=dry_run,
        )
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.get("/v1/incidents/{incident_id}")
def v1_incident(incident_id: str) -> dict:
    rec = store.get_incident(incident_id)
    if rec is None:
        raise HTTPException(404, f"unknown incident {incident_id}")
    return {
        "incident_id": incident_id,
        "incident": rec.incident.model_dump(),
        "versions": [
            {"model_version": r.model_version, "report": r.model_dump()}
            for r in rec.reports
        ],
        "feedback": [
            {"audit_id": r.audit_id, "feedback": r.feedback.model_dump(), "applied": r.applied}
            for r in store.feedbacks(incident_id)
        ],
        "narrative": narrator.narrate(rec.reports[-1]) if rec.reports else None,
    }