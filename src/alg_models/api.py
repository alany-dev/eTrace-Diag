"""HTTP API (FastAPI). API-first interaction surface; no browser frontend.

Endpoints:
- POST /v1/score          TelemetryPoint[] -> IncidentWindow[]
- POST /v1/causal/analyze incident window + joint series + config
                          -> CausalReport
- POST /v1/feedback       FeedbackEvent -> new model_version + audit id
- GET  /v1/incidents/{id} causal report versions + feedback

All responses use the contract models.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException

from .data.replay import TelemetryFrame
from .detection import DETECTOR_REGISTRY
from .interactive.controller import IncidentController, VersionedStore
from .interactive.explainer import EvidenceNarrator
from .schemas import (
    CausalReport,
    FeedbackEvent,
    IncidentWindow,
    LogEvent,
    TelemetryPoint,
    TraceSpan,
)

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
    "torai": {
        "resample_s": 15,
        "gamma": 5,
        "bins": 5,
        "localized": True,
        "scaler": "standard",
        "covariance_type": "full",
        "n_components_max": None,
        "discretize_strategy": "kmeans",
        "random_state": 0,
        "gmm_max_iter": 50,
        "normal_post_trim": 0,
        "variant": "faithful",
    },
}


def _merge_config(config: dict | None) -> dict:
    merged = {}
    for k, v in DEFAULT_CONFIG.items():
        merged[k] = dict(v) if isinstance(v, dict) else v
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
    from .causal import ToraiRCA

    points = [TelemetryPoint.model_validate(p) for p in payload.get("points", [])]
    if not points:
        raise HTTPException(400, "empty points array")
    frame = TelemetryFrame(points=tuple(sorted(points, key=lambda p: p.ts_ns)))
    cfg = _merge_config(payload.get("config"))
    train, val, _ = _split(frame, cfg)
    traces = tuple(TraceSpan.model_validate(s) for s in payload.get("traces", []))
    logs = tuple(LogEvent.model_validate(l) for l in payload.get("logs", []))

    rca = ToraiRCA(cfg, seed=payload.get("seed", 7))
    report = rca.analyze(
        frame,
        train,
        val,
        top_k=payload.get("top_k", 3),
        logs=logs,
        traces=traces,
    )
    store.put_incident(report.window)
    store.put_report(report)
    return report.model_dump()


@app.post("/v1/feedback")
def v1_feedback(payload: dict) -> dict:
    feedback = FeedbackEvent.model_validate(payload.get("feedback", payload))
    try:
        return controller.process_feedback(feedback)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


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
