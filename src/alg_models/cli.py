"""Command-line entrypoint.

    uv run python -m alg_models.cli detect --config configs/smoke.yaml \
        --input tests/fixtures/host_spike.jsonl --seed 7
    uv run python -m alg_models.cli causal --config configs/smoke.yaml \
        --input tests/fixtures/causal_disk_chain.jsonl --top-k 3 --seed 7

Detection and causal output use the contract models and are written as JSON
(replayable, versioned). Thresholds are fit on train/validation only.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import yaml

from .data.replay import load_replay
from .detection import DETECTOR_REGISTRY
from .schemas import TelemetryFrame


def load_config(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"config not found: {p}")
    with open(p, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def split_by_time(frame: TelemetryFrame, train_frac: float, val_frac: float):
    """Strict time split; anomaly segments never cross a split because the
    boundary is a timestamp threshold, not a label."""
    if len(frame) == 0:
        raise ValueError("cannot split an empty frame")
    ts = sorted(p.ts_ns for p in frame.points)
    t0, t1 = ts[0], ts[-1]
    span = t1 - t0
    cut1 = t0 + int(span * train_frac)
    cut2 = t0 + int(span * (train_frac + val_frac))
    train = TelemetryFrame(points=tuple(p for p in frame.points if p.ts_ns <= cut1))
    val = TelemetryFrame(points=tuple(p for p in frame.points if cut1 < p.ts_ns <= cut2))
    test = TelemetryFrame(points=tuple(p for p in frame.points if p.ts_ns > cut2))
    return train, val, test


def _detector_kwargs(cfg: dict, cls) -> dict:
    """Pass only the params the detector constructor accepts; the smoke
    config carries edge_cascade extras (low_freq, n_fft, ...) that
    streaming/fits constructors reject."""
    import inspect

    sig = inspect.signature(cls.__init__)
    det = dict(cfg.get("detector", {}))
    det.pop("name", None)
    return {k: v for k, v in det.items() if k in sig.parameters}


def cmd_detect(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    frame = load_replay(args.input)
    split = cfg.get("split", {"train_frac": 0.6, "val_frac": 0.2})
    train, val, _test = split_by_time(frame, split["train_frac"], split["val_frac"])
    name = args.model or cfg.get("detector", {}).get("name", "edge_cascade")
    if name not in DETECTOR_REGISTRY:
        print(f"error: unknown detector {name!r}; available {sorted(DETECTOR_REGISTRY)}", file=sys.stderr)
        return 2
    detector = DETECTOR_REGISTRY[name](**_detector_kwargs(cfg, DETECTOR_REGISTRY[name]))
    card = detector.fit(train, val, seed=args.seed)
    incidents = detector.score(frame)
    result = {
        "model_card": card.model_dump(),
        "incidents": [i.model_dump() for i in incidents],
        "counts": {"windows": detector._gate_stats["windows"],
                   "trend_run": detector._gate_stats["trend_run"]}
        if hasattr(detector, "_gate_stats")
        else {},
    }
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    else:
        print(json.dumps(result, indent=2))
    print(
        f"[detect] model={card.model_version} incidents={len(incidents)} "
        f"anomaly={sum(1 for i in incidents if i.status == 'anomaly')} "
        f"uncertain={sum(1 for i in incidents if i.status == 'uncertain')}",
        file=sys.stderr,
    )
    return 0


def cmd_causal(args: argparse.Namespace) -> int:
    from .causal.graph_rca import CausalGraphRCA  # lazy: causal deps optional

    cfg = load_config(args.config)
    frame = load_replay(args.input)
    split = cfg.get("split", {"train_frac": 0.6, "val_frac": 0.2})
    train, val, _test = split_by_time(frame, split["train_frac"], split["val_frac"])
    rca = CausalGraphRCA(cfg, seed=args.seed)
    report = rca.analyze(frame, train, val, top_k=args.top_k)
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.model_dump(), indent=2), encoding="utf-8")
    else:
        print(json.dumps(report.model_dump(), indent=2))
    print(
        f"[causal] incident={report.incident_id} candidates={len(report.candidates)} "
        f"edges={len(report.edges)} top1={report.candidates[0].entity_id if report.candidates else None}",
        file=sys.stderr,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="alg_models.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    d = sub.add_parser("detect", help="run a detection model over a replay")
    d.add_argument("--config", required=True)
    d.add_argument("--input", required=True)
    d.add_argument("--model", default=None, help="override detector name")
    d.add_argument("--seed", type=int, default=7)
    d.add_argument("--output", default=None)
    d.set_defaults(func=cmd_detect)

    c = sub.add_parser("causal", help="detect + causal RCA over a replay")
    c.add_argument("--config", required=True)
    c.add_argument("--input", required=True)
    c.add_argument("--top-k", type=int, default=3)
    c.add_argument("--seed", type=int, default=7)
    c.add_argument("--output", default=None)
    c.set_defaults(func=cmd_causal)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())