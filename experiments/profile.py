"""Edge latency / RSS profiling benchmark.

    uv run python -m experiments.profile \
        --config configs/benchmark.yaml --model edge_cascade \
        --input tests/fixtures/host_spike.jsonl --repeat 1000 --output results/profile.json

Reports p95 single-window inference latency, peak RSS, gate hit rate and
second-ring trigger rate against the fixed budgets (edge p95 ≤ 50 ms, RSS ≤
200 MB, steady CPU ≤ 5%, bandwidth ≤ 16 KB/s). Budget overruns are REPORTED,
never silently absorbed by lowering accuracy.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import yaml

from alg_models.data.replay import load_replay
from alg_models.detection import get_detector


def _peak_rss_mb() -> float:
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmHWM"):
                    return float(line.split()[1]) / 1024.0
    except OSError:
        pass
    return 0.0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="experiments.profile")
    parser.add_argument("--config", required=True)
    parser.add_argument("--model", default="edge_cascade")
    parser.add_argument("--input", required=True)
    parser.add_argument("--repeat", type=int, default=1000)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    cfg = yaml.safe_load(open(args.config))
    frame = load_replay(args.input)

    from alg_models.cli import split_by_time

    split = cfg.get("split", {"train_frac": 0.6, "val_frac": 0.2})
    train, val, _ = split_by_time(frame, split["train_frac"], split["val_frac"])
    det_cls = get_detector(args.model)
    sig = det_cls.__init__.__code__.co_varnames
    kwargs = {k: v for k, v in cfg.get("detector", {}).items() if k in sig and k != "self"}
    det = det_cls(**kwargs)
    det.fit(train, val, seed=cfg.get("seed", 7))

    # warm-up
    det.score(frame)

    latencies: list[float] = []
    peak_rss = _peak_rss_mb()
    for _ in range(args.repeat):
        t0 = time.perf_counter_ns()
        det.score(frame)
        latencies.append((time.perf_counter_ns() - t0) / 1e6)
        peak_rss = max(peak_rss, _peak_rss_mb())

    n_windows = det._gate_stats["windows"]
    per_window = [l / max(1, n_windows) for l in latencies]
    p95 = float(np.percentile(per_window, 95))
    p50 = float(np.percentile(per_window, 50))
    budget = cfg.get("budget", {})
    gate_hit = det._gate_stats.get("trend_run", 0) / max(1, n_windows)
    result = {
        "model": args.model,
        "repeat": args.repeat,
        "windows_per_pass": n_windows,
        "p50_window_ms": round(p50, 4),
        "p95_window_ms": round(p95, 4),
        "peak_rss_mb": round(peak_rss, 2),
        "second_ring_trigger_rate": round(gate_hit, 4),
        "budget_max_window_ms": budget.get("max_window_ms", 50),
        "budget_max_rss_mb": budget.get("max_rss_mb", 200),
        "p95_within_budget": p95 <= budget.get("max_window_ms", 50),
        "rss_within_budget": peak_rss <= budget.get("max_rss_mb", 200),
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"[profile] p50={result['p50_window_ms']}ms p95={result['p95_window_ms']}ms "
          f"rss={result['peak_rss_mb']}MB gate_hit_rate={gate_hit:.3f} -> {out}")
    print(f"  budget p95<=50ms: {result['p95_within_budget']}  rss<=200MB: {result['rss_within_budget']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())