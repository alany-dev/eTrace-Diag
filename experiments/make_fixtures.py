"""Deterministic fixture generation (committed provenance for tests/fixtures).

Run: uv run python -m experiments.make_fixtures
Regenerates:
- tests/fixtures/host_spike.jsonl
- tests/fixtures/causal_disk_chain.jsonl
- tests/fixtures/*_request.json  (API request payloads)

All random noise uses fixed seeds; the files are byte-deterministic per numpy
version family. Anomaly segments are wholly inside the test split so that
threshold calibration never sees them (60/20/20 time split).
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import numpy as np

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def _pt(ts_ns, entity_id, entity_type, metric_id, value, *, role=None, source="replay",
        unit=None, interval_ns=None) -> dict:
    obj = {
        "ts_ns": ts_ns,
        "entity_id": entity_id,
        "entity_type": entity_type,
        "metric_id": metric_id,
        "value": round(float(value), 6),
        "source": source,
    }
    if role:
        obj["attrs"] = {"role": role}
    if unit:
        obj["unit"] = unit
    if interval_ns:
        obj["sample_interval_ns"] = interval_ns
    return obj


def gen_host_spike(seed: int = 7) -> list[dict]:
    rng = np.random.default_rng(seed)
    interval = 5.0  # seconds
    t_end = 5000.0  # seconds
    n = int(t_end / interval) + 1
    ts = np.arange(n) * interval
    interval_ns = int(interval * 1e9)

    cpu = 30 + 5 * np.sin(2 * np.pi * ts / 600.0) + rng.normal(0, 1.5, n)
    mem = 45 + rng.normal(0, 0.8, n)
    io = 2 + rng.normal(0, 0.4, n)
    net = 50 + rng.normal(0, 4.0, n)
    # anomaly window [4200, 4500) seconds — inside the test split [4000, 5000)
    anom = (ts >= 4200) & (ts < 4500)
    cpu = np.where(anom, cpu + 40.0, cpu)
    io = np.where(anom, io + 20.0, io)

    points: list[dict] = []
    for i, t in enumerate(ts):
        ns = int(t * 1e9)
        points.append(_pt(ns, "host", "host", "cpu.utilization", cpu[i], unit="%", interval_ns=interval_ns))
        points.append(_pt(ns, "host", "host", "memory.utilization", mem[i], unit="%", interval_ns=interval_ns))
        points.append(_pt(ns, "host", "host", "disk.io_wait", io[i], unit="%", interval_ns=interval_ns))
        points.append(_pt(ns, "host", "host", "net.rx_mbps", net[i], unit="MB/s", interval_ns=interval_ns))
        state = 0 if not anom[i] else 0  # state does not change during CPU spike
        points.append(_pt(ns, "host", "host", "sched.state", state, role="state", interval_ns=interval_ns))
    return points


def gen_causal_disk_chain(seed: int = 7) -> list[dict]:
    rng = np.random.default_rng(seed)
    interval = 1.0  # seconds
    t_end = 500.0
    n = int(t_end / interval)
    ts = np.arange(n) * interval
    interval_ns = int(interval * 1e9)

    # Root cause: disk io_wait with rich dynamics (two sinusoids + noise) so
    # the lag structure is identified from steady-state dynamics, plus a
    # detectable (but not collinearity-dominating) level shift at t>=420.
    io_wait = 5 + 0.5 * np.sin(2 * np.pi * ts / 25.0) + 0.3 * np.sin(2 * np.pi * ts / 7.0) + rng.normal(0, 0.3, n)
    anom = ts >= 420  # anomaly window [420, 500) — inside test split [400, 500)
    io_wait = np.where(anom, io_wait + 6.0, io_wait)

    # Known-lag causal chain (noise-driven, recoverable by conditional tests)
    process_io = np.full(n, np.nan)
    for i in range(n):
        if i - 3 >= 0:
            process_io[i] = 0.7 * io_wait[i - 3] + rng.normal(0, 0.4)
    process_io = np.nan_to_num(process_io, nan=0.7 * io_wait[0])

    off_cpu = np.full(n, np.nan)
    for i in range(n):
        if i - 2 >= 0:
            off_cpu[i] = 0.8 * process_io[i - 2] + rng.normal(0, 0.4)
    off_cpu = np.nan_to_num(off_cpu, nan=0.8 * process_io[0])

    latency = np.full(n, np.nan)
    for i in range(n):
        if i - 2 >= 0:
            latency[i] = 100 + 1.1 * off_cpu[i - 2] + rng.normal(0, 2.0)
    latency = np.nan_to_num(latency, nan=100 + 1.1 * off_cpu[0])

    # synchronous, non-root CPU metric (confounder trap: contemporaneous with
    # io_wait, no causal downstream effect); strong enough coupling to be
    # flagged anomalous but not a cause.
    cpu = 40 + 0.6 * (io_wait - 5) + rng.normal(0, 1.0, n)

    points: list[dict] = []
    for i, t in enumerate(ts):
        ns = int(t * 1e9)
        points.append(_pt(ns, "host", "host", "disk.io_wait", io_wait[i], unit="%", interval_ns=interval_ns))
        points.append(_pt(ns, "process", "process", "process.io_wait", process_io[i], unit="%", interval_ns=interval_ns))
        points.append(_pt(ns, "thread", "thread", "thread.off_cpu", off_cpu[i], unit="ms", interval_ns=interval_ns))
        points.append(_pt(ns, "service", "service", "service.request_latency", latency[i], unit="ms", interval_ns=interval_ns))
        points.append(_pt(ns, "host", "host", "cpu.utilization", cpu[i], unit="%", interval_ns=interval_ns))
    return points


def write_jsonl(points: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for p in points:
            f.write(json.dumps(p, sort_keys=True) + "\n")


def write_request(points: list[dict], path: Path, extra: dict | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    obj: dict = {"points": points}
    if extra:
        obj.update(extra)
    path.write_text(json.dumps(obj, sort_keys=True), encoding="utf-8")


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    write_jsonl(gen_host_spike(7), FIXTURES / "host_spike.jsonl")
    write_jsonl(gen_causal_disk_chain(7), FIXTURES / "causal_disk_chain.jsonl")
    # API request payloads (detection/analysis run server-side with this config)
    detect_cfg = {
        "config": {
            "detector": {
                "name": "edge_cascade",
                "window_ns": 60000000000,
                "stride_ns": 30000000000,
                "low_freq": 3,
                "n_fft": 16,
            },
            "split": {"train_frac": 0.6, "val_frac": 0.2},
        }
    }
    causal_cfg = {
        "config": {
            "detector": {
                "name": "edge_cascade",
                "window_ns": 60000000000,
                "stride_ns": 30000000000,
                "low_freq": 3,
                "n_fft": 16,
            },
            "split": {"train_frac": 0.6, "val_frac": 0.2},
            "causal": {
                "tau_max_s": 5,
                "alpha_level": 0.05,
                "min_edge_stability": 0.6,
                "candidate_hop": 2,
                "background_pre_s": 60,
                "background_post_s": 60,
                "stability_bootstraps": 30,
            },
        },
        "top_k": 3,
    }
    write_request(gen_host_spike(7), FIXTURES / "host_spike_request.json", detect_cfg)
    write_request(gen_causal_disk_chain(7), FIXTURES / "causal_request.json", causal_cfg)
    print("fixtures written:", FIXTURES)


if __name__ == "__main__":
    main()