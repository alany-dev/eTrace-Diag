"""WebSocket bridge server for the eBPF collector (protocol v1, ADR-0003).

Endpoints (single process, one port):

- ``/anomaly``: receives the collector's per-tick ``AnomalyFeatures`` JSON,
  adapts it into a telemetry stream, buffers a warmup window, fits the
  zero-shot Time-RCD-Fuse detector on it, then scores every ``stride_ns``.
  Replies ``{v, seq, ts_ns, is_anomaly, type, confidence, indicators}``.
- ``/causal``: receives the DEEP evidence bundle (``CausalContext``), maps it
  to TORAI's multi-modal input (ADR-0004), runs ``ToraiRCA.analyze`` and
  replies ``{v, seq, ok, report}`` (CausalReport model_dump) or an
  abstention.

Run: ``uv run uvicorn alg_models.ws_server:app --host 127.0.0.1 --port 9000``
"""

from __future__ import annotations

import argparse
import asyncio
import time
from typing import Any

import numpy as np
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from .causal.torai import ToraiRCA
from .cli import load_config, split_by_time
from .detection import TimeRCDFuseDetector
from .schemas import (
    IncidentWindow,
    LogEvent,

    TelemetryFrame,
    TelemetryPoint,
    TraceSpan,
)

app = FastAPI(title="alg-models-ws", version="0.2.0")

DEFAULT_CONFIG_PATH = "configs/smoke.yaml"
DEFAULT_WARMUP_SECONDS = 90
DEFAULT_STRIDE_SECONDS = 30
DEFAULT_WINDOW_SECONDS = 60

ANOMALY_TYPES = ("cpu", "io", "mem", "lock", "net")


# ---------------------------------------------------------------------------
# AnomalyFeatures channel mapping (collector wire keys -> telemetry stream)
# ---------------------------------------------------------------------------

# kind: "gauge" passthrough | "cumulative" -> per-tick delta (>=0, first tick
# yields no value). group drives the anomaly-type classification.
HOST_CHANNELS: list[dict[str, Any]] = [
    # cpu group — cumulative CPU ticks on the system-wide aggregate
    {"path": ["host", "total", "user"], "metric_id": "cpu_user", "group": "cpu", "kind": "cumulative"},
    {"path": ["host", "total", "system"], "metric_id": "cpu_sys", "group": "cpu", "kind": "cumulative"},
    {"path": ["host", "total", "iowait"], "metric_id": "cpu_iowait", "group": "cpu", "kind": "cumulative"},
    # io group — disk busy ticks, in-flight depth, PSI io
    {"path": ["host", "disks", "io_ticks_ms"], "metric_id": "io_ticks", "group": "io", "kind": "cumulative"},
    {"path": ["host", "disks", "weighted_ticks_ms"], "metric_id": "io_wticks", "group": "io", "kind": "cumulative"},
    {"path": ["host", "disks", "ios_in_flight"], "metric_id": "io_inflight", "group": "io", "kind": "gauge"},
    {"path": ["host", "psi", "io"], "metric_id": "psi_io", "group": "io", "kind": "gauge"},
    # mem group — free/available, major faults, kswapd scanning
    {"path": ["host", "mem", "mem_free_kb"], "metric_id": "mem_free", "group": "mem", "kind": "gauge"},
    {"path": ["host", "mem", "mem_available_kb"], "metric_id": "mem_avail", "group": "mem", "kind": "gauge"},
    {"path": ["host", "vm", "pgmajfault"], "metric_id": "pgmajfault", "group": "mem", "kind": "cumulative"},
    {"path": ["host", "vm", "pgscan_kswapd"], "metric_id": "pgscan_kswapd", "group": "mem", "kind": "cumulative"},
    {"path": ["host", "psi", "memory"], "metric_id": "psi_mem", "group": "mem", "kind": "gauge"},
    # lock group — context switches, runnable queue, lock waits (ebpf), PSI cpu
    {"path": ["host", "ctxt"], "metric_id": "ctxt", "group": "lock", "kind": "cumulative"},
    {"path": ["host", "procs_running"], "metric_id": "procs_running", "group": "lock", "kind": "gauge"},
    {"path": ["host", "psi", "cpu"], "metric_id": "psi_cpu", "group": "lock", "kind": "gauge"},
    {"path": ["ebpf", "lock_waits_total"], "metric_id": "lock_waits", "group": "lock", "kind": "cumulative"},
    {"path": ["ebpf", "switch_total"], "metric_id": "switches", "group": "lock", "kind": "cumulative"},
]

# per-process channels (entity = proc_<pid>); cumulative fields are deltas.
PROC_CHANNELS: list[dict[str, Any]] = [
    {"key": "utime", "metric_id": "cpu_user", "group": "cpu", "kind": "cumulative"},
    {"key": "stime", "metric_id": "cpu_sys", "group": "cpu", "kind": "cumulative"},
    {"key": "nvcsw", "metric_id": "nvcsw", "group": "lock", "kind": "cumulative"},
    {"key": "nivcsw", "metric_id": "nivcsw", "group": "lock", "kind": "cumulative"},
    {"key": "minflt", "metric_id": "minflt", "group": "mem", "kind": "cumulative"},
    {"key": "majflt", "metric_id": "majflt", "group": "mem", "kind": "cumulative"},
    {"key": "rss_kb", "metric_id": "rss", "group": "mem", "kind": "gauge"},
    {"key": "read_bytes", "metric_id": "io_read", "group": "io", "kind": "cumulative"},
    {"key": "write_bytes", "metric_id": "io_write", "group": "io", "kind": "cumulative"},
    {"key": "run_delay_ns", "metric_id": "run_delay", "group": "lock", "kind": "cumulative"},
    {"key": "syscr", "metric_id": "syscr", "group": "cpu", "kind": "cumulative"},
    {"key": "syscw", "metric_id": "syscw", "group": "cpu", "kind": "cumulative"},
]


def _dig(d: dict, path: list[str], default=None):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def _sum_disks(d: dict, key: str) -> float:
    disks = _dig(d, ["host", "disks"], None)
    if not isinstance(disks, list) or not disks:
        return 0.0
    return float(sum(x.get(key, 0) or 0 for x in disks if isinstance(x, dict)))


def _sum_net(d: dict, key: str) -> float:
    ifs = _dig(d, ["network", "ifaces"], None)
    if isinstance(ifs, list) and ifs:
        return float(sum(x.get(key, 0) or 0 for x in ifs if isinstance(x, dict)))
    return float(_dig(d, ["network", key], 0.0) or 0.0)


def anomaly_features_to_points(msg: dict, prev: dict) -> tuple[list[TelemetryPoint], dict]:
    """Adapt one collector AnomalyFeatures message into TelemetryPoints.

    Cumulative channels become per-tick deltas (first observation yields no
    value for them); gauges pass through. ``prev`` carries the previous raw
    value per channel key and is returned updated.
    """
    ts_ns = int(msg.get("ts_ns", 0) or 0)
    points: list[TelemetryPoint] = []
    entity = "host"

    for ch in HOST_CHANNELS:
        key = "|".join(ch["path"])
        raw = None
        if ch["path"][0:1] == ["host"] and ch["path"][1] == "disks":
            raw = _sum_disks(msg, ch["path"][2])
        else:
            raw = _dig(msg, ch["path"], None)
        if raw is None:
            continue
        if isinstance(raw, dict):  # psi windows serialize as {some, full}
            raw = raw.get("some", raw.get("avg10", 0.0))
        raw = float(raw)
        if ch["kind"] == "cumulative":
            prev_raw = prev.get(key)
            if prev_raw is None:
                prev[key] = raw
                continue
            value = max(0.0, raw - prev_raw)
            prev[key] = raw
        else:
            value = raw
        points.append(
            TelemetryPoint(
                ts_ns=ts_ns, entity_id=entity, entity_type="host",
                metric_id=ch["metric_id"], value=value, source="ebpf",
                quality="observed", attrs={"group": ch["group"]},
            )
        )

    for ch in ({"path": ["network", "rx_bytes"], "metric_id": "net_rx", "group": "net", "kind": "cumulative"},
               {"path": ["network", "tx_bytes"], "metric_id": "net_tx", "group": "net", "kind": "cumulative"}):
        key = "net|" + ch["metric_id"]
        raw = _sum_net(msg, ch["path"][1])
        if raw is None:
            continue
        if isinstance(raw, dict):  # psi windows serialize as {some, full}
            raw = raw.get("some", raw.get("avg10", 0.0))
        raw = float(raw)
        if ch["kind"] == "cumulative":
            prev_raw = prev.get(key)
            if prev_raw is None:
                prev[key] = raw
                continue
            value = max(0.0, raw - prev_raw)
            prev[key] = raw
        else:
            value = raw
        points.append(
            TelemetryPoint(
                ts_ns=ts_ns, entity_id=entity, entity_type="host",
                metric_id=ch["metric_id"], value=value, source="ebpf",
                quality="observed", attrs={"group": ch["group"]},
            )
        )

    for proc in msg.get("top_tasks", []) or []:
        if not isinstance(proc, dict):
            continue
        pid = proc.get("pid") or proc.get("tgid")
        if pid is None:
            continue
        ent = f"proc{pid}"
        for ch in PROC_CHANNELS:
            key = f"{ent}|{ch['key']}"
            raw = proc.get(ch["key"])
            if raw is None or not isinstance(raw, (int, float)):
                continue
            raw = float(raw)
            if ch["kind"] == "cumulative":
                prev_raw = prev.get(key)
                if prev_raw is None:
                    prev[key] = raw
                    continue
                value = max(0.0, raw - prev_raw)
                prev[key] = raw
            else:
                value = raw
            points.append(
                TelemetryPoint(
                    ts_ns=ts_ns, entity_id=ent, entity_type="process",
                    metric_id=ch["metric_id"], value=value, source="ebpf",
                    quality="observed", attrs={"group": ch["group"], "comm": str(proc.get("comm", ""))},
                )
            )

    return points, prev


# ---------------------------------------------------------------------------
# Anomaly session (per WS connection): warmup -> fit -> periodic scoring
# ---------------------------------------------------------------------------

class AnomalySession:
    def __init__(self, cfg: dict):
        ws = cfg.get("ws", {}) or {}
        det = cfg.get("detector", {}) or {}
        self.warmup_seconds = float(ws.get("warmup_seconds", DEFAULT_WARMUP_SECONDS))
        self.stride_ns = int(ws.get("stride_seconds", DEFAULT_STRIDE_SECONDS)) * 1_000_000_000
        self.window_ns = int(ws.get("window_seconds", DEFAULT_WINDOW_SECONDS)) * 1_000_000_000
        self.detector = TimeRCDFuseDetector(
            fuse_w=float(ws.get("fuse_w", 0.3)),
            threshold=float(ws.get("threshold", 0.5)),
            window_ns=self.window_ns,
            stride_ns=self.stride_ns,
        )
        self.buffer: list[TelemetryPoint] = []
        self.prev: dict[str, float] = {}
        self.last_score_ts_ns = 0
        self.fit_done = False
        self.avg_interval_ns = 1_000_000_000

    def ingest(self, msg: dict) -> None:
        points, self.prev = anomaly_features_to_points(msg, self.prev)
        self.buffer.extend(points)
        # retain warmup + two scoring windows of history, by time not count
        if self.buffer:
            cutoff = self.buffer[-1].ts_ns - int(
                (self.warmup_seconds + 2 * (self.window_ns / 1e9)) * 1e9
            )
            if self.buffer[0].ts_ns < cutoff:
                self.buffer = [p for p in self.buffer if p.ts_ns >= cutoff]

    def _frame(self, points: list[TelemetryPoint]) -> TelemetryFrame:
        return TelemetryFrame(points=tuple(sorted(points, key=lambda p: p.ts_ns)))

    async def maybe_score(self, now_ns: int) -> dict | None:
        """Returns an AnomalyResult dict when a scoring tick fires, else None."""
        span = now_ns - (self.buffer[0].ts_ns if self.buffer else now_ns)
        if not self.fit_done:
            if span < int(self.warmup_seconds * 1e9):
                return None
            try:
                train = self._frame(self.buffer)
                await asyncio.to_thread(self.detector.fit, train, None, seed=7)
                self.fit_done = True
                self.last_score_ts_ns = now_ns
                return None  # first scoring happens next stride
            except Exception as exc:  # model load/download failure -> stay silent
                app.state.last_error = f"fit failed: {exc}"
                return None
        if now_ns - self.last_score_ts_ns < self.stride_ns:
            return None
        self.last_score_ts_ns = now_ns
        window = [p for p in self.buffer if now_ns - p.ts_ns <= self.window_ns * 2]
        try:
            incidents = await asyncio.to_thread(self.detector.score, self._frame(window))
        except Exception as exc:
            app.state.last_error = f"score failed: {exc}"
            return None
        if not incidents:
            return None
        inc = max(incidents, key=lambda i: i.severity)
        return self._result(inc, now_ns)

    def _result(self, inc: IncidentWindow, now_ns: int) -> dict:
        group_scores: dict[str, float] = {}
        for metric_id, score in inc.metric_scores.items():
            grp = self._group_of(metric_id)
            group_scores[grp] = group_scores.get(grp, 0.0) + score
        anomaly_type = max(group_scores, key=group_scores.get) if group_scores else "cpu"
        indicators = [
            {"type": grp, "confidence": round(s, 4)}
            for grp, s in sorted(group_scores.items(), key=lambda x: x[1], reverse=True)
        ]
        return {
            "v": 1,
            "seq": 0,
            "ts_ns": now_ns,
            "is_anomaly": True,
            "type": anomaly_type,
            "confidence": round(inc.severity, 4),
            "indicators": indicators,
        }

    @staticmethod
    def _group_of(metric_id: str) -> str:
        for ch in HOST_CHANNELS:
            if ch["metric_id"] == metric_id:
                return ch["group"]
        return "cpu"


# ---------------------------------------------------------------------------
# /causal: evidence bundle -> TORAI multi-modal input (ADR-0004)
# ---------------------------------------------------------------------------

def evidence_to_inputs(body: dict) -> tuple[TelemetryFrame, tuple[LogEvent, ...], tuple[TraceSpan, ...], IncidentWindow | None]:
    series = body.get("series", []) or []
    points: list[TelemetryPoint] = []
    for row in series:
        if not isinstance(row, dict):
            continue
        try:
            points.append(
                TelemetryPoint(
                    ts_ns=int(row["ts_ns"]), entity_id=str(row["entity"]),
                    entity_type=row.get("entity_type", "process"),
                    metric_id=str(row["metric"]), value=float(row["value"]),
                    source="ebpf", quality="observed",
                )
            )
        except (KeyError, TypeError, ValueError):
            continue

    logs: list[LogEvent] = []
    for ev in body.get("events", {}).get("oom", []) or []:
        if not isinstance(ev, dict):
            continue
        logs.append(
            LogEvent(
                ts_ns=int(ev.get("ts_ns", 0)), entity_id=str(ev.get("entity", "host")),
                template_id=f"oom_{ev.get('kind', 'event')}",
                attrs={"evidence": "oom_event"},
            )
        )
    for ev in body.get("events", {}).get("syscall", []) or []:
        if not isinstance(ev, dict):
            continue
        logs.append(
            LogEvent(
                ts_ns=int(ev.get("ts_ns", 0)), entity_id=str(ev.get("entity", "host")),
                template_id=f"syscall_{ev.get('name', 'unknown')}",
                attrs={"evidence": "syscall_hotspot"},
            )
        )

    traces: list[TraceSpan] = []
    for kind, status in (("runq", "OK"), ("lock", "ERR")):
        for ev in body.get("events", {}).get(kind, []) or []:
            if not isinstance(ev, dict):
                continue
            start = int(ev.get("ts_ns", 0))
            dur = max(0, int(ev.get("wait_ns", ev.get("dur_ns", 0)) or 0))
            traces.append(
                TraceSpan(
                    start_ts_ns=start, end_ts_ns=start + dur,
                    trace_id=f"deep-{kind}-{start}",
                    span_id=str(ev.get("span_id", start)),
                    service_name=str(ev.get("entity", "host")),
                    span_kind="internal", status=status,
                    attrs={"evidence": f"{kind}_wait"},
                )
            )

    start = int(body.get("anomaly_start_ts", 0) or 0)
    end = int(body.get("anomaly_end_ts", 0) or 0)
    incident: IncidentWindow | None = None
    if start and end and end >= start:
        indicators = body.get("deep_indicators", []) or []
        metric_scores = {
            str(i.get("type", "cpu")): float(i.get("confidence", 0.9)) for i in indicators if isinstance(i, dict)
        } or {"cpu": 0.9}
        incident = IncidentWindow(
            incident_id=f"inc-{start}-{end}-deep",
            start_ts_ns=start, end_ts_ns=end, detected_at_ns=start,
            status="anomaly", severity=0.9,
            metric_scores=metric_scores, directions={m: "up" for m in metric_scores},
            model_version="collector",
        )

    frame = TelemetryFrame(points=tuple(sorted(points, key=lambda p: p.ts_ns)))
    return frame, tuple(logs), tuple(traces), incident


def run_causal(cfg: dict, body: dict, seed: int = 7) -> dict:
    frame, logs, traces, incident = evidence_to_inputs(body)
    if incident is None:
        return {"ok": False, "abstained_reason": "no valid anomaly window in evidence"}
    if len(frame.points) < 2:
        return {"ok": False, "abstained_reason": "empty evidence series"}
    rca = ToraiRCA(cfg, seed=seed)
    train, val, _ = split_by_time(frame, 0.6, 0.2)
    report = rca.analyze(frame, train, val, top_k=int(cfg.get("torai", {}).get("top_k", 3)),
                         incident=incident, logs=logs, traces=traces)
    return {"ok": True, "report": report.model_dump()}


# ---------------------------------------------------------------------------
# WS endpoints
# ---------------------------------------------------------------------------

@app.websocket("/anomaly")
async def ws_anomaly(ws: WebSocket) -> None:
    await ws.accept()
    cfg = _load_cfg()
    session = AnomalySession(cfg)
    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json_loads(raw)
            except ValueError:
                continue
            session.ingest(msg)
            now_ns = time.time_ns()
            if not session.fit_done:
                span = now_ns - (session.buffer[0].ts_ns if session.buffer else now_ns)
                if span < int(session.warmup_seconds * 1e9):
                    await ws.send_text(json_dumps({
                        "v": 1, "seq": msg.get("seq", 0), "ts_ns": now_ns,
                        "is_anomaly": False, "type": "none", "confidence": 0.0,
                        "indicators": [{"type": "warmup", "confidence": 0.0}],
                    }))
                    continue
            result = await session.maybe_score(now_ns)
            if result is None:
                await ws.send_text(json_dumps({
                    "v": 1, "seq": msg.get("seq", 0), "ts_ns": now_ns,
                    "is_anomaly": False, "type": "none", "confidence": 0.0,
                    "indicators": [],
                }))
            else:
                result["seq"] = msg.get("seq", 0)
                await ws.send_text(json_dumps(result))
    except WebSocketDisconnect:
        return


@app.websocket("/causal")
async def ws_causal(ws: WebSocket) -> None:
    await ws.accept()
    cfg = _load_cfg()
    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json_loads(raw)
            except ValueError:
                continue
            seq = msg.get("seq", 0)
            body = msg.get("evidence", msg.get("body", {})) or {}
            try:
                result = await asyncio.to_thread(run_causal, cfg, body)
            except Exception as exc:
                result = {"ok": False, "abstained_reason": f"causal analysis failed: {exc}"}
            await ws.send_text(json_dumps({"v": 1, "seq": seq, **result}))
    except WebSocketDisconnect:
        return


def _load_cfg() -> dict:
    import sys
    from pathlib import Path

    cfg_path = getattr(app.state, "config_path", None)
    if cfg_path and Path(cfg_path).exists():
        return load_config(cfg_path)
    if Path(DEFAULT_CONFIG_PATH).exists():
        return load_config(DEFAULT_CONFIG_PATH)
    return {}


def json_loads(raw: str) -> dict:
    import json

    return json.loads(raw)


def json_dumps(obj: dict) -> str:
    import json

    return json.dumps(obj)


def main() -> None:
    parser = argparse.ArgumentParser(description="eTrace-Diag WS bridge server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    args = parser.parse_args()

    import uvicorn

    app.state.config_path = args.config
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
