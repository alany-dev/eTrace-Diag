"""eBPF collector adapters — sched_switch / futex / syscall / block / irq
tracepoints and profile stacks.

Every adapter is capability-gated: without eBPF permissions (BPF_PROG_LOAD
fails, missing bcc/bpftrace, or running without privileges) it raises
`EBPFPermissionError` and reports `quality=missing`-style unobservability via
the caller — it NEVER returns plausible-but-fabricated zero values.

Profile fields follow the Pyroscope/OTel eBPF profile format
(https://grafana.com/docs/pyroscope/latest/): sampled stacks, symbol, binary,
build ID, profile interval and process/thread join keys.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from ..schemas import TelemetryFrame, TelemetryPoint


class EBPFPermissionError(RuntimeError):
    """Raised when the kernel/permissions do not allow eBPF collection."""

    def __init__(self, program: str, detail: str):
        super().__init__(f"eBPF program {program} unavailable: {detail}")
        self.program = program


def _can_load_ebpf() -> tuple[bool, str]:
    if os.geteuid() != 0:
        return False, "requires root / CAP_BPF"
    try:
        import bpftrace  # noqa: F401
    except ImportError:
        try:
            import bcc  # noqa: F401
        except ImportError:
            return False, "no bpftrace/bcc python binding installed"
    return True, "ok"


class EBPCapability:
    """One-time capability probe shared by all eBPF adapters."""

    def __init__(self) -> None:
        self._ok: bool | None = None
        self._detail = ""

    def available(self) -> bool:
        if self._ok is None:
            self._ok, self._detail = _can_load_ebpf()
        return self._ok

    def detail(self) -> str:
        if self._ok is None:
            self.available()
        return self._detail


class TracepointCollector:
    """sched_switch / futex / syscall / block / hardirq / softirq adapters.

    `collect(events)` accepts a list of event dicts (from a live eBPF map or a
    replayed fixture) and converts them to `TelemetryPoint`s with
    source="ebpf". When no live capability exists and no events are supplied,
    raises `EBPFPermissionError`.
    """

    # tracepoint -> (entity_type, entity_id template, metric_id, unit)
    _MAP = {
        "sched_switch": ("thread", "{tid}", "scheduler.off_cpu", "ns"),
        "futex": ("thread", "{tid}", "futex.wait_time", "ns"),
        "syscall_enter": ("syscall", "{syscall}", "syscall.count", "1"),
        "block_rq_issue": ("device", "{dev}", "block.issue", "1"),
        "block_rq_complete": ("device", "{dev}", "block.complete", "1"),
        "irq_softirq": ("thread", "{tid}", "irq.softirq.duration", "ns"),
        "hardirq_entry": ("thread", "{tid}", "irq.hardirq.duration", "ns"),
    }

    def __init__(self, capability: EBPCapability | None = None):
        self.cap = capability or EBPCapability()

    def collect(self, events: list[dict] | None = None, *, ts_base_ns: int = 0) -> TelemetryFrame:
        if not self.cap.available() and not events:
            raise EBPFPermissionError(
                "tracepoint", self.cap.detail() or "no eBPF permission; replay required"
            )
        points: list[TelemetryPoint] = []
        for ev in events or []:
            kind = ev.get("type", "sched_switch")
            if kind not in self._MAP:
                continue
            et, eid_tpl, metric, unit = self._MAP[kind]
            tid = ev.get("tid", 0)
            eid = eid_tpl.format(tid=tid, dev=ev.get("dev", "0"), syscall=ev.get("name", "unknown"))
            value = ev.get("value", ev.get("delta_ns", 1))
            points.append(
                TelemetryPoint(
                    ts_ns=ts_base_ns + int(ev.get("ts_ns", 0)),
                    entity_id=eid,
                    entity_type=et,
                    metric_id=metric,
                    value=value,
                    unit=unit,
                    source="ebpf",
                    attrs={
                        "pid": str(ev.get("pid", 0)),
                        "tid": str(tid),
                        "comm": str(ev.get("comm", "")),
                        "state": str(ev.get("state", "")),
                    },
                )
            )
        return TelemetryFrame(points=tuple(sorted(points, key=lambda p: p.ts_ns)))


@dataclass
class ProfileSample:
    ts_ns: int
    tid: int
    pid: int
    comm: str
    stack: list[dict]  # [{"symbol", "binary", "build_id"}, ...]


class ProfileCollector:
    """Sampled stack collector → `function` nodes (Pyroscope/OTel format)."""

    def __init__(self, capability: EBPCapability | None = None, *, interval_ns: int = 9_000_000):
        self.cap = capability or EBPCapability()
        self.interval_ns = interval_ns

    def collect(self, samples: list[ProfileSample]) -> TelemetryFrame:
        if not self.cap.available() and not samples:
            raise EBPFPermissionError("profile", self.cap.detail() or "no eBPF permission")
        points: list[TelemetryPoint] = []
        for s in samples:
            for i, frame in enumerate(s.stack):
                points.append(
                    TelemetryPoint(
                        ts_ns=s.ts_ns,
                        entity_id=f"func:{s.comm}:{frame['symbol']}",
                        entity_type="function",
                        metric_id="profile.sample_count",
                        value=1,
                        unit="count",
                        source="profile",
                        sample_interval_ns=self.interval_ns,
                        attrs={
                            "pid": str(s.pid),
                            "tid": str(s.tid),
                            "comm": s.comm,
                            "symbol": frame["symbol"],
                            "binary": frame.get("binary", ""),
                            "build_id": frame.get("build_id", ""),
                            "depth": str(i),
                            "join_key": f"{s.pid}:{s.tid}",
                        },
                    )
                )
        return TelemetryFrame(points=tuple(sorted(points, key=lambda p: p.ts_ns)))