"""OTLP collector adapter — coarse- and fine-grained observability intake.

Uses OpenTelemetry semantic conventions
(https://opentelemetry.io/docs/specs/semconv/) as the resource/span/metric
attribute basis. Points are mapped onto `TelemetryPoint` with
source="otlp"/"profile"/"trace". When the collector is unavailable, the
adapter raises `CollectorUnavailableError` so callers can fall back to
replay — never fabricate zero-like fine-grained values.
"""

from __future__ import annotations

from ..data.replay import telemetry_from_otlp
from ..schemas import TelemetryFrame, TelemetryPoint


class CollectorUnavailableError(RuntimeError):
    def __init__(self, component: str, detail: str):
        super().__init__(f"{component} unavailable: {detail}")
        self.component = component


class OTLPCollector:
    """Minimal OTLP/HTTP JSON intake adapter.

    `available()` is a capability probe: but the adapter NEVER fabricates data
    when the endpoint is unreachable — `collect` raises
    `CollectorUnavailableError`, and the caller decides replay.
    """

    def __init__(self, endpoint: str | None = None, *, project: str = ""):
        self.endpoint = endpoint
        self.project = project
        self._probe: bool | None = None

    def available(self) -> bool:
        if self._probe is not None:
            return self._probe
        if not self.endpoint:
            self._probe = False
            return False
        try:
            import httpx

            resp = httpx.get(self.endpoint, timeout=1.0)
            self._probe = resp.status_code < 500
        except Exception:
            self._probe = False
        return self._probe

    def collect(self, resource_metrics: list[dict] | None = None) -> TelemetryFrame:
        if not self.available():
            raise CollectorUnavailableError(
                "otlp", f"endpoint {self.endpoint or '<none>'} unreachable"
            )
        if resource_metrics is None:
            raise CollectorUnavailableError("otlp", "no resource_metrics payload provided")
        points = telemetry_from_otlp(resource_metrics, source="otlp")
        return TelemetryFrame(points=tuple(sorted(points, key=lambda p: p.ts_ns)))


# Host-level coarse metrics (required minimum fields, per plan §6)
HOST_COARSE_METRICS = (
    "system.cpu.utilization",
    "system.cpu.load.1",
    "system.memory.usage",
    "system.memory.swap",
    "system.processes.count",
    "system.cpu.context_switches",
    "system.cpu.irq",
    "system.disk.io",
    "system.disk.operation_time",
    "system.network.io",
    "system.network.errors",
)

# Container layer metrics (required minimum fields, per plan §6)
CONTAINER_METRICS = (
    "k8s.pod.cpu.usage",
    "k8s.pod.memory.usage",
    "container.cpu.usage",
    "container.memory.usage",
    "container.filesystem.usage",
    "container.restart.count",
)

# Fine-grained fields (kept when the eBPF/profile collector provides them)
FINE_GRAINED_FIELDS = (
    "process.pid",
    "thread.tid",
    "process.ppid",
    "process.comm",
    "process.state",
    "process.memory.rss",
    "process.memory.page_faults",
    "process.context_switches.voluntary",
    "process.context_switches.involuntary",
    "process.disk.bytes",
    "process.network.io",
    "scheduler.runnable_to_on_cpu",
    "scheduler.off_cpu",
    "futex.wait_time",
    "syscall.count",
    "block.disk.operation_time",
    "irq.hardirq.duration",
    "irq.softirq.duration",
)