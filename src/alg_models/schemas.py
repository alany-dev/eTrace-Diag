"""Unified observability, result, and feedback contracts.

These are the single data contract for Model 1, Model 2 (TORAI), the API, and
distributed messages. Field names and semantics are fixed; do not add aliases
or duplicate schemas elsewhere.

All models are frozen (immutable) Pydantic v2 models so that results can be
cached, versioned, and audited without silent mutation.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

EntityType = Literal[
    "host",
    "device",
    "cluster",
    "pod",
    "service",
    "process",
    "thread",
    "function",
    "syscall",
]
Source = Literal["prometheus", "otlp", "ebpf", "profile", "trace", "replay"]
Quality = Literal["observed", "imputed", "missing", "stale", "out_of_order"]
Direction = Literal["up", "down", "variance", "missing", "stale", "mixed"]
WindowStatus = Literal["normal", "anomaly", "uncertain"]
FeedbackLabel = Literal[
    "true_positive",
    "false_positive",
    "wrong_direction",
    "wrong_root_cause",
    "confirmed",
    "rejected",
]


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class TelemetryPoint(FrozenModel):
    """One observation of one metric for one entity at one instant.

    `value=None` with `quality="missing"` denotes a known absence; a point may
    carry a value and `quality="stale"`/`"out_of_order"` when the value is
    present but unreliable — causal discovery must exclude those.
    """

    ts_ns: int = Field(ge=0, description="Unix UTC timestamp in nanoseconds")
    entity_id: str
    entity_type: EntityType
    metric_id: str
    value: float | int | bool | None = None
    unit: str | None = None
    source: Source = "replay"
    sample_interval_ns: int | None = Field(default=None, gt=0)
    quality: Quality = "observed"
    attrs: dict[str, str] = Field(default_factory=dict)

    @field_validator("value")
    @classmethod
    def _bool_as_float_allowed(cls, v: float | int | bool | None) -> float | int | bool | None:
        return v


class TraceSpan(FrozenModel):
    """One span from a trace sidecar. Rejects negative times, inverted spans,
    empty service/span/trace ids. A duplicate `(trace_id, span_id)` is invalid
    (callers reject before constructing the span set)."""

    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    service_name: str
    peer_service: str | None = None
    start_ts_ns: int = Field(ge=0)
    end_ts_ns: int = Field(ge=0)
    span_kind: Literal["client", "server", "producer", "consumer", "internal"]
    status: str | None = None
    attrs: dict[str, str] = Field(default_factory=dict)

    @field_validator("trace_id", "span_id", "service_name")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must be a non-empty string")
        return v

    @model_validator(mode="after")
    def _time_order(self) -> "TraceSpan":
        if self.end_ts_ns < self.start_ts_ns:
            raise ValueError("end_ts_ns must be >= start_ts_ns")
        return self


class LogEvent(FrozenModel):
    """One log line reduced to (entity, template). Template parsing failures or
    entities absent from the telemetry frame are counted in audit only and
    never produce edges."""

    ts_ns: int = Field(ge=0)
    entity_id: str
    template_id: str
    status: str | None = None
    attrs: dict[str, str] = Field(default_factory=dict)


class IncidentWindow(FrozenModel):
    incident_id: str
    start_ts_ns: int = Field(ge=0)
    end_ts_ns: int = Field(ge=0)
    detected_at_ns: int = Field(ge=0)
    status: WindowStatus
    severity: float = Field(ge=0.0, le=1.0)
    metric_scores: dict[str, float] = Field(default_factory=dict)
    directions: dict[str, Direction] = Field(default_factory=dict)
    model_version: str = "0.0.0"

    @field_validator("end_ts_ns")
    @classmethod
    def _window_order(cls, v: int, info: Any) -> int:
        start = info.data.get("start_ts_ns")
        if start is not None and v < start:
            raise ValueError("end_ts_ns must be >= start_ts_ns")
        return v


class RootCauseCandidate(FrozenModel):
    """TORAI root cause candidate: a service-level rank with per-modality
    severity and fine-grained evidence indicators."""

    entity_id: str
    rank: int = Field(ge=1)
    score: float = 0.0
    direction: Direction = "mixed"
    severity: dict[str, float] = Field(default_factory=dict)
    evidence_indicators: list[str] = Field(default_factory=list)
    cluster_id: int = -1
    abstained_reason: str | None = None


class SymptomCluster(FrozenModel):
    """GMM symptom cluster: services sharing the same failure signature."""

    cluster_id: int
    members: list[str] = Field(default_factory=list)
    cluster_score: float = 0.0


class CausalReport(FrozenModel):
    incident_id: str
    window: IncidentWindow
    anomalous_metrics: list[str] = Field(default_factory=list)
    candidates: list[RootCauseCandidate] = Field(default_factory=list)
    clusters: list[SymptomCluster] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    model_version: str = "0.0.0"


class FeedbackEvent(FrozenModel):
    feedback_id: str
    incident_id: str
    actor: str
    label: FeedbackLabel
    target_id: str
    created_at_ns: int = Field(ge=0)
    comment: str | None = None
    model_version: str = "0.0.0"


class TelemetryFrame(FrozenModel):
    """Ordered, deduplicated collection of telemetry points.

    Immutable by construction; use the data-pipeline helpers (window.py) to
    derive sub-frames, never mutate in place.
    """

    points: tuple[TelemetryPoint, ...] = Field(default_factory=tuple)

    @field_validator("points")
    @classmethod
    def _ordered_unique(cls, pts: tuple[TelemetryPoint, ...]) -> tuple[TelemetryPoint, ...]:
        prev = -1
        seen: set[tuple[str, str, str, int]] = set()
        for p in pts:
            if p.ts_ns < prev:
                raise ValueError("TelemetryFrame points must be sorted by ts_ns")
            prev = p.ts_ns
            key = (p.entity_id, p.metric_id, p.ts_ns, p.quality)
            if key in seen:
                raise ValueError(f"duplicate point {key} in TelemetryFrame")
            seen.add(key)
        return pts

    def __len__(self) -> int:
        return len(self.points)

    def __iter__(self):
        return iter(self.points)

    def slice_window(self, start_ns: int, end_ns: int) -> "TelemetryFrame":
        return TelemetryFrame(
            points=tuple(p for p in self.points if start_ns <= p.ts_ns <= end_ns)
        )

    def entity_metrics(self) -> set[tuple[str, str]]:
        return {(p.entity_id, p.metric_id) for p in self.points}

    def observed_only(self) -> "TelemetryFrame":
        return TelemetryFrame(points=tuple(p for p in self.points if p.quality == "observed"))


class ModelCard(FrozenModel):
    model_version: str
    model_name: str
    created_at_ns: int
    params: int = 0
    architecture: str = ""
    thresholds: dict[str, float] = Field(default_factory=dict)
    state: dict[str, Any] = Field(default_factory=dict)
    calibration_basis: str = Field(
        default="", description="description of which splits produced the thresholds"
    )
    parents: list[str] = Field(default_factory=list)


CONTRACT_MODELS = (
    TelemetryPoint,
    TraceSpan,
    LogEvent,
    IncidentWindow,
    RootCauseCandidate,
    SymptomCluster,
    CausalReport,
    FeedbackEvent,
    TelemetryFrame,
    ModelCard,
)