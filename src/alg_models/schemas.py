"""Unified observability, graph, result, and feedback contracts.

These are the single data contract for Model 1, Model 2, the API, and
distributed messages. Field names and semantics are fixed; do not add aliases
or duplicate schemas elsewhere.

All models are frozen (immutable) Pydantic v2 models so that results can be
cached, versioned, and audited without silent mutation.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

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
EdgeMark = Literal["directed", "undirected", "bidirected", "unknown"]
EvidenceLevel = Literal["strong", "weak", "insufficient"]
Identifiability = Literal["identified", "not_identifiable", "not_tested"]
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


class TopologyEdge(FrozenModel):
    """Candidate-edge prior only. Topology restricts candidate edges; it is
    never causal evidence by itself."""

    src_entity_id: str
    dst_entity_id: str
    edge_type: Literal["contains", "calls", "communicates", "shares_resource", "profiles"]
    valid_from_ns: int = Field(ge=0)
    valid_to_ns: int | None = Field(default=None, ge=0)
    confidence: float = Field(ge=0.0, le=1.0)
    source: str = "static"


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


class CausalEdge(FrozenModel):
    """One discovered or prior edge with its statistical evidence.

    `src_entity_id`/`dst_entity_id` use the causal-node convention: a full
    `{entity_id}::{metric_id}` node id, because one entity may expose several
    causally distinct metrics (e.g. `host::disk.io_wait` vs
    `host::cpu.utilization`).
    """

    edge_id: str
    src_entity_id: str
    dst_entity_id: str
    lag_ns: int
    edge_mark: EdgeMark = "directed"
    statistic: float = 0.0
    p_value: float | None = Field(default=None, ge=0.0, le=1.0)
    confidence_interval: tuple[float, float] | None = None
    stability: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_level: EvidenceLevel = "insufficient"

    @field_validator("confidence_interval")
    @classmethod
    def _ci_order(cls, v: tuple[float, float] | None) -> tuple[float, float] | None:
        if v is not None and v[0] > v[1]:
            raise ValueError("confidence_interval must be ordered [lo, hi]")
        return v


class RootCauseCandidate(FrozenModel):
    entity_id: str
    rank: int = Field(ge=1)
    score: float = 0.0
    direction: Direction = "mixed"
    effect_estimate: float | None = None
    effect_interval: tuple[float, float] | None = None
    identifiability: Identifiability = "not_tested"
    evidence_edge_ids: list[str] = Field(default_factory=list)
    evidence_metric_ids: list[str] = Field(default_factory=list)
    abstained_reason: str | None = None


class EvidenceChainItem(FrozenModel):
    """One link in an evidence chain. MUST reference concrete artifacts."""

    claim: str
    ref_type: Literal["metric", "edge", "intervention", "statistic"]
    ref_id: str
    start_ts_ns: int | None = None
    end_ts_ns: int | None = None
    lag_ns: int | None = None
    statistic: float | None = None
    p_value: float | None = None
    effect_estimate: float | None = None


class CausalReport(FrozenModel):
    incident_id: str
    window: IncidentWindow
    anomalous_metrics: list[str] = Field(default_factory=list)
    edges: list[CausalEdge] = Field(default_factory=list)
    candidates: list[RootCauseCandidate] = Field(default_factory=list)
    evidence_chain: list[EvidenceChainItem] = Field(default_factory=list)
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


# Registry of all contract models for API serialization and validation
CONTRACT_MODELS = (
    TelemetryPoint,
    TopologyEdge,
    IncidentWindow,
    CausalEdge,
    RootCauseCandidate,
    CausalReport,
    FeedbackEvent,
    TelemetryFrame,
    ModelCard,
)