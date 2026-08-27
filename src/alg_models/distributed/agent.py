"""Edge agent — one per host, Model 1 only.

The EdgeAgent runs the edge detector on its host, emits incident SUMMARY
messages (never raw series by default), and can estimate the summary-report
bandwidth against the plan's 16 KB/s budget.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass

from ..schemas import IncidentWindow, TelemetryFrame


@dataclass
class AgentMessage:
    message_id: str
    cluster_id: str
    host_id: str
    clock_offset_ns: int
    schema_version: str
    model_version: str
    incident_id: str
    incident: IncidentWindow
    quality_summary: dict[str, int]
    topology_change: str | None = None
    sent_at_ns: int = 0

    def to_dict(self) -> dict:
        d = {
            "message_id": self.message_id,
            "cluster_id": self.cluster_id,
            "host_id": self.host_id,
            "clock_offset_ns": self.clock_offset_ns,
            "schema_version": self.schema_version,
            "model_version": self.model_version,
            "incident_id": self.incident_id,
            "incident": self.incident.model_dump(),
            "quality_summary": self.quality_summary,
            "topology_change": self.topology_change,
            "sent_at_ns": self.sent_at_ns,
        }
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "AgentMessage":
        return cls(
            message_id=d["message_id"],
            cluster_id=d["cluster_id"],
            host_id=d["host_id"],
            clock_offset_ns=d["clock_offset_ns"],
            schema_version=d["schema_version"],
            model_version=d["model_version"],
            incident_id=d["incident_id"],
            incident=IncidentWindow.model_validate(d["incident"]),
            quality_summary=d["quality_summary"],
            topology_change=d.get("topology_change"),
            sent_at_ns=d.get("sent_at_ns", 0),
        )


class EdgeAgent:
    """Runs Model 1 on one host; emits summary messages (never raw series)."""

    SCHEMA_VERSION = "1.0.0"

    def __init__(self, host_id: str, cluster_id: str, *, clock_offset_ns: int = 0,
                 config: dict | None = None):
        self.host_id = host_id
        self.cluster_id = cluster_id
        self.clock_offset_ns = clock_offset_ns
        self.config = config or {}
        self._detector = None

    def fit(self, train: TelemetryFrame, val: TelemetryFrame | None, *, seed: int = 7) -> str:
        from ..detection import DETECTOR_REGISTRY

        det_cfg = dict(self.config.get("detector", {}))
        name = det_cfg.pop("name", "edge_cascade")
        det = DETECTOR_REGISTRY[name](**det_cfg)
        card = det.fit(train, val, seed=seed)
        self._detector = det
        return card.model_version

    def process(self, frame: TelemetryFrame) -> list[AgentMessage]:
        if self._detector is None:
            raise RuntimeError("EdgeAgent must be fit() before process()")
        from ..data.window import summarize_quality

        incidents = self._detector.score(frame)
        out: list[AgentMessage] = []
        for inc in incidents:
            out.append(
                AgentMessage(
                    message_id=f"msg-{uuid.uuid4().hex[:8]}",
                    cluster_id=self.cluster_id,
                    host_id=self.host_id,
                    clock_offset_ns=self.clock_offset_ns,
                    schema_version=self.SCHEMA_VERSION,
                    model_version=self._detector.model_version,
                    incident_id=inc.incident_id,
                    incident=inc,
                    quality_summary=summarize_quality(frame),
                    sent_at_ns=time.time_ns(),
                )
            )
        return out

    def estimate_bandwidth_bytes(self, messages: list[AgentMessage]) -> int:
        """Summary-only event reporting: JSON size of the messages."""
        return sum(len(json.dumps(m.to_dict()).encode("utf-8")) for m in messages)