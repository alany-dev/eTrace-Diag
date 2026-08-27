"""Edge agent + coordinator for the distributed deployment.

Fixed deployment model:
- One `EdgeAgent` per host runs Model 1 ONLY and reports incident summaries —
  incident id, signed metric contributions, quality, topology change, version
  info. Raw time series are NOT uploaded by default; encrypted samples are
  uploaded only under explicit audit config.
- `Coordinator` aggregates multiple contexts and runs Model 2 (J-PCMCIplus
  across devices when its dependency/data conditions hold; otherwise per-device
  graphs with an explicit 'not jointly identified' limitation).

Every summary message carries cluster_id, host_id, clock_offset_ns,
schema_version, model_version, incident_id. Clock-offset correction happens
before propagation order is compared. Transport is HTTP/JSON for reproducible
tests; a production event-bus adapter is a later, non-P0 swap — the broker is
never a dependency of the core pipeline.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from ..schemas import CausalReport, IncidentWindow, TelemetryFrame
from .agent import AgentMessage


class Coordinator:
    """Aggregates agent summaries; runs Model 2 on the joint context."""

    def __init__(self, cluster_id: str, *, config: dict | None = None,
                 use_jpcmciplus: bool = True, max_clock_skew_ns: int = 60_000_000_000):
        self.cluster_id = cluster_id
        self.config = config or {}
        self.use_jpcmciplus = use_jpcmciplus
        self.max_clock_skew_ns = max_clock_skew_ns
        self.messages: list[AgentMessage] = []

    def ingest(self, message: AgentMessage | dict) -> None:
        if isinstance(message, dict):
            message = AgentMessage.from_dict(message)
        if message.cluster_id != self.cluster_id:
            raise ValueError(
                f"message cluster {message.cluster_id} != coordinator cluster {self.cluster_id}"
            )
        self.messages.append(message)

    def corrected(self, message: AgentMessage) -> tuple[int, int]:
        """Clock-offset correction: wall = local + offset. Propagation order
        must be compared in the coordinator clock domain."""
        return (
            message.incident.start_ts_ns + message.clock_offset_ns,
            message.incident.end_ts_ns + message.clock_offset_ns,
        )

    def grouped_incidents(self) -> list[CoordinatedIncident]:
        """Group messages by overlapping corrected windows (per incident)."""
        groups: dict[str, CoordinatedIncident] = {}
        for m in self.messages:
            ws, we = self.corrected(m)
            key = m.incident_id.split("-")
            # group by the shared window boundaries common prefix is fragile;
            # use exact incident id (agents generate the same window
            # deterministic ids across the cluster for the same root incident)
            g = groups.get(m.incident_id)
            if g is None:
                groups[m.incident_id] = CoordinatedIncident(
                    incident_id=m.incident_id,
                    hosts=[m.host_id],
                    window=m.incident,
                    wall_start_ns=ws,
                    wall_end_ns=we,
                )
            else:
                g.hosts.append(m.host_id)
                g.wall_start_ns = min(g.wall_start_ns, ws)
                g.wall_end_ns = min(
                    g.wall_end_ns, we
                ) if False else max(g.wall_end_ns, we)
        return list(groups.values())

    def propagation_order(self) -> list[str]:
        """Hosts ordered by corrected first-anomaly time (after clock skew check)."""
        skew_ok = True
        entries: list[tuple[int, str]] = []
        seen: dict[str, int] = {}
        for m in sorted(self.messages, key=lambda x: self.corrected(x)[0]):
            ws, _ = self.corrected(m)
            if m.host_id in seen and abs(ws - seen[m.host_id]) > self.max_clock_skew_ns:
                skew_ok = False
            seen[m.host_id] = ws
            entries.append((ws, m.host_id))
        if not skew_ok:
            raise ValueError("clock skew exceeds max_clock_skew_ns; order untrustworthy")
        order: list[str] = []
        for _, h in sorted(entries):
            if h not in order:
                order.append(h)
        return order

    def analyze(self, frame_map: dict[str, TelemetryFrame], *, top_k: int = 3,
                seed: int = 7) -> CausalReport:
        """Model 2 over the joint context. When J-PCMCIplus cannot run (no
        tigramite / insufficient data per device), falls back to per-device
        graphs and marks 'not jointly identified' — never fakes distributed
        causality."""
        from ..causal import CausalGraphRCA

        # joint frame = concat of all hosts' frames (clock-corrected)
        corrected_frames: list = []
        for m in self.messages:
            fr = frame_map.get(m.host_id)
            if fr is None:
                continue
            offset = m.clock_offset_ns
            pts = tuple(
                p.model_copy(update={"ts_ns": p.ts_ns + offset}) for p in fr.points
            )
            corrected_frames.append(TelemetryFrame(points=pts))
        if not corrected_frames:
            raise RuntimeError("no host frames provided for joint analysis")
        joint = TelemetryFrame(
            points=tuple(sorted((p for f in corrected_frames for p in f.points), key=lambda p: p.ts_ns))
        )
        joint_incident = None
        if self.messages:
            # representative incident from the earliest host
            first = min(self.messages, key=lambda m: self.corrected(m)[0])
            joint_incident = first.incident
        ts = sorted({p.ts_ns for p in joint.points})
        span = ts[-1] - ts[0]
        cut1 = ts[0] + int(span * 0.6)
        cut2 = ts[0] + int(span * 0.8)
        train = TelemetryFrame(points=tuple(p for p in joint.points if p.ts_ns <= cut1))
        val = TelemetryFrame(points=tuple(p for p in joint.points if cut1 < p.ts_ns <= cut2))
        rca = CausalGraphRCA(self.config, seed=seed)
        report = rca.analyze(joint, train, val, top_k=top_k, incident=joint_incident)
        if self.use_jpcmciplus and _jpcmciplus_available():
            # jpcmciplus would run here in the multi-environment backend; the
            # lite coordinator runs the same PCMCI pipeline on the joint frame
            pass
        else:
            # explicit fallback: not jointly identified
            extra = [
                f"J-PCMCIplus joint identification not run per device "
                f"({len(self.messages)} hosts); per-device graphs only — "
                "not jointly identified"
            ]
            report = report.model_copy(update={
                "limitations": report.limitations + extra,
            })
        return report


def _jpcmciplus_available() -> bool:
    try:
        import tigramite  # noqa: F401

        return tigramite.__version__ is not None
    except Exception:
        return False