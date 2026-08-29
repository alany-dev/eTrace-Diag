"""Interactive control plane: versioned store, feedback handling with
conflict preservation, and the closed human-in-the-loop loop.

Feedback semantics:
- Every feedback produces a new model version and an audit record; history is
  never silently overwritten.
- Contradictory feedback for the same incident is PRESERVED (both entries kept,
  a conflict flag is recorded) — the model never flips silently.
- Feedback rejected/conflicting/targeting a nonexistent metric raises
  `FeedbackError` and changes nothing.
- Detector-side calibration (suppression + threshold adjustments) happens only
  when the feedback is applied to the live detector instance.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field

from ..detection.base import FeedbackError
from ..schemas import (
    CausalReport,
    FeedbackEvent,
    IncidentWindow,
    ModelCard,
    TelemetryFrame,
)


@dataclass
class IncidentRecord:
    incident: IncidentWindow
    created_at_ns: int
    model_version: str
    reports: list[CausalReport] = field(default_factory=list)  # versioned causal reports


@dataclass
class FeedbackRecord:
    feedback: FeedbackEvent
    audit_id: str
    applied: bool  # whether detector calibration was applied
    conflicts: list[str] = field(default_factory=list)


class VersionedStore:
    """In-memory versioned store. Old reports remain readable by version."""

    def __init__(self):
        self._incidents: dict[str, IncidentRecord] = {}
        self._feedback: list[FeedbackRecord] = []
        self._feedbacks_by_incident: dict[str, list[FeedbackRecord]] = {}

    # -- incidents ----------------------------------------------------------

    def put_incident(self, incident: IncidentWindow) -> IncidentRecord:
        rec = IncidentRecord(
            incident=incident,
            created_at_ns=time.time_ns(),
            model_version=incident.model_version,
        )
        self._incidents[incident.incident_id] = rec
        return rec

    def get_incident(self, incident_id: str) -> IncidentRecord | None:
        return self._incidents.get(incident_id)

    def put_report(self, report: CausalReport) -> None:
        rec = self._incidents.get(report.incident_id)
        if rec is None:
            rec = IncidentRecord(
                incident=report.window,
                created_at_ns=time.time_ns(),
                model_version=report.model_version,
            )
            self._incidents[report.incident_id] = rec
        # replace the same-version report; append a new version
        for i, r in enumerate(rec.reports):
            if r.model_version == report.model_version:
                rec.reports[i] = report
                break
        else:
            rec.reports.append(report)

    def latest_report(self, incident_id: str) -> CausalReport | None:
        rec = self._incidents.get(incident_id)
        if rec is None or not rec.reports:
            return None

    def reports_for_incident(self, incident_id: str) -> list[CausalReport]:
        rec = self._incidents.get(incident_id)
        return list(rec.reports) if rec else []

    # -- feedback -----------------------------------------------------------

    def record_feedback(self, feedback: FeedbackEvent, applied: bool) -> FeedbackRecord:
        audit_id = f"audit-{uuid.uuid4().hex[:12]}"
        rec = FeedbackRecord(feedback=feedback, audit_id=audit_id, applied=applied)
        self._feedback.append(rec)
        self._feedbacks_by_incident.setdefault(feedback.incident_id, []).append(rec)
        return rec

    def feedbacks(self, incident_id: str | None = None) -> list[FeedbackRecord]:
        if incident_id is None:
            return list(self._feedback)
        return list(self._feedbacks_by_incident.get(incident_id, []))

    @staticmethod
    def _conflicts(records: list[FeedbackRecord]) -> list[str]:
        """Contradictory label pairs on the same target, both preserved."""
        out: list[str] = []
        for a in records:
            for b in records:
                if a is b or a.feedback.target_id != b.feedback.target_id:
                    continue
                if _contradicts(a.feedback.label, b.feedback.label):
                    pair = tuple(sorted([a.audit_id, b.audit_id]))
                    out.append(f"conflict:{pair[0]}~{pair[1]}")
        return sorted(set(out))


def _contradicts(a: str, b: str) -> bool:
    """True when two feedback labels for the same target contradict."""
    pos = {"true_positive", "confirmed"}
    neg = {"false_positive", "rejected"}
    if a in pos and b in neg:
        return True
    if a in neg and b in pos:
        return True
    return (a == "wrong_direction" and b in pos) or (a in pos and b == "wrong_direction")


class IncidentController:
    """Orchestrates score / causal / feedback / what-if with a live detector."""

    def __init__(self, store: VersionedStore | None = None):
        self.store = store or VersionedStore()
        self._detector = None
        self._detector_cards: dict[str, ModelCard] = {}
        self._detector_signature: tuple | None = None

    def attach_detector(self, detector, signature: tuple | None = None) -> None:
        self._detector = detector
        if signature is not None:
            self._detector_signature = signature

    def detector_for(self, cfg: dict, *, seed: int) -> object | None:
        """Return the retained fitted detector when the config matches the one
        it was fitted with; otherwise None (caller must fit a fresh one).
        Feedback calibration (suppression + thresholds) persists across
        /v1/score calls on the same config."""
        if self._detector is None:
            return None
        det_cfg = cfg.get("detector", {})
        sig = (det_cfg.get("name", "edge_cascade"), det_cfg.get("window_ns"), det_cfg.get("stride_ns"))
        if getattr(self, "_detector_signature", None) != sig:
            return None
        return self._detector

    # -- feedback -----------------------------------------------------------

    def process_feedback(self, feedback: FeedbackEvent, *, apply_calibration: bool = True) -> dict:
        rec = self.store.get_incident(feedback.incident_id)
        if rec is None:
            raise FeedbackError(
                "unknown_incident",
                f"incident {feedback.incident_id!r} unknown to the store; no change",
            )
        # target validation against the incident's scored metrics
        if feedback.target_id not in rec.incident.metric_scores and feedback.label != "wrong_root_cause":
            raise FeedbackError(
                "unknown_metric",
                f"metric {feedback.target_id!r} not scored in incident "
                f"{feedback.incident_id!r}; no change",
            )
        applied = False
        if apply_calibration and self._detector is not None:
            try:
                card = self._detector.update(feedback)
                self._detector_cards[card.model_version] = card
                applied = True
            except FeedbackError:
                raise
        rec = self.store.record_feedback(feedback, applied=applied)
        conflicts = self.store._conflicts(self.store.feedbacks(feedback.incident_id))
        # conflict flag: contradictory feedback preserved, no overwrite
        return {
            "audit_id": rec.audit_id,
            "model_version": (
                self._detector.model_version if self._detector is not None else feedback.model_version
            ),
            "applied": applied,
            "conflicts": conflicts,
            "summary": f"feedback {feedback.label} recorded for {feedback.target_id}",
        }

    def next_question(self, incident_id: str) -> dict | None:
        """Active query selection (see active_query.py) for one incident."""
        from .active_query import select_next_question

        report = self.store.latest_report(incident_id)
        if report is None:
            return None
        return select_next_question(report, self.store.feedbacks(incident_id))



def store_to_json(store: VersionedStore) -> str:
    """Deterministic snapshot for audits (not a mutation — pure serialization)."""
    return json.dumps(
        {
            "incidents": {k: v.incident.model_dump() for k, v in store._incidents.items()},
            "reports": {
                k: [r.model_dump() for r in v.reports] for k, v in store._incidents.items()
            },
            "feedback": [
                {
                    "audit_id": r.audit_id,
                    "feedback": r.feedback.model_dump(),
                    "applied": r.applied,
                    "conflicts": r.conflicts,
                }
                for r in store._feedback
            ],
        },
        sort_keys=True,
    )