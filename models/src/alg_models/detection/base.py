"""Common detector base: protocol, versioning, feedback handling, suppression.

All detectors share the `Detector` protocol. `update(feedback)` never mutates
history silently: it returns a NEW `ModelCard` with an incremented version and
a `parents` chain, and raises `FeedbackError` (structured) for unknown
incidents/metrics so the model is provably unchanged.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Protocol

from ..schemas import FeedbackEvent, IncidentWindow, ModelCard, TelemetryFrame

DETECTOR_ROLE_STATE = "state"  # metric attrs role for discrete state metrics


class FeedbackError(ValueError):
    """Structured feedback rejection; the model is unchanged after raising."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class Detector(Protocol):
    def fit(self, train: TelemetryFrame, validation: TelemetryFrame | None, *, seed: int) -> ModelCard: ...

    def score(self, frame: TelemetryFrame, *, state: TelemetryFrame | None = None) -> list[IncidentWindow]: ...

    def update(self, feedback: FeedbackEvent) -> ModelCard: ...


class BaseDetector(ABC):
    """Shared versioned state: incident registry, suppression, calibration base."""

    def __init__(self, model_version: str = "0.1.0", model_name: str = "base"):
        self.model_version = model_version
        self.model_name = model_name
        self.parents: list[str] = []
        self.calibration_basis: str = ""
        self._suppressed: dict[str, str] = {}  # incident_id -> reason
        self._emitted: dict[str, IncidentWindow] = {}  # registry for feedback
        self._threshold_adjustments: dict[str, float] = {}
        self._feedback_labels: dict[str, list[str]] = {}  # incident -> labels

    # -- lifecycle ----------------------------------------------------------

    def _bump_version(self) -> str:
        try:
            base, minor, patch = self.model_version.split(".")
            return f"{base}.{int(minor)}.{int(patch) + 1}"
        except ValueError:
            return f"{self.model_version}.1"

    def _card(self, params: int, architecture: str, thresholds: dict[str, float], state: dict) -> ModelCard:
        return ModelCard(
            model_version=self.model_version,
            model_name=self.model_name,
            created_at_ns=time.time_ns(),
            params=params,
            architecture=architecture,
            thresholds=thresholds,
            state=state,
            calibration_basis=self.calibration_basis,
            parents=list(self.parents),
        )

    # -- feedback -----------------------------------------------------------

    def update(self, feedback: FeedbackEvent) -> ModelCard:
        inc = self._emitted.get(feedback.incident_id)
        if inc is None:
            raise FeedbackError(
                "unknown_incident",
                f"incident {feedback.incident_id!r} unknown to model {self.model_version}; no change",
            )
        if feedback.model_version and feedback.model_version != self.model_version:
            raise FeedbackError(
                "version_mismatch",
                f"feedback model_version {feedback.model_version!r} != current "
                f"{self.model_version!r}; no change",
            )
        # target metric validation: wrong_root_cause targets an entity, others
        # target a metric that must exist in the incident's metric_scores.
        if feedback.label != "wrong_root_cause" and feedback.target_id not in inc.metric_scores:
            raise FeedbackError(
                "unknown_metric",
                f"metric {feedback.target_id!r} not scored in incident "
                f"{feedback.incident_id!r}; no change",
            )
        # Apply calibration/suppression per label.
        if feedback.label in ("false_positive", "rejected"):
            self._suppressed[feedback.incident_id] = feedback.label
            if feedback.label == "false_positive" and feedback.target_id in inc.metric_scores:
                key = (feedback.incident_id, feedback.target_id)
                self._threshold_adjustments[f"loosen::{key[1]}"] = (
                    self._threshold_adjustments.get(f"loosen::{key[1]}", 1.0) * 1.15
                )
        elif feedback.label == "true_positive":
            # record calibration memory: tighten per metric slightly. Do NOT
            # pop suppression when a contradictory rejection already exists —
            # conflicting feedback is preserved, never silently flipped.
            if not any(
                l in ("false_positive", "rejected")
                for l in self._feedback_labels.get(feedback.incident_id, [])
            ):
                self._suppressed.pop(feedback.incident_id, None)
            if feedback.target_id in inc.metric_scores:
                self._threshold_adjustments[f"tighten::{feedback.target_id}"] = (
                    self._threshold_adjustments.get(f"tighten::{feedback.target_id}", 1.0) * 1.02
                )
        elif feedback.label == "wrong_direction":
            # versioned note only; no threshold change, audit via parents chain.
            pass
        # wrong_root_cause: not applicable to detector calibration; recorded.
        self._feedback_labels.setdefault(feedback.incident_id, []).append(feedback.label)
        self.parents.append(self.model_version)
        self.model_version = self._bump_version()
        self._emit_audit(feedback)
        return self._card(
            params=self.params(),
            architecture=self.architecture_name(),
            thresholds=self._threshold_map(),
            state=self._state_snapshot(),
        )

    def _emit_audit(self, feedback: FeedbackEvent) -> None:
        """Hook for subclass-specific audit logging; default no-op."""
        return None

    @abstractmethod
    def params(self) -> int: ...

    @abstractmethod
    def architecture_name(self) -> str: ...

    @abstractmethod
    def _threshold_map(self) -> dict[str, float]: ...

    @abstractmethod
    def _state_snapshot(self) -> dict: ...

    # -- incident helpers ---------------------------------------------------

    def _register(self, inc: IncidentWindow) -> None:
        if inc.incident_id in self._emitted and self._emitted[inc.incident_id] != inc:
            # same id, different content — new version, keep latest
            pass
        self._emitted[inc.incident_id] = inc

    def _is_suppressed(self, inc: IncidentWindow) -> bool:
        return inc.incident_id in self._suppressed

    def _apply_adjustment(self, metric_id: str, base_threshold: float) -> float:
        t = self._threshold_adjustments.get(f"tighten::{metric_id}", 1.0)
        l = self._threshold_adjustments.get(f"loosen::{metric_id}", 1.0)
        return base_threshold * l / t

    @staticmethod
    def incident_id_for(start_ns: int, end_ns: int, entity_id: str, metric_hint: str) -> str:
        import hashlib

        h = hashlib.sha1(f"{start_ns}:{end_ns}:{entity_id}".encode()).hexdigest()[:8]
        return f"inc-{start_ns}-{end_ns}-{metric_hint}-{h}"


DETECTOR_REGISTRY: dict[str, type] = {}


def register_detector(name: str):
    def deco(cls):
        DETECTOR_REGISTRY[name] = cls
        return cls

    return deco


def get_detector(name: str) -> type:
    try:
        return DETECTOR_REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown detector {name!r}; available: {sorted(DETECTOR_REGISTRY)}") from None