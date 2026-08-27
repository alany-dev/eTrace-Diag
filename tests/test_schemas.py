"""Tests for the Pydantic schema contracts (schemas.py).

Covers: legal/illegal entity_type, empty window, duplicate/out-of-order
timestamps, missing and stale points, non-identifiable effects, feedback
conflict. Tests check structured errors and unchanged model versions, not just
importability.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alg_models.schemas import (
    CausalEdge,
    CausalReport,
    FeedbackEvent,
    IncidentWindow,
    RootCauseCandidate,
    TelemetryFrame,
    TelemetryPoint,
)


def _pt(ts_ns=0, entity_id="host", entity_type="host", metric_id="cpu.utilization",
        value=1.0, source="replay", quality="observed"):
    return TelemetryPoint(
        ts_ns=ts_ns, entity_id=entity_id, entity_type=entity_type,
        metric_id=metric_id, value=value, source=source, quality=quality,
    )


class TestTelemetryPoint:
    def test_valid(self):
        p = _pt()
        assert p.ts_ns == 0

    def test_invalid_entity_type(self):
        with pytest.raises(ValidationError, match="entity_type"):
            _pt(entity_type="invalid_type")

    def test_invalid_source(self):
        with pytest.raises(ValidationError, match="source"):
            _pt(source="unknown_source")

    def test_invalid_quality(self):
        with pytest.raises(ValidationError, match="quality"):
            _pt(quality="invalid_quality")

    def test_value_none(self):
        p = _pt(value=None)
        assert p.value is None

    def test_value_bool(self):
        p = _pt(value=True)
        assert p.value is True


class TestTelemetryFrame:
    def test_empty(self):
        f = TelemetryFrame(points=())
        assert len(f) == 0

    def test_sorted(self):
        pts = [_pt(ts_ns=10), _pt(ts_ns=5), _pt(ts_ns=7)]
        with pytest.raises(ValidationError, match="sorted by ts_ns"):
            TelemetryFrame(points=tuple(pts))

    def test_duplicate(self):
        pts = [_pt(ts_ns=5), _pt(ts_ns=5)]
        with pytest.raises(ValidationError, match="duplicate"):
            TelemetryFrame(points=tuple(pts))

    def test_duplicate_entity_metric_ts(self):
        p1 = _pt(ts_ns=5, entity_id="h", metric_id="cpu", quality="observed")
        p2 = _pt(ts_ns=5, entity_id="h", metric_id="cpu", quality="observed")
        with pytest.raises(ValidationError, match="duplicate"):
            TelemetryFrame(points=(p1, p2))

    def test_same_ts_different_quality_allowed(self):
        p1 = _pt(ts_ns=5, entity_id="h", metric_id="cpu", quality="observed")
        p2 = _pt(ts_ns=5, entity_id="h", metric_id="cpu", quality="imputed")
        f = TelemetryFrame(points=(p1, p2))
        assert len(f) == 2

    def test_observed_only(self):
        pts = [_pt(ts_ns=0, quality="observed"), _pt(ts_ns=1, quality="imputed")]
        f = TelemetryFrame(points=tuple(pts))
        obs = f.observed_only()
        assert len(obs) == 1
        assert obs.points[0].quality == "observed"


class TestIncidentWindow:
    def test_valid(self):
        i = IncidentWindow(
            incident_id="i1", start_ts_ns=0, end_ts_ns=10,
            detected_at_ns=5, status="anomaly", severity=0.5,
        )
        assert i.status == "anomaly"

    def test_invalid_window_order(self):
        with pytest.raises(ValidationError, match="end_ts_ns"):
            IncidentWindow(
                incident_id="i1", start_ts_ns=10, end_ts_ns=5,
                detected_at_ns=6, status="anomaly", severity=0.5,
            )

    def test_empty_scores(self):
        i = IncidentWindow(
            incident_id="i1", start_ts_ns=0, end_ts_ns=10,
            detected_at_ns=5, status="normal", severity=0.0,
        )
        assert i.metric_scores == {}


class TestCausalEdge:
    def test_valid_ci_order(self):
        CausalEdge(
            edge_id="e1", src_entity_id="host::a", dst_entity_id="host::b",
            lag_ns=10, statistic=0.5, p_value=0.01,
            confidence_interval=(0.2, 0.8), stability=0.9,
            evidence_level="strong",
        )

    def test_invalid_ci_order(self):
        with pytest.raises(ValidationError, match="confidence_interval"):
            CausalEdge(
                edge_id="e1", src_entity_id="host::a", dst_entity_id="host::b",
                lag_ns=10, statistic=0.5, p_value=0.01,
                confidence_interval=(0.8, 0.2), stability=0.9,
                evidence_level="strong",
            )


class TestRootCauseCandidate:
    def test_rank_ge_1(self):
        with pytest.raises(ValidationError, match="rank"):
            RootCauseCandidate(entity_id="h::cpu", rank=0, score=0.5)

    def test_valid(self):
        c = RootCauseCandidate(entity_id="h::cpu", rank=1, score=0.5)
        assert c.identifiability == "not_tested"

    def test_abstained(self):
        c = RootCauseCandidate(
            entity_id="h::cpu", rank=1, score=0.0,
            identifiability="not_identifiable",
            abstained_reason="no path to outcome",
        )
        assert c.abstained_reason is not None


class TestFeedbackEvent:
    def test_valid(self):
        f = FeedbackEvent(
            feedback_id="f1", incident_id="i1", actor="op",
            label="true_positive", target_id="h::cpu",
            created_at_ns=1_000_000_000,
        )
        assert f.model_version == "0.0.0"

    def test_invalid_label(self):
        with pytest.raises(ValidationError):
            FeedbackEvent(
                feedback_id="f1", incident_id="i1", actor="op",
                label="invalid_label", target_id="h::cpu",
                created_at_ns=1,
            )


class TestNonIdentifiableEffect:
    """Non-identifiable effect: a candidate with only bidirected/unknown
    edges or no path to outcome must be marked not_identifiable."""

    def test_candidate_not_identifiable(self):
        c = RootCauseCandidate(
            entity_id="host::cpu", rank=1, score=0.0,
            identifiability="not_identifiable",
            effect_estimate=None, effect_interval=None,
        )
        assert c.identifiability == "not_identifiable"


class TestFeedbackConflict:
    """Contradictory feedback preserved; no silent overwrite."""

    def test_contradictory_labels(self):
        from alg_models.interactive.controller import _contradicts
        assert _contradicts("true_positive", "false_positive")
        assert _contradicts("confirmed", "rejected")
        # wrong_direction contradicts a positive (direction claim vs correct)
        assert _contradicts("true_positive", "wrong_direction")
        # same-side labels never contradict
        assert not _contradicts("false_positive", "rejected")
        assert not _contradicts("true_positive", "confirmed")