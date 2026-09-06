"""Tests for the Pydantic schema contracts (schemas.py).

Covers: legal/illegal entity_type, empty window, duplicate/out-of-order
timestamps, missing and stale points, TORAI candidate/cluster/report shapes,
feedback conflict. Tests check structured errors, not just importability.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alg_models.schemas import (
    CausalReport,
    FeedbackEvent,
    IncidentWindow,
    RootCauseCandidate,
    SymptomCluster,
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


class TestToraiSchemas:
    def test_candidate_rank_ge_1(self):
        with pytest.raises(ValidationError, match="rank"):
            RootCauseCandidate(entity_id="adservice", rank=0, score=0.5)

    def test_candidate_defaults(self):
        c = RootCauseCandidate(entity_id="adservice", rank=1)
        assert c.severity == {}
        assert c.evidence_indicators == []
        assert c.cluster_id == -1
        assert c.abstained_reason is None

    def test_candidate_valid(self):
        c = RootCauseCandidate(
            entity_id="adservice", rank=2, score=0.3,
            severity={"metric": 0.8, "log": 0.1},
            evidence_indicators=["adservice_cpu", "adservice_mem"],
            cluster_id=0,
        )
        assert c.direction == "mixed"
        assert c.evidence_indicators[0] == "adservice_cpu"

    def test_symptom_cluster(self):
        cl = SymptomCluster(cluster_id=0, members=["adservice", "cartservice"], cluster_score=0.9)
        assert cl.cluster_id == 0
        assert len(cl.members) == 2
        assert cl.cluster_score == 0.9

    def test_report_no_edges_field(self):
        r = CausalReport(
            incident_id="i1",
            window=IncidentWindow(
                incident_id="i1", start_ts_ns=0, end_ts_ns=10,
                detected_at_ns=5, status="anomaly", severity=0.5,
            ),
            candidates=[RootCauseCandidate(entity_id="adservice", rank=1)],
            clusters=[SymptomCluster(cluster_id=0, members=["adservice"])],
        )
        assert r.candidates[0].entity_id == "adservice"
        assert r.clusters[0].cluster_id == 0
        assert r.limitations == []

    def test_report_rejects_edges_kwarg(self):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            CausalReport(
                incident_id="i1",
                window=IncidentWindow(
                    incident_id="i1", start_ts_ns=0, end_ts_ns=10,
                    detected_at_ns=5, status="anomaly", severity=0.5,
                ),
                edges=[],
            )


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
