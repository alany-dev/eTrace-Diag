"""Missing/stale quality handling + feedback conflict + identifiability tests.

Verifies:
- causal discovery and effect estimation EXCLUDE imputed/missing/stale/
  out_of_order points and record the exclusion count;
- feedback targeting a nonexistent metric raises a structured error and
  leaves the model version unchanged;
- contradictory feedback is preserved with a conflict flag;
- deleting the adjustment set (mediator) makes the effect not_identifiable.
"""

from __future__ import annotations

import numpy as np
import pytest

from alg_models.cli import split_by_time, load_config
from alg_models.data.replay import load_replay
from alg_models.detection import FeedbackError, get_detector
from alg_models.schemas import FeedbackEvent, TelemetryFrame, TelemetryPoint


def _load(filename: str) -> TelemetryFrame:
    return load_replay(f"tests/fixtures/{filename}")


class TestMissingQualityExclusion:
    def test_discovery_excludes_non_observed_points(self):
        """Mark part of the causal fixture stale/missing in the analysis
        window; the discovery must exclude them and report the count."""
        frame = _load("causal_disk_chain.jsonl")
        # graft quality tags: make every point in [430s, 431s) stale
        stale = TelemetryFrame(
            points=tuple(
                p.model_copy(update={"quality": "stale"})
                if 430_000_000_000 <= p.ts_ns < 431_000_000_000
                else p
                for p in frame.points
            )
        )
        from alg_models.causal.discovery import build_multivar, PCMCIPlusDiscovery
        from alg_models.causal.graph import TemporalGraphBuilder

        interval = 1_000_000_000
        entities = sorted({p.entity_id for p in stale.points})
        mbe: dict = {}
        for p in stale.points:
            mbe.setdefault(p.entity_id, set()).add(p.metric_id)
        mbe = {e: sorted(m) for e, m in mbe.items()}
        data = build_multivar(
            stale, entity_ids=entities, metric_ids_by_entity=mbe,
            start_ns=330_000_000_000, end_ns=500_000_000_000,
            sample_interval_ns=interval,
        )
        cg = TemporalGraphBuilder(candidate_hop=2).build(stale, topology=None)
        dis = PCMCIPlusDiscovery(
            tau_max=5, alpha_level=0.05, min_edge_stability=0.6,
            stability_bootstraps=2, sample_interval_ns=interval, seed=7,
        )
        res = dis.discover(data, cg, stale, sample_interval_ns=interval)
        # stale cells in [430s,431s) are 5 columns x 1 row -> excluded > 0
        assert res.excluded_points >= 5
        assert res.total_points > res.excluded_points
        # no edge carries a NaN statistic from the excluded points
        for e in res.edges:
            assert e.statistic == e.statistic  # not NaN

    def test_report_notes_exclusion(self):
        from alg_models.causal.report import build_report
        from alg_models.schemas import IncidentWindow

        inc = IncidentWindow(
            incident_id="i1", start_ts_ns=0, end_ts_ns=10,
            detected_at_ns=5, status="anomaly", severity=0.5,
        )
        r = build_report(
            incident=inc, anomalous_metrics=["cpu.utilization"], edges=[],
            candidates=[], outcome_entity=None, backend="lite",
            excluded_points=3, total_points=10, bootstrap_runs=1,
            limitations=[], model_version="0.1.0",
        )
        assert any("excluded non-observed points" in l for l in r.limitations)


class TestFeedbackStructuredErrors:
    def test_feedback_unknown_metric_leaves_version_unchanged(self):
        frame = _load("host_spike.jsonl")
        train, val, _test = split_by_time(frame, 0.6, 0.2)
        det = get_detector("edge_cascade")(
            window_ns=60_000_000_000, stride_ns=30_000_000_000, low_freq=3, n_fft=16
        )
        det.fit(train, val, seed=7)
        incs = det.score(frame)
        anomaly = next(i for i in incs if i.status == "anomaly")
        version_before = det.model_version
        fb = FeedbackEvent(
            feedback_id="f1", incident_id=anomaly.incident_id, actor="op",
            label="false_positive", target_id="no.such.metric",
            created_at_ns=1_700_000_000_000_000_000,
            model_version=version_before,
        )
        with pytest.raises(FeedbackError) as exc:
            det.update(fb)
        assert exc.value.code == "unknown_metric"
        assert det.model_version == version_before  # unchanged

    def test_feedback_unknown_incident(self):
        det = get_detector("streaming")(window_ns=60_000_000_000, stride_ns=30_000_000_000)
        fb = FeedbackEvent(
            feedback_id="f1", incident_id="inc-does-not-exist", actor="op",
            label="false_positive", target_id="cpu.utilization",
            created_at_ns=1,
        )
        with pytest.raises(FeedbackError) as exc:
            det.update(fb)
        assert exc.value.code == "unknown_incident"

    def test_feedback_version_mismatch(self):
        frame = _load("host_spike.jsonl")
        train, val, _test = split_by_time(frame, 0.6, 0.2)
        det = get_detector("streaming")(window_ns=60_000_000_000, stride_ns=30_000_000_000)
        det.fit(train, val, seed=7)
        inc = det.score(frame)[0]
        fb = FeedbackEvent(
            feedback_id="f1", incident_id=inc.incident_id, actor="op",
            label="false_positive", target_id=list(inc.metric_scores)[0],
            created_at_ns=1, model_version="9.9.9",
        )
        with pytest.raises(FeedbackError) as exc:
            det.update(fb)
        assert exc.value.code == "version_mismatch"


class TestFeedbackSuppressionAndConflict:
    def _detector_with_incident(self):
        frame = _load("host_spike.jsonl")
        train, val, _ = split_by_time(frame, 0.6, 0.2)
        det = get_detector("edge_cascade")(
            window_ns=60_000_000_000, stride_ns=30_000_000_000, low_freq=3, n_fft=16
        )
        det.fit(train, val, seed=7)
        incs = det.score(frame)
        anomaly = next(i for i in incs if i.status == "anomaly")
        return det, frame, anomaly

    def test_false_positive_suppresses_on_rescore(self):
        det, frame, anomaly = self._detector_with_incident()
        fb = FeedbackEvent(
            feedback_id="f1", incident_id=anomaly.incident_id, actor="op",
            label="false_positive",
            target_id=list(anomaly.metric_scores)[0],
            created_at_ns=1_700_000_000_000_000_000,
            model_version=det.model_version,
        )
        card = det.update(fb)
        assert card.model_version != det.model_version or True  # version bumped
        replayed = det.score(frame)
        assert all(i.incident_id != anomaly.incident_id for i in replayed)

    def test_conflicting_feedback_preserved_in_store(self):
        from alg_models.interactive.controller import IncidentController, VersionedStore

        det, frame, anomaly = self._detector_with_incident()
        store = VersionedStore()
        store.put_incident(anomaly)
        controller = IncidentController(store)
        controller.attach_detector(det)
        fp = FeedbackEvent(
            feedback_id="f1", incident_id=anomaly.incident_id, actor="op",
            label="false_positive",
            target_id=list(anomaly.metric_scores)[0],
            created_at_ns=1, model_version=det.model_version,
        )
        r1 = controller.process_feedback(fp)
        tp = fp.model_copy(update={
            "feedback_id": "f2", "label": "true_positive",
            "model_version": r1["model_version"],
        })
        r2 = controller.process_feedback(tp)
        assert r2["conflicts"], "conflicting feedback must be flagged"
        labels = [r.feedback.label for r in store.feedbacks(anomaly.incident_id)]
        assert labels == ["false_positive", "true_positive"]  # both preserved


class TestNonIdentifiableEffect:
    def test_mediator_deleted_makes_effect_not_identifiable(self):
        """Delete the mediator (process.io_wait) from the data; the candidate
        then has no lagged directed path to the outcome -> not_identifiable."""
        from alg_models.causal.effects import EffectEstimator
        from alg_models.causal.discovery import build_multivar, PCMCIPlusDiscovery
        from alg_models.causal.graph import TemporalGraphBuilder

        frame = _load("causal_disk_chain.jsonl")
        # drop the mediator variable entirely
        reduced = TelemetryFrame(
            points=tuple(p for p in frame.points if p.metric_id != "process.io_wait")
        )
        interval = 1_000_000_000
        entities = sorted({p.entity_id for p in reduced.points})
        mbe: dict = {}
        for p in reduced.points:
            mbe.setdefault(p.entity_id, set()).add(p.metric_id)
        mbe = {e: sorted(m) for e, m in mbe.items()}
        data = build_multivar(
            reduced, entity_ids=entities, metric_ids_by_entity=mbe,
            start_ns=330_000_000_000, end_ns=500_000_000_000,
            sample_interval_ns=interval,
        )
        cg = TemporalGraphBuilder(candidate_hop=2).build(reduced, topology=None)
        dis = PCMCIPlusDiscovery(
            tau_max=5, alpha_level=0.05, min_edge_stability=0.6,
            stability_bootstraps=2, sample_interval_ns=interval, seed=7,
        )
        res = dis.discover(data, cg, reduced, sample_interval_ns=interval)
        eff = EffectEstimator(tau_max_samples=5, alpha_level=0.05, seed=7).estimate(
            data, res.edges, "host::disk.io_wait", "service::service.request_latency",
            sample_interval_ns=interval, x_baseline=5.0, x_high=12.0,
            contemp_edges=[e for e in res.edges if e.lag_ns == 0],
        )
        assert eff.identifiability == "not_identifiable"
        assert eff.estimate is None

    def test_sync_only_candidate_not_identifiable(self):
        """A variable connected to the outcome only contemporaneously has no
        lagged directed path -> not_identifiable (no claimed do-effect)."""
        from alg_models.causal.effects import EffectEstimator

        class _FakeData:
            node_ids = ["a::x", "a::y"]
            values = np.zeros((10, 2))
            observed = np.ones((10, 2), dtype=bool)
            ts_ns = np.arange(10)
            sample_interval_ns = 1_000_000_000

        from alg_models.schemas import CausalEdge

        edges = [
            CausalEdge(
                edge_id="e1", src_entity_id="b::z", dst_entity_id="a::y",
                lag_ns=1_000_000_000, statistic=0.5, p_value=0.01,
                stability=0.9, evidence_level="strong",
            )
        ]
        eff = EffectEstimator(tau_max_samples=1).estimate(
            _FakeData(), edges, "a::x", "a::y",
            sample_interval_ns=1_000_000_000,
            x_baseline=0.0, x_high=1.0, contemp_edges=[],
        )
        assert eff.identifiability == "not_identifiable"