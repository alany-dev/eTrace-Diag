"""Missing/stale quality handling + feedback conflict + TORAI quality tests.

Verifies:
- feedback targeting a nonexistent metric raises a structured error and
  leaves the model version unchanged;
- contradictory feedback is preserved with a conflict flag;
- TORAI: non-observed (imputed/missing/stale/out_of_order) points are excluded
  from the severity statistics (only observed points feed to_torai_frames);
- missing modalities (no logs/traces) yield zero severity;
- normal-window statistics come only from before inject time.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from alg_models.cli import split_by_time
from alg_models.data.replay import load_replay
from alg_models.detection import FeedbackError, get_detector
from alg_models.schemas import (
    FeedbackEvent,
    IncidentWindow,
    LogEvent,
    TelemetryFrame,
    TelemetryPoint,
)
from alg_models.causal.torai import ToraiRCA, severity_scores, to_torai_frames


def _load(filename: str) -> TelemetryFrame:
    return load_replay(f"tests/fixtures/{filename}")


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
        assert card.model_version  # a new calibration card is produced
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


class TestToraiQuality:
    def _incident(self, start_ns: int = 300_000_000_000) -> IncidentWindow:
        return IncidentWindow(
            incident_id="i1", start_ts_ns=start_ns, end_ts_ns=600_000_000_000,
            detected_at_ns=start_ns, status="anomaly", severity=0.8,
            metric_scores={"adservice_cpu": 0.9},
        )

    def _frame(self) -> TelemetryFrame:
        pts = []
        rng = np.random.default_rng(0)
        for t in range(0, 600, 10):
            for svc in ("adservice", "cartservice"):
                for metric in ("cpu", "mem"):
                    pts.append(
                        TelemetryPoint(
                            ts_ns=t * 1_000_000_000, entity_id=svc,
                            entity_type="service", metric_id=metric,
                            value=50.0 + (metric == "cpu") * 10.0 + rng.normal(0, 0.5),
                        )
                    )
        return TelemetryFrame(points=tuple(sorted(pts, key=lambda p: p.ts_ns)))

    def test_to_torai_frames_excludes_non_observed_points(self):
        """Only quality == "observed" points feed the metric table."""
        frame = self._frame()
        # mark 40% of points non-observed
        mixed = TelemetryFrame(
            points=tuple(
                p.model_copy(update={"quality": "stale"}) if p.ts_ns % 4 == 0 else p
                for p in frame.points
            )
        )
        tables = to_torai_frames(mixed, (), ())
        metric = tables["metric"]
        # observed-only points
        n_obs_ts = sum(1 for t in range(0, 600, 10) if (t * 1_000_000_000) % 4 != 0)
        assert len(metric) == n_obs_ts
        assert len(metric) < len(range(0, 600, 10))

    def test_missing_modality_zero_severity(self):
        """No logs/traces -> their severity contributions are zero (blind spot),
        metric-only ranking still produced."""
        frame = self._frame()
        rca = ToraiRCA({"torai": {"variant": "faithful"}}, seed=7)
        tables = to_torai_frames(frame, (), ())
        result = rca.analyze_tables(
            tables["metric"], tables["logts"], None, None,
            inject_ns=300_000_000_000,
        )
        for svc, sev in result["severity_matrix"].items():
            assert sev["log"] == 0.0
            assert sev["trace_lat"] == 0.0
            assert sev["trace_err"] == 0.0
        assert len(result["service_ranks"]) > 0
        assert any("traces absent" in l for l in result["limitations"])

    def test_normal_stats_only_pre_inject(self):
        """Severity z-scores are computed against pre-inject mean/std only:
        the normalized severity ratio of two columns must match the ratio of
        their manual max-|z| computed from the pre-inject window."""
        rng = np.random.default_rng(3)
        pre = rng.normal(50, 1, 60)
        post = rng.normal(50, 1, 60)
        df = pd.DataFrame(
            {
                "time": list(range(120)),
                "x_cpu": np.concatenate([pre, post + 30.0]),
                "y_cpu": np.concatenate([pre, post]),
            }
        )
        normal = df[df["time"] < 60][["x_cpu", "y_cpu"]]
        anomal = df[df["time"] >= 60][["x_cpu", "y_cpu"]]
        ranks = severity_scores(normal, anomal, variant="fast")
        d = dict(ranks)
        mu, sd = pre.mean(), pre.std(ddof=0)
        z_x = np.max(np.abs((post + 30.0 - mu) / sd))
        z_y = np.max(np.abs((post - mu) / sd))
        ratio_expected = z_x / (z_x + z_y)
        assert np.isclose(d["x_cpu"], ratio_expected, rtol=1e-3)
        assert np.isclose(sum(d.values()), 1.0, rtol=1e-6)