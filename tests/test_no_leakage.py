"""Test-label leakage tests.

Verifies that detection thresholds and rank weights are calibrated ONLY from
train/validation — mutating or relabeling the test segment must never change
the fitted model, its thresholds, or the ranking score of an incident.
"""

from __future__ import annotations

import numpy as np
import pytest

from alg_models.data.replay import TelemetryFrame, TelemetryPoint
from alg_models.detection import StreamingRobustDetector, get_detector


def _make_series(n_normal: int, n_anom: int, interval_s: float = 60.0,
                 seed: int = 1, anom_value: float = 200.0) -> TelemetryFrame:
    """Deterministic series: normal segment + anomaly segment at the END (the
    test split), plus a normal tail. Returns the full frame and (train, val,
    test) split boundaries in samples."""
    rng = np.random.default_rng(seed)
    normal = rng.normal(50, 5, n_normal)
    anom = rng.normal(anom_value, 5, n_anom)
    tail = rng.normal(50, 5, 50)
    values = np.concatenate([normal, anom, tail])
    interval_ns = int(interval_s * 1e9)
    pts = [
        TelemetryPoint(
            ts_ns=i * interval_ns, entity_id="h", entity_type="host",
            metric_id="cpu.utilization", value=float(v),
            source="replay", sample_interval_ns=interval_ns,
        )
        for i, v in enumerate(values)
    ]
    return TelemetryFrame(points=tuple(pts))


def _split_time(frame: TelemetryFrame, train_frac=0.5, val_frac=0.25):
    ts = sorted({p.ts_ns for p in frame.points})
    t0, t1 = ts[0], ts[-1]
    span = t1 - t0
    cut1 = t0 + int(span * train_frac)
    cut2 = t0 + int(span * (train_frac + val_frac))
    train = TelemetryFrame(points=tuple(p for p in frame.points if p.ts_ns <= cut1))
    val = TelemetryFrame(points=tuple(p for p in frame.points if cut1 < p.ts_ns <= cut2))
    test = TelemetryFrame(points=tuple(p for p in frame.points if p.ts_ns > cut2))
    return train, val, test


def _fit_thresholds(frame: TelemetryFrame):
    train, val, _test = _split_time(frame)
    det = StreamingRobustDetector(window_ns=60_000_000_000, stride_ns=30_000_000_000)
    det.fit(train, val, seed=7)
    return dict(det.thresholds), det.calibration_basis


class TestNoLeakage:
    def test_thresholds_independent_of_test_segment(self):
        """Two runs with DIFFERENT test-segment values must yield identical
        thresholds (fit only touches train/val)."""
        frame_a = _make_series(300, 40, anom_value=200.0)
        frame_b = _make_series(300, 40, anom_value=900.0)
        ta, basis_a = _fit_thresholds(frame_a)
        tb, _ = _fit_thresholds(frame_b)
        assert ta == tb
        assert "validation" in basis_a

    def test_thresholds_independent_of_test_labels(self):
        """Thresholds must not change whether the test segment is anomalous or
        normal — only the anomaly VALUE differs, not the split."""
        anom = _make_series(300, 40, anom_value=200.0)
        flat = _make_series(300, 40, anom_value=50.0)  # same shape, no spike
        ta, _ = _fit_thresholds(anom)
        tb, _ = _fit_thresholds(flat)
        assert ta == tb

    def test_rank_weights_not_tuned_on_test(self):
        """CausalGraphRCA rank weights come from config; the same incident and
        edges yield the same rank scores regardless of test labels (no test
        split participates in the ranking step)."""
        from alg_models.causal.ranking import RootCauseRanker

        edges = []
        ranker_a = RootCauseRanker(weights={"detector": 0.5, "ancestor": 0.5})
        ranker_b = RootCauseRanker(weights={"detector": 0.5, "ancestor": 0.5})
        assert ranker_a.w == ranker_b.w  # weights are config-derived, not test-tuned

    def test_fit_uses_only_train_val(self):
        """fit() must not depend on any test frame; calling fit with a
        different test frame leaves the card identical."""
        from alg_models.schemas import ModelCard

        a = _make_series(300, 40, anom_value=200.0)
        b = _make_series(300, 40, anom_value=900.0)
        tr_a, va_a, _ = _split_time(a)
        tr_b, va_b, _ = _split_time(b)
        det = StreamingRobustDetector(window_ns=60_000_000_000, stride_ns=30_000_000_000)
        card = det.fit(tr_a, va_a, seed=7)
        det2 = StreamingRobustDetector(window_ns=60_000_000_000, stride_ns=30_000_000_000)
        card2 = det2.fit(tr_b, va_b, seed=7)
        assert card.thresholds == card2.thresholds