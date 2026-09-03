"""Test-label leakage tests.

Verifies that detection thresholds are calibrated ONLY from train/validation —
mutating or relabeling the test segment must never change the fitted model —
and that TORAI's normal-window statistics come only from the pre-inject
segment (anomalous samples pushed into the train side must not change them).
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from alg_models.data.replay import TelemetryFrame, TelemetryPoint
from alg_models.detection import StreamingRobustDetector, get_detector
from alg_models.causal.torai import severity_scores


def _make_series(n_normal: int, n_anom: int, interval_s: float = 60.0,
                 seed: int = 1, anom_value: float = 200.0) -> TelemetryFrame:
    """Deterministic series: normal segment + anomaly segment at the END (the
    test split), plus a normal tail."""
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

    def test_fit_uses_only_train_val(self):
        """fit() must not depend on any test frame; calling fit with a
        different test frame leaves the card identical."""
        a = _make_series(300, 40, anom_value=200.0)
        b = _make_series(300, 40, anom_value=900.0)
        tr_a, va_a, _ = _split_time(a)
        tr_b, va_b, _ = _split_time(b)
        det = StreamingRobustDetector(window_ns=60_000_000_000, stride_ns=30_000_000_000)
        card = det.fit(tr_a, va_a, seed=7)
        det2 = StreamingRobustDetector(window_ns=60_000_000_000, stride_ns=30_000_000_000)
        card2 = det2.fit(tr_b, va_b, seed=7)
        assert card.thresholds == card2.thresholds


class TestToraiNoLeakage:
    def test_normal_stats_only_from_pre_inject(self):
        """TORAI's severity z-scores use pre-inject mean/std only: the
        normalized severity ratio of two columns matches a manual computation
        against the pre-inject window, regardless of post-inject magnitude."""
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
        ranks = severity_scores(normal, anomal, "standard")
        d = dict(ranks)
        mu, sd = pre.mean(), pre.std(ddof=0)
        z_x = np.max(np.abs((post + 30.0 - mu) / sd))
        z_y = np.max(np.abs((post - mu) / sd))
        assert np.isclose(d["x_cpu"], z_x / (z_x + z_y), rtol=1e-3)

class TestModuleNoLeakage:
    def test_empirical_tail_fit_only_from_normal(self):
        """Two inputs with identical normal, different post: the tail
        reference (median(normal), d=abs(normal-center)) is unchanged and
        only d* (max|anomal-center|) moves with the post values."""
        normal2 = pd.DataFrame({"x_cpu": [0.0, 1.0, 2.0, 3.0, 4.0],
                                "y_cpu": [0.0, 1.0, 2.0, 3.0, 4.0]})
        pa = pd.DataFrame({"x_cpu": [3.0] * 3, "y_cpu": [3.0] * 3})
        pb = pd.DataFrame({"x_cpu": [100.0] * 3, "y_cpu": [3.0] * 3})
        sa = severity_scores(normal2, pa, "standard", method="empirical_tail")
        sb = severity_scores(normal2, pb, "standard", method="empirical_tail")
        da, db = dict(sa), dict(sb)
        # y unchanged (post identical): its normalized share shrinks only
        # because x's raw score grew; the y raw score is post-independent
        assert da["y_cpu"] > db["y_cpu"]
        # manual recomputation proves the reference uses normal-only stats:
        # center=median(normal)=2, d=[2,1,0,1,2]
        p_y = (1 + 4) / 6.0  # y post 3 -> d*=1, count(d>=1)=4 (2,1,1,2)
        raw_y = -np.log(p_y)
        p_xa = (1 + 4) / 6.0  # x post 3 -> d*=1, same as y
        p_xb = (1 + 0) / 6.0  # x post 100 -> d*=98, count(d>=98)=0
        assert da["y_cpu"] == pytest.approx(raw_y / (raw_y + -np.log(p_xa)), rel=1e-9)
        assert db["y_cpu"] == pytest.approx(raw_y / (raw_y + -np.log(p_xb)), rel=1e-9)

    def test_onset_fit_only_from_pre_inject(self):
        """Same pre-inject window, different post: mean/std fit (pre only)
        identical; post values only move the detected onset index."""
        from alg_models.causal.torai import temporal_precedence_scores

        n = 40
        t = np.arange(n) * 15
        pre = 50.0 + 0.1 * np.sin(2 * np.pi * np.arange(n) / 60)
        a = pd.DataFrame({"time": t, "root_cpu": pre.copy(), "child_cpu": pre.copy()})
        b = pd.DataFrame({"time": t, "root_cpu": pre.copy(), "child_cpu": pre.copy()})
        post = t >= 300
        a.loc[post & (t >= 330), "root_cpu"] += 20  # onset idx 2
        a.loc[post & (t >= 360), "child_cpu"] += 20
        b.loc[post & (t >= 360), "root_cpu"] += 20  # onset idx 4 (later)
        b.loc[post & (t >= 330), "child_cpu"] += 20
        pa = temporal_precedence_scores(a, 300, ["root", "child"])
        pb = temporal_precedence_scores(b, 300, ["root", "child"])
        # pre-inject fit identical -> the onset flip comes solely from post
        assert pa == {"root": 1.0, "child": 0.0}
        assert pb == {"root": 0.0, "child": 1.0}

    def test_module_parser_rejects_truth_and_metadata(self):
        from experiments.torai_ablation_matrix import parse_modules

        for bad in ("truth", "fault", "system", "object", "tail,fault",
                    "tail,system", "tail,object", "tail,truth"):
            with pytest.raises(ValueError):
                parse_modules(bad)
        # valid canonical modules still parse
        assert parse_modules("tail,guided,onset,consensus") == {
            "severity_method": "empirical_tail",
            "guided_ci": True,
            "temporal_precedence": True,
            "rcd_consensus": True,
        }
