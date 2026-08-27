"""StreamingRobustDetector — zero-parameter-style streaming statistical baseline.

Per-metric median/MAD fit on train, EWMA smoothing of the signed robust
residual, POT-style per-metric threshold calibrated on validation ONLY. Outputs
signed robust residuals so `up`/`down` directions and per-metric contributions
fall out directly. Thresholds trace back to train/validation splits.
"""

from __future__ import annotations

import time

from ..data.normalize import Normalizer
from ..data.window import SlidingWindowMaker, align_window, summarize_quality
from ..schemas import FeedbackEvent, IncidentWindow, ModelCard, TelemetryFrame
from .base import BaseDetector, DETECTOR_ROLE_STATE, register_detector


@register_detector("shesd")
@register_detector("streaming")
class StreamingRobustDetector(BaseDetector):
    """S-H-ESD-style robust streaming detector (median/MAD + EWMA + POT).

    Registered under both `shesd` (S-H-ESD benchmark name) and `streaming`
    (implementation name). Uses the same median/MAD robust residual family as
    S-H-ESD's seasonal decomposition residual — a zero-parameter lower bound
    that never views test labels.
    """

    def __init__(self, *, window_ns: int = 60_000_000_000, stride_ns: int = 30_000_000_000,
                 ewma_alpha: float = 0.2, pot_quantile: float = 0.99,
                 pot_multiplier: float = 1.5, min_observed_frac: float = 0.5):
        super().__init__(model_version="0.2.0", model_name="StreamingRobustDetector")
        self.window_ns = window_ns
        self.stride_ns = stride_ns
        self.ewma_alpha = ewma_alpha
        self.pot_quantile = pot_quantile
        self.pot_multiplier = pot_multiplier
        self.min_observed_frac = min_observed_frac
        self.normalizer: Normalizer | None = None
        self.thresholds: dict[tuple[str, str], float] = {}
        self.sample_interval_ns: int = 10_000_000_000
        self._fit_done = False

    # -- lifecycle ----------------------------------------------------------

    def fit(self, train: TelemetryFrame, validation: TelemetryFrame | None, *, seed: int) -> ModelCard:
        if len(train) == 0:
            raise ValueError("fit requires non-empty train frame")
        self._fit_done = True
        self.normalizer = Normalizer().fit_frame(train)
        # sample interval from the most common observed gap
        ts = sorted({p.ts_ns for p in train.points})
        gaps = [b - a for a, b in zip(ts, ts[1:]) if b > a]
        if gaps:
            from collections import Counter

            self.sample_interval_ns = Counter(gaps).most_common(1)[0][0]
        # Thresholds from validation only (if validation absent, from train —
        # never from test; calibration_basis records which).
        basis = _split_label(train, validation)
        for (entity_id, metric_id), stats in self.normalizer.per_metric.items():
            if stats.mad <= 0.0:
                self.thresholds[(entity_id, metric_id)] = 1.0
                continue
            cal_pts = validation if validation is not None and len(validation) > 0 else train
            zs = [
                stats.robust_z(float(p.value))
                for p in cal_pts.points
                if p.entity_id == entity_id and p.metric_id == metric_id and p.value is not None
                and p.quality == "observed"
            ]
            if not zs:
                self.thresholds[(entity_id, metric_id)] = 4.0
                continue
            import numpy as np

            q = float(np.quantile([abs(z) for z in zs], self.pot_quantile))
            self.thresholds[(entity_id, metric_id)] = max(1.5, q * self.pot_multiplier)
        self.calibration_basis = basis
        return self._card(
            params=self.params(),
            architecture=self.architecture_name(),
            thresholds=self._threshold_map(),
            state={"ewma_alpha": self.ewma_alpha, "pot_quantile": self.pot_quantile},
        )

    def score(self, frame: TelemetryFrame, *, state: TelemetryFrame | None = None) -> list[IncidentWindow]:
        if not self._fit_done or self.normalizer is None:
            raise RuntimeError("detector must be fit() before score()")
        entities = sorted({p.entity_id for p in frame.points})
        incidents: list[IncidentWindow] = []
        for entity_id in entities:
            windows = SlidingWindowMaker(self.window_ns, self.stride_ns).windows(frame)
            detected: list[tuple[int, int, dict[str, float], dict[str, str]]] = []
            for w_start, w_end, wframe in windows:
                win = self._score_window(entity_id, w_start, w_end, wframe)
                if win is None:
                    continue
                w_start_ns, w_end_ns, metric_scores, directions = win
                detected.append((w_start_ns, w_end_ns, metric_scores, directions))
            incidents.extend(self._merge(entity_id, detected))
        for inc in incidents:
            self._register(inc)
        return [i for i in incidents if not self._is_suppressed(i)]

    def _score_window(
        self, entity_id: str, w_start: int, w_end: int, wframe: TelemetryFrame
    ) -> tuple[int, int, dict[str, float], dict[str, str]] | None:
        assert self.normalizer is not None
        aligned = align_window(
            wframe, entity_id=entity_id, start_ns=w_start, end_ns=w_end,
            sample_interval_ns=self.sample_interval_ns,
        )
        per_metric: dict[str, float] = {}
        directions: dict[str, str] = {}
        for mi, metric_id in enumerate(aligned.metrics):
            if wframe.points and any(
                p.attrs.get("role") == DETECTOR_ROLE_STATE for p in wframe.points
                if p.metric_id == metric_id
            ):
                continue  # discrete state handled by the state branch only
            vals = [aligned.values[r][mi] for r in range(len(aligned.ts_ns))]
            obs = [aligned.observed_mask[r][mi] for r in range(len(aligned.ts_ns))]
            if not any(obs):
                continue
            stats = self.normalizer.per_metric.get((entity_id, metric_id))
            if stats is None:
                continue
            # EWMA smoothing of the signed robust residual over observed cells
            ewma: float | None = None
            for v, o in zip(vals, obs):
                if not o:
                    continue
                z = stats.robust_z(v)
                ewma = z if ewma is None else self.ewma_alpha * z + (1 - self.ewma_alpha) * ewma
            if ewma is None:
                continue
            thr = self._apply_adjustment(metric_id, self.thresholds.get((entity_id, metric_id), 4.0))
            if abs(ewma) > thr:
                per_metric[metric_id] = min(1.0, abs(ewma) / max(thr, 1e-9))
                directions[metric_id] = "up" if ewma > 0 else "down"
        missing_frac = 1.0 - _observed_fraction(aligned)
        if missing_frac > self.min_observed_frac:
            from ..data.window import real_mid_stream_gap

            if not real_mid_stream_gap(aligned):
                return None
            per_metric["_quality"] = missing_frac
            directions["_quality"] = "missing"
        if not per_metric:
            return None
        return (w_start, w_end, per_metric, directions)

    def _merge(
        self, entity_id: str, detected: list[tuple[int, int, dict[str, float], dict[str, str]]]
    ) -> list[IncidentWindow]:
        if not detected:
            return []
        detected.sort(key=lambda d: d[0])
        merged: list[IncidentWindow] = []
        cur_start, cur_end, cur_scores, cur_dirs = detected[0]
        for d in detected[1:]:
            ds, de, scores, dirs = d
            if ds <= cur_end:  # contiguous/overlapping windows merge
                cur_end = max(cur_end, de)
                for k, v in scores.items():
                    cur_scores[k] = max(cur_scores.get(k, 0.0), v)
                for k, v in dirs.items():
                    cur_dirs[k] = v if v != "down" or k not in cur_dirs else cur_dirs[k]
            else:
                merged.append(self._make_incident(entity_id, cur_start, cur_end, cur_scores, cur_dirs))
                cur_start, cur_end, cur_scores, cur_dirs = ds, de, scores, dirs
        merged.append(self._make_incident(entity_id, cur_start, cur_end, cur_scores, cur_dirs))
        return merged

    def _make_incident(
        self, entity_id: str, start: int, end: int,
        scores: dict[str, float], dirs: dict[str, str],
    ) -> IncidentWindow:
        severity = min(1.0, max(scores.values()) if scores else 0.0)
        metric_hint = max(scores, key=scores.get) if scores else "unknown"
        return IncidentWindow(
            incident_id=self.incident_id_for(start, end, entity_id, metric_hint),
            start_ts_ns=start,
            end_ts_ns=end,
            detected_at_ns=time.time_ns(),
            status="anomaly",
            severity=severity,
            metric_scores=scores,
            directions=dirs,
            model_version=self.model_version,
        )

    # -- feedback -----------------------------------------------------------

    def update(self, feedback: FeedbackEvent) -> ModelCard:
        return super().update(feedback)

    # -- metadata -----------------------------------------------------------

    def params(self) -> int:
        # median/MAD per metric + one threshold per metric
        return 4 * len(self.normalizer.per_metric) if self.normalizer else 0

    def architecture_name(self) -> str:
        return "median/MAD + EWMA(pot) signed-residual streaming"

    def _threshold_map(self) -> dict[str, float]:
        return {f"{e}::{m}": v for (e, m), v in self.thresholds.items()}

    def _state_snapshot(self) -> dict:
        return {
            "suppressed_incidents": len(self._suppressed),
            "adjustments": dict(self._threshold_adjustments),
        }


def _split_label(train: TelemetryFrame, validation: TelemetryFrame | None) -> str:
    if validation is not None and len(validation) > 0:
        return f"train({len(train)} pts) + validation({len(validation)} pts); thresholds from validation"
    return f"train({len(train)} pts); thresholds from train (no validation provided)"


def _observed_fraction(aligned) -> float:
    if not aligned.observed_mask:
        return 0.0
    tot = len(aligned.observed_mask) * max(1, len(aligned.observed_mask[0]))
    obs = sum(sum(row) for row in aligned.observed_mask)
    return obs / tot if tot else 1.0