"""EdgeCascadeDetector — cross-band evidence fusion with
uncertainty-triggered conditional computation (this project's innovation).

Architecture (per plan §3):
1. Resident event ring (robust streaming): median/MAD residual, change point,
   short-window band energy, missing/stale rate, detector confidence.
   Catches interrupts/futex/lock-wait/IO burst.
2. Frequency trend ring: shared FITS-style low-pass complex-linear
   reconstruction on `uncertain`/divergent/drift windows only (conditional
   computation — normal high-confidence windows never enter the learned
   branch).
3. Cross-scale consistency gate: both rings agreeing raises confidence; a
   single-ring trigger yields `uncertain`/lower severity — never a forced
   binary decision.
4. State-conditioning branch: discrete state metrics encoded separately
   (STAR-style state/variable identity + per-state memory); missing state
   keeps the numeric branch and records `state_unobserved` (never state=0).
5. Feedback calibration: update() adjusts thresholds, prototype memory, and
   suppression; rejected/conflicting/nonexistent feedback raises
   `FeedbackError` and leaves the model unchanged.
"""

from __future__ import annotations

import time

import numpy as np

from ..data.normalize import Normalizer
from ..data.window import SlidingWindowMaker, align_window, real_mid_stream_gap
from ..schemas import FeedbackEvent, IncidentWindow, ModelCard, TelemetryFrame
from .base import BaseDetector, DETECTOR_ROLE_STATE, register_detector
from .event_branch import EventRing, RingOutput
from .fits_adapter import _MetricFreqModel


@register_detector("edge_cascade")
class EdgeCascadeDetector(BaseDetector):
    def __init__(
        self,
        *,
        window_ns: int = 60_000_000_000,
        stride_ns: int = 30_000_000_000,
        low_freq: int = 6,
        n_fft: int = 64,
        event_pot_quantile: float = 0.99,
        event_pot_multiplier: float = 1.5,
        trend_pot_quantile: float = 0.99,
        trend_pot_multiplier: float = 1.5,
        confidence_threshold: float = 0.6,
        max_missing_frac: float = 0.5,
        drift_residual_z: float = 1.5,
    ):
        super().__init__(model_version="0.4.0", model_name="EdgeCascadeDetector")
        self.window_ns = window_ns
        self.stride_ns = stride_ns
        self.low_freq = low_freq
        self.n_fft = n_fft
        self.event_pot_quantile = event_pot_quantile
        self.event_pot_multiplier = event_pot_multiplier
        self.trend_pot_quantile = trend_pot_quantile
        self.trend_pot_multiplier = trend_pot_multiplier
        self.confidence_threshold = confidence_threshold
        self.max_missing_frac = max_missing_frac
        self.drift_residual_z = drift_residual_z

        self.normalizer: Normalizer | None = None
        self.event_thresholds: dict[tuple[str, str], float] = {}
        self.trend_models: dict[tuple[str, str], _MetricFreqModel] = {}
        self.trend_thresholds: dict[tuple[str, str], float] = {}
        self.sample_interval_ns: int = 10_000_000_000
        self._param_count = 0
        self._fit_done = False
        self._gate_stats = {"windows": 0, "trend_run": 0, "state_seen": 0}
        # STAR-style per-state memory: {(entity, metric): {state: (median, mad)}}
        self._state_memory: dict[tuple[str, str], dict[int, tuple[float, float]]] = {}

    # -- lifecycle ----------------------------------------------------------

    def fit(self, train: TelemetryFrame, validation: TelemetryFrame | None, *, seed: int) -> ModelCard:
        if len(train) == 0:
            raise ValueError("fit requires non-empty train frame")
        self.normalizer = Normalizer().fit_frame(train)
        ts = sorted({p.ts_ns for p in train.points})
        gaps = [b - a for a, b in zip(ts, ts[1:]) if b > a]
        if gaps:
            from collections import Counter

            self.sample_interval_ns = Counter(gaps).most_common(1)[0][0]

        # --- event ring thresholds (validation-calibrated) ---
        cal = validation if validation is not None and len(validation) > 0 else train
        for (e, m), stats in self.normalizer.per_metric.items():
            if stats.mad <= 0.0:
                self.event_thresholds[(e, m)] = 1.5
                continue
            zs = [
                stats.robust_z(float(p.value))
                for p in cal.points
                if p.entity_id == e and p.metric_id == m and p.value is not None
                and p.quality == "observed"
            ]
            if not zs:
                self.event_thresholds[(e, m)] = 4.0
                continue
            q = float(np.quantile([abs(z) for z in zs], self.event_pot_quantile))
            self.event_thresholds[(e, m)] = max(1.5, q * self.event_pot_multiplier)

        # --- trend ring (FITS-style) fit + thresholds ---
        per_metric_windows: dict[tuple[str, str], list[np.ndarray]] = {}
        for w_start, w_end, wframe in SlidingWindowMaker(self.window_ns, self.stride_ns).windows(train):
            for entity_id in {p.entity_id for p in wframe.points}:
                aligned = align_window(
                    wframe, entity_id=entity_id, start_ns=w_start, end_ns=w_end,
                    sample_interval_ns=self.sample_interval_ns,
                )
                for mi, metric_id in enumerate(aligned.metrics):
                    vals = [aligned.values[r][mi] for r in range(len(aligned.ts_ns))]
                    obs = [aligned.observed_mask[r][mi] for r in range(len(aligned.ts_ns))]
                    arr = np.asarray([v for v, o in zip(vals, obs) if o and np.isfinite(v)])
                    if arr.size >= self.low_freq + 4:
                        per_metric_windows.setdefault((entity_id, metric_id), []).append(arr)
        for (e, m), wins in per_metric_windows.items():
            allvals = np.concatenate(wins)
            med = float(np.median(allvals))
            mads = float(np.median(np.abs(allvals - med))) or 1.0
            model = _MetricFreqModel(e, m, self.low_freq, self.n_fft, med, mads)
            model.fit(wins)
            if model.W is not None:
                self.trend_models[(e, m)] = model
        self._param_count = sum(m.params for m in self.trend_models.values()) + 4 * len(
            self.normalizer.per_metric
        )

        for (e, m), model in self.trend_models.items():
            zs: list[float] = []
            for w_start, w_end, wframe in SlidingWindowMaker(self.window_ns, self.stride_ns).windows(cal):
                aligned = align_window(
                    wframe, entity_id=e, start_ns=w_start, end_ns=w_end,
                    sample_interval_ns=self.sample_interval_ns,
                )
                if m not in aligned.metrics:
                    continue
                mi = aligned.metrics.index(m)
                vals = [aligned.values[r][mi] for r in range(len(aligned.ts_ns))]
                obs = [aligned.observed_mask[r][mi] for r in range(len(aligned.ts_ns))]
                arr = np.asarray([v for v, o in zip(vals, obs) if o and np.isfinite(v)])
                if arr.size >= self.low_freq + 4:
                    zs.append(model.score(arr))
            if zs:
                q = float(np.quantile(zs, self.trend_pot_quantile))
                self.trend_thresholds[(e, m)] = max(0.5, q * self.trend_pot_multiplier + 1e-6)
            else:
                self.trend_thresholds[(e, m)] = 2.0

        # --- per-state memory from train (state metrics only) ---
        self._state_memory = _fit_state_memory(train, self.sample_interval_ns)

        self.calibration_basis = (
            f"train({len(train)} pts) + validation({len(validation)} pts); "
            "event thresholds + trend thresholds from validation, "
            "FITS complex-linear fit + state memory from train"
            if validation is not None
            else f"train({len(train)} pts); all calibration from train"
        )
        self._fit_done = True
        return self._card(
            params=self._param_count,
            architecture=self.architecture_name(),
            thresholds=self._threshold_map(),
            state={
                "gate_stats": dict(self._gate_stats),
                "n_trend_models": len(self.trend_models),
                "n_state_memory": len(self._state_memory),
            },
        )

    # -- scoring ------------------------------------------------------------

    def score(self, frame: TelemetryFrame, *, state: TelemetryFrame | None = None) -> list[IncidentWindow]:
        if not self._fit_done or self.normalizer is None:
            raise RuntimeError("detector must be fit() before score()")
        state_pts = {p.entity_id: p for p in state.points} if state else {}
        entities = sorted({p.entity_id for p in frame.points})
        incidents: list[IncidentWindow] = []
        for entity_id in entities:
            detected: list[tuple[int, int, dict[str, float], dict[str, str], str]] = []
            for w_start, w_end, wframe in SlidingWindowMaker(
                self.window_ns, self.stride_ns
            ).windows(frame):
                self._gate_stats["windows"] += 1
                win = self._score_window(entity_id, w_start, w_end, wframe, state_pts.get(entity_id))
                if win is not None:
                    detected.append(win)
            incidents.extend(self._merge_detected(entity_id, detected))
        for inc in incidents:
            self._register(inc)
        return [i for i in incidents if not self._is_suppressed(i)]

    def _score_window(
        self, entity_id: str, w_start: int, w_end: int, wframe: TelemetryFrame,
        state_point,
    ) -> tuple[int, int, dict[str, float], dict[str, str], str] | None:
        assert self.normalizer is not None
        aligned = align_window(
            wframe, entity_id=entity_id, start_ns=w_start, end_ns=w_end,
            sample_interval_ns=self.sample_interval_ns,
        )
        if len(aligned.ts_ns) == 0:
            return None

        # split metrics: numeric vs discrete-state -- restricted to the metrics
        # actually present for THIS entity (wframe contains points of every
        # entity in the time range; other entities' metrics would pollute the
        # observed-fraction accounting).
        numeric_metrics = []
        state_metrics = []
        for p in wframe.points:
            if p.entity_id != entity_id:
                continue
            if p.metric_id in state_metrics or p.metric_id in numeric_metrics:
                continue
            if p.attrs.get("role") == DETECTOR_ROLE_STATE:
                state_metrics.append(p.metric_id)
            else:
                numeric_metrics.append(p.metric_id)

        # --- event ring on numeric metrics ---
        ring = EventRing(min_observed_frac=self.max_missing_frac)
        vals = np.asarray(
            [
                [aligned.values[r][aligned.metrics.index(m)] if m in aligned.metrics else float("nan")
                 for m in numeric_metrics]
                for r in range(len(aligned.ts_ns))
            ],
            dtype=float,
        )
        mask = np.asarray(
            [
                [aligned.observed_mask[r][aligned.metrics.index(m)] if m in aligned.metrics else False
                 for m in numeric_metrics]
                for r in range(len(aligned.ts_ns))
            ],
            dtype=bool,
        )
        if vals.size == 0:
            vals = np.zeros((len(aligned.ts_ns), 0))
            mask = np.zeros((len(aligned.ts_ns), 0), dtype=bool)
        stats_map = {m: self.normalizer.per_metric.get((entity_id, m)) for m in numeric_metrics}
        ring_out: RingOutput = ring.evaluate(
            vals, mask, per_metric_stats=stats_map, entity_id=entity_id,
            metric_ids=numeric_metrics,
        )

        # per-metric event residual scores + direction
        event_scores: dict[str, float] = {}
        event_dirs: dict[str, str] = {}
        for mi, m in enumerate(numeric_metrics):
            st = stats_map.get(m)
            if st is None:
                continue
            thr = self._apply_adjustment(m, self.event_thresholds.get((entity_id, m), 4.0))
            cells = [aligned.values[r][aligned.metrics.index(m)] for r in range(len(aligned.ts_ns))]
            obs = [aligned.observed_mask[r][aligned.metrics.index(m)] for r in range(len(aligned.ts_ns))]
            arr = np.asarray([v for v, o in zip(cells, obs) if o and np.isfinite(v)])
            if arr.size == 0:
                event_scores["_quality"] = 1.0
                event_dirs["_quality"] = "missing"
                continue
            z = st.robust_z(float(arr[-1])) if arr.size else 0.0
            # window-level: max |z|
            zs = st.robust_z(arr)
            zmax = float(np.max(np.abs(zs)))
            if zmax > thr:
                event_scores[m] = min(1.0, zmax / max(thr, 1e-9))
                mean_val = float(arr.mean())
                event_dirs[m] = "up" if mean_val > st.median else "down"

        missing_frac = ring_out.missing_frac
        if missing_frac > self.max_missing_frac:
            # A real mid-stream gap (observed before AND after the hole) is a
            # quality incident; a truncated data boundary (frame ends inside
            # this window) is a scoring artifact and must be skipped.
            if real_mid_stream_gap(aligned):
                event_scores["_quality"] = min(1.0, missing_frac)
                event_dirs["_quality"] = "missing"
            else:
                return None

        event_trigger = bool(event_scores) and "_quality" not in event_scores
        quality_trigger = "_quality" in event_scores
        drift_trigger = ring_out.mean_residual_z > self.drift_residual_z and not event_trigger

        # --- conditional computation: the trend ring runs only when the event
        # ring triggers (cross-scale confirmation), is uncertain (low
        # confidence), sees drift, or sees a quality gap. Quiet high-confidence
        # windows never enter the learned branch.
        trend_scores: dict[str, float] = {}
        trend_dirs: dict[str, str] = {}
        need_trend = (
            event_trigger
            or ring_out.confidence < self.confidence_threshold
            or drift_trigger
            or quality_trigger
        )
        if need_trend:
            self._gate_stats["trend_run"] += 1
            trend_ran = True
            for m in numeric_metrics:
                model = self.trend_models.get((entity_id, m))
                if model is None:
                    continue
                cells = [aligned.values[r][aligned.metrics.index(m)] for r in range(len(aligned.ts_ns))]
                obs = [aligned.observed_mask[r][aligned.metrics.index(m)] for r in range(len(aligned.ts_ns))]
                arr = np.asarray([v for v, o in zip(cells, obs) if o and np.isfinite(v)])
                if arr.size < self.low_freq + 4:
                    continue
                score = model.score(arr)
                thr = self._apply_adjustment(m, self.trend_thresholds.get((entity_id, m), 2.0))
                if score > thr:
                    trend_scores[m] = min(1.0, score / max(thr, 1e-9))
                    trend_dirs[m] = "up" if float(arr.mean()) > model.median else "down"

        # --- cross-scale consistency gate ---
        strong: dict[str, float] = {}
        strong_dirs: dict[str, str] = {}
        uncertain_metrics: dict[str, float] = {}
        for m in numeric_metrics:
            e_s = event_scores.get(m)
            t_s = trend_scores.get(m)
            if e_s is not None and t_s is not None:
                # both rings triggered this metric — agree on direction?
                same_dir = event_dirs.get(m) == trend_dirs.get(m)
                if same_dir:
                    strong[m] = max(e_s, t_s)
                    strong_dirs[m] = event_dirs[m]
                else:
                    uncertain_metrics[m] = max(e_s, t_s)
            elif e_s is not None or t_s is not None:
                uncertain_metrics[m] = e_s if e_s is not None else t_s

        status = "normal"
        metric_scores: dict[str, float] = {}
        directions: dict[str, str] = {}
        if strong:
            # cross-confirmed metrics carry the anomaly; single-ring metrics
            # are kept as uncertain contributions (never silently dropped).
            metric_scores = {**dict(uncertain_metrics), **dict(strong)}
            directions = {**{m: event_dirs.get(m) or trend_dirs.get(m) or "mixed"
                             for m in uncertain_metrics}, **dict(strong_dirs)}
            if quality_trigger:
                metric_scores["_quality"] = event_scores.get("_quality", 1.0)
                directions["_quality"] = "missing"
            status = "anomaly"
        elif quality_trigger:
            metric_scores = {"_quality": event_scores.get("_quality", 1.0)}
            directions = {"_quality": "missing"}
            status = "uncertain"
        elif uncertain_metrics:
            metric_scores = dict(uncertain_metrics)
            for m, v in uncertain_metrics.items():
                directions[m] = event_dirs.get(m) or trend_dirs.get(m) or "mixed"
            status = "uncertain"
        else:
            return None

        # --- state-conditioning branch ---
        state_note = None
        if state_metrics:
            self._gate_stats["state_seen"] += 1
            state_note = self._state_branch(
                entity_id, w_start, w_end, wframe, state_metrics, aligned, state_point,
                metric_scores, directions,
            )
            if state_note == "state_unobserved":
                # keep numeric branch; limitation recorded at incident level
                state_note = None

        severity = min(1.0, max(metric_scores.values()) if metric_scores else 0.0)
        if status == "uncertain":
            severity *= 0.6
        return (w_start, w_end, metric_scores, directions, status)

    def _state_branch(self, entity_id, w_start, w_end, wframe, state_metrics,
                      aligned, state_point, metric_scores, directions) -> str | None:
        """STAR-style state identity: discrete state metrics encoded separately.

        Returns "state_unobserved" if a state metric is missing in this window;
        None otherwise. If a known state's historical normal range covers the
        window's numeric deviation, suppress (down-weight) the score; an
        unknown state id yields `state_unobserved` limitation without zeroing.
        """
        if state_point is None:
            return "state_unobserved"
        suppressed = False
        for m in state_metrics:
            if m not in aligned.metrics:
                return "state_unobserved"
            mi = aligned.metrics.index(m)
            cells = [aligned.values[r][mi] for r in range(len(aligned.ts_ns))]
            obs = [aligned.observed_mask[r][mi] for r in range(len(aligned.ts_ns))]
            arr = np.asarray([v for v, o in zip(cells, obs) if o and np.isfinite(v)])
            if arr.size == 0:
                return "state_unobserved"
            state_id = int(round(float(arr[-1])))
            mem = self._state_memory.get((entity_id, m))
            if mem is None or state_id not in mem:
                return "state_unobserved"
            med, mad = mem[state_id]
            # if the window's deviation matches the state's normal band, suppress
            for k, v in list(metric_scores.items()):
                if k in ("_quality",):
                    continue
                st = self.normalizer.per_metric.get((entity_id, k))
                if st is None:
                    continue
                cells2 = [
                    aligned.values[r][aligned.metrics.index(k)] for r in range(len(aligned.ts_ns))
                ]
                obs2 = [aligned.observed_mask[r][aligned.metrics.index(k)] for r in range(len(aligned.ts_ns))]
                arr2 = np.asarray([v2 for v2, o2 in zip(cells2, obs2) if o2 and np.isfinite(v2)])
                if arr2.size == 0:
                    continue
                if abs(float(arr2[-1]) - med) <= 2.0 * (mad + 1e-9):
                    metric_scores[k] *= 0.5
                    suppressed = True
        return None

    def _merge_detected(self, entity_id, detected):
        if not detected:
            return []
        detected.sort(key=lambda d: d[0])
        out: list[IncidentWindow] = []
        cur_start, cur_end, cur_scores, cur_dirs, cur_status = detected[0]
        for ds, de, scores, dirs, status in detected[1:]:
            if ds <= cur_end:
                cur_end = max(cur_end, de)
                for k, v in scores.items():
                    cur_scores[k] = max(cur_scores.get(k, 0.0), v)
                for k, v in dirs.items():
                    cur_dirs[k] = v if k not in cur_dirs else cur_dirs[k]
                if status == "anomaly" and cur_status != "anomaly":
                    cur_status = "anomaly"
            else:
                out.append(self._make_incident(entity_id, cur_start, cur_end, cur_scores, cur_dirs, cur_status))
                cur_start, cur_end, cur_scores, cur_dirs, cur_status = ds, de, scores, dirs, status
        out.append(self._make_incident(entity_id, cur_start, cur_end, cur_scores, cur_dirs, cur_status))
        return out

    def _make_incident(self, entity_id, start, end, scores, dirs, status) -> IncidentWindow:
        severity = min(1.0, max(scores.values()) if scores else 0.0)
        if status == "uncertain":
            severity *= 0.6
        metric_hint = max(scores, key=scores.get) if scores else "unknown"
        return IncidentWindow(
            incident_id=self.incident_id_for(start, end, entity_id, metric_hint),
            start_ts_ns=start,
            end_ts_ns=end,
            detected_at_ns=time.time_ns(),
            status=status,
            severity=severity,
            metric_scores=scores,
            directions=dirs,
            model_version=self.model_version,
        )

    def update(self, feedback: FeedbackEvent) -> ModelCard:
        return super().update(feedback)

    def params(self) -> int:
        return self._param_count

    def architecture_name(self) -> str:
        return (
            "event ring (median/MAD+CUSUM+band energy) → uncertainty gate → "
            "FITS-style trend ring → cross-scale consistency gate → state branch"
        )

    def _threshold_map(self) -> dict[str, float]:
        return {
            **{f"event::{e}::{m}": v for (e, m), v in self.event_thresholds.items()},
            **{f"trend::{e}::{m}": v for (e, m), v in self.trend_thresholds.items()},
        }

    def _state_snapshot(self) -> dict:
        return {
            "suppressed_incidents": len(self._suppressed),
            "adjustments": dict(self._threshold_adjustments),
            "gate_stats": dict(self._gate_stats),
        }


def _fit_state_memory(train: TelemetryFrame, sample_interval_ns: int) -> dict[tuple[str, str], dict[int, tuple[float, float]]]:
    """Per-(entity, state-metric) → {state_id: (median, mad)} of the state value
    over train windows, used by the STAR-style state-conditioning branch."""
    mem: dict[tuple[str, str], dict[int, list[float]]] = {}
    for p in train.points:
        if p.attrs.get("role") != DETECTOR_ROLE_STATE or p.value is None:
            continue
        try:
            state_id = int(round(float(p.value)))
        except (TypeError, ValueError):
            continue
        mem.setdefault((p.entity_id, p.metric_id), {}).setdefault(state_id, []).append(state_id)
    out: dict[tuple[str, str], dict[int, tuple[float, float]]] = {}
    for key, states in mem.items():
        for sid, vals in states.items():
            arr = np.asarray(vals, dtype=float)
            med = float(np.median(arr))
            mad = float(np.median(np.abs(arr - med)))
            out.setdefault(key, {})[sid] = (med, mad)
    return out
