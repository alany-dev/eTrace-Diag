"""FITSDetector — numpy adapter of the FITS frequency-domain linear
reconstruction (arXiv:2307.03756).

FITS properties: rFFT → keep low-frequency coefficients → learn a complex
linear map from low- to high-frequency coefficients → iFFT reconstruction.
The reconstruction residual is the anomaly score. This numpy adapter is a
faithful reproduction of the *operation* (low-pass + complex linear
interpolation in the frequency domain + time-domain reconstruction) with a
least-squares-complex fit on train windows; parameter count is deliberately
tiny (~2*(H*L+H) real params per metric). The low-pass structure alone cannot
carry high-frequency anomaly detection — that is why the edge runtime pairs
this with the event branch (see edge_cascade.py).

`Real_FITS`/ONNX is an optional backend only after license/dependency
confirmation; third-party test numbers are never reported as this project's
results.
"""

from __future__ import annotations

import time

import numpy as np

from ..data.window import SlidingWindowMaker, align_window
from ..schemas import FeedbackEvent, IncidentWindow, ModelCard, TelemetryFrame
from .base import BaseDetector, register_detector



def _nfft_for(x_size: int, base_fft: int) -> int:
    """FFT length covering at least x_size samples (pow2 >= base_fft)."""
    n = max(base_fft, 1)
    while n < x_size:
        n *= 2
    return n


def _fit_complex_linear(low: np.ndarray, high: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Solve high ≈ W @ low + b over complex data via real linear least squares.

    Args:
        low: (N, L) complex
        high: (N, H) complex
    Returns:
        W: (H, L) complex, b: (H,) complex
    """
    N, L = low.shape
    H = high.shape[1]
    # real design matrix: [Re(low), Im(low), 1] -> (N, 2L+1)
    X = np.column_stack([low.real, low.imag, np.ones(N)])
    Y = np.column_stack([high.real, high.imag])  # (N, 2H)
    coef, *_ = np.linalg.lstsq(X, Y, rcond=None)  # (2L+1, 2H)
    Wr = coef[:L, :H].T  # (H, L)
    Wi = coef[L : 2 * L, :H].T  # (H, L)
    br = coef[2 * L, :H]
    bi = coef[2 * L, H:]
    W = Wr + 1j * Wi
    b = br + 1j * bi
    return W, b


def _pred_high(low: np.ndarray, W: np.ndarray, b: np.ndarray) -> np.ndarray:
    return low @ W.T + b


class _MetricFreqModel:
    def __init__(self, entity_id: str, metric_id: str, low_freq: int, n_fft: int, median: float, mad: float):
        self.entity_id = entity_id
        self.metric_id = metric_id
        self.low_freq = low_freq
        self.n_fft = n_fft
        self.median = median
        self.mad = mad
        self.W: np.ndarray | None = None
        self.b: np.ndarray | None = None
        self.resid_median = 0.0
        self.resid_mad = 1.0
        self.params = 0

    def fit(self, windows: list[np.ndarray]) -> None:
        """windows: list of observed-aligned 1-D arrays (same length, >= low_freq*2)."""
        lows: list[np.ndarray] = []
        highs: list[np.ndarray] = []
        residuals: list[float] = []
        fixed_n: int | None = None
        for x in windows:
            if x.size < self.low_freq + 4:
                continue
            n = _nfft_for(x.size, self.n_fft)
            if fixed_n is None:
                fixed_n = n
            elif n != fixed_n:
                continue  # keep the frequency grid consistent across windows
            X = np.fft.rfft(x, n=n)
            low = X[: self.low_freq]
            high = X[self.low_freq :]
            if high.size == 0 or low.size == 0:
                continue
            lows.append(low)
            highs.append(high)
            x_hat = np.fft.irfft(np.concatenate([low, np.zeros(high.size, dtype=complex)]), n=n)[: x.size]
            residuals.append(float(np.std(x - x_hat)))
        if len(lows) < 2:
            return
        W, b = _fit_complex_linear(np.asarray(lows), np.asarray(highs))
        self.W, self.b = W, b
        self.params = int(2 * (W.size + b.size))
        # residual stats over held training windows
        train_resid: list[float] = []
        for x in windows:
            if x.size < self.low_freq + 4:
                continue
            n = _nfft_for(x.size, self.n_fft)
            X = np.fft.rfft(x, n=n)
            x_hat = np.fft.irfft(
                np.concatenate([X[: self.low_freq], _pred_high(X[: self.low_freq], W, b)]),
                n=n,
            )[: x.size]
            train_resid.append(float(np.std(x - x_hat)))
        if train_resid:
            self.resid_median = float(np.median(train_resid))
            self.resid_mad = float(np.median(np.abs(np.asarray(train_resid) - self.resid_median))) or 1.0

    def score(self, x: np.ndarray) -> float:
        if self.W is None or x.size < self.low_freq + 4:
            return 0.0
        n = _nfft_for(x.size, self.n_fft)
        X = np.fft.rfft(x, n=n)
        x_hat = np.fft.irfft(
            np.concatenate([X[: self.low_freq], _pred_high(X[: self.low_freq], self.W, self.b)]),
            n=n,
        )[: x.size]
        resid = float(np.std(x - x_hat))
        z = (resid - self.resid_median) / (1.4826 * self.resid_mad + 1e-9)
        return max(0.0, z)


@register_detector("fits")
class FITSDetector(BaseDetector):
    def __init__(self, *, window_ns: int = 60_000_000_000, stride_ns: int = 30_000_000_000,
                 low_freq: int = 6, n_fft: int = 64, pot_quantile: float = 0.99,
                 pot_multiplier: float = 1.5, min_observed_frac: float = 0.5):
        super().__init__(model_version="0.3.0", model_name="FITSDetector")
        self.window_ns = window_ns
        self.stride_ns = stride_ns
        self.low_freq = low_freq
        self.n_fft = n_fft
        self.pot_quantile = pot_quantile
        self.pot_multiplier = pot_multiplier
        self.min_observed_frac = min_observed_frac
        self.models: dict[tuple[str, str], _MetricFreqModel] = {}
        self.thresholds: dict[tuple[str, str], float] = {}
        self.sample_interval_ns: int = 10_000_000_000
        self._param_count = 0
        self._fit_done = False

    def fit(self, train: TelemetryFrame, validation: TelemetryFrame | None, *, seed: int) -> ModelCard:
        rng = np.random.default_rng(seed)
        entities = sorted({p.entity_id for p in train.points})
        ts = sorted({p.ts_ns for p in train.points})
        gaps = [b - a for a, b in zip(ts, ts[1:]) if b > a]
        if gaps:
            from collections import Counter

            self.sample_interval_ns = Counter(gaps).most_common(1)[0][0]
        for entity_id in entities:
            win_maker = SlidingWindowMaker(self.window_ns, self.stride_ns)
            ws = win_maker.windows(train)
            per_metric_windows: dict[tuple[str, str], list[np.ndarray]] = {}
            medians: dict[tuple[str, str], float] = {}
            for w_start, w_end, wframe in ws:
                aligned = align_window(
                    wframe, entity_id=entity_id, start_ns=w_start, end_ns=w_end,
                    sample_interval_ns=self.sample_interval_ns,
                )
                for mi, metric_id in enumerate(aligned.metrics):
                    vals = np.asarray([aligned.values[r][mi] for r in range(len(aligned.ts_ns))])
                    mask = np.asarray([aligned.observed_mask[r][mi] for r in range(len(aligned.ts_ns))])
                    if not mask.any() or vals[mask].size < self.low_freq + 4:
                        continue
                    x = vals[mask]
                    per_metric_windows.setdefault((entity_id, metric_id), []).append(x)
                    meds = medians.setdefault((entity_id, metric_id), []) if False else medians
            # fit per metric
            for (e, m), wins in per_metric_windows.items():
                allvals = np.concatenate(wins) if wins else np.array([])
                med = float(np.median(allvals)) if allvals.size else 0.0
                mads = float(np.median(np.abs(allvals - med))) if allvals.size else 0.0
                model = _MetricFreqModel(e, m, self.low_freq, self.n_fft, med, mads or 1.0)
                model.fit(wins)
                if model.W is not None:
                    self.models[(e, m)] = model
        self._param_count = sum(m.params for m in self.models.values())
        # thresholds from validation (or train) — never test
        cal = validation if validation is not None and len(validation) > 0 else train
        for (e, m), model in self.models.items():
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
                q = float(np.quantile(zs, self.pot_quantile))
                self.thresholds[(e, m)] = max(0.5, q * self.pot_multiplier + 1e-6)
            else:
                self.thresholds[(e, m)] = 2.0
        self.calibration_basis = (
            f"train({len(train)} pts) + validation({len(validation)} pts); "
            "FITS complex-linear fit on train, thresholds from validation"
            if validation is not None
            else f"train({len(train)} pts); FITS fit+thresholds from train"
        )
        self._fit_done = True
        return self._card(
            params=self._param_count,
            architecture=self.architecture_name(),
            thresholds=self._threshold_map(),
            state={"low_freq": self.low_freq, "n_fft": self.n_fft,
                   "per_metric_params": {f"{e}::{m}": mo.params for (e, m), mo in self.models.items()}},
        )

    def score(self, frame: TelemetryFrame, *, state: TelemetryFrame | None = None) -> list[IncidentWindow]:
        if not self._fit_done:
            raise RuntimeError("detector must be fit() before score()")
        incidents: list[IncidentWindow] = []
        entities = sorted({p.entity_id for p in frame.points})
        for entity_id in entities:
            detected: list[tuple[int, int, dict[str, float], dict[str, str]]] = []
            for w_start, w_end, wframe in SlidingWindowMaker(
                self.window_ns, self.stride_ns
            ).windows(frame):
                aligned = align_window(
                    wframe, entity_id=entity_id, start_ns=w_start, end_ns=w_end,
                    sample_interval_ns=self.sample_interval_ns,
                )
                scores: dict[str, float] = {}
                dirs: dict[str, str] = {}
                for mi, metric_id in enumerate(aligned.metrics):
                    model = self.models.get((entity_id, metric_id))
                    if model is None:
                        continue
                    vals = [aligned.values[r][mi] for r in range(len(aligned.ts_ns))]
                    obs = [aligned.observed_mask[r][mi] for r in range(len(aligned.ts_ns))]
                    arr = np.asarray([v for v, o in zip(vals, obs) if o and np.isfinite(v)])
                    if arr.size < self.low_freq + 4:
                        if arr.size == 0:
                            scores["_quality"] = 1.0
                            dirs["_quality"] = "missing"
                        continue
                    score = model.score(arr)
                    thr = self._apply_adjustment(metric_id, self.thresholds.get((entity_id, metric_id), 2.0))
                    if score > thr:
                        scores[metric_id] = min(1.0, score / max(thr, 1e-9))
                        mean_val = float(arr.mean())
                        dirs[metric_id] = "up" if mean_val > model.median else "down"
                if scores:
                    detected.append((w_start, w_end, scores, dirs))
            incidents.extend(self._merge_detected(entity_id, detected))
        for inc in incidents:
            self._register(inc)
        return [i for i in incidents if not self._is_suppressed(i)]

    def _merge_detected(
        self, entity_id: str, detected: list[tuple[int, int, dict[str, float], dict[str, str]]]
    ) -> list[IncidentWindow]:
        if not detected:
            return []
        detected.sort(key=lambda d: d[0])
        out: list[IncidentWindow] = []
        cur_start, cur_end, cur_scores, cur_dirs = detected[0]
        for ds, de, scores, dirs in detected[1:]:
            if ds <= cur_end:
                cur_end = max(cur_end, de)
                for k, v in scores.items():
                    cur_scores[k] = max(cur_scores.get(k, 0.0), v)
                for k, v in dirs.items():
                    cur_dirs[k] = v if k not in cur_dirs else cur_dirs[k]
            else:
                out.append(self._make_incident(entity_id, cur_start, cur_end, cur_scores, cur_dirs))
                cur_start, cur_end, cur_scores, cur_dirs = ds, de, scores, dirs
        out.append(self._make_incident(entity_id, cur_start, cur_end, cur_scores, cur_dirs))
        return out

    def _make_incident(self, entity_id, start, end, scores, dirs) -> IncidentWindow:
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

    def update(self, feedback: FeedbackEvent) -> ModelCard:
        return super().update(feedback)

    def params(self) -> int:
        return self._param_count

    def architecture_name(self) -> str:
        return "FITS-style rFFT/low-pass/complex-linear-interpolation reconstruction"

    def _threshold_map(self) -> dict[str, float]:
        return {f"{e}::{m}": v for (e, m), v in self.thresholds.items()}

    def _state_snapshot(self) -> dict:
        return {"suppressed_incidents": len(self._suppressed),
                "adjustments": dict(self._threshold_adjustments)}