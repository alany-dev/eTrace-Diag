"""TimeRCDFuseDetector — live zero-shot detector (Time-RCD-Fuse).

Frozen Time-RCD checkpoint (``thu-sail-lab/Time-RCD``, Apache-2.0) scores a
(T,C) window zero-shot; two pure-numpy post-processing modules are applied in
order (identical math to the offline combo ``combo-fusion03-med5`` in
``experiments/baselines/time_rcd.py``, which is the evaluation source of
truth):

1. Robust-z cross-channel fusion (w=0.3):
   ``z_t = max_c |x_tc - med_c| / (1.4826 * max(MAD_c, 1e-8))`` with
   ``med_c``/``MAD_c`` fit on the train split only; ``z`` is truncated by
   ``q99(z_train)`` and fused ``s_t <- 0.7*s_t + 0.3*z_t``.
2. Median-k5 smoothing: ``s_t <- median(s_{t-2..t+2})`` (scipy median_filter,
   reflect edges).

Threshold 0.5 binarization (prior, no test labels involved). Channel stats
and q99 are recomputed per fit(); the checkpoint itself is never modified
(zero-shot, no per-task training). Requires the ``torch`` extra
(``time-rcd`` package + HF checkpoint; cached after first download).
"""

from __future__ import annotations

import time

import numpy as np

from ..schemas import FeedbackEvent, IncidentWindow, ModelCard, TelemetryFrame
from .base import BaseDetector, register_detector

_MODEL_VERSION = "0.1.0"
_MIN_ROWS = 16  # shorter windows cannot be scored (transformers context floor)


@register_detector("time_rcd_fuse")
class TimeRCDFuseDetector(BaseDetector):
    def __init__(
        self,
        *,
        checkpoint_path: str | None = None,
        variant: str = "multi",
        win_size: int = 5000,
        device: str | None = None,
        fuse_w: float = 0.3,
        threshold: float = 0.5,
        median_k: int = 5,
        window_ns: int = 60_000_000_000,
        stride_ns: int = 30_000_000_000,
    ):
        super().__init__(model_version=_MODEL_VERSION, model_name="TimeRCDFuseDetector")
        self.checkpoint_path = checkpoint_path
        self.time_rcd_variant = variant
        self.win_size = win_size
        self.device = device
        self.fuse_w = fuse_w
        self.threshold = threshold
        self.median_k = median_k
        self.window_ns = window_ns
        self.stride_ns = stride_ns
        self._det: object | None = None
        self._fit_done = False
        self._channels: list[tuple[str, str]] = []
        self._med: np.ndarray | None = None
        self._mad: np.ndarray | None = None
        self._q99: float = 0.0
        self._calibration_basis = ""

    # -- lifecycle ----------------------------------------------------------

    def _ensure_model(self) -> object:
        if self._det is None:
            from time_rcd import TimeRCDDetector

            if self.checkpoint_path:
                self._det = TimeRCDDetector.from_local(
                    self.checkpoint_path, variant=self.time_rcd_variant,
                    win_size=self.win_size, device=self.device,
                )
            else:
                self._det = TimeRCDDetector.from_pretrained(
                    variant=self.time_rcd_variant, win_size=self.win_size,
                    device=self.device,
                )
        return self._det

    def fit(
        self, train: TelemetryFrame, validation: TelemetryFrame | None, *, seed: int
    ) -> ModelCard:
        if len(train) == 0:
            raise ValueError("fit requires non-empty train frame")
        mat, ts, channels = self._frame_to_matrix(train)
        if mat.shape[0] < _MIN_ROWS:
            raise ValueError(
                f"train frame too short for Time-RCD-Fuse fit: {mat.shape[0]} rows < {_MIN_ROWS}"
            )
        self._channels = channels
        self._med = np.median(mat, axis=0)
        self._mad = np.median(np.abs(mat - self._med), axis=0)
        z_train = self._robust_z(mat)
        self._q99 = max(float(np.quantile(z_train, 0.99)), 1e-8)
        self._fit_done = True
        self._calibration_basis = "train-split" if validation is not None else "train-only"
        return self._card(
            params=0,  # frozen checkpoint: zero trainable parameters
            architecture=self.architecture_name(),
            thresholds=self._threshold_map(),
            state={"channels": len(self._channels), "q99": self._q99},
        )

    def _frame_to_matrix(
        self, frame: TelemetryFrame
    ) -> tuple[np.ndarray, np.ndarray, list[tuple[str, str]]]:
        """Pivot an observed frame into a (T,C) float matrix aligned on the
        sorted unique timestamps (ffill for missing ticks, 0 for never-seen
        values). Channel order = sorted (entity_id, metric_id)."""
        if self._channels:
            channels = list(self._channels)
        else:
            channels = sorted(
                {(p.entity_id, p.metric_id) for p in frame.points if p.quality == "observed"}
            )
        ts = np.array(sorted({p.ts_ns for p in frame.points}), dtype=np.int64)
        cols: dict[tuple[str, str], dict[int, float]] = {}
        for p in frame.points:
            if p.quality != "observed" or p.value is None:
                continue
            cols.setdefault((p.entity_id, p.metric_id), {})[p.ts_ns] = float(p.value)
        mat = np.full((len(ts), len(channels)), np.nan)
        for ci, ch in enumerate(channels):
            d = cols.get(ch, {})
            mat[:, ci] = [d.get(t, np.nan) for t in ts]
        mat = pd_ffill(mat)
        return np.nan_to_num(mat, nan=0.0), ts, channels

    def _robust_z(self, mat: np.ndarray) -> np.ndarray:
        denom = 1.4826 * np.maximum(self._mad, 1e-8)
        return np.max(np.abs(mat - self._med) / denom, axis=1)

    def score(
        self, frame: TelemetryFrame, *, state: TelemetryFrame | None = None
    ) -> list[IncidentWindow]:
        if not self._fit_done:
            raise RuntimeError("detector must be fit() before score()")
        self._ensure_model()
        mat, ts, _ = self._frame_to_matrix(frame)
        if mat.shape[0] < _MIN_ROWS:
            return []

        raw = np.asarray(self._det.predict(mat), dtype=np.float64)
        if raw.ndim == 2:  # some checkpoints emit (T,1)
            raw = raw.ravel()
        # robust-z fusion
        z_test = self._robust_z(mat)
        zn = np.minimum(1.0, z_test / self._q99)
        fused = (1.0 - self.fuse_w) * raw + self.fuse_w * zn
        # median-k5 smoothing
        from scipy.ndimage import median_filter

        smooth = median_filter(fused, size=self.median_k)
        return self._segments(smooth, ts, mat)

    def _segments(
        self, smooth: np.ndarray, ts: np.ndarray, mat: np.ndarray
    ) -> list[IncidentWindow]:
        flag = smooth > self.threshold
        if not flag.any():
            return []
        incidents: list[IncidentWindow] = []
        i = 0
        while i < len(flag):
            if not flag[i]:
                i += 1
                continue
            j = i
            while j + 1 < len(flag) and flag[j + 1]:
                j += 1
            peak = int(np.argmax(smooth[i : j + 1])) + i
            start_ns = int(ts[i])
            end_ns = int(ts[j])
            severity = float(min(1.0, smooth[peak]))
            # per-channel contribution at the peak tick (normalized to sum 1)
            denom = 1.4826 * np.maximum(self._mad, 1e-8)
            zc = np.abs(mat[peak] - self._med) / denom
            zsum = float(np.sum(zc)) or 1.0
            metric_scores = {
                metric_id: float(zc[k] / zsum)
                for k, (_, metric_id) in enumerate(self._channels)
                if zc[k] > 0
            }
            directions = {
                metric_id: ("up" if mat[peak, k] > self._med[k] else "down")
                for k, (_, metric_id) in enumerate(self._channels)
                if zc[k] > 0
            }
            inc = IncidentWindow(
                incident_id=self.incident_id_for(start_ns, end_ns, "host", "fuse"),
                start_ts_ns=start_ns,
                end_ts_ns=end_ns,
                detected_at_ns=int(ts[peak]),
                status="anomaly" if severity >= self.threshold + 0.1 else "uncertain",
                severity=severity,
                metric_scores=metric_scores,
                directions=directions,
                model_version=self.model_version,
            )
            self._register(inc)
            incidents.append(inc)
            i = j + 1
        return [inc for inc in incidents if not self._is_suppressed(inc)]

    # -- BaseDetector abstracts --------------------------------------------

    def params(self) -> int:
        return 0  # frozen checkpoint; no trainable parameters

    def architecture_name(self) -> str:
        return (
            f"Time-RCD-Fuse(checkpoint={self.time_rcd_variant}, w={self.fuse_w}, "
            f"median-k{self.median_k}, thr={self.threshold})"
        )

    def _threshold_map(self) -> dict[str, float]:
        return {
            "fuse_w": self.fuse_w,
            "threshold": self.threshold,
            "q99": self._q99,
        }

    def _state_snapshot(self) -> dict:
        return {
            "channels": len(self._channels),
            "median_k": self.median_k,
            "win_size": self.win_size,
            "calibration_basis": self._calibration_basis,
        }

    def update(self, feedback: FeedbackEvent) -> ModelCard:
        # zero-shot frozen model: feedback adjusts the binarization prior only
        if feedback.label in ("false_positive", "rejected"):
            self.threshold = min(0.95, self.threshold + 0.02)
        elif feedback.label == "true_positive":
            self.threshold = max(0.2, self.threshold - 0.01)
        return super().update(feedback)


def pd_ffill(mat: np.ndarray) -> np.ndarray:
    """Forward-fill NaN columns (pandas ffill semantics, no pandas needed)."""
    out = mat.copy()
    mask = np.isnan(out)
    idx = np.where(~mask, np.arange(mask.shape[0])[:, None], 0)
    np.maximum.accumulate(idx, axis=0, out=idx)
    return np.where(mask, out[idx, np.arange(mask.shape[1])[None, :]], out)
