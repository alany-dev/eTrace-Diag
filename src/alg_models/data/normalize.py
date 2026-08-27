"""Normalization utilities. Statistics are ALWAYS fit on train/validation data
only — a normalized value must never leak test-set statistics into the model."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np


@dataclass(frozen=True)
class MetricStats:
    """Per-metric robust statistics fit on a training split only."""

    median: float
    mad: float
    mean: float
    std: float
    count: int
    min_value: float
    max_value: float
    # fraction of the train split where this metric was missing/stale/etc.
    non_observed_frac: float = 0.0

    def robust_z(self, value):
        """Signed robust residual (scalar or ndarray). 0 for degenerate
        metrics (zero MAD)."""
        v = np.asarray(value, dtype=float)
        out = np.zeros_like(v)
        if self.mad <= 0.0:
            return float(out) if v.ndim == 0 else out
        mask = np.isfinite(v)
        out[mask] = (v[mask] - self.median) / (1.4826 * self.mad)
        if v.ndim == 0:
            return float(out)
        return out

    def z(self, value: float) -> float:
        if not np.isfinite(value):
            return 0.0
        if self.std <= 0.0:
            return 0.0
        return (float(value) - self.mean) / self.std

    def to_dict(self) -> dict[str, float]:
        return {
            "median": self.median,
            "mad": self.mad,
            "mean": self.mean,
            "std": self.std,
            "count": float(self.count),
            "min": self.min_value,
            "max": self.max_value,
            "non_observed_frac": self.non_observed_frac,
        }


@dataclass
class Normalizer:
    """Fits per-(entity, metric) stats and exposes them for scoring.

    Only observed points are used to fit statistics; imputed/missing/stale/
    out_of_order points are excluded from stats, matching the causal contract
    that unreliable points never shape learned parameters.
    """

    per_metric: dict[tuple[str, str], MetricStats] = field(default_factory=dict)

    def fit_frame(self, frame) -> "Normalizer":
        """frame: iterable of TelemetryPoint (observed only by caller)."""
        per: dict[tuple[str, str], list[float]] = {}
        non_observed: dict[tuple[str, str], int] = {}
        total: dict[tuple[str, str], int] = {}
        for p in frame:
            key = (p.entity_id, p.metric_id)
            total[key] = total.get(key, 0) + 1
            if p.quality != "observed" or p.value is None:
                non_observed[key] = non_observed.get(key, 0) + 1
                continue
            per.setdefault(key, []).append(float(p.value))
        for key, values in per.items():
            arr = np.asarray(values, dtype=float)
            med = float(np.median(arr))
            mad = float(np.median(np.abs(arr - med)))
            self.per_metric[key] = MetricStats(
                median=med,
                mad=mad,
                mean=float(arr.mean()),
                std=float(arr.std(ddof=0) if len(arr) > 1 else 0.0),
                count=len(arr),
                min_value=float(arr.min()),
                max_value=float(arr.max()),
                non_observed_frac=(
                    non_observed.get(key, 0) / total[key] if total.get(key, 0) else 0.0
                ),
            )
        return self

    def stats(self, entity_id: str, metric_id: str) -> MetricStats | None:
        return self.per_metric.get((entity_id, metric_id))

    def robust_z(self, entity_id: str, metric_id: str, value: float) -> float:
        st = self.per_metric.get((entity_id, metric_id))
        if st is None:
            return 0.0
        return st.robust_z(value)

    def serialize(self) -> dict:
        return {f"{e}::{m}": s.to_dict() for (e, m), s in self.per_metric.items()}

    @classmethod
    def deserialize(cls, data: dict) -> "Normalizer":
        n = cls()
        for key, d in data.items():
            e, m = key.split("::", 1)
            n.per_metric[(e, m)] = MetricStats(
                median=d["median"],
                mad=d["mad"],
                mean=d["mean"],
                std=d["std"],
                count=int(d["count"]),
                min_value=d["min"],
                max_value=d["max"],
                non_observed_frac=d.get("non_observed_frac", 0.0),
            )
        return n


def sigmoid_score(z: float, scale: float = 1.0) -> float:
    """Map a signed residual to [0, 1]."""

    def _s(x: float) -> float:
        if x >= 0:
            return 1.0 / (1.0 + math.exp(-x))
        return math.exp(x) / (1.0 + math.exp(x))

    return _s(scale * z)
