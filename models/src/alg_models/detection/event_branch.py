"""Event ring — lightweight robust streaming branch for high-frequency anomalies.

Calculates per-window: median/MAD residual, change point (CUSUM/first
difference), short-window band energy (variance of high-pass filtered signal),
missing/stale rate, and detector confidence. These detect interrupts,
futex/lock-wait, IO burst, and other high-frequency events that the FITS
low-pass trend ring would miss.

The event ring is the resident loop of `EdgeCascadeDetector`; it runs on every
window and gates the more expensive trend ring via `RingDecision` confidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

import numpy as np

from ..data.normalize import MetricStats


@dataclass
class RingOutput:
    """Result of the event ring for one window × one set of metrics."""

    max_residual_z: float  # max absolute signed robust z across metrics
    mean_residual_z: float
    max_change_point: float  # max change-point score across metrics
    max_band_energy: float  # max short-window high-pass energy
    missing_frac: float  # fraction of expected cells that are non-observed
    stale_rate: float  # fraction of stale-quality points
    confidence: float  # 0..1; 1 = high confidence in the ring's assessment
    direction: str  # "up" / "down" / "mixed" / "flat"
    n_metrics: int
    n_observed: int


@dataclass
class EventRing:
    """Resident event ring computing per-window summary statistics.

    For each window, the ring consumes one aligned `AlignedSeries` per entity
    (or per entity+metric group) and produces a `RingOutput` that the
    edge-cascade gate uses to decide whether to trigger the trend ring.
    """

    min_observed_frac: float = 0.5
    change_point_threshold: float = 3.0
    band_energy_window: int = 3  # samples for short energy window
    # store a short EWMA residual for CUSUM-style change point
    _ewma: float = 0.0
    _ewma_var: float = 1.0

    def evaluate(
        self,
        values: np.ndarray,  # (T, M) float array, NaN for missing
        observed_mask: np.ndarray,  # (T, M) bool
        per_metric_stats: dict[str, MetricStats] | None = None,
        entity_id: str = "",
        metric_ids: Sequence[str] | None = None,
    ) -> RingOutput:
        T, M = values.shape
        if M == 0 or T == 0:
            return RingOutput(
                max_residual_z=0, mean_residual_z=0, max_change_point=0,
                max_band_energy=0, missing_frac=1, stale_rate=0,
                confidence=0, direction="flat", n_metrics=M, n_observed=0,
            )
        # missing / stale rate
        obs_mask = observed_mask & np.isfinite(values)
        total_cells = T * M
        n_observed = int(obs_mask.sum())
        missing_frac = 1.0 - n_observed / max(total_cells, 1)
        # stale rate: assume stale is encoded in attrs — not in value/quality
        # here we approximate: quality=="stale" is excluded from observed_mask
        # by the align_window function, so missing_frac includes stale.
        stale_rate = 0.0  # exact tracking requires quality field; skip here

        # per-metric robust z (if stats provided)
        residual_zs: list[float] = []
        for m in range(M):
            vals = values[obs_mask[:, m], m]
            if vals.size == 0:
                continue
            if per_metric_stats and metric_ids and m < len(metric_ids):
                st = per_metric_stats.get(metric_ids[m])
                if st is not None:
                    zs = st.robust_z(vals) if st.mad > 0 else np.zeros_like(vals)
                    residual_zs.extend(zs.tolist())
                else:
                    residual_zs.extend(((vals - vals.mean()) / (vals.std() + 1e-9)).tolist())
            else:
                # fallback: internal z-score
                mmean = float(vals.mean())
                mstd = float(vals.std()) + 1e-9
                residual_zs.extend(((vals - mmean) / mstd).tolist())

        max_residual_z = max(abs(z) for z in residual_zs) if residual_zs else 0.0
        mean_residual_z = float(np.mean([abs(z) for z in residual_zs])) if residual_zs else 0.0

        # change-point detection per metric — first-difference z-score
        cp_scores: list[float] = []
        for m in range(M):
            vals = values[:, m]
            obs = obs_mask[:, m]
            idx = np.where(obs)[0]
            if idx.size < 3:
                continue
            diffs = np.diff(vals[idx])
            if diffs.size == 0:
                continue
            md = float(np.median(diffs))
            ad = float(np.median(np.abs(diffs - md))) + 1e-9
            cp_scores.extend([abs(float(d) - md) / ad for d in diffs])

        max_change_point = float(np.max(cp_scores)) if cp_scores else 0.0

        # short-window band energy: high-pass residual variance
        band_energies: list[float] = []
        for m in range(M):
            vals = values[:, m]
            obs = obs_mask[:, m]
            idx = np.where(obs)[0]
            if idx.size < self.band_energy_window + 2:
                continue
            # high-pass: first difference
            hp = np.diff(vals[idx])
            # sliding window energy (variance)
            sw = self.band_energy_window
            for i in range(len(hp) - sw + 1):
                band_energies.append(float(np.var(hp[i : i + sw])))

        max_band_energy = float(np.max(band_energies)) if band_energies else 0.0

        # confidence: high when missing_frac ↓, observed n ↑, residual
        # distribution is clear (not all zero)
        quality_conf = 1.0 - missing_frac
        signal_conf = min(1.0, max_residual_z / 8.0) if max_residual_z > 0.5 else 0.3
        confidence = 0.7 * quality_conf + 0.3 * signal_conf

        # direction
        direction = "flat"
        if residual_zs:
            pos = sum(1 for z in residual_zs if z > 2.0)
            neg = sum(1 for z in residual_zs if z < -2.0)
            if pos > 0 and neg > 0:
                direction = "mixed"
            elif pos > 0:
                direction = "up"
            elif neg > 0:
                direction = "down"

        return RingOutput(
            max_residual_z=max_residual_z,
            mean_residual_z=mean_residual_z,
            max_change_point=max_change_point,
            max_band_energy=max_band_energy,
            missing_frac=missing_frac,
            stale_rate=stale_rate,
            confidence=confidence,
            direction=direction,
            n_metrics=M,
            n_observed=n_observed,
        )