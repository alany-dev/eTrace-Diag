"""Sliding-window handling, alignment, and bounded out-of-order buffering.

Windows are derived frames (immutable `TelemetryFrame`). The out-of-order
buffer accepts points within a bounded tolerance: points older than the buffer
are rejected with a structured error instead of silently reordering history.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable

from ..schemas import TelemetryFrame, TelemetryPoint


class OutOfOrderError(ValueError):
    """A point arrived too far in the past to accept into the sliding window."""

    def __init__(self, ts_ns: int, buffer_tolerance_ns: int, earliest_accepted_ns: int):
        super().__init__(
            f"out_of_order point ts_ns={ts_ns} older than buffer tolerance "
            f"{buffer_tolerance_ns} ns; earliest accepted ts_ns={earliest_accepted_ns}"
        )
        self.ts_ns = ts_ns
        self.buffer_tolerance_ns = buffer_tolerance_ns
        self.earliest_accepted_ns = earliest_accepted_ns


class DuplicatePointError(ValueError):
    def __init__(self, key: tuple[str, str, int, str]):
        super().__init__(f"duplicate point {key}")
        self.key = key


@dataclass
class SlidingWindowMaker:
    """Slices a sorted frame into fixed windows with a stride.

    Windows are returned in (start_ns, end_ns, frame) triples. Points exactly
    at the window boundary belong to the window they fall inside (inclusive).
    """

    window_ns: int
    stride_ns: int

    def windows(self, frame: TelemetryFrame) -> list[tuple[int, int, TelemetryFrame]]:
        """Linear scan over the sorted frame (points are ordered by ts_ns), so
        per-window cost stays O(#points + #windows), never O(#windows × #points)."""
        n = len(frame.points)
        if n == 0:
            return []
        start = frame.points[0].ts_ns
        end = frame.points[-1].ts_ns
        out: list[tuple[int, int, TelemetryFrame]] = []
        w_start = (start // self.stride_ns) * self.stride_ns
        i = 0
        while w_start <= end:
            w_end = w_start + self.window_ns
            while i < n and frame.points[i].ts_ns < w_start:
                i += 1
            j = i
            while j < n and frame.points[j].ts_ns < w_end:
                j += 1
            if j > i:
                out.append((w_start, w_end, TelemetryFrame(points=frame.points[i:j])))
            w_start += self.stride_ns
        return out


@dataclass
class AlignedSeries:
    """Multi-metric time grid for one entity over one window.

    Rows = aligned timestamps; columns = metrics. Missing cells are NaN.
    Never filled with fabricated fine-grained values: detection may
    reconstruct from train statistics plus a mask, but causal analysis must
    operate on observed cells only (see `observed_mask`).
    """

    entity_id: str
    ts_ns: list[int]
    metrics: list[str]
    values: list[list[float]]
    # True where the grid cell came from an observed point; causal/discovery
    # code MUST exclude cells where this is False.
    observed_mask: list[list[bool]]

    def array(self) -> "object":
        import numpy as np

        return np.asarray(self.values, dtype=float)

    def mask(self) -> "object":
        import numpy as np

        return np.asarray(self.observed_mask, dtype=bool)


def align_window(
    frame: TelemetryFrame,
    *,
    entity_id: str,
    start_ns: int,
    end_ns: int,
    sample_interval_ns: int,
    metrics: Iterable[str] | None = None,
) -> AlignedSeries:
    """Align observed points of one entity into a uniform time grid.

    `metrics=None` collects all metrics present in the window for the entity,
    sorted. Cells without an observed point are NaN and masked out; missing
    points are NOT imputed here (detection may impute for scoring, causal must
    exclude).
    """
    import numpy as np

    entity_pts = [
        p
        for p in frame.points
        if p.entity_id == entity_id and start_ns <= p.ts_ns < end_ns
    ]
    metric_list = (
        sorted({p.metric_id for p in entity_pts}) if metrics is None else list(metrics)
    )
    idx = {m: i for i, m in enumerate(metric_list)}
    grid = max(1, sample_interval_ns)
    t0 = start_ns - (start_ns % grid)
    t1 = end_ns - 1 if end_ns > start_ns else start_ns
    ts_ns = list(range(t0, t1 + 1, grid))
    keys: dict[tuple[int, str], tuple[float, bool]] = {}
    for p in entity_pts:
        if p.value is None:
            continue
        cell_ts = p.ts_ns - (p.ts_ns % grid)
        if cell_ts < t0 or cell_ts > t1:
            continue
        if p.metric_id not in idx:
            continue
        keys[(cell_ts, p.metric_id)] = (float(p.value), p.quality == "observed")
    values: list[list[float]] = []
    observed: list[list[bool]] = []
    for t in ts_ns:
        row = [float("nan")] * len(metric_list)
        mask = [False] * len(metric_list)
        for m in metric_list:
            cell = keys.get((t, m))
            if cell is not None:
                row[idx[m]] = cell[0]
                mask[idx[m]] = cell[1]
        values.append(row)
        observed.append(mask)
    return AlignedSeries(
        entity_id=entity_id,
        ts_ns=ts_ns,
        metrics=metric_list,
        values=values,
        observed_mask=observed,
    )


@dataclass
class OutOfOrderBuffer:
    """Bounded out-of-order buffer feeding a sliding window.

    Accepts a point if its timestamp is within `tolerance_ns` behind the
    newest accepted timestamp (points ahead of the newest are always fine).
    Older points raise `OutOfOrderError`; duplicate (entity, metric, ts,
    quality) points raise `DuplicatePointError`.
    """

    tolerance_ns: int = 5_000_000_000
    _newest: int = 0
    _points: list[TelemetryPoint] = field(default_factory=list)

    def accept(self, point: TelemetryPoint) -> None:
        if len(self._points) == 0:
            self._newest = point.ts_ns
        else:
            if point.ts_ns < self._newest - self.tolerance_ns:
                raise OutOfOrderError(
                    point.ts_ns, self.tolerance_ns, self._newest - self.tolerance_ns
                )
            self._newest = max(self._newest, point.ts_ns)
        key = (point.entity_id, point.metric_id, point.ts_ns, point.quality)
        if any(
            (
                p.entity_id,
                p.metric_id,
                p.ts_ns,
                p.quality,
            )
            == key
            for p in self._points
        ):
            raise DuplicatePointError(key)
        self._points.append(point)

    def drain(self) -> TelemetryFrame:
        pts = sorted(self._points, key=lambda p: p.ts_ns)
        self._points = []
        self._newest = 0
        return TelemetryFrame(points=tuple(pts))


def partition_quality(frame: TelemetryFrame) -> tuple[TelemetryFrame, TelemetryFrame]:
    """Split a frame into (observed, non_observed) sub-frames.

    Non-observed includes imputed/missing/stale/out_of_order; the causal and
    effect-estimation pipelines operate only on the observed sub-frame and
    record the count of excluded points.
    """
    obs = tuple(p for p in frame.points if p.quality == "observed")
    non_obs = tuple(p for p in frame.points if p.quality != "observed")
    return TelemetryFrame(points=obs), TelemetryFrame(points=non_obs)


def summarize_quality(frame: TelemetryFrame) -> dict[str, int]:
    counts: dict[str, int] = {}
    for p in frame.points:
        counts[p.quality] = counts.get(p.quality, 0) + 1
    return counts


def real_mid_stream_gap(aligned: AlignedSeries) -> bool:
    """True when an aligned window has observed points on BOTH sides of a gap
    (a real mid-stream outage); False when points only touch one boundary
    (truncated data — a scoring artifact, not an anomaly)."""
    if len(aligned.ts_ns) < 2:
        return False
    column_observed = [any(row) for row in aligned.observed_mask]
    first_missing = next((i for i, o in enumerate(column_observed) if not o), None)
    if first_missing is None:
        return False
    has_obs_before = any(column_observed[:first_missing])
    has_obs_after = any(column_observed[first_missing + 1 :])
    return has_obs_before and has_obs_after