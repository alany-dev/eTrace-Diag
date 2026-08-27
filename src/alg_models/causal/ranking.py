"""Root-cause ranking: configurable linear combination of detection
contribution, causal-ancestor coverage, temporal order, edge stability, effect
size, minus a confounding penalty.

    rank = w_detector*detector_contrib + w_ancestor*ancestor_score
         + w_temporal*temporal_order + w_stability*edge_stability
         + w_effect*effect_size - w_confounding*confounding_penalty

Weights are calibrated ONLY on train/validation or synthetic ground truth —
never on test labels. A separate Pearson/PCC ranking is kept as a lower bound
(see experiments.run_rca).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from ..schemas import CausalEdge, IncidentWindow, RootCauseCandidate
from .discovery import MultivarData
from .effects import EffectEstimate


@dataclass
class RankWeights:
    detector: float = 0.25
    ancestor: float = 0.25
    temporal: float = 0.20
    stability: float = 0.15
    effect: float = 0.10
    confounding: float = 0.05


class RootCauseRanker:
    def __init__(self, weights: dict[str, float] | None = None,
                 min_edge_stability: float = 0.6, alpha_level: float = 0.05):
        w = RankWeights(**weights) if weights else RankWeights()
        self.w = w
        self.min_edge_stability = min_edge_stability
        self.alpha_level = alpha_level

    def rank(
        self,
        *,
        incident: IncidentWindow,
        data: MultivarData,
        edges: list[CausalEdge],
        effects: dict[str, EffectEstimate],
        outcome_entity: str,
        anomalous_metrics: list[str],
    ) -> list[RootCauseCandidate]:
        node_ids = data.node_ids
        anomalous = [m for m in anomalous_metrics if not m.startswith("_")]
        # normalize: anomalous entries may be full node ids ("svc::agg") or bare
        # metric names ("agg"); build both lookup sets so the skip/scoring below
        # is convention-agnostic.
        anom_ids = {m for m in anomalous if "::" in m}
        anom_metrics = {m.split("::", 1)[1] if "::" in m else m for m in anomalous}

        def _is_anomalous(nid: str) -> bool:
            metric = nid.split("::", 1)[1]
            return nid in anom_ids or metric in anom_metrics

        # directed lagged ancestry (candidate -> descendant)
        children: dict[str, list[CausalEdge]] = {}
        parents: dict[str, list[CausalEdge]] = {}
        for e in edges:
            if e.edge_mark != "directed" or e.lag_ns <= 0:
                continue
            children.setdefault(e.src_entity_id, []).append(e)
            parents.setdefault(e.dst_entity_id, []).append(e)

        def descendants(node: str, max_depth: int = 8) -> set[str]:
            seen: set[str] = set()
            frontier = [node]
            for _ in range(max_depth):
                nxt: list[str] = []
                for f in frontier:
                    for e in children.get(f, []):
                        if e.dst_entity_id not in seen:
                            seen.add(e.dst_entity_id)
                            nxt.append(e.dst_entity_id)
                frontier = nxt
                if not frontier:
                    break
            return seen

        # per-node first-anomaly time within the incident window
        first_trigger: dict[str, float] = {}
        window_start, window_end = incident.start_ts_ns, incident.end_ts_ns
        for ni, nid in enumerate(node_ids):
            col = ni
            vals = data.values[:, col]
            obs = data.observed[:, col]
            rows = np.where(
                obs & np.isfinite(vals) & (data.ts_ns >= window_start) & (data.ts_ns <= window_end)
            )[0]
            if not _is_anomalous(nid) or rows.size == 0:
                continue
            # first row whose value deviates > 3 MAD from its window median
            med = float(np.median(vals[rows]))
            mad = float(np.median(np.abs(vals[rows] - med))) + 1e-9
            dev = np.abs(vals[rows] - med) > 3.0 * 1.4826 * mad
            trigger_rows = rows[dev]
            if trigger_rows.size:
                first_trigger[nid] = float(data.ts_ns[trigger_rows[0]])
        if first_trigger:
            t_min = min(first_trigger.values())
            t_max = max(first_trigger.values())
        else:
            t_min = t_max = 0.0

        candidates: list[RootCauseCandidate] = []
        for nid in node_ids:
            metric = nid.split("::", 1)[1]
            entity = nid.split("::", 1)[0]
            if not _is_anomalous(nid) and not children.get(nid):
                continue  # skip non-anomalous, non-ancestor nodes

            detector_contrib = max(
                incident.metric_scores.get(metric, 0.0),
                incident.metric_scores.get(nid, 0.0),
            )
            desc = descendants(nid)
            desc_metrics = {d.split("::", 1)[1] for d in desc}
            ancestor_hit = sum(
                1 for m in anomalous
                if m in desc or (m.split("::", 1)[1] if "::" in m else m) in desc_metrics
            )
            if anomalous:
                ancestor_score = min(1.0, ancestor_hit / len(anomalous))
            else:
                ancestor_score = 0.0

            if first_trigger and nid in first_trigger and t_max > t_min:
                temporal_order = 1.0 - (first_trigger[nid] - t_min) / (t_max - t_min + 1e-9)
            elif first_trigger and t_min == t_max and nid in first_trigger:
                temporal_order = 1.0
            else:
                temporal_order = 0.5

            out_edges = children.get(nid, [])
            stab = [e.stability for e in out_edges]
            edge_stability = float(np.mean(stab)) if stab else 0.0

            eff = effects.get(nid)
            if eff is not None and eff.identifiability == "identified" and eff.estimate is not None:
                effect_size = min(1.0, abs(eff.estimate) / (abs(eff.estimate) + 1.0))
            else:
                effect_size = 0.0

            bad = 0
            for e in out_edges:
                if e.edge_mark in ("bidirected", "unknown") or (e.p_value is not None and e.p_value > self.alpha_level) or e.stability < self.min_edge_stability:
                    bad += 1
            confounding_penalty = bad / len(out_edges) if out_edges else 1.0

            score = (
                self.w.detector * detector_contrib
                + self.w.ancestor * ancestor_score
                + self.w.temporal * temporal_order
                + self.w.stability * edge_stability
                + self.w.effect * effect_size
                - self.w.confounding * confounding_penalty
            )
            if score < 0:
                score = 0.0

            identifiability = eff.identifiability if eff is not None else "not_tested"
            abstained = eff.abstained_reason if eff is not None and eff.identifiability == "not_identifiable" else None
            candidates.append(
                RootCauseCandidate(
                    entity_id=nid,
                    rank=1,  # filled after sorting
                    score=round(float(score), 6),
                    direction=incident.directions.get(metric, "mixed"),
                    effect_estimate=eff.estimate if eff is not None else None,
                    effect_interval=(eff.ci_lo, eff.ci_hi)
                    if eff is not None and eff.ci_lo is not None else None,
                    identifiability=identifiability,
                    evidence_edge_ids=[e.edge_id for e in out_edges],
                    evidence_metric_ids=list({e.src_entity_id.split('::')[1] for e in out_edges} | {metric}),
                    abstained_reason=abstained,
                )
            )
        candidates.sort(key=lambda c: c.score, reverse=True)
        for i, c in enumerate(candidates, start=1):
            c = c.model_copy(update={"rank": i})
            candidates[i - 1] = c
        return candidates


class CorrelationRanker:
    """Pearson correlation ranking — explicit lower bound, NOT causal."""

    def rank(self, *, data: MultivarData, incident: IncidentWindow,
             anomalous_metrics: list[str]) -> list[RootCauseCandidate]:
        anomalous = [m for m in anomalous_metrics if not m.startswith("_")]
        obs = data.observed.all(axis=1)
        if obs.sum() < 3:
            return []
        X = data.values[obs]
        target_cols = [
            i for i, nid in enumerate(data.node_ids)
            if nid.split("::")[1] in anomalous and np.isfinite(X[:, i]).all()
        ]
        if not target_cols:
            return []
        # correlation of each node with the max-score anomalous metric
        max_metric = max(anomalous, key=lambda m: incident.metric_scores.get(m, 0.0))
        max_col = next(i for i, nid in enumerate(data.node_ids) if nid.split("::")[1] == max_metric)
        out: list[RootCauseCandidate] = []
        for i, nid in enumerate(data.node_ids):
            if not np.isfinite(X[:, i]).all():
                continue
            r = float(np.corrcoef(X[:, i], X[:, max_col])[0, 1] if np.std(X[:, i]) > 0 else 0.0)
            out.append(
                RootCauseCandidate(
                    entity_id=nid,
                    rank=1,
                    score=float(abs(r)),
                    direction="mixed",
                    identifiability="not_tested",
                    abstained_reason="correlation-only lower bound; not causal",
                )
            )
        out.sort(key=lambda c: c.score, reverse=True)
        for i, c in enumerate(out, start=1):
            c = c.model_copy(update={"rank": i})
            out[i - 1] = c
        return out