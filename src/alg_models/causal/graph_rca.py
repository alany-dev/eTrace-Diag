"""CausalGraphRCA — end-to-end orchestration for Model 2.

Pipeline (fixed order):
1. Detect the anomaly window with the edge detector (Model 1).
2. Build the candidate temporal graph from topology + entity hierarchy
   (finite hop; pruned edges counted for audit).
3. Run PCMCI+ discovery (Tigramite when installed, ParCorr PCMCI-lite
   otherwise) over background + anomaly window.
4. Stability bootstrap filter.
5. Effect estimation (g-computation) with identifiability checks.
6. Configurable linear-combination ranking.
7. CausalReport with an evidence chain and honest limitations.

Never: GDN attention weights named as causal edges; observational scores
presented as verified do-effects; fabricated fine-grained values.
"""

from __future__ import annotations

import time

import numpy as np

from ..schemas import CausalReport, IncidentWindow, TelemetryFrame, TopologyEdge
from .discovery import PCMCIPlusDiscovery, build_multivar
from .effects import EffectEstimator, default_baseline_high
from .graph import CandidateGraph, TemporalGraphBuilder
from .ranking import RootCauseRanker
from .report import build_report


class CausalGraphRCA:
    def __init__(self, cfg: dict, *, seed: int = 7, topology: list[TopologyEdge] | None = None):
        self.cfg = cfg
        self.seed = seed
        self.topology = topology
        c = cfg.get("causal", {})
        self.tau_max_s = c.get("tau_max_s", 5)
        self.alpha_level = c.get("alpha_level", 0.05)
        self.fdr = c.get("fdr_method", "bh")
        self.min_edge_stability = c.get("min_edge_stability", 0.6)
        self.bootstrap_runs = c.get("stability_bootstraps", 30)
        self.candidate_hop = c.get("candidate_hop", 2)
        self.bg_pre_s = c.get("background_pre_s", 60)
        self.bg_post_s = c.get("background_post_s", 60)
        self.rank_weights = c.get("rank_weights", {})

    # -- detection ----------------------------------------------------------

    def _detect(self, frame: TelemetryFrame, train: TelemetryFrame, val: TelemetryFrame) -> tuple[IncidentWindow, str]:
        from ..detection import DETECTOR_REGISTRY

        det_cfg = dict(self.cfg.get("detector", {}))
        name = det_cfg.pop("name", "edge_cascade")
        det = DETECTOR_REGISTRY[name](**det_cfg)
        det.fit(train, val, seed=self.seed)
        incidents = self._merge_overlapping(det.score(frame))
        flagged = [
            i for i in incidents if i.status in ("anomaly", "uncertain") and i.severity > 0
        ]
        if not flagged:
            raise RuntimeError(
                "no anomalous/uncertain incident detected in causal input; cannot analyze"
            )
        best = max(
            flagged,
            key=lambda i: (i.status == "anomaly", len(i.metric_scores), i.severity),
        )
        return best, det.model_version

    @staticmethod
    def _merge_overlapping(incidents: list[IncidentWindow]) -> list[IncidentWindow]:
        """Merge incidents that overlap in time across entities: one RCA
        incident spans every entity whose metrics went anomalous in the same
        window. Scores/directions are unioned; severity takes the max."""
        if not incidents:
            return []
        incidents = sorted(incidents, key=lambda i: (i.start_ts_ns, -i.end_ts_ns))
        merged: list[IncidentWindow] = [incidents[0]]
        for inc in incidents[1:]:
            last = merged[-1]
            if inc.start_ts_ns <= last.end_ts_ns:
                scores = dict(last.metric_scores)
                dirs = dict(last.directions)
                for k, v in inc.metric_scores.items():
                    scores[k] = max(scores.get(k, 0.0), v)
                for k, v in inc.directions.items():
                    dirs.setdefault(k, v)
                merged[-1] = IncidentWindow(
                    incident_id=last.incident_id,
                    start_ts_ns=last.start_ts_ns,
                    end_ts_ns=max(last.end_ts_ns, inc.end_ts_ns),
                    detected_at_ns=last.detected_at_ns,
                    status=(
                        "anomaly"
                        if (last.status == "anomaly" or inc.status == "anomaly")
                        else "uncertain"
                    ),
                    severity=max(last.severity, inc.severity),
                    metric_scores=scores,
                    directions=dirs,
                    model_version=last.model_version,
                )
            else:
                merged.append(inc)
        return merged

    # -- analysis -----------------------------------------------------------

    def analyze(
        self,
        frame: TelemetryFrame,
        train: TelemetryFrame,
        val: TelemetryFrame,
        *,
        top_k: int = 3,
        incident: IncidentWindow | None = None,
    ) -> CausalReport:
        if incident is not None:
            model_version = incident.model_version
        else:
            incident, model_version = self._detect(frame, train, val)

        # sample interval from frame (most common gap)
        ts = sorted({p.ts_ns for p in frame.points})
        gaps = [b - a for a, b in zip(ts, ts[1:]) if b > a]
        if not gaps:
            raise ValueError("cannot infer sample interval from empty frame")
        from collections import Counter

        interval = Counter(gaps).most_common(1)[0][0]
        tau_max_samples = max(1, int(round(self.tau_max_s * 1e9 / interval)))

        # discovery range: incident ± background, clipped to the frame bounds
        frame_min = min(p.ts_ns for p in frame.points)
        frame_max = max(p.ts_ns for p in frame.points)
        start_ns = max(frame_min, incident.start_ts_ns - int(self.bg_pre_s * 1e9))
        end_ns = min(frame_max + 1, incident.end_ts_ns + int(self.bg_post_s * 1e9))

        entities = sorted({p.entity_id for p in frame.points})
        metrics_by_entity: dict[str, list[str]] = {}
        for p in frame.points:
            metrics_by_entity.setdefault(p.entity_id, set()).add(p.metric_id)
        metrics_by_entity = {e: sorted(m) for e, m in metrics_by_entity.items()}

        data = build_multivar(
            frame,
            entity_ids=entities,
            metric_ids_by_entity=metrics_by_entity,
            start_ns=start_ns,
            end_ns=end_ns,
            sample_interval_ns=interval,
        )
        if data.values.shape[0] == 0 or len(data.node_ids) == 0:
            return build_report(
                incident=incident,
                anomalous_metrics=list(incident.metric_scores.keys()),
                edges=[],
                candidates=[],
                outcome_entity=None,
                backend="none",
                excluded_points=0,
                total_points=0,
                bootstrap_runs=0,
                limitations=["no aligned discovery data in range"],
                model_version=model_version,
            )

        # candidate graph (topology prior limits candidate edges)
        builder = TemporalGraphBuilder(candidate_hop=self.candidate_hop)
        cand_graph: CandidateGraph = builder.build(
            frame,
            anomalous_metrics=[(p.entity_id, p.metric_id) for p in frame.points],
            topology=self.topology,
        )

        discovery = PCMCIPlusDiscovery(
            tau_max=tau_max_samples,
            alpha_level=self.alpha_level,
            fdr=self.fdr,
            min_edge_stability=self.min_edge_stability,
            stability_bootstraps=self.bootstrap_runs,
            sample_interval_ns=interval,
            seed=self.seed,
        )
        result = discovery.discover(data, cand_graph, frame, sample_interval_ns=interval)
        edges = result.edges

        # outcome: the deepest anomalous metric (longest directed-lagged chain
        # ending at it) — the most downstream observed symptom.
        anomalous = [m for m in incident.metric_scores if not m.startswith("_")]
        depth: dict[str, int] = {}
        for _ in range(len(data.node_ids) + 1):  # fixpoint over the DAG
            for e in edges:
                if e.edge_mark != "directed" or e.lag_ns <= 0:
                    continue
                depth[e.dst_entity_id] = max(
                    depth.get(e.dst_entity_id, 0), depth.get(e.src_entity_id, 0) + 1
                )
        outcome_entity = max(
            (
                nid for nid in data.node_ids
                if nid.split("::")[1] in anomalous and depth.get(nid, 0) > 0
            ),
            key=lambda nid: depth.get(nid, 0),
            default=None,
        )

        # effects for every candidate node
        estimator = EffectEstimator(
            tau_max_samples=tau_max_samples,
            alpha_level=self.alpha_level,
            seed=self.seed,
        )
        contemp_edges = [e for e in edges if e.lag_ns == 0]
        effects = {}
        for nid in data.node_ids:
            if outcome_entity is None or nid == outcome_entity:
                effects[nid] = None
                continue
            baseline, high = default_baseline_high(data, nid)
            effects[nid] = estimator.estimate(
                data, edges, nid, outcome_entity,
                sample_interval_ns=interval,
                x_baseline=baseline, x_high=high,
                contemp_edges=contemp_edges,
            )
        ranker = RootCauseRanker(
            weights=self.rank_weights or None,
            min_edge_stability=self.min_edge_stability,
            alpha_level=self.alpha_level,
        )
        candidates = ranker.rank(
            incident=incident,
            data=data,
            edges=edges,
            effects=effects,
            outcome_entity=outcome_entity,
            anomalous_metrics=anomalous,
        )
        candidates = candidates[:top_k]

        limitations = list(result.limitations)
        for nid, eff in effects.items():
            if eff is not None and eff.note:
                limitations.append(f"candidate {nid}: {eff.note}")
        limitations.append(f"candidate edges pruned: {cand_graph.pruned_edge_count}")
        if self.topology is None:
            limitations.append("topology inferred from entity hierarchy (no explicit topology file)")
        if outcome_entity is None:
            limitations.append("no downstream outcome metric with causal incoming edge found")

        return build_report(
            incident=incident,
            anomalous_metrics=anomalous,
            edges=edges,
            candidates=candidates,
            outcome_entity=outcome_entity,
            backend=result.backend,
            excluded_points=result.excluded_points,
            total_points=result.total_points,
            bootstrap_runs=result.bootstrap_runs,
            limitations=limitations,
            model_version=model_version,
        )