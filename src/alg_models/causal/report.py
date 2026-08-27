"""CausalReport assembly: fixed report order and the evidence chain.

Report order (fixed): anomaly window → metrics & directions → causal edges /
lags / stability → candidate paths → intervention effect / interval →
insufficient evidence and unobserved confounding.
"""

from __future__ import annotations

from ..schemas import (
    CausalEdge,
    CausalReport,
    EvidenceChainItem,
    IncidentWindow,
    RootCauseCandidate,
)


def build_report(
    *,
    incident: IncidentWindow,
    anomalous_metrics: list[str],
    edges: list[CausalEdge],
    candidates: list[RootCauseCandidate],
    outcome_entity: str | None,
    backend: str,
    excluded_points: int,
    total_points: int,
    bootstrap_runs: int,
    limitations: list[str],
    model_version: str,
) -> CausalReport:
    chain: list[EvidenceChainItem] = []
    # evidence chain: per strong edge
    for e in edges:
        chain.append(
            EvidenceChainItem(
                claim=(
                    f"{e.src_entity_id} at lag {e.lag_ns / 1e9:g}s affects "
                    f"{e.dst_entity_id} (mark={e.edge_mark}, "
                    f"stability={e.stability:.2f})"
                ),
                ref_type="edge",
                ref_id=e.edge_id,
                lag_ns=e.lag_ns,
                statistic=e.statistic,
                p_value=e.p_value,
            )
        )
    # evidence chain: per candidate effect
    for c in candidates:
        if c.effect_estimate is not None and c.identifiability == "identified":
            chain.append(
                EvidenceChainItem(
                    claim=(
                        f"do({c.entity_id}=high) − do({c.entity_id}=baseline) "
                        f"on {outcome_entity or 'outcome'} = {c.effect_estimate:.3g} "
                        f"(CI [{c.effect_interval[0]:.3g}, {c.effect_interval[1]:.3g}])"
                        if c.effect_interval
                        else f"do({c.entity_id}=high) − baseline on "
                        f"{outcome_entity or 'outcome'} = {c.effect_estimate:.3g}"
                    ),
                    ref_type="intervention",
                    ref_id=f"do:{c.entity_id}->{outcome_entity or 'outcome'}",
                    effect_estimate=c.effect_estimate,
                )
            )
    full_limitations = list(limitations)
    full_limitations.append(
        f"causal backend: {backend}; bootstrap runs: {bootstrap_runs}"
    )
    full_limitations.append(
        f"excluded non-observed points from causal analysis: "
        f"{excluded_points}/{total_points}"
    )
    if excluded_points > 0:
        full_limitations.append(
            "excluded points (imputed/missing/stale/out_of_order) never enter "
            "discovery or effect estimation"
        )
    if outcome_entity is None:
        full_limitations.append("no downstream outcome identified; effect column abstains")
    # model version flows from the detector used to detect the incident
    return CausalReport(
        incident_id=incident.incident_id,
        window=incident,
        anomalous_metrics=anomalous_metrics,
        edges=edges,
        candidates=candidates,
        evidence_chain=chain,
        limitations=full_limitations,
        model_version=model_version,
    )