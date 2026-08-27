"""Active query selection: chooses the next human question from graph
inconsistencies, low edge stability, wide effect CI, and model/human opinion
conflicts.

The human only needs to confirm: anomaly window, direction, candidate root
cause, or reject the result. Contradictory feedback is preserved (see
controller); this module only ranks WHICH incident/candidate to ask about.
"""

from __future__ import annotations

from ..schemas import CausalReport, FeedbackEvent


def _uncertainty_score(report: CausalReport) -> float:
    """Composite uncertainty in [0, 1]: low stability + wide CIs + abstentions."""
    score = 0.0
    n = max(1, len(report.edges))
    for e in report.edges:
        if e.stability < 0.6:
            score += 0.3
        if e.evidence_level in ("weak", "insufficient"):
            score += 0.2
    score /= n
    candidates = report.candidates
    if candidates:
        wide_ci = sum(
            1
            for c in candidates
            if c.effect_interval is not None
            and (c.effect_interval[1] - c.effect_interval[0]) > 2.0
        )
        abstained = sum(1 for c in candidates if c.identifiability != "identified")
        score += 0.3 * (wide_ci / len(candidates)) + 0.2 * (abstained / len(candidates))
    return min(1.0, score)


def _disagreement(feedbacks: list[FeedbackEvent], report: CausalReport) -> bool:
    """Model/human opinion conflict: any rejection of a top-1 candidate or any
    label that contradicts the top ranking."""
    if not report.candidates or not feedbacks:
        return False
    top = report.candidates[0].entity_id
    for fb in feedbacks:
        if fb.target_id == top and fb.label in ("false_positive", "rejected", "wrong_root_cause"):
            return True
    return False


def select_next_question(report: CausalReport, feedback_records: list, ctx: dict | None = None) -> dict | None:
    """Returns a question descriptor or None when nothing needs asking.

    Priority: contradiction > abstained top candidates > unstable strong
    edges > wide effect CI. All outputs reference concrete incident/entity ids.
    """
    feedbacks = [r.feedback for r in feedback_records]
    if _disagreement(feedbacks, report):
        return {
            "incident_id": report.incident_id,
            "kind": "conflict",
            "question": (
                f"Feedback contradicts the top candidate "
                f"{report.candidates[0].entity_id}; confirm which is correct."
            ),
            "target_id": report.candidates[0].entity_id,
            "options": ["true_positive", "false_positive", "wrong_root_cause"],
        }
    abstained = [c for c in report.candidates if c.identifiability != "identified"]
    if abstained:
        c = abstained[0]
        return {
            "incident_id": report.incident_id,
            "kind": "abstained_candidate",
            "question": (
                f"Candidate {c.entity_id} could not be identified "
                f"({c.abstained_reason or 'non-identifiable'}); "
                "is it the root cause?"
            ),
            "target_id": c.entity_id,
            "options": ["confirmed", "rejected"],
        }
    unstable = [e for e in report.edges if e.stability < 0.6 and e.edge_mark == "directed"]
    if unstable:
        e = unstable[0]
        return {
            "incident_id": report.incident_id,
            "kind": "unstable_edge",
            "question": (
                f"Edge {e.src_entity_id}->{e.dst_entity_id} has stability "
                f"{e.stability:.2f}; confirm the propagation direction."
            ),
            "target_id": e.dst_entity_id,
            "options": ["confirmed", "wrong_root_cause"],
        }
    if report.candidates:
        c = report.candidates[0]
        if c.effect_interval is not None and (c.effect_interval[1] - c.effect_interval[0]) > 2.0:
            return {
                "incident_id": report.incident_id,
                "kind": "wide_effect_ci",
                "question": (
                    f"Effect CI for {c.entity_id} is wide "
                    f"({c.effect_interval[0]:.2f}, {c.effect_interval[1]:.2f}); "
                    "confirm the magnitude."
                ),
                "target_id": c.entity_id,
                "options": ["confirmed", "rejected"],
            }
    return None