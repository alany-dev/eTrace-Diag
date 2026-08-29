"""Active query selection: chooses the next human question from TORAI
candidate scores and feedback conflicts.

The human only needs to confirm: anomaly window, direction, candidate root
cause, or reject the result. Contradictory feedback is preserved (see
controller); this module only ranks WHICH incident/candidate to ask about.
"""

from __future__ import annotations

from ..schemas import CausalReport, FeedbackEvent


def _uncertainty_score(report: CausalReport) -> float:
    """Composite uncertainty [0, 1] based on the top-2 candidate score gap and
    abstention reasons."""
    candidates = report.candidates
    if len(candidates) >= 2:
        gap = candidates[0].score - candidates[1].score
        score = 1.0 - min(1.0, max(0.0, gap))
    else:
        score = 1.0
    n_abstained = sum(1 for c in candidates if c.abstained_reason is not None)
    score += 0.1 * n_abstained
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


def select_next_question(report: CausalReport, feedback_records: list) -> dict | None:
    """Returns a question descriptor or None when nothing needs asking.

    Priority: feedback/top-1 contradiction > no candidates > top-1/top-2
    score gap < 0.05. All outputs reference concrete incident/entity ids.
    """
    feedbacks = [r.feedback for r in feedback_records] if feedback_records else []
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
    if not report.candidates:
        return {
            "incident_id": report.incident_id,
            "kind": "observe",
            "question": "No candidates were ranked; continue observing?",
            "options": ["confirmed", "rejected"],
        }
    if len(report.candidates) >= 2 and report.candidates[0].score - report.candidates[1].score < 0.05:
        c = report.candidates[0]
        return {
            "incident_id": report.incident_id,
            "kind": "confirm_top1",
            "question": (
                f"Top-1 ({c.entity_id}) and top-2 are within 0.05 score; "
                f"confirm {c.entity_id} as root cause."
            ),
            "target_id": c.entity_id,
            "options": ["confirmed", "wrong_root_cause"],
        }
    return None
