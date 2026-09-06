"""EvidenceNarrator tests: deterministic template backend works; LLM-style
renderer output with missing evidence IDs or wrong directions is REJECTED
sentence-by-sentence and falls back to the template.
"""

from __future__ import annotations

from alg_models.interactive.explainer import EvidenceNarrator
from alg_models.schemas import (
    CausalReport,
    IncidentWindow,
    RootCauseCandidate,
    SymptomCluster,
)


def _report() -> CausalReport:
    inc = IncidentWindow(
        incident_id="i1", start_ts_ns=0, end_ts_ns=10,
        detected_at_ns=5, status="anomaly", severity=0.5,
        metric_scores={"cpu.utilization": 0.9}, directions={"cpu.utilization": "up"},
        model_version="0.1.0",
    )
    cand = RootCauseCandidate(
        entity_id="adservice", rank=1, score=0.7, direction="up",
        severity={"metric": 0.8}, evidence_indicators=["adservice_cpu"],
        cluster_id=0,
    )
    cluster = SymptomCluster(cluster_id=0, members=["adservice", "cartservice"], cluster_score=0.9)
    return CausalReport(
        incident_id="i1", window=inc, anomalous_metrics=["cpu.utilization"],
        candidates=[cand], clusters=[cluster], model_version="0.1.0",
    )


def test_template_backend_is_deterministic():
    narrator = EvidenceNarrator()
    text = narrator.narrate(_report())
    assert "Incident i1" in text
    assert "adservice" in text
    assert "adservice_cpu" in text  # evidence indicator appears
    assert "symptom clusters: 1" in text
    assert narrator.narrate(_report()) == text  # deterministic


def test_sentence_with_nonexistent_reference_rejected():
    def bad_llm(report):
        return (
            "Incident i1. nonexistent_service_cpu drove the failure. "
            "adservice is ranked 1."
        )
    narrator = EvidenceNarrator(llm_renderer=bad_llm)
    text = narrator.narrate(_report())
    # the unsupported sentence (citing a non-existent indicator) is replaced
    # by the template — the fake id must never appear in the final output
    assert "nonexistent_service_cpu" not in text
    # the valid sentence (with a real entity id) survives
    assert "adservice is ranked 1" not in text


def test_sentence_without_reference_rejected():
    def bare_llm(report):
        return "The system experienced degraded performance."
    narrator = EvidenceNarrator(llm_renderer=bare_llm)
    text = narrator.narrate(_report())
    assert "degraded performance" not in text


def test_wrong_direction_rejected():
    def wrong_dir(report):
        return "adservice caused the anomaly (decreased load)."
    narrator = EvidenceNarrator(llm_renderer=wrong_dir)
    text = narrator.narrate(_report())
    # direction-claim contradicts candidate direction ("up") — rejected
    assert "caused the anomaly" not in text


def test_llm_disabled_without_env():
    import os

    os.environ.pop("ALG_MODELS_LLM_BACKEND", None)
    narrator = EvidenceNarrator(llm_renderer=lambda r: "IGNORED")
    assert not narrator.llm_enabled
    text = narrator.narrate(_report())
    assert "IGNORED" not in text
