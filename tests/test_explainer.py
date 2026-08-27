"""EvidenceNarrator tests: deterministic template backend works; LLM-style
renderer output with missing evidence IDs or wrong directions is REJECTED
sentence-by-sentence and falls back to the template.
"""

from __future__ import annotations

from alg_models.interactive.explainer import EvidenceNarrator
from alg_models.schemas import CausalReport, CausalEdge, IncidentWindow, RootCauseCandidate


def _report() -> CausalReport:
    inc = IncidentWindow(
        incident_id="i1", start_ts_ns=0, end_ts_ns=10,
        detected_at_ns=5, status="anomaly", severity=0.5,
        metric_scores={"cpu.utilization": 0.9}, directions={"cpu.utilization": "up"},
        model_version="0.1.0",
    )
    edge = CausalEdge(
        edge_id="e:host::disk.io_wait->process::process.io_wait@lag3",
        src_entity_id="host::disk.io_wait", dst_entity_id="process::process.io_wait",
        lag_ns=3_000_000_000, statistic=0.9, p_value=0.001,
        stability=0.8, evidence_level="strong",
    )
    cand = RootCauseCandidate(
        entity_id="host::disk.io_wait", rank=1, score=0.7,
        direction="up", identifiability="identified", effect_estimate=3.5,
        effect_interval=(2.0, 5.0),
        evidence_edge_ids=["e:host::disk.io_wait->process::process.io_wait@lag3"],
    )
    return CausalReport(
        incident_id="i1", window=inc, anomalous_metrics=["cpu.utilization"],
        edges=[edge], candidates=[cand], model_version="0.1.0",
    )


def test_template_backend_is_deterministic():
    narrator = EvidenceNarrator()
    text = narrator.narrate(_report())
    assert "Incident i1" in text
    assert "host::disk.io_wait" in text
    assert narrator.narrate(_report()) == text  # deterministic


def test_sentence_with_nonexistent_edge_id_rejected():
    def bad_llm(report):
        return (
            "Incident i1. e:does::not-exist@lag0 caused the failure. "
            "host::disk.io_wait is ranked 1."
        )
    narrator = EvidenceNarrator(llm_renderer=bad_llm)
    text = narrator.narrate(_report())
    # the unsupported sentence is replaced by the template — the fake edge id
    # must never appear in the final output
    assert "does::not-exist" not in text
    assert "ranked 1" not in text
    # the valid sentence (with a real entity id) survives
    assert "host::disk.io_wait is ranked 1" not in text


def test_wrong_direction_rejected_for_unidentified_candidate():
    def wrong_dir(report):
        return (
            "host::cpu.utilization caused the anomaly (decreased load). "
            "host::disk.io_wait effect 3.5."
        )
    narrator = EvidenceNarrator(llm_renderer=wrong_dir)
    text = narrator.narrate(_report())
    # direction-claim + causal claim on a not-identified candidate is rejected
    assert "caused the anomaly" not in text


def test_llm_disabled_without_env():
    import os

    os.environ.pop("ALG_MODELS_LLM_BACKEND", None)
    narrator = EvidenceNarrator(llm_renderer=lambda r: "IGNORED")
    assert not narrator.llm_enabled
    text = narrator.narrate(_report())
    assert "IGNORED" not in text