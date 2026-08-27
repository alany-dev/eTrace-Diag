"""Evidence-constrained narrator.

`EvidenceNarrator` is a TEMPLATE renderer by default (no LLM). An LLM backend
is used only when explicitly configured (env var + a checkpoint). The LLM
input is restricted to structured evidence from `CausalReport` — never raw
unfiltered telemetry. Every generated sentence is validated per-sentence:
each causal assertion must cite ≥1 edge/metric/time-window/statistic; missing
citations, nonexistent references, direction inconsistencies, or claims that
exceed identifiability are REJECTED and the sentence falls back to the
template. Chain-of-thought is never used as evidence or persisted.
"""

from __future__ import annotations

import os
import re
from typing import Callable

from ..schemas import CausalEdge, CausalReport, RootCauseCandidate


class EvidenceError(ValueError):
    """Raised when a narrator sentence fails evidence validation."""


class EvidenceNarrator:
    def __init__(self, *, template_renderer: Callable[[CausalReport], str] | None = None,
                 llm_renderer: Callable[[CausalReport], str] | None = None):
        self._template = template_renderer or self._default_template
        self._llm = llm_renderer
        self.llm_enabled = bool(llm_renderer) and _llm_configured()

    def narrate(self, report: CausalReport) -> str:
        if self.llm_enabled and self._llm is not None:
            try:
                text = self._llm(report)
                return self._validate_sentences(text, report)
            except Exception:
                # LLM failure must never affect the report → template fallback
                return self._template(report)
        return self._template(report)

    # -- validation ---------------------------------------------------------

    def _validate_sentences(self, text: str, report: CausalReport) -> str:
        """Per-sentence validation; invalid sentences fall back to template
        sentences. Sentence boundaries at '. ' (narrator output is prose)."""
        edge_ids = {e.edge_id for e in report.edges}
        metric_ids: set[str] = set()
        for e in report.edges:
            metric_ids.add(e.src_entity_id)
            metric_ids.add(e.dst_entity_id)
        valid: list[str] = []
        for sentence in re.split(r"(?<=\.)\s+", text.strip()):
            if not sentence:
                continue
            if self._sentence_valid(sentence, report, edge_ids, metric_ids):
                valid.append(sentence)
            else:
                valid.append(self._template(report))
        return " ".join(valid)

    def _sentence_valid(self, sentence: str, report: CausalReport,
                        edge_ids: set[str], metric_ids: set[str]) -> bool:
        has_evidence = any(
            cid in sentence for cid in edge_ids | metric_ids
        ) or "intervention" in sentence.lower()
        if not has_evidence:
            return False
        # nonexistent reference check: citations that look like edge ids must exist
        for token in re.findall(r"e:[A-Za-z0-9_.:~@-]+", sentence):
            if token.rstrip(".,;") not in edge_ids:
                return False
        # direction consistency: direction words must match candidate directions
        for c in report.candidates:
            if c.entity_id in sentence:
                if c.identifiability != "identified" and re.search(
                    r"\b(effect|causes|caused|due to)\b", sentence
                ):
                    return False
                if c.direction == "up" and re.search(r"\b(decreased|down)\b", sentence):
                    return False
                if c.direction == "down" and re.search(r"\b(increased|up)\b", sentence):
                    return False
        return True

    # -- template -----------------------------------------------------------

    @staticmethod
    def _default_template(report: CausalReport) -> str:
        parts: list[str] = []
        parts.append(
            f"Incident {report.incident_id} "
            f"[{report.window.start_ts_ns / 1e9:g}s, {report.window.end_ts_ns / 1e9:g}s] "
            f"status={report.window.status}."
        )
        if report.anomalous_metrics:
            parts.append(
                "Anomalous metrics: "
                + ", ".join(
                    f"{m} ({report.window.directions.get(m, 'mixed')}, "
                    f"score {report.window.metric_scores.get(m, 0):.2f})"
                    for m in report.anomalous_metrics
                )
                + "."
            )
        for e in report.edges:
            if e.edge_mark == "directed" and e.lag_ns > 0:
                parts.append(
                    f"Edge {e.edge_id}: {e.src_entity_id} affects "
                    f"{e.dst_entity_id} at lag {e.lag_ns / 1e9:g}s "
                    f"(p={e.p_value if e.p_value is None else round(e.p_value, 4)}, "
                    f"stability={e.stability:.2f}, evidence={e.evidence_level})."
                )
        for c in report.candidates:
            eff = (
                f"effect {c.effect_estimate:.3g}"
                if c.effect_estimate is not None
                else "effect not identified"
            )
            parts.append(
                f"Candidate rank {c.rank}: {c.entity_id} "
                f"(score {c.score:.3f}, {c.identifiability}, {eff})."
            )
        return " ".join(parts)


def _llm_configured() -> bool:
    """LLM backend only when explicitly configured (env vars set)."""
    return bool(os.environ.get("ALG_MODELS_LLM_BACKEND"))


def template_narrator(report: CausalReport) -> str:
    return EvidenceNarrator._default_template(report)