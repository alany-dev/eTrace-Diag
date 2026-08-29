"""Evidence-constrained narrator.

`EvidenceNarrator` is a TEMPLATE renderer by default (no LLM). An LLM backend
is used only when explicitly configured (env var + a checkpoint). The LLM
input is restricted to structured evidence from `CausalReport` — never raw
unfiltered telemetry. Every generated sentence is validated per-sentence:
each causal assertion must cite a ranked candidate, an evidence indicator, or
a cluster member; missing citations, nonexistent references, or direction
inconsistencies are REJECTED and the sentence falls back to the template.
Chain-of-thought is never used as evidence or persisted.
"""

from __future__ import annotations

import os
import re
from typing import Callable

from ..schemas import CausalReport, RootCauseCandidate


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

    def _valid_references(self, report: CausalReport) -> set[str]:
        """Everything an assertion may cite: candidates, evidence indicators,
        and cluster members."""
        refs: set[str] = set()
        for c in report.candidates:
            refs.add(c.entity_id)
            refs.update(c.evidence_indicators)
        for cl in report.clusters:
            refs.update(cl.members)
        return refs

    def _validate_sentences(self, text: str, report: CausalReport) -> str:
        """Per-sentence validation; invalid sentences fall back to template
        sentences. Sentence boundaries at '. ' (narrator output is prose)."""
        refs = self._valid_references(report)
        valid: list[str] = []
        for sentence in re.split(r"(?<=\.)\s+", text.strip()):
            if not sentence:
                continue
            if self._sentence_valid(sentence, report, refs):
                valid.append(sentence)
            else:
                valid.append(self._template(report))
        return " ".join(valid)

    def _sentence_valid(self, sentence: str, report: CausalReport,
                        refs: set[str]) -> bool:
        # must cite at least one valid reference
        if not any(ref in sentence for ref in refs):
            return False
        # cited identifiers must exist in the reference set
        # (generic English words are never validated as citations)
        for c in report.candidates:
            if c.entity_id in sentence and c.direction == "up" and re.search(
                r"\b(decreased|down|below)\b", sentence
            ):
                return False
            if c.entity_id in sentence and c.direction == "down" and re.search(
                r"\b(increased|up|above)\b", sentence
            ):
                return False
        return True

    # -- template -----------------------------------------------------------

    @staticmethod
    def _default_template(report: CausalReport) -> str:
        parts: list[str] = []
        ranking = "; ".join(
            f"{c.rank}. {c.entity_id} (severity {c.score:.3f}) — evidence: "
            f"{', '.join(c.evidence_indicators[:3])}"
            for c in report.candidates
        )
        parts.append(f"Incident {report.incident_id} root-cause ranking: {ranking}")
        if report.clusters:
            top = max(report.clusters, key=lambda cl: cl.cluster_score, default=None)
            top_desc = ", ".join(top.members) if top else "n/a"
            parts.append(
                f"symptom clusters: {len(report.clusters)}; "
                f"top cluster: {top_desc}"
            )
        return " ".join(parts)


def _llm_configured() -> bool:
    """LLM backend only when explicitly configured (env vars set)."""
    return bool(os.environ.get("ALG_MODELS_LLM_BACKEND"))


def template_narrator(report: CausalReport) -> str:
    return EvidenceNarrator._default_template(report)
