"""Investigator Agent (NCE) output.

Per the paper (Sec. III-B), each hypothesis carries a confidence score, an
evidence explanation, missing context, and MITRE ATT&CK anchors. We add
explicit benign hypotheses and evidence citations by event ID.

Whether cited event IDs actually belong to the incident is checked by the
investigator against the Incident (Phase 3) — this schema cannot know them.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import AwareDatetime, Field, StringConstraints, model_validator

from agentsoc.schemas.common import Contract, Identifier, LongText, ShortText, UnitInterval

AttackTechniqueId = Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")]


class HypothesisKind(StrEnum):
    MALICIOUS = "MALICIOUS"
    BENIGN = "BENIGN"


class Hypothesis(Contract):
    hypothesis_id: Identifier
    kind: HypothesisKind
    title: ShortText
    narrative: LongText
    attack_techniques: list[AttackTechniqueId] = Field(default_factory=list, max_length=10)
    # Ordered node IDs (users/hosts) the scenario traverses; validated by SSE, not trusted here.
    proposed_path: list[Identifier] = Field(default_factory=list, max_length=20)
    supporting_event_ids: list[Identifier] = Field(default_factory=list)
    contradicting_event_ids: list[Identifier] = Field(default_factory=list)
    missing_information: list[ShortText] = Field(default_factory=list, max_length=10)
    confidence: UnitInterval

    @model_validator(mode="after")
    def _check_kind(self) -> Hypothesis:
        if self.kind is HypothesisKind.BENIGN and self.attack_techniques:
            raise ValueError("benign hypotheses must not carry ATT&CK techniques")
        overlap = set(self.supporting_event_ids) & set(self.contradicting_event_ids)
        if overlap:
            raise ValueError(f"events both support and contradict: {sorted(overlap)}")
        return self


class InvestigationSource(StrEnum):
    LLM = "llm"
    FALLBACK = "fallback"


class InvestigationResult(Contract):
    incident_id: Identifier
    hypotheses: list[Hypothesis] = Field(min_length=1, max_length=10)
    source: InvestigationSource
    provider: Identifier | None = None
    model: Identifier | None = None
    latency_ms: float = Field(ge=0)
    warnings: list[ShortText] = Field(default_factory=list)
    created_at: AwareDatetime

    @model_validator(mode="after")
    def _check_result(self) -> InvestigationResult:
        ids = [h.hypothesis_id for h in self.hypotheses]
        if len(set(ids)) != len(ids):
            raise ValueError("hypothesis_id values must be unique")
        # Design requirement: every investigation must weigh a benign explanation.
        if not any(h.kind is HypothesisKind.BENIGN for h in self.hypotheses):
            raise ValueError("at least one BENIGN hypothesis is required")
        if self.source is InvestigationSource.LLM and not (self.provider and self.model):
            raise ValueError("LLM results must record provider and model")
        return self
