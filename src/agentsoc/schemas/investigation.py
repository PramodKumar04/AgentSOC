"""Investigator Agent (NCE) output.

Per the paper (Sec. III-B), each hypothesis carries a confidence score, an
evidence explanation, missing context, and MITRE ATT&CK anchors. We add
explicit benign hypotheses, per-event evidence notes, and a conclusion that
cannot represent proof of compromise (`is_proof_of_compromise: Literal[False]`).

Confidence values are investigative estimates, NOT calibrated probabilities.

Whether cited event IDs actually belong to the incident is checked by the
investigator against the Incident (`investigator.grounding`) — this schema
cannot know them; it only checks internal consistency.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, StringConstraints, model_validator

from agentsoc.schemas.common import Contract, Identifier, LongText, ShortText, UnitInterval

AttackTechniqueId = Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")]
# Model names such as "openai/gpt-oss-120b" contain "/", which Identifier forbids.
ModelId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._/:\-]{1,128}$")]
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class HypothesisKind(StrEnum):
    MALICIOUS = "MALICIOUS"
    BENIGN = "BENIGN"


class EvidenceNote(Contract):
    """Why one cited event matters to a hypothesis."""

    event_id: Identifier
    relevance: ShortText


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
    evidence_notes: list[EvidenceNote] = Field(default_factory=list, max_length=40)
    missing_information: list[ShortText] = Field(default_factory=list, max_length=10)
    confidence: UnitInterval

    @model_validator(mode="after")
    def _check_kind(self) -> Hypothesis:
        if self.kind is HypothesisKind.BENIGN and self.attack_techniques:
            raise ValueError("benign hypotheses must not carry ATT&CK techniques")
        overlap = set(self.supporting_event_ids) & set(self.contradicting_event_ids)
        if overlap:
            raise ValueError(f"events both support and contradict: {sorted(overlap)}")
        cited = set(self.supporting_event_ids) | set(self.contradicting_event_ids)
        unexplained = {n.event_id for n in self.evidence_notes} - cited
        if unexplained:
            raise ValueError(f"evidence notes reference uncited events: {sorted(unexplained)}")
        return self


class InvestigationConclusion(Contract):
    most_plausible_hypothesis_id: Identifier
    summary: LongText
    confidence: UnitInterval
    uncertainty: LongText
    alternative_hypothesis_ids: list[Identifier] = Field(default_factory=list)
    next_steps: list[ShortText] = Field(min_length=1, max_length=10)
    evidence_gaps: list[ShortText] = Field(default_factory=list, max_length=15)
    # An investigation recommends; it never proves compromise.
    is_proof_of_compromise: Literal[False] = False


class InvestigationSource(StrEnum):
    LLM = "llm"
    FALLBACK = "fallback"


class InvestigationResult(Contract):
    incident_id: Identifier
    # SHA-256 of the exact Incident JSON investigated; binds the result to that incident.
    incident_sha256: Sha256Hex
    hypotheses: list[Hypothesis] = Field(min_length=1, max_length=10)
    conclusion: InvestigationConclusion
    source: InvestigationSource
    provider: Identifier | None = None
    model: ModelId | None = None
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
        c = self.conclusion
        known = set(ids)
        if c.most_plausible_hypothesis_id not in known:
            raise ValueError("conclusion names an unknown most plausible hypothesis")
        if not set(c.alternative_hypothesis_ids) <= known:
            raise ValueError("conclusion names unknown alternative hypotheses")
        if c.most_plausible_hypothesis_id in c.alternative_hypothesis_ids:
            raise ValueError("most plausible hypothesis cannot also be an alternative")
        return self
