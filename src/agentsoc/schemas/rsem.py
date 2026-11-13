"""RSEM output for one incident.

Three different numbers, deliberately separate:

  incident risk (0-100)            how much evidence-supported risk this incident shows.
  investigation confidence (0-100) how far that assessment can be relied on.
  action priority (ActionScore)    which proposed response to consider first.

None is a calibrated probability. An action's priority never feeds back into the risk.
Neither score uses the LLM's numeric confidence. Detection severity is reported beside
the risk and is not an input to it.
"""

from __future__ import annotations

import math
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from agentsoc.schemas.audit import Sha256Hex
from agentsoc.schemas.common import Contract, Identifier, Severity, ShortText
from agentsoc.schemas.graph import PathKind
from agentsoc.schemas.response import ActionStatus, ActionType, ResponseAction
from agentsoc.schemas.risk import IncidentRiskAssessment, RiskComponent

TOLERANCE = 1e-6


class AdjustmentKind(StrEnum):
    FACTOR = "FACTOR"
    CAP = "CAP"


class ScoreAdjustment(Contract):
    name: Identifier
    kind: AdjustmentKind
    value: float = Field(ge=0)
    before: float = Field(ge=0, le=100)
    after: float = Field(ge=0, le=100)
    explanation: ShortText

    @model_validator(mode="after")
    def _check(self) -> ScoreAdjustment:
        expected = (self.before * self.value if self.kind is AdjustmentKind.FACTOR
                    else min(self.before, self.value))
        if not math.isclose(self.after, expected, abs_tol=TOLERANCE):
            raise ValueError(f"{self.name}: {self.after} does not follow from {self.before}")
        return self


class EvidenceAttribution(Contract):
    """The single risk component an event is credited to."""

    event_id: Identifier
    component: Identifier


class SelectedRoute(Contract):
    event_ids: list[Identifier] = Field(min_length=2)
    hosts: list[Identifier] = Field(min_length=3)
    kind: PathKind
    effective_hops: float = Field(gt=0)
    source_path_id: Identifier
    reduced_jump_route: bool = False


class ConfidenceLevel(StrEnum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"


class ConfidenceAssessment(Contract):
    score: float = Field(ge=0, le=100)
    level: ConfidenceLevel
    components: list[RiskComponent] = Field(min_length=1)
    includes_investigation: bool = False

    @model_validator(mode="after")
    def _check(self) -> ConfidenceAssessment:
        total = 100 * sum(c.contribution for c in self.components)
        if not math.isclose(self.score, round(total, 1), abs_tol=TOLERANCE):
            raise ValueError("confidence score does not match its components")
        return self


class SeverityComparison(Contract):
    detection_severity: Severity
    risk_band: Severity
    relation: Literal["SAME", "RISK_HIGHER", "RISK_LOWER"]
    explanation: ShortText


class WithheldAction(Contract):
    action_type: ActionType
    reasons: list[ShortText] = Field(min_length=1)


class IncidentRiskRecord(Contract):
    incident_id: Identifier
    incident_sha256: Sha256Hex
    structural_sha256: Sha256Hex
    risk: IncidentRiskAssessment
    base_score: float = Field(ge=0, le=100)
    adjustments: list[ScoreAdjustment] = Field(default_factory=list)
    route: SelectedRoute | None = None
    attributions: list[EvidenceAttribution] = Field(default_factory=list)
    confidence: ConfidenceAssessment
    severity_comparison: SeverityComparison
    actions: list[ResponseAction] = Field(min_length=1)
    withheld_actions: list[WithheldAction] = Field(default_factory=list)
    limitations: list[ShortText] = Field(min_length=1)
    is_proof_of_compromise: Literal[False] = False

    @model_validator(mode="after")
    def _check(self) -> IncidentRiskRecord:
        base = 100 * sum(c.contribution for c in self.risk.components)
        if not math.isclose(self.base_score, base, abs_tol=TOLERANCE):
            raise ValueError("base score does not match its components")
        current = self.base_score
        for step in self.adjustments:
            if not math.isclose(step.before, current, abs_tol=TOLERANCE):
                raise ValueError(f"{step.name} does not continue from the previous step")
            current = step.after
        if not math.isclose(self.risk.score, round(current, 1), abs_tol=TOLERANCE):
            raise ValueError("score does not match its breakdown")
        ids = [a.event_id for a in self.attributions]
        if len(set(ids)) != len(ids):
            raise ValueError("an event can be credited to only one component")
        if self.severity_comparison.risk_band is not self.risk.band:
            raise ValueError("severity comparison disagrees with the risk band")
        priorities = [a.score.composite if a.score else 0.0 for a in self.actions]
        if priorities != sorted(priorities, reverse=True):
            raise ValueError("actions must be ordered by priority")
        if any(a.status is not ActionStatus.PROPOSED for a in self.actions):
            raise ValueError("RSEM can only propose actions")
        return self
