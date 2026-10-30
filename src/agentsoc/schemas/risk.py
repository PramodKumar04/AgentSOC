"""Risk contracts (RSEM).

Two distinct scores, deliberately kept separate:

* `IncidentRiskAssessment` — how dangerous is this incident? (our extension;
  the paper scores actions, not incidents).
* `ActionScore` — the paper's Eq. (1):
      Composite = α × Containment − β × BusinessImpact
  The schema enforces that the stored composite matches the formula, so a
  score can never silently disagree with its own inputs.
"""

from __future__ import annotations

import math

from pydantic import Field, model_validator

from agentsoc.schemas.common import Contract, Identifier, Severity, ShortText, UnitInterval


class RiskComponent(Contract):
    name: Identifier
    value: UnitInterval
    weight: float = Field(ge=0)
    explanation: ShortText

    @property
    def contribution(self) -> float:
        return self.value * self.weight


class IncidentRiskAssessment(Contract):
    incident_id: Identifier
    score: float = Field(ge=0, le=100)
    band: Severity
    components: list[RiskComponent] = Field(min_length=1)


class ActionScore(Contract):
    containment: UnitInterval
    business_impact: UnitInterval
    alpha: float = Field(ge=0)
    beta: float = Field(ge=0)
    composite: float

    @classmethod
    def compute(
        cls, containment: float, business_impact: float, alpha: float, beta: float
    ) -> ActionScore:
        return cls(
            containment=containment,
            business_impact=business_impact,
            alpha=alpha,
            beta=beta,
            composite=alpha * containment - beta * business_impact,
        )

    @model_validator(mode="after")
    def _check_formula(self) -> ActionScore:
        expected = self.alpha * self.containment - self.beta * self.business_impact
        if not math.isclose(self.composite, expected, abs_tol=1e-6):
            raise ValueError(f"composite {self.composite} != α·C − β·I = {expected}")
        return self
