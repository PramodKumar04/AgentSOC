"""Investigation confidence: how far the risk assessment can be relied on.

Deterministic, from verifiable evidence. Incomplete baseline coverage lowers confidence
here and never raises risk. The LLM's numeric confidence is not an input.
"""

from __future__ import annotations

from collections.abc import Collection

from agentsoc.detection.config import DetectionConfig
from agentsoc.risk.config import RiskConfig
from agentsoc.schemas import Feasibility, Incident, InvestigationResult
from agentsoc.schemas.graph import StructuralAssessment
from agentsoc.schemas.risk import RiskComponent
from agentsoc.schemas.rsem import ConfidenceAssessment, ConfidenceLevel

NOT_APPLICABLE = 0.5
INJECTION_MARKER = "prompt-injection"


def structural_support(assessment: StructuralAssessment) -> float:
    """1 for FEASIBLE findings, half for conditional, 0 for infeasible; neutral if none."""
    points = {Feasibility.FEASIBLE: 1.0, Feasibility.CONDITIONALLY_FEASIBLE: 0.5,
              Feasibility.INFEASIBLE: 0.0}
    items = assessment.finding_validations
    return sum(points[v.verdict] for v in items) / len(items) if items else NOT_APPLICABLE


def baseline_coverage(
    incident: Incident, detection_config: DetectionConfig,
    users_without_baseline: Collection[str], config: RiskConfig,
) -> float:
    if incident.principal_user in users_without_baseline:
        return 0.0
    return min(1.0, detection_config.baseline_seconds / config.full_baseline_seconds)


def investigation_quality(result: InvestigationResult | None, config: RiskConfig) -> float:
    """Facts about how the investigation was produced; never the model's own estimates."""
    if result is None:
        return 0.0
    quality = (config.llm_investigation_quality if result.source.value == "llm"
               else config.fallback_investigation_quality)
    verdicts = [v.verdict for v in result.path_validations]
    if verdicts and Feasibility.INFEASIBLE not in verdicts:
        quality = min(1.0, quality + config.validated_proposals_bonus)
    if Feasibility.INFEASIBLE in verdicts:
        quality = max(0.0, quality - config.unsupported_proposal_penalty)
    if any(INJECTION_MARKER in w for w in result.warnings):
        quality = min(quality, config.injection_flag_quality_cap)
    return quality


def confidence_level(score: float, config: RiskConfig) -> ConfidenceLevel:
    if score >= config.confidence_high_at:
        return ConfidenceLevel.HIGH
    return (ConfidenceLevel.MODERATE if score >= config.confidence_moderate_at
            else ConfidenceLevel.LOW)


def assess_confidence(
    incident: Incident, assessment: StructuralAssessment, detection_config: DetectionConfig,
    users_without_baseline: Collection[str], config: RiskConfig,
    investigation: InvestigationResult | None = None,
) -> ConfidenceAssessment:
    weights = config.confidence
    cited = len(incident.event_ids)
    missing = len(assessment.missing_event_ids)
    found = (cited - missing) / cited if cited else 0.0
    components = [
        RiskComponent(name="evidence_found", value=found, weight=weights.evidence_found,
                      explanation=f"{cited - missing} of {cited} cited events were found."),
        RiskComponent(name="structural_support", value=structural_support(assessment),
                      weight=weights.structural_support,
                      explanation="How well movement findings were validated edge by edge."),
        RiskComponent(name="baseline_coverage",
                      value=baseline_coverage(incident, detection_config, users_without_baseline,
                                              config),
                      weight=weights.baseline_coverage,
                      explanation="How much behavioural baseline supports the first-seen rules."),
        RiskComponent(name="context_complete",
                      value=0.5 if assessment.stats.truncated else 1.0,
                      weight=weights.context_complete,
                      explanation="Whether surrounding context was truncated."),
        RiskComponent(name="investigation_quality",
                      value=investigation_quality(investigation, config),
                      weight=weights.investigation_quality,
                      explanation="How the investigation was produced and whether its proposed "
                                  "paths held up."),
    ]
    score = round(100 * sum(c.contribution for c in components), 1)
    return ConfidenceAssessment(
        score=score, level=confidence_level(score, config), components=components,
        includes_investigation=investigation is not None,
    )
