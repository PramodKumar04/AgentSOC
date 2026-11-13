"""Deterministic incident risk. Inputs are detection findings and validated structure only.

Detection severity and all LLM output are deliberately not inputs. A connected graph
raises the score only through bounded components and can never reach High by itself.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentsoc.detection.catalog import RuleId
from agentsoc.detection.config import DetectionConfig
from agentsoc.risk.config import RiskConfig
from agentsoc.risk.ledger import (
    BREADTH,
    CREDENTIAL,
    DEPTH,
    FAILURE_RULES,
    NOVELTY,
    NOVELTY_RULES,
    SENSITIVE,
    Selection,
    cited_by,
    has_continuous_observed_route,
    select_attribution,
)
from agentsoc.schemas import Incident, Severity
from agentsoc.schemas.graph import EdgeKind, Feasibility, PathKind, StructuralAssessment
from agentsoc.schemas.risk import IncidentRiskAssessment, RiskComponent
from agentsoc.schemas.rsem import AdjustmentKind, EvidenceAttribution, ScoreAdjustment

CAP_MARGIN = 0.1  # caps sit just under a band boundary


@dataclass(frozen=True)
class RiskResult:
    assessment: IncidentRiskAssessment
    base_score: float
    adjustments: list[ScoreAdjustment]
    selection: Selection
    attributions: list[EvidenceAttribution]
    sensitive_value: float
    credential_value: float


def credential_value(
    incident: Incident, assessment: StructuralAssessment, config: RiskConfig
) -> float:
    """Highest applicable value, never a sum: the two rules share their failures."""
    attempts = {e.event_id for e in assessment.edges if e.kind is EdgeKind.ATTEMPT}
    rules = {f.rule_id for f in incident.findings if set(f.event_ids) & attempts}
    if RuleId.FAIL_THEN_SUCCESS.value in rules:
        return config.fail_then_success_value
    return config.failure_burst_value if RuleId.FAILURE_BURST.value in rules else 0.0


def sensitive_value(
    assessment: StructuralAssessment, detection_config: DetectionConfig, config: RiskConfig
) -> float:
    """A property of the host reached, not an event count, so it credits no event."""
    sensitive = set(detection_config.sensitive_host_access.hosts)
    best = 0.0
    for path in assessment.paths:
        if set(path.hosts[1:]) & sensitive:
            if path.kind is PathKind.OBSERVED:
                value = config.sensitive_observed_value
            elif any(k.ambiguous for k in path.links):
                value = config.sensitive_ambiguous_value
            else:
                value = config.sensitive_inferred_value
            best = max(best, value)
    return best


def _quality_factor(assessment: StructuralAssessment, config: RiskConfig) -> float:
    factor = 1.0
    if assessment.missing_event_ids:
        factor -= config.missing_evidence_penalty
    if assessment.stats.truncated:
        factor -= config.truncated_context_penalty
    if any(v.verdict is Feasibility.INFEASIBLE for v in assessment.finding_validations):
        factor -= config.infeasible_finding_penalty
    return max(factor, config.quality_floor)


def _attributions(
    incident: Incident, assessment: StructuralAssessment, selection: Selection
) -> list[EvidenceAttribution]:
    edges = {e.event_id: e for e in assessment.edges}
    credit: dict[str, str] = {}
    for event_id in cited_by(incident, FAILURE_RULES):
        if event_id in edges and edges[event_id].kind is EdgeKind.ATTEMPT:
            credit[event_id] = CREDENTIAL
    if selection.route:
        credit.update(dict.fromkeys(selection.route.event_ids, DEPTH))
    credit.update(dict.fromkeys(selection.breadth_ids, BREADTH))
    credit.update(dict.fromkeys(selection.novelty_ids, NOVELTY))
    return [EvidenceAttribution(event_id=e, component=c) for e, c in sorted(credit.items())]


def _clip(text: str) -> str:
    return text if len(text) <= 300 else text[:297] + "..."


def score_incident(
    incident: Incident, assessment: StructuralAssessment,
    detection_config: DetectionConfig, config: RiskConfig,
) -> RiskResult:
    selection = select_attribution(incident, assessment, detection_config, config)
    weights = config.weights
    credential = credential_value(incident, assessment, config)
    sensitive = sensitive_value(assessment, detection_config, config)
    route = selection.route
    route_text = (f"{' > '.join(route.hosts)} ({route.kind.value.lower()}, "
                  f"{route.effective_hops:g} effective hops)" if route else "no multi-hop route")
    components = [
        RiskComponent(name=CREDENTIAL, value=credential, weight=weights.credential_pressure,
                      explanation="Repeated failed authentication; strongest applicable rule, "
                                  "not a sum."),
        RiskComponent(name=NOVELTY, value=selection.novelty_value, weight=weights.access_novelty,
                      explanation=f"{len(selection.novelty_ids)} first-seen event(s) not credited "
                                  "elsewhere."),
        RiskComponent(name=DEPTH, value=selection.depth_value, weight=weights.movement_depth,
                      explanation=_clip(f"Selected route: {route_text}.")),
        RiskComponent(name=BREADTH, value=selection.breadth_value,
                      weight=weights.sequence_breadth,
                      explanation=f"{len(selection.breadth_ids)} connected suspicious event(s) "
                                  "off the route."),
        RiskComponent(name=SENSITIVE, value=sensitive, weight=weights.sensitive_exposure,
                      explanation="Highest exposure of a configured sensitive host; observed "
                                  "paths count most."),
    ]
    base = 100 * sum(c.contribution for c in components)
    adjustments: list[ScoreAdjustment] = []
    current = base

    def step(name: str, kind: AdjustmentKind, value: float, explanation: str) -> None:
        nonlocal current
        after = current * value if kind is AdjustmentKind.FACTOR else min(current, value)
        if after != current:
            adjustments.append(ScoreAdjustment(name=name, kind=kind, value=value, before=current,
                                               after=after, explanation=explanation))
            current = after

    step("evidence_quality", AdjustmentKind.FACTOR, _quality_factor(assessment, config),
         "Reduced for missing evidence, truncated context or an unsupported finding.")
    if incident.principal_user in detection_config.admin_users and sensitive == 0:
        step("admin_context", AdjustmentKind.FACTOR, config.admin_factor,
             "Configured administrative account with no sensitive host exposed.")
    edge_ids = {e.event_id for e in assessment.edges}
    corroborated = (credential > 0 or sensitive > 0
                    or bool(cited_by(incident, NOVELTY_RULES) & edge_ids))
    if not corroborated:
        step("uncorroborated_structure", AdjustmentKind.CAP, config.bands.high_at - CAP_MARGIN,
             "Graph structure alone cannot reach High.")
    if not has_continuous_observed_route(assessment):
        step("no_observed_route", AdjustmentKind.CAP, config.bands.critical_at - CAP_MARGIN,
             "No observed multi-hop route, so this cannot reach Critical.")

    score = round(current, 1)
    return RiskResult(
        assessment=IncidentRiskAssessment(
            incident_id=incident.incident_id, score=score, band=config.bands.band(score),
            components=components,
        ),
        base_score=base, adjustments=adjustments, selection=selection,
        attributions=_attributions(incident, assessment, selection),
        sensitive_value=sensitive, credential_value=credential,
    )


def compare_with_severity(detection: Severity, band: Severity, order: list[Severity]) -> tuple:
    if detection is band:
        return ("SAME", "Detection severity and evidence-supported risk fall in the same band.")
    if order.index(band) > order.index(detection):
        return ("RISK_HIGHER", "Structural evidence supports more risk than rule points alone.")
    return ("RISK_LOWER", "Rule points overlap or lack structural support; severity stays visible.")
