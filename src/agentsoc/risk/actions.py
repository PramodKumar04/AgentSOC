"""Response proposals, ranked by the paper's Eq. 1: priority = alpha*C - beta*I.

Priority ranks actions; it is computed after the risk and never changes it. Every action
stays PROPOSED and dry-run: nothing here can execute. Targets come only from the
validated evidence, never from LLM text. Destructive actions are withheld, with reasons,
unless the risk, the confidence and the observed evidence all support them.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentsoc.detection.config import DetectionConfig
from agentsoc.risk.config import RiskConfig
from agentsoc.risk.score import RiskResult
from agentsoc.schemas import Incident, Severity
from agentsoc.schemas.graph import PathKind, StructuralAssessment
from agentsoc.schemas.response import ActionType, ResponseAction
from agentsoc.schemas.risk import ActionScore
from agentsoc.schemas.rsem import ConfidenceAssessment, WithheldAction

DESTRUCTIVE = (ActionType.ISOLATE_HOST, ActionType.DISABLE_ACCOUNT, ActionType.QUARANTINE_ACCESS)
_BAND_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


@dataclass(frozen=True)
class _Candidate:
    action: ActionType
    target: str
    is_host: bool
    full_coverage: bool
    rationale: str


def _at_least(band: Severity, minimum: Severity) -> bool:
    return _BAND_ORDER.index(band) >= _BAND_ORDER.index(minimum)


def _destructive_gaps(
    result: RiskResult, confidence: ConfidenceAssessment, config: RiskConfig
) -> list[str]:
    gaps = []
    if not _at_least(result.assessment.band, Severity.HIGH):
        gaps.append("Risk is below High.")
    if confidence.score < config.destructive_min_confidence:
        gaps.append(f"Investigation confidence is below {config.destructive_min_confidence:g}.")
    route = result.selection.route
    if route is None or route.kind is not PathKind.OBSERVED:
        gaps.append("No observed multi-hop route supports it.")
    return gaps


def _host_target(result: RiskResult, assessment: StructuralAssessment) -> tuple[str, bool] | None:
    """A host every observed route must cross if one exists, else the route's first transit."""
    route = result.selection.route
    if route is None:
        return None
    for point in assessment.choke_points:
        for host in point.via_hosts:
            if host in route.hosts:
                return host, True
    return route.hosts[1], False


def _candidates(
    incident: Incident, result: RiskResult, assessment: StructuralAssessment,
    detection_config: DetectionConfig,
) -> list[_Candidate]:
    user, band = incident.principal_user, result.assessment.band
    route = result.selection.route
    out = [_Candidate(ActionType.MONITOR_ONLY, user, False, True,
                      "Keep watching this account while the incident is reviewed.")]
    if result.credential_value > 0 or result.selection.novelty_ids:
        out.append(_Candidate(ActionType.ENABLE_MFA, user, False, False,
                              "Failed or first-seen authentication was recorded for this account."))
    if _at_least(band, Severity.MEDIUM):
        out.append(_Candidate(ActionType.REVOKE_SESSION, user, False, route is not None,
                              "Evidence-supported risk is Medium or above for this account."))
        if user in detection_config.admin_users or result.sensitive_value > 0:
            out.append(_Candidate(ActionType.RESTRICT_PRIVILEGES, user, False, True,
                                  "The account is administrative or reached a sensitive host."))
    out.append(_Candidate(ActionType.DISABLE_ACCOUNT, user, False, route is not None,
                          "Stops further authentication by the account on this route."))
    target = _host_target(result, assessment)
    if target:
        host, choke = target
        out.append(_Candidate(ActionType.ISOLATE_HOST, host, True, choke,
                              "Host lies on the selected route."))
        out.append(_Candidate(ActionType.QUARANTINE_ACCESS, host, True, choke,
                              "Limits further authentication through this host."))
    return out


def propose_actions(
    incident: Incident, result: RiskResult, confidence: ConfidenceAssessment,
    assessment: StructuralAssessment, detection_config: DetectionConfig, config: RiskConfig,
) -> tuple[list[ResponseAction], list[WithheldAction]]:
    gaps = _destructive_gaps(result, confidence, config)
    sensitive = set(detection_config.sensitive_host_access.hosts)
    admins = set(detection_config.admin_users)
    scored: list[tuple[float, _Candidate, ActionScore]] = []
    withheld: list[WithheldAction] = []
    for candidate in _candidates(incident, result, assessment, detection_config):
        if candidate.action in DESTRUCTIVE and gaps:
            withheld.append(WithheldAction(action_type=candidate.action, reasons=gaps))
            continue
        profile = config.actions[candidate.action]
        containment = profile.containment * (
            1.0 if candidate.full_coverage else config.partial_coverage)
        impact = profile.business_impact
        if candidate.is_host and candidate.target in sensitive:
            impact += config.sensitive_host_impact
        if not candidate.is_host and candidate.target in admins:
            impact += config.admin_account_impact
        action_score = ActionScore.compute(containment, min(1.0, impact), config.alpha,
                                           config.beta)
        scored.append((action_score.composite, candidate, action_score))
    scored.sort(key=lambda item: (-item[0], item[1].action.value))
    return [
        ResponseAction(
            action_id=f"A-{incident.incident_id}-{n}", incident_id=incident.incident_id,
            action_type=candidate.action, target=candidate.target, rationale=candidate.rationale,
            requires_approval=candidate.action is not ActionType.MONITOR_ONLY, score=action_score,
        )
        for n, (_, candidate, action_score) in enumerate(scored[:config.max_actions], start=1)
    ], withheld
