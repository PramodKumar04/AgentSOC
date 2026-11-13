"""Independent verification of a stored risk record.

Recomputes every number from the stored breakdown and the incident's structural evidence,
with plain arithmetic. It shares no code with the ledger, the scorer or the action ranker,
so a bug or an edit there cannot vouch for itself. Run before any score is served.
"""

from __future__ import annotations

import hashlib
import math

from agentsoc.detection.config import DetectionConfig
from agentsoc.exceptions import AgentSOCError
from agentsoc.risk.config import RiskConfig
from agentsoc.schemas import Incident, Severity
from agentsoc.schemas.graph import EdgeKind, StructuralAssessment
from agentsoc.schemas.response import ActionStatus, ActionType
from agentsoc.schemas.rsem import IncidentRiskRecord

_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_GATED = {ActionType.ISOLATE_HOST, ActionType.DISABLE_ACCOUNT, ActionType.QUARANTINE_ACCESS}
_EPS = 1e-6


class RiskVerificationError(AgentSOCError):
    """A stored risk record is not reproducible from its evidence."""


def _fail(record: IncidentRiskRecord, message: str) -> None:
    raise RiskVerificationError(f"{record.incident_id}: {message}")


def _sha(model) -> str:
    return hashlib.sha256(model.model_dump_json().encode("utf-8")).hexdigest()


def _expected_depth(effective: float, config: RiskConfig) -> float:
    if effective <= 1:
        return 0.0
    two = config.depth_two_hop_value
    return two * (effective - 1) if effective < 2 else min(
        1.0, two + config.depth_step_per_hop * (effective - 2))


def _check_ledger(record, incident, assessment, components, detection, config) -> None:
    edges = {e.event_id: e for e in assessment.edges}
    by_component: dict[str, list[str]] = {}
    for item in record.attributions:
        if item.event_id not in edges:
            _fail(record, f"credited event {item.event_id} is not on the graph")
        by_component.setdefault(item.component, []).append(item.event_id)
    for event_id in by_component.get("credential_pressure", []):
        if edges[event_id].kind is not EdgeKind.ATTEMPT:
            _fail(record, f"{event_id} is credited to credential pressure but is not a failure")
    route = record.route
    route_ids = by_component.get("movement_depth", [])
    if route is None:
        if route_ids:
            _fail(record, "movement credit without a route")
        if not math.isclose(components["movement_depth"].value, 0.0, abs_tol=_EPS):
            _fail(record, "movement value without a route")
    else:
        if sorted(route_ids) != sorted(route.event_ids):
            _fail(record, "route events and movement credit disagree")
        source = next((p for p in assessment.paths if p.path_id == route.source_path_id), None)
        if source is None or not _is_stretch(route.event_ids, source.event_ids):
            _fail(record, "route is not a stretch of a reported path")
        for a, b in zip(route.event_ids, route.event_ids[1:], strict=False):
            if edges[a].dst_host != edges[b].src_host or edges[a].timestamp >= edges[b].timestamp:
                _fail(record, "route is not continuous in host and time")
        value = _expected_depth(route.effective_hops, config)
        if route.reduced_jump_route:
            value *= config.jump_route_factor
        if not math.isclose(components["movement_depth"].value, value, abs_tol=_EPS):
            _fail(record, "movement value does not follow from the route")
    novelty = len(by_component.get("access_novelty", []))
    expected = min(1.0, novelty / config.novelty_saturation_events)
    if not math.isclose(components["access_novelty"].value, expected, abs_tol=_EPS):
        _fail(record, "novelty value does not follow from its credited events")
    if record.incident_id != incident.incident_id:
        _fail(record, "record belongs to another incident")
    if detection is None:
        _fail(record, "detection configuration is required")


def _is_stretch(part, whole) -> bool:
    size = len(part)
    return any(list(whole[k:k + size]) == list(part) for k in range(len(whole) - size + 1))


def _check_actions(record, incident, assessment, config) -> None:
    allowed = {incident.principal_user} | {h for e in assessment.edges
                                           for h in (e.src_host, e.dst_host)}
    for action in record.actions:
        if action.status is not ActionStatus.PROPOSED or action.dry_run is not True:
            _fail(record, f"{action.action_id} is not a proposed dry-run action")
        if action.target not in allowed:
            _fail(record, f"{action.action_id} targets something outside the evidence")
        if action.requires_approval != (action.action_type is not ActionType.MONITOR_ONLY):
            _fail(record, f"{action.action_id} has the wrong approval requirement")
        if action.action_type in _GATED:
            route = record.route
            if (_ORDER.index(record.risk.band) < _ORDER.index(Severity.HIGH)
                    or record.confidence.score < config.destructive_min_confidence
                    or route is None or route.kind != "OBSERVED"):
                _fail(record, f"{action.action_id} bypasses the destructive-action gate")


def verify_record(
    record: IncidentRiskRecord, incident: Incident, assessment: StructuralAssessment,
    detection_config: DetectionConfig, config: RiskConfig,
) -> None:
    """Raise RiskVerificationError unless the record is exactly reproducible."""
    if record.incident_sha256 != _sha(incident):
        _fail(record, "incident hash does not match")
    if record.structural_sha256 != _sha(assessment):
        _fail(record, "structural assessment hash does not match")
    components = {c.name: c for c in record.risk.components}
    weights = config.weights.model_dump()
    if set(components) != set(weights):
        _fail(record, "unexpected risk components")
    for name, weight in weights.items():
        if not math.isclose(components[name].weight, weight, abs_tol=_EPS):
            _fail(record, f"{name} does not use the configured weight")
    current = 100 * sum(c.value * c.weight for c in components.values())
    if not math.isclose(current, record.base_score, abs_tol=_EPS):
        _fail(record, "base score is not reproducible")
    for step in record.adjustments:
        current = current * step.value if step.kind == "FACTOR" else min(current, step.value)
        if not math.isclose(current, step.after, abs_tol=_EPS):
            _fail(record, f"{step.name} is not reproducible")
    if not math.isclose(round(current, 1), record.risk.score, abs_tol=_EPS):
        _fail(record, "final score is not reproducible")
    bands = config.bands
    score = record.risk.score
    expected = (Severity.CRITICAL if score >= bands.critical_at else Severity.HIGH
                if score >= bands.high_at else Severity.MEDIUM if score >= bands.medium_at
                else Severity.LOW)
    if record.risk.band is not expected:
        _fail(record, "band does not match the score")
    if record.severity_comparison.detection_severity is not incident.severity:
        _fail(record, "detection severity is misreported")
    seen = [a.event_id for a in record.attributions]
    if len(seen) != len(set(seen)):
        _fail(record, "an event is credited twice")
    _check_ledger(record, incident, assessment, components, detection_config, config)
    _check_actions(record, incident, assessment, config)
    total = 100 * sum(c.value * c.weight for c in record.confidence.components)
    if not math.isclose(round(total, 1), record.confidence.score, abs_tol=_EPS):
        _fail(record, "confidence is not reproducible")
