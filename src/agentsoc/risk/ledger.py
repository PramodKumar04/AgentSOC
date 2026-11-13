"""Evidence attribution: every event is credited to at most one risk component.

Failed attempts go to credential pressure. A hop on the selected route goes to movement
depth. Other movement events connected to that route can go to sequence breadth, and
first-seen events left over go to access novelty.

The attribution chosen is the one with the highest value among all allowed ones. Removing
evidence can only shrink that set of choices, so it can never raise the value. A simple
"off-route events count as novelty" rule would break that: shortening a saturated route
would release its events to novelty and raise the score.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from agentsoc.detection.catalog import RuleId
from agentsoc.detection.config import DetectionConfig
from agentsoc.detection.lateral import account_name
from agentsoc.risk.config import RiskConfig
from agentsoc.schemas import Incident
from agentsoc.schemas.graph import (
    EdgeKind,
    GraphEdge,
    LinkBasis,
    PathKind,
    StructuralAssessment,
    StructuralPath,
)

FAILURE_RULES = {RuleId.FAILURE_BURST.value, RuleId.FAIL_THEN_SUCCESS.value}
NOVELTY_RULES = {RuleId.NEW_SRC_HOST.value, RuleId.NEW_DST_HOST.value,
                 RuleId.MULTI_HOST_SPREAD.value, RuleId.SENSITIVE_HOST_ACCESS.value}
CREDENTIAL, NOVELTY, DEPTH, BREADTH, SENSITIVE = (
    "credential_pressure", "access_novelty", "movement_depth", "sequence_breadth",
    "sensitive_exposure",
)


@dataclass(frozen=True)
class Route:
    event_ids: tuple[str, ...]
    hosts: tuple[str, ...]
    kind: PathKind
    effective_hops: float
    source_path_id: str
    reduced_jump_route: bool


@dataclass(frozen=True)
class Selection:
    route: Route | None
    depth_value: float
    breadth_value: float
    breadth_ids: tuple[str, ...]
    novelty_value: float
    novelty_ids: tuple[str, ...]


def depth_value(effective_hops: float, config: RiskConfig) -> float:
    """1 hop or fewer: 0. Two hops: the two-hop value. Each further hop adds a step, up to 1."""
    if effective_hops <= 1:
        return 0.0
    if effective_hops < 2:
        return config.depth_two_hop_value * (effective_hops - 1)
    return min(1.0, config.depth_two_hop_value
               + config.depth_step_per_hop * (effective_hops - 2))


def _routes_of(
    path: StructuralPath, detection_config: DetectionConfig, config: RiskConfig
) -> list[Route]:
    """Every contiguous stretch of a reported path with at least two hops."""
    routes = []
    sensitive = set(detection_config.sensitive_host_access.hosts)
    count = len(path.event_ids)
    for start in range(count):
        for end in range(start + 2, count + 1):
            links = path.links[start:end - 1]
            switched = any(k.basis is LinkBasis.ACCOUNT_SWITCH for k in links)
            hosts = path.hosts[start:end + 1]
            hops = end - start
            if switched:
                run = longest = 1
                for link in links:
                    run = run + 1 if link.basis is LinkBasis.SAME_ACCOUNT else 1
                    longest = max(longest, run)
                discount = (config.ambiguous_hop_discount if any(k.ambiguous for k in links)
                            else config.inferred_hop_discount)
                effective = longest + (hops - longest) * discount
            else:
                effective = float(hops)
            routes.append(Route(
                event_ids=tuple(path.event_ids[start:end]), hosts=tuple(hosts),
                kind=PathKind.INFERRED if switched else PathKind.OBSERVED,
                effective_hops=effective, source_path_id=path.path_id,
                reduced_jump_route=(
                    all(detection_config.is_jump_host(h) for h in hosts[1:-1])
                    and not sensitive & set(hosts)
                ),
            ))
    return routes


def candidate_routes(
    assessment: StructuralAssessment, detection_config: DetectionConfig, config: RiskConfig
) -> list[Route]:
    unique: dict[tuple[str, ...], Route] = {}
    for path in assessment.paths:
        for route in _routes_of(path, detection_config, config):
            unique.setdefault(route.event_ids, route)
    return [unique[k] for k in sorted(unique)]


def route_value(route: Route, config: RiskConfig) -> float:
    value = depth_value(route.effective_hops, config)
    return value * config.jump_route_factor if route.reduced_jump_route else value


def cited_by(incident: Incident, rules: set[str]) -> set[str]:
    return {e for f in incident.findings if f.rule_id in rules for e in f.event_ids}


def _best_for_route(
    route: Route | None, edges: Mapping[str, GraphEdge], novel: set[str],
    assessment: StructuralAssessment, supported: set[str], config: RiskConfig,
) -> tuple[float, Selection]:
    weights = config.weights
    on_route = set(route.event_ids) if route else set()
    depth = route_value(route, config) if route else 0.0
    eligible: list[str] = []
    if route:
        for sequence in assessment.sequences:
            if on_route & set(sequence.event_ids):
                eligible += [e for e in sequence.event_ids if e not in on_route and e in edges]
    accounts = {account_name(edges[e].account) for e in on_route}
    full = sorted(e for e in eligible if account_name(edges[e].account) in accounts)
    # Another account's event counts only with positive support: a busy shared host
    # connects many unrelated accounts, and that must not add risk.
    half = sorted(e for e in eligible
                  if account_name(edges[e].account) not in accounts and e in supported)
    # Events already novel are the last to move: breadth then costs novelty nothing.
    full.sort(key=lambda e: e in novel)
    half.sort(key=lambda e: e in novel)
    saturation = config.breadth_saturation_events
    switch_credit = config.breadth_account_switch_credit
    max_half = (min(len(half), int(saturation / switch_credit) + 1)
                if switch_credit > 0 else 0)
    available_novel = novel - on_route
    best_total, best = -1.0, None
    for use_full in range(min(len(full), saturation) + 1):
        for use_half in range(max_half + 1):
            chosen = full[:use_full] + half[:use_half]
            breadth = min(1.0, (use_full + use_half * switch_credit) / saturation)
            novelty_ids = available_novel - set(chosen)
            novelty = min(1.0, len(novelty_ids) / config.novelty_saturation_events)
            total = (weights.movement_depth * depth + weights.sequence_breadth * breadth
                     + weights.access_novelty * novelty)
            if total > best_total + 1e-12:
                best_total = total
                best = Selection(route, depth, breadth, tuple(sorted(chosen)), novelty,
                                 tuple(sorted(novelty_ids)))
    return best_total, best


def select_attribution(
    incident: Incident, assessment: StructuralAssessment,
    detection_config: DetectionConfig, config: RiskConfig,
) -> Selection:
    """The highest-value allowed attribution; ties prefer longer, then observed, routes."""
    edges = {e.event_id: e for e in assessment.edges}
    novel = {e for e in cited_by(incident, NOVELTY_RULES)
             if e in edges and edges[e].kind is not EdgeKind.ATTEMPT}
    supported = {e for p in assessment.paths
                 if p.kind is PathKind.INFERRED and not any(k.ambiguous for k in p.links)
                 for e in p.event_ids}
    best_total, best = _best_for_route(None, edges, novel, assessment, supported, config)
    best_key = (best_total, 0, 0, ())
    for route in candidate_routes(assessment, detection_config, config):
        total, selection = _best_for_route(route, edges, novel, assessment, supported, config)
        key = (round(total, 12), len(route.event_ids), route.kind is PathKind.OBSERVED,
               route.event_ids)
        if key[:3] > (round(best_key[0], 12), best_key[1], best_key[2]) or (
            key[:3] == (round(best_key[0], 12), best_key[1], best_key[2])
            and key[3] < best_key[3]
        ):
            best, best_key = selection, key
    return best


def has_continuous_observed_route(assessment: StructuralAssessment) -> bool:
    return any(p.kind is PathKind.OBSERVED and len(p.event_ids) >= 2 for p in assessment.paths)
