"""Structural validation of one incident against its observed authentication graph.

Paths are extracted from the time-expanded event graph and may run through events no
rule cited. Same-account routes are OBSERVED; routes that need an account switch are
INFERRED. No link is ever created without a shared host and a valid time order.
"""

from __future__ import annotations

import itertools
from collections.abc import Sequence

import networkx as nx

from agentsoc.detection.catalog import RuleId
from agentsoc.graph.build import (
    USER,
    EventGraph,
    build_authentication_graph,
    build_event_graph,
    expand_context,
    movement_view,
    to_edge,
)
from agentsoc.graph.config import StructuralConfig
from agentsoc.graph.index import EventIndex, IndexedEvent
from agentsoc.schemas import Finding, Incident
from agentsoc.schemas.graph import (
    AccountBridge,
    AssessmentStats,
    ChokePoint,
    DisconnectedEvent,
    DisconnectReason,
    Edge,
    EdgeKind,
    Feasibility,
    FindingValidation,
    HopLink,
    LinkBasis,
    MovementSequence,
    PathKind,
    StructuralAssessment,
    StructuralPath,
)
from agentsoc.schemas.incidents import incident_sha256

PATH_RULES = {RuleId.LATERAL_CHAIN.value, RuleId.CROSS_ACCOUNT_PIVOT.value}
LIMITATIONS = (
    "Validated against observed authentication logs only; no enterprise topology is assumed.",
    "A connected path is not evidence of compromise; it shows authentication sequences only.",
    "INFEASIBLE means the required evidence was not observed, not that movement was impossible.",
)
Score = tuple[int, int, int, float]  # hops, -switches, -ambiguous switches, -waiting time


def _clip(text: str) -> str:
    return text if len(text) <= 300 else text[:297] + "..."


def _is_switch(data: dict) -> bool:
    return data["basis"] is LinkBasis.ACCOUNT_SWITCH


def _best_routes(graph) -> tuple[dict, dict, dict, dict]:
    """Longest route ending at and starting from every node; O(V + E) on the DAG."""
    order = list(nx.lexicographical_topological_sort(graph))
    up: dict[str, Score] = {}
    up_from: dict[str, str | None] = {}
    down: dict[str, Score] = {}
    down_to: dict[str, str | None] = {}

    def extend(score: Score, data: dict) -> Score:
        return (score[0] + 1, score[1] - _is_switch(data), score[2] - data["ambiguous"],
                score[3] - data["gap"])

    for node in order:
        best, choice = (1, 0, 0, 0.0), None
        for prior in sorted(graph.predecessors(node)):
            candidate = extend(up[prior], graph[prior][node])
            if candidate > best:
                best, choice = candidate, prior
        up[node], up_from[node] = best, choice
    for node in reversed(order):
        best, choice = (1, 0, 0, 0.0), None
        for next_node in sorted(graph.successors(node)):
            candidate = extend(down[next_node], graph[node][next_node])
            if candidate > best:
                best, choice = candidate, next_node
        down[node], down_to[node] = best, choice
    return up, up_from, down, down_to


def _route_through(anchor: str, up_from: dict, down_to: dict) -> list[str]:
    before: list[str] = []
    node = up_from[anchor]
    while node is not None:
        before.append(node)
        node = up_from[node]
    after: list[str] = []
    node = down_to[anchor]
    while node is not None:
        after.append(node)
        node = down_to[node]
    return [*reversed(before), anchor, *after]


def _contained(short: Sequence[str], long: Sequence[str]) -> bool:
    return any(list(long[k:k + len(short)]) == list(short)
               for k in range(len(long) - len(short) + 1))


def _candidate_routes(graph: nx.DiGraph, anchors: Sequence[str]) -> list[tuple[list[str], bool]]:
    """Best same-account route through each anchor, then any longer cross-account route."""
    same = nx.subgraph_view(graph, filter_edge=lambda a, b: not _is_switch(graph[a][b]))
    _, up_from, _, down_to = _best_routes(same)
    routes: list[tuple[list[str], bool]] = []
    observed_hops: dict[str, int] = {}
    for anchor in anchors:
        route = _route_through(anchor, up_from, down_to)
        observed_hops[anchor] = len(route)
        routes.append((route, False))
    _, up_from, _, down_to = _best_routes(graph)
    for anchor in anchors:
        route = _route_through(anchor, up_from, down_to)
        if len(route) > observed_hops[anchor] and any(
            _is_switch(graph[a][b]) for a, b in itertools.pairwise(route)
        ):
            routes.append((route, True))
    kept: list[tuple[list[str], bool]] = []
    for route, inferred in sorted(routes, key=lambda r: (-len(r[0]), r[1], r[0])):
        if not any(r[1] == inferred and _contained(route, r[0]) for r in kept):
            kept.append((route, inferred))
    return kept


def _make_path(
    route: Sequence[str], inferred: bool, graph: nx.DiGraph,
    rules_by_event: dict[str, set[str]], findings_by_event: dict[str, list[str]],
) -> StructuralPath:
    events: list[IndexedEvent] = [graph.nodes[n]["event"] for n in route]
    hosts = [events[0].src_host, *(e.dst_host for e in events)]
    links, conditions = [], []
    for prior, event in itertools.pairwise(events):
        data = graph[prior.event_id][event.event_id]
        links.append(HopLink(
            from_event_id=prior.event_id, to_event_id=event.event_id, host=data["host"],
            gap_seconds=data["gap"], basis=data["basis"],
            other_accounts_arriving=data["other_accounts"], ambiguous=data["ambiguous"],
        ))
        if _is_switch(data):
            weak = (f" {data['host']} also received other accounts in the window, so this is "
                    "weak evidence." if data["ambiguous"] else "")
            conditions.append(_clip(f"Requires that {prior.account} and {event.account} were "
                                    f"operated by the same party on {data['host']}; the logs do "
                                    f"not show this.{weak}"))
    accounts = list(dict.fromkeys(e.account for e in events))
    seen: set[str] = set()
    revisited = sorted({h for h in hosts if h in seen or seen.add(h)})
    if inferred:
        reasons = ["Each hop was observed, but joining them assumes an account switch."]
    elif len(events) == 1:
        reasons = [_clip(f"One successful authentication by {events[0].account}.")]
    else:
        reasons = [_clip(f"Every hop is a successful authentication by {accounts[0]}, in time "
                         "order, each starting where the previous one ended.")]
    return StructuralPath(
        path_id="P000", kind=PathKind.INFERRED if inferred else PathKind.OBSERVED,
        verdict=(Feasibility.CONDITIONALLY_FEASIBLE if inferred else Feasibility.FEASIBLE),
        event_ids=[e.event_id for e in events], hosts=hosts, accounts=accounts, links=links,
        finding_ids=sorted({f for e in route for f in findings_by_event.get(e, ())}),
        anchor_event_ids=[e for e in route if e in rules_by_event],
        context_event_ids=[e for e in route if e not in rules_by_event],
        revisited_hosts=revisited, conditions=conditions, reasons=reasons,
    )


def _ranked_paths(paths: list[StructuralPath], limit: int) -> tuple[list[StructuralPath], bool]:
    def rank(p: StructuralPath) -> tuple:
        return (p.kind is PathKind.INFERRED, any(k.ambiguous for k in p.links),
                -len(p.event_ids), p.event_ids[0])

    ordered = sorted(paths, key=rank)
    kept = [p.model_copy(update={"path_id": f"P{n:03d}"})
            for n, p in enumerate(ordered[:limit], start=1)]
    return kept, len(ordered) > limit


def _validate_chain(
    finding: Finding, index: EventIndex, config: StructuralConfig
) -> FindingValidation:
    found, missing = _resolve(finding, index)
    hosts: list[str] = [found[0].src_host] if found else []
    edges: list[Edge] = []
    conditions: list[str] = []
    reasons: list[str] = []
    for event in found:
        if event.kind is not EdgeKind.MOVEMENT:
            reasons.append(_clip(f"{event.event_id} is not a successful remote authentication."))
    for prior, event in itertools.pairwise(found):
        if prior.dst_host != event.src_host:
            edges.append(Edge(source=prior.dst_host, target=event.src_host))
            reasons.append(_clip(f"No observed link joins {prior.dst_host} to {event.src_host}."))
        elif event.t < prior.t:
            reasons.append(_clip(f"{event.event_id} happened before {prior.event_id}."))
        elif event.t == prior.t:
            conditions.append(_clip(f"{prior.event_id} and {event.event_id} share one second, "
                                    "so their order is assumed."))
        elif event.t - prior.t > config.max_link_gap_seconds:
            reasons.append(_clip(f"{event.t - prior.t:.0f} s between hops exceeds the "
                                 f"{config.max_link_gap_seconds} s link limit."))
    hosts += [e.dst_host for e in found]
    if missing:
        reasons.append(f"{len(missing)} cited event(s) could not be found in the dataset.")
    if reasons:
        verdict, conditions = Feasibility.INFEASIBLE, []
    elif conditions:
        verdict = Feasibility.CONDITIONALLY_FEASIBLE
        reasons = ["Hops are continuous, but the order of some could not be established."]
    else:
        verdict = Feasibility.FEASIBLE
        reasons = ["Every cited hop is a successful authentication, continuous in host and time."]
    return FindingValidation(
        finding_id=finding.finding_id, rule_id=finding.rule_id, verdict=verdict,
        checked_path=hosts, event_ids=finding.event_ids, missing_event_ids=missing,
        missing_edges=edges, conditions=conditions, reasons=reasons,
    )


def _resolve(finding: Finding, index: EventIndex) -> tuple[list[IndexedEvent], list[str]]:
    found, missing = [], []
    for event_id in finding.event_ids:
        event = index.get(event_id)
        if event is None:
            missing.append(event_id)
        else:
            found.append(event)
    return found, missing


def _validate_pivot(
    finding: Finding, index: EventIndex, config: StructuralConfig
) -> FindingValidation:
    found, missing = _resolve(finding, index)
    reasons: list[str] = []
    conditions: list[str] = []
    edges: list[Edge] = []
    if missing:
        reasons.append(f"{len(missing)} cited event(s) could not be found in the dataset.")
    hosts: list[str] = []
    if len(found) >= 2 and not missing:
        departure, arrivals = found[-1], found[:-1]
        hub = departure.src_host
        hosts = [arrivals[-1].src_host, hub, departure.dst_host]
        for arrival in arrivals:
            gap = departure.t - arrival.t
            if arrival.kind is not EdgeKind.MOVEMENT or departure.kind is not EdgeKind.MOVEMENT:
                reasons.append("A cited event is not a successful remote authentication.")
            elif arrival.dst_host != hub:
                edges.append(Edge(source=arrival.dst_host, target=hub))
                reasons.append(_clip(f"{arrival.event_id} did not arrive on {hub}."))
            elif arrival.account_key == departure.account_key:
                reasons.append(_clip(f"{arrival.event_id} is the same account as the departure."))
            elif gap <= 0 or gap > config.max_link_gap_seconds:
                reasons.append(_clip(f"{arrival.event_id} is outside the time-valid window."))
            else:
                others = index.other_accounts_arriving(
                    hub, departure.t, config.max_link_gap_seconds, departure.account_key,
                    config.ambiguous_link_accounts + 1)
                weak = (" The host received many accounts, so this is weak evidence."
                        if others > config.ambiguous_link_accounts else "")
                conditions.append(_clip(
                    f"Requires that {arrival.account} and {departure.account} were operated by "
                    f"the same party on {hub}; the logs do not show this.{weak}"))
    elif not missing:
        reasons.append("A pivot needs at least one arrival and one departure.")
    if reasons:
        verdict, conditions = Feasibility.INFEASIBLE, []
    else:
        verdict = Feasibility.CONDITIONALLY_FEASIBLE
        reasons = ["Both authentications were observed; linking them assumes an account switch."]
    return FindingValidation(
        finding_id=finding.finding_id, rule_id=finding.rule_id, verdict=verdict,
        checked_path=hosts, event_ids=finding.event_ids, missing_event_ids=missing,
        missing_edges=edges, conditions=list(dict.fromkeys(conditions)), reasons=reasons,
    )


def _claimed_events(finding: Finding) -> set[str]:
    if finding.rule_id == RuleId.CROSS_ACCOUNT_PIVOT.value:
        return {str(finding.metrics["arrival_event_id"]),
                str(finding.metrics["departure_event_id"])}
    return set(finding.event_ids)


def _with_extensions(
    validations: list[FindingValidation], findings: dict[str, Finding],
    paths: list[StructuralPath],
) -> list[FindingValidation]:
    out = []
    for item in validations:
        claimed = _claimed_events(findings[item.finding_id])
        extended = [p.path_id for p in paths
                    if claimed < set(p.event_ids)]
        out.append(item.model_copy(update={"extended_by": extended}))
    return out


def _disconnected(
    seeds: Sequence[IndexedEvent], graph: nx.DiGraph, index: EventIndex, config: StructuralConfig,
) -> tuple[list[MovementSequence], list[DisconnectedEvent], list[IndexedEvent], bool]:
    """Group the suspicious movement events and explain any that do not connect."""
    component_of: dict[str, int] = {}
    for number, nodes in enumerate(nx.weakly_connected_components(graph)):
        for node in nodes:
            component_of[node] = number
    same = nx.subgraph_view(graph, filter_edge=lambda a, b: not _is_switch(graph[a][b]))
    same_of: dict[str, int] = {}
    for number, nodes in enumerate(nx.weakly_connected_components(same)):
        for node in nodes:
            same_of[node] = number
    groups: dict[int, list[IndexedEvent]] = {}
    for seed in sorted(seeds, key=lambda e: e.order):
        groups.setdefault(component_of[seed.event_id], []).append(seed)
    ordered = sorted(groups.values(), key=lambda g: (-len(g), g[0].order))
    sequences = [
        MovementSequence(
            sequence_id=f"S{n:02d}", event_ids=[e.event_id for e in group],
            hosts=sorted({h for e in group for h in (e.src_host, e.dst_host)}),
            requires_account_switch=len({same_of[e.event_id] for e in group}) > 1,
        ) for n, group in enumerate(ordered, start=1)
    ]
    if len(ordered) < 2:
        return sequences, [], [], False
    results: list[DisconnectedEvent] = []
    attempts: dict[str, IndexedEvent] = {}
    limit = config.max_anchors_compared
    outside_main = [e for group in ordered[1:] for e in group]
    cut = len(outside_main) > limit or len(seeds) > limit
    compared = list(sorted(seeds, key=lambda e: e.order))[:limit]
    for event in outside_main[:limit]:
        others = [o for o in compared if component_of[o.event_id] != component_of[event.event_id]]
        results.append(_explain(event, others, index, config, attempts))
    return sequences, results, list(attempts.values()), cut


def _explain(
    event: IndexedEvent, others: Sequence[IndexedEvent], index: EventIndex,
    config: StructuralConfig, attempts: dict[str, IndexedEvent],
) -> DisconnectedEvent:
    gap = config.max_link_gap_seconds
    time_order = gap_exceeded = None
    for other in others:
        for first, second in ((event, other), (other, event)):
            failed = [
                x for x in index.attempts_from(first.dst_host, first.t, second.t)
                if x.dst_host == second.src_host
            ] if first.t <= second.t else []
            if failed:
                attempts[failed[0].event_id] = failed[0]
                return DisconnectedEvent(
                    event_id=event.event_id, reason=DisconnectReason.FAILED_LINK_ONLY,
                    nearest_event_id=other.event_id,
                    detail=_clip(f"Only a failed attempt ({failed[0].event_id}) from "
                                 f"{first.dst_host} to {second.src_host} would have joined these "
                                 "events; a failed authentication is not movement."),
                )
            if first.dst_host == second.src_host:
                if second.t <= first.t:
                    time_order = time_order or (first, second, other)
                elif second.t - first.t > gap:
                    gap_exceeded = gap_exceeded or (first, second, other)
    if time_order:
        first, second, other = time_order
        order = "the same second" if second.t == first.t else "the wrong order"
        return DisconnectedEvent(
            event_id=event.event_id, reason=DisconnectReason.TIME_ORDER,
            nearest_event_id=other.event_id,
            detail=_clip(f"Both events touch {first.dst_host} but happened in {order}, so one "
                         "cannot continue the other."),
        )
    if gap_exceeded:
        first, second, other = gap_exceeded
        return DisconnectedEvent(
            event_id=event.event_id, reason=DisconnectReason.GAP_EXCEEDED,
            nearest_event_id=other.event_id,
            detail=_clip(f"Both events touch {first.dst_host}, but {second.t - first.t:.0f} s "
                         f"apart exceeds the {gap} s link limit."),
        )
    return DisconnectedEvent(
        event_id=event.event_id, reason=DisconnectReason.NO_SHARED_HOST,
        detail="No other suspicious movement event in this incident shares a host with it.",
    )


def _choke_points(
    graph: nx.DiGraph, paths: Sequence[StructuralPath], limit: int
) -> list[ChokePoint]:
    """Hosts every observed route to a path's final host must pass through (dominators)."""
    out: list[ChokePoint] = []
    seen: set[str] = set()
    root = "__entry__"
    for path in paths:
        target = path.event_ids[-1]
        final = graph.nodes[target]["event"]
        if final.dst_host in seen or len(out) >= limit:
            continue
        seen.add(final.dst_host)
        ancestors: set[str] = set()
        for node, data in graph.nodes(data=True):  # every route reaching the host, not one event
            if data["event"].dst_host == final.dst_host:
                ancestors |= nx.ancestors(graph, node) | {node}
        hosts = nx.DiGraph()
        entries: set[str] = set()
        for node in ancestors:
            event = graph.nodes[node]["event"]
            hosts.add_edge(event.src_host, event.dst_host)
            if not set(graph.predecessors(node)) & ancestors:
                entries.add(event.src_host)
        for entry in entries:
            hosts.add_edge(root, entry)
        dominators = nx.immediate_dominators(hosts, root)
        target_host = final.dst_host
        via: list[str] = []
        node = dominators.get(target_host)
        while node is not None and node != root:
            if node not in entries and node != target_host:
                via.append(node)
            parent = dominators.get(node)
            if parent == node:
                break
            node = parent
        if via:
            out.append(ChokePoint(target_event_id=target, target_host=target_host,
                                  entry_hosts=sorted(entries), via_hosts=list(reversed(via))))
    return out


def _bridges(auth: nx.MultiDiGraph, view: nx.MultiDiGraph) -> list[AccountBridge]:
    groups: dict[str, int] = {}
    members: list[list[str]] = []
    for number, nodes in enumerate(nx.weakly_connected_components(view)):
        members.append(sorted(n[1] for n in nodes))
        for node in nodes:
            groups[node[1]] = number
    out = []
    for node in sorted(n for n in auth.nodes if n[0] == USER):
        touched = sorted({groups[s[1]] for s in auth.successors(node)})
        if len(touched) >= 2:
            out.append(AccountBridge(account=node[1],
                                     host_groups=sorted(members[t] for t in touched)))
    return out


def assess_incident(
    incident: Incident, index: EventIndex, config: StructuralConfig
) -> StructuralAssessment:
    rules_by_event: dict[str, set[str]] = {}
    findings_by_event: dict[str, list[str]] = {}
    path_findings: dict[str, Finding] = {}
    for finding in incident.findings:
        for event_id in finding.event_ids:
            rules_by_event.setdefault(event_id, set()).add(finding.rule_id)
            if finding.rule_id in PATH_RULES:
                findings_by_event.setdefault(event_id, []).append(finding.finding_id)
        if finding.rule_id in PATH_RULES:
            path_findings[finding.finding_id] = finding

    anchors: dict[str, IndexedEvent] = {}
    missing: list[str] = []
    for event_id in incident.event_ids:
        event = index.get(event_id)
        if event is None:
            missing.append(event_id)
        else:
            anchors[event.event_id] = event
    seeds = [e for e in anchors.values() if e.kind is EdgeKind.MOVEMENT]
    expansion = expand_context(index, seeds, config)
    built: EventGraph = build_event_graph(
        expansion.events.values(), set(anchors), index, config)
    graph = built.graph
    truncation = list(expansion.truncation_reasons)
    if built.arcs_dropped:
        truncation.append(f"{built.arcs_dropped} links between unrelated accounts were not "
                          "followed.")

    routes = _candidate_routes(graph, [e.event_id for e in seeds])
    paths, paths_cut = _ranked_paths(
        [_make_path(r, inferred, graph, rules_by_event, findings_by_event)
         for r, inferred in routes], config.max_paths)
    if paths_cut:
        truncation.append(f"Only the {config.max_paths} strongest paths are reported.")

    validations = _with_extensions([
        (_validate_chain if f.rule_id == RuleId.LATERAL_CHAIN.value
         else _validate_pivot)(f, index, config)
        for f in path_findings.values()
    ], path_findings, paths)

    sequences, disconnected, attempts, compare_cut = _disconnected(seeds, graph, index, config)
    if compare_cut:
        truncation.append(f"Disconnection analysis compared at most "
                          f"{config.max_anchors_compared} suspicious events.")
    edges = {e.event_id: to_edge(e, rules_by_event.get(e.event_id, ()))
             for e in (*anchors.values(), *expansion.events.values(), *attempts)}
    ordered_edges = sorted(edges.values(), key=lambda e: (e.timestamp, e.event_id))
    auth = build_authentication_graph(ordered_edges)
    view = movement_view(auth)
    cyclic = sorted(sorted(n[1] for n in group)
                    for group in nx.strongly_connected_components(view) if len(group) > 1)
    non_movement: dict[EdgeKind, int] = {}
    for event in anchors.values():
        if event.kind is not EdgeKind.MOVEMENT:
            non_movement[event.kind] = non_movement.get(event.kind, 0) + 1

    return StructuralAssessment(
        incident_id=incident.incident_id, incident_sha256=incident_sha256(incident),
        datasets=incident.datasets, edges=ordered_edges, paths=paths,
        finding_validations=validations, sequences=sequences, disconnected=disconnected,
        choke_points=_choke_points(graph, paths, config.max_choke_targets),
        cyclic_host_groups=cyclic, account_bridges=_bridges(auth, view),
        non_movement_anchors=non_movement, missing_event_ids=missing,
        stats=AssessmentStats(
            anchors=len(anchors),
            context_events=sum(1 for e in expansion.events if e not in anchors),
            movement_edges=sum(e.kind is EdgeKind.MOVEMENT for e in ordered_edges),
            attempt_edges=sum(e.kind is EdgeKind.ATTEMPT for e in ordered_edges),
            local_edges=sum(e.kind is EdgeKind.LOCAL for e in ordered_edges),
            event_graph_nodes=graph.number_of_nodes(),
            event_graph_arcs=graph.number_of_edges(),
            account_switch_arcs=sum(_is_switch(d) for _, _, d in graph.edges(data=True)),
            depth_reached=expansion.depth_reached,
            truncated=bool(truncation),
            truncation_reasons=[_clip(t) for t in truncation],
        ),
        limitations=list(LIMITATIONS),
    )
