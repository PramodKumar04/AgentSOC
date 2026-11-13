"""Turn a stored structural assessment into the display graph.

Node and link structure comes from `build_authentication_graph`, the same NetworkX graph
the engine uses. Parallel events are bundled by source, target and kind so a busy pair of
hosts stays readable; every link still lists the event IDs it stands for. Nothing is
scored and no path is searched for here: paths are copied from the assessment.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from datetime import datetime

from agentsoc.detection.config import DetectionConfig
from agentsoc.graph.build import HOST, build_authentication_graph
from agentsoc.schemas.graph import EdgeKind, GraphEdge, LinkBasis, StructuralAssessment
from agentsoc.schemas.graph_view import (
    AccountSwitch,
    GraphEvent,
    GraphLink,
    GraphNode,
    GraphPath,
    IncidentGraph,
    LinkKind,
    NodeRole,
)

_ACCOUNT_RELATIONS = {"ACTED_FROM", "REACHED"}


def node_id(kind: str, name: str) -> str:
    return f"{kind}:{name}"


def link_id(source: str, target: str, kind: LinkKind) -> str:
    return f"{kind.value}|{source}|{target}"


def _event_link_id(edge: GraphEdge) -> str:
    return link_id(node_id(HOST, edge.src_host), node_id(HOST, edge.dst_host),
                   LinkKind(edge.kind.value))


def _host_roles(
    assessment: StructuralAssessment, detection_config: DetectionConfig
) -> dict[str, set[NodeRole]]:
    roles: dict[str, set[NodeRole]] = defaultdict(set)
    sensitive = set(detection_config.sensitive_host_access.hosts)
    for edge in assessment.edges:
        for host in (edge.src_host, edge.dst_host):
            if host in sensitive:
                roles[host].add(NodeRole.SENSITIVE)
            if detection_config.is_jump_host(host):
                roles[host].add(NodeRole.JUMP_HOST)
    for point in assessment.choke_points:
        for host in point.via_hosts:
            roles[host].add(NodeRole.CHOKE_POINT)
    for path in assessment.paths:
        for hop in path.links:
            if hop.basis is LinkBasis.ACCOUNT_SWITCH:
                roles[hop.host].add(NodeRole.ACCOUNT_SWITCH)
                if hop.ambiguous:
                    roles[hop.host].add(NodeRole.AMBIGUOUS_SWITCH)
    return roles


def _paths(assessment: StructuralAssessment, by_id: dict[str, GraphEdge]) -> list[GraphPath]:
    out = []
    for path in assessment.paths:
        switches = [
            AccountSwitch(
                host=hop.host, from_event_id=hop.from_event_id, to_event_id=hop.to_event_id,
                gap_seconds=hop.gap_seconds, other_accounts_arriving=hop.other_accounts_arriving,
                ambiguous=hop.ambiguous,
            )
            for hop in path.links if hop.basis is LinkBasis.ACCOUNT_SWITCH
        ]
        out.append(GraphPath(
            path_id=path.path_id, kind=path.kind, verdict=path.verdict, event_ids=path.event_ids,
            link_ids=[_event_link_id(by_id[e]) for e in path.event_ids], hosts=path.hosts,
            accounts=path.accounts, switches=switches, ambiguous=any(s.ambiguous for s in switches),
            finding_ids=path.finding_ids, anchor_event_ids=path.anchor_event_ids,
            context_event_ids=path.context_event_ids, revisited_hosts=path.revisited_hosts,
            conditions=path.conditions, reasons=path.reasons,
        ))
    return out


def build_incident_graph(
    assessment: StructuralAssessment,
    *,
    detection_config: DetectionConfig,
    principal_user: str,
    time_label: Callable[[datetime], str],
) -> IncidentGraph:
    graph = build_authentication_graph(assessment.edges)
    by_id = {e.event_id: e for e in assessment.edges}
    path_ids: dict[str, list[str]] = defaultdict(list)
    for path in assessment.paths:
        for event_id in path.event_ids:
            path_ids[event_id].append(path.path_id)

    bundles: dict[tuple[str, str, LinkKind], list[tuple[str, str | None]]] = defaultdict(list)
    touching: dict[str, set[str]] = defaultdict(set)
    for (src_kind, src), (dst_kind, dst), key, attrs in graph.edges(keys=True, data=True):
        relation = attrs["kind"]
        if relation in _ACCOUNT_RELATIONS:
            event_id = key.split(":", 1)[1]
            kind, note = LinkKind.ACCOUNT, relation
        else:
            event_id = key
            kind, note = LinkKind(EdgeKind(relation).value), None
        source, target = node_id(src_kind, src), node_id(dst_kind, dst)
        bundles[(source, target, kind)].append((event_id, note))
        touching[source].add(event_id)
        touching[target].add(event_id)
    for edge in assessment.edges:  # a failed attempt adds no account link, but it is theirs
        touching[node_id("user", edge.account)].add(edge.event_id)

    host_roles = _host_roles(assessment, detection_config)
    nodes = []
    for kind, name in sorted(graph.nodes):
        if kind == HOST:
            roles = host_roles.get(name, set())
        else:
            roles = {r for r, on in ((NodeRole.PRINCIPAL, name == principal_user),
                                     (NodeRole.ADMIN, name in detection_config.admin_users)) if on}
        nodes.append(GraphNode(
            node_id=node_id(kind, name), kind=kind, label=name, roles=sorted(roles),
            event_count=len(touching[node_id(kind, name)]),
        ))

    links = []
    for (source, target, kind), items in sorted(
        bundles.items(), key=lambda item: (*item[0][:2], item[0][2].value)
    ):
        events = sorted((by_id[e] for e in {e for e, _ in items}),
                        key=lambda e: (e.timestamp, e.event_id))
        links.append(GraphLink(
            link_id=link_id(source, target, kind), source=source, target=target, kind=kind,
            event_ids=[e.event_id for e in events],
            accounts=sorted({e.account for e in events}),
            relations=sorted({n for _, n in items if n}),
            rule_ids=sorted({r for e in events for r in e.rule_ids}),
            first_seen_label=time_label(events[0].timestamp),
            last_seen_label=time_label(events[-1].timestamp),
            path_ids=(sorted({p for e in events for p in path_ids.get(e.event_id, [])})
                      if kind is not LinkKind.ACCOUNT else []),
        ))

    return IncidentGraph(
        incident_id=assessment.incident_id, incident_sha256=assessment.incident_sha256,
        datasets=assessment.datasets, nodes=nodes, links=links,
        events=[GraphEvent(
            event_id=e.event_id, duplicate_event_ids=e.duplicate_event_ids,
            timestamp=e.timestamp, time_label=time_label(e.timestamp), account=e.account,
            src_host=e.src_host, dst_host=e.dst_host, kind=e.kind, auth_type=e.auth_type,
            logon_type=e.logon_type, dataset=e.dataset, raw_file=e.raw_ref.file,
            raw_line=e.raw_ref.line, rule_ids=e.rule_ids, path_ids=path_ids.get(e.event_id, []),
        ) for e in assessment.edges],
        paths=_paths(assessment, by_id), finding_validations=assessment.finding_validations,
        disconnected=assessment.disconnected, choke_points=assessment.choke_points,
        cyclic_host_groups=assessment.cyclic_host_groups,
        account_bridges=assessment.account_bridges, missing_event_ids=assessment.missing_event_ids,
        stats=assessment.stats, limitations=assessment.limitations,
    )
