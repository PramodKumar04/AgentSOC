"""Incident graphs: bounded context expansion and the two NetworkX graphs.

Authentication graph (`MultiDiGraph`): user and host nodes; one host-to-host edge per
event, keyed by event ID and carrying its timestamp and provenance.

Time-expanded event graph (`DiGraph`): each movement event is a node. An arc means the
first event's destination is the second's source, time strictly increases and the gap is
within the limit. Time only moves forward, so it is acyclic even when hosts form cycles.
"""

from __future__ import annotations

from bisect import bisect_left
from collections import deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

import networkx as nx

from agentsoc.graph.config import StructuralConfig
from agentsoc.graph.index import EventIndex, IndexedEvent
from agentsoc.schemas import RawRef
from agentsoc.schemas.graph import EdgeKind, GraphEdge, LinkBasis

HOST, USER = "host", "user"


@dataclass
class Expansion:
    events: dict[str, IndexedEvent]
    depth_reached: int = 0
    truncation_reasons: list[str] = field(default_factory=list)


def expand_context(
    index: EventIndex, seeds: Sequence[IndexedEvent], config: StructuralConfig
) -> Expansion:
    """Walk forward-only and backward-only from the rule-cited movement events.

    Separate directions keep the search from zigzagging through busy shared hosts. The
    breadth-first order means a cap always removes the farthest events first.
    """
    result = Expansion(events={e.event_id: e for e in seeds})
    gap, limit, cap = (config.max_link_gap_seconds, config.max_links_per_event,
                       config.max_context_events)
    branch_cut = event_cap_hit = depth_cut = False
    for forward in (True, False):
        queue = deque((e, 0) for e in seeds)
        seen = {e.event_id for e in seeds}
        while queue:
            event, depth = queue.popleft()
            chosen, cut = index.linked(event, forward=forward, gap=gap, skip=seen, limit=limit)
            if not chosen:
                continue
            if depth >= config.max_expansion_hops:
                depth_cut = True
                continue
            branch_cut = branch_cut or cut
            for item in chosen:
                if len(result.events) >= cap and item.event_id not in result.events:
                    event_cap_hit = True
                    break
                seen.add(item.event_id)
                result.events[item.event_id] = item
                result.depth_reached = max(result.depth_reached, depth + 1)
                queue.append((item, depth + 1))
    if depth_cut:
        result.truncation_reasons.append(
            f"Context stops at {config.max_expansion_hops} hops from the rule-cited events; "
            "more linked events exist."
        )
    if branch_cut:
        result.truncation_reasons.append(
            f"At most {limit} linked events were followed per event; others were not followed."
        )
    if event_cap_hit:
        result.truncation_reasons.append(
            f"Context reached the limit of {cap} events; the farthest events were dropped."
        )
    return result


def to_edge(event: IndexedEvent, rule_ids: Iterable[str] = ()) -> GraphEdge:
    return GraphEdge(
        event_id=event.event_id, duplicate_event_ids=event.duplicate_event_ids,
        timestamp=event.timestamp, account=event.account, src_host=event.src_host,
        dst_host=event.dst_host, kind=event.kind, auth_type=event.auth_type,
        logon_type=event.logon_type, dataset=event.dataset,
        raw_ref=RawRef(file=event.raw_file, line=event.raw_line),
        rule_ids=sorted(set(rule_ids)),
    )


def build_authentication_graph(edges: Iterable[GraphEdge]) -> nx.MultiDiGraph:
    graph = nx.MultiDiGraph()
    for edge in edges:
        src, dst, user = (HOST, edge.src_host), (HOST, edge.dst_host), (USER, edge.account)
        graph.add_node(src, kind=HOST)
        graph.add_node(dst, kind=HOST)
        graph.add_node(user, kind=USER)
        graph.add_edge(src, dst, key=edge.event_id, kind=edge.kind, edge=edge)
        if edge.kind is not EdgeKind.ATTEMPT:  # a failure never relates an account to a host
            graph.add_edge(user, src, key=f"from:{edge.event_id}", kind="ACTED_FROM")
            graph.add_edge(user, dst, key=f"to:{edge.event_id}", kind="REACHED")
    return graph


def movement_view(graph: nx.MultiDiGraph) -> nx.MultiDiGraph:
    """Hosts and movement edges only: a read-only view, not a copy."""
    return nx.subgraph_view(
        graph,
        filter_node=lambda n: n[0] == HOST,
        filter_edge=lambda u, v, k: graph[u][v][k]["kind"] is EdgeKind.MOVEMENT,
    )


@dataclass
class EventGraph:
    graph: nx.DiGraph
    arcs_dropped: int = 0


def build_event_graph(
    events: Iterable[IndexedEvent], anchors: set[str], index: EventIndex, config: StructuralConfig,
) -> EventGraph:
    """Link each departure to earlier arrivals on its source host.

    Same-account arcs and arcs between two rule-cited events are always considered first,
    so the per-event limit can only drop context links between unrelated accounts.
    """
    moves = sorted(events, key=lambda e: e.order)
    graph = nx.DiGraph()
    arrivals: dict[str, list[IndexedEvent]] = {}
    times: dict[str, list[float]] = {}
    for event in moves:
        graph.add_node(event.event_id, event=event)
        arrivals.setdefault(event.dst_host, []).append(event)
        times.setdefault(event.dst_host, []).append(event.t)
    gap, limit = config.max_link_gap_seconds, config.max_links_per_event
    threshold = config.ambiguous_link_accounts
    dropped = 0
    for event in moves:
        host = event.src_host
        if host not in arrivals:
            continue
        low = bisect_left(times[host], event.t - gap)
        high = bisect_left(times[host], event.t)  # strictly earlier only
        candidates = list(reversed(arrivals[host][low:high]))
        candidates.sort(key=lambda e: (
            e.account_key != event.account_key,
            not (e.event_id in anchors and event.event_id in anchors),
        ))
        keep = [c for c in candidates if c.account_key == event.account_key
                or (c.event_id in anchors and event.event_id in anchors)]
        kept_ids = {c.event_id for c in keep}
        for other in candidates:
            if len(keep) >= limit:
                break
            if other.event_id not in kept_ids:
                keep.append(other)
        dropped += len(candidates) - len(keep)
        if not any(c.account_key != event.account_key for c in keep):
            accounts_here = 0
        else:
            accounts_here = index.other_accounts_arriving(
                host, event.t, gap, event.account_key, threshold + 1)
        for prior in keep:
            switch = prior.account_key != event.account_key
            graph.add_edge(
                prior.event_id, event.event_id,
                basis=LinkBasis.ACCOUNT_SWITCH if switch else LinkBasis.SAME_ACCOUNT,
                host=host, gap=event.t - prior.t,
                other_accounts=accounts_here if switch else 0,
                ambiguous=switch and accounts_here > threshold,
            )
    return EventGraph(graph, dropped)
