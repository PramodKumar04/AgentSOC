"""Independent evidence verification.

Plain Python over the original `AuthEvent` records. This module deliberately shares no
code with the index, the graph builder or the path search, so a bug there cannot
vouch for itself: an edge or path that the raw events do not support is rejected here.
"""

from __future__ import annotations

import itertools
from collections.abc import Mapping, Sequence

from agentsoc.detection.baseline import is_access, is_failure
from agentsoc.detection.config import DetectionConfig
from agentsoc.exceptions import AgentSOCError
from agentsoc.graph.config import StructuralConfig
from agentsoc.schemas import AuthEvent
from agentsoc.schemas.graph import EdgeKind, Feasibility, GraphEdge, PathKind, StructuralAssessment


class StructuralVerificationError(AgentSOCError):
    """A structural result is not supported by the original events."""


def _derive_kind(event: AuthEvent, config: DetectionConfig) -> EdgeKind | None:
    if is_access(event, config):
        return EdgeKind.LOCAL if event.src_host == event.dst_host else EdgeKind.MOVEMENT
    if is_failure(event, config):
        return EdgeKind.ATTEMPT
    return None


def _same_name(a: str, b: str) -> bool:
    return a.split("@", 1)[0].casefold() == b.split("@", 1)[0].casefold()


def verify_chain(
    event_ids: Sequence[str],
    events: Mapping[str, AuthEvent],
    detection_config: DetectionConfig,
    config: StructuralConfig,
) -> list[AuthEvent]:
    """Each hop must be a real successful remote event, continuous in host and strict time."""
    hops: list[AuthEvent] = []
    for event_id in event_ids:
        event = events.get(event_id)
        if event is None:
            raise StructuralVerificationError(f"{event_id} is not an original event")
        if _derive_kind(event, detection_config) is not EdgeKind.MOVEMENT:
            raise StructuralVerificationError(f"{event_id} is not a successful remote logon")
        hops.append(event)
    for prior, event in itertools.pairwise(hops):
        if prior.dst_host != event.src_host:
            raise StructuralVerificationError(
                f"{prior.event_id} and {event.event_id} do not share a host")
        gap = (event.timestamp - prior.timestamp).total_seconds()
        if gap <= 0:
            raise StructuralVerificationError(
                f"{event.event_id} does not happen after {prior.event_id}")
        if gap > config.max_link_gap_seconds:
            raise StructuralVerificationError(
                f"{prior.event_id} to {event.event_id} exceeds the link limit")
    return hops


def _verify_edge(
    edge: GraphEdge, events: Mapping[str, AuthEvent], detection_config: DetectionConfig
) -> None:
    event = events.get(edge.event_id)
    if event is None:
        raise StructuralVerificationError(f"edge {edge.event_id} has no original event")
    observed = (event.timestamp, event.src_user, event.src_host, event.dst_host,
                event.dataset, event.raw_ref.file, event.raw_ref.line)
    claimed = (edge.timestamp, edge.account, edge.src_host, edge.dst_host,
               edge.dataset, edge.raw_ref.file, edge.raw_ref.line)
    if observed != claimed:
        raise StructuralVerificationError(f"edge {edge.event_id} differs from its original event")
    if _derive_kind(event, detection_config) is not edge.kind:
        raise StructuralVerificationError(f"edge {edge.event_id} has the wrong kind")
    for duplicate in edge.duplicate_event_ids:
        if duplicate not in events:
            raise StructuralVerificationError(f"duplicate {duplicate} has no original event")


def verify_assessment(
    assessment: StructuralAssessment,
    events: Mapping[str, AuthEvent],
    detection_config: DetectionConfig,
    config: StructuralConfig,
) -> None:
    """Raise StructuralVerificationError unless the raw events support the whole assessment."""
    for edge in assessment.edges:
        _verify_edge(edge, events, detection_config)
    for path in assessment.paths:
        hops = verify_chain(path.event_ids, events, detection_config, config)
        walk = [hops[0].src_host, *(h.dst_host for h in hops)]
        if walk != path.hosts:
            raise StructuralVerificationError(f"{path.path_id} misreports its hosts")
        switched = any(not _same_name(a.src_user, b.src_user)
                       for a, b in itertools.pairwise(hops))
        if switched != (path.kind is PathKind.INFERRED):
            raise StructuralVerificationError(f"{path.path_id} misreports account continuity")
    edge_ids = {e.event_id for e in assessment.edges}
    for item in assessment.finding_validations:
        if item.verdict is Feasibility.FEASIBLE:
            if not set(item.event_ids) <= edge_ids:
                raise StructuralVerificationError(f"{item.finding_id} cites events off the graph")
            verify_chain(item.event_ids, events, detection_config, config)
