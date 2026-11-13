"""Post-LLM validation: the LLM proposes a path; deterministic code checks every hop.

Each proposed hop must exist as a successful authentication in the incident's graph.
A time-ordered sequence is then searched over the recorded events and re-checked against
the original events by the independent verifier. The LLM's claim is never trusted.
"""

from __future__ import annotations

import hashlib
import itertools
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from agentsoc.detection.config import DetectionConfig
from agentsoc.detection.lateral import account_name
from agentsoc.graph.build import HOST, build_authentication_graph
from agentsoc.graph.config import StructuralConfig
from agentsoc.graph.verify import StructuralVerificationError, verify_chain
from agentsoc.schemas import AuthEvent
from agentsoc.schemas.graph import (
    Edge,
    EdgeKind,
    Feasibility,
    GraphEdge,
    PathValidation,
    StructuralAssessment,
)


@dataclass(frozen=True)
class StructuralEvidence:
    assessment: StructuralAssessment
    events: Mapping[str, AuthEvent]  # original events for every graph edge
    detection_config: DetectionConfig
    config: StructuralConfig


def assessment_sha256(assessment: StructuralAssessment) -> str:
    return hashlib.sha256(assessment.model_dump_json().encode("utf-8")).hexdigest()


def _clip(text: str) -> str:
    return text if len(text) <= 300 else text[:297] + "..."


def _not_validated(
    hypothesis_id: str, proposed: Sequence[str], reasons: list[str], missing: Sequence[Edge] = (),
) -> PathValidation:
    return PathValidation(
        hypothesis_id=hypothesis_id, verdict=Feasibility.INFEASIBLE, checked_path=list(proposed),
        missing_edges=list(missing), reasons=[_clip(r) for r in reasons],
    )


def _best_sequence(
    layers: Sequence[Sequence[GraphEdge]], gap: float
) -> list[GraphEdge] | None:
    """Time-valid choice of one edge per hop, with the fewest account switches."""
    best: dict[str, tuple[int, list[GraphEdge]]] = {
        e.event_id: (0, [e]) for e in layers[0]
    }
    for layer in layers[1:]:
        reached: dict[str, tuple[int, list[GraphEdge]]] = {}
        for edge in layer:
            for switches, sequence in best.values():
                prior = sequence[-1]
                wait = (edge.timestamp - prior.timestamp).total_seconds()
                if wait <= 0 or wait > gap:
                    continue
                cost = switches + (account_name(prior.account) != account_name(edge.account))
                current = reached.get(edge.event_id)
                if current is None or cost < current[0]:
                    reached[edge.event_id] = (cost, [*sequence, edge])
        best = reached
        if not best:
            return None
    return min(best.values(), key=lambda item: (item[0], [e.event_id for e in item[1]]))[1]


def validate_proposed_path(
    hypothesis_id: str, proposed: Sequence[str], evidence: StructuralEvidence | None,
) -> PathValidation:
    """Verdict for one proposed host path. Only original events can make it FEASIBLE."""
    if evidence is None:
        return _not_validated(hypothesis_id, proposed, [
            "No structural assessment is available, so this path could not be validated."])
    if len(proposed) < 2:
        return _not_validated(hypothesis_id, proposed, [
            "A path needs at least two hosts."])
    assessment = evidence.assessment
    graph = build_authentication_graph(assessment.edges)
    truncated = ("Context was truncated, so supporting events may exist beyond it."
                 if assessment.stats.truncated else None)
    layers: list[list[GraphEdge]] = []
    missing: list[Edge] = []
    reasons: list[str] = []
    for src, dst in itertools.pairwise(proposed):
        pair = ((HOST, src), (HOST, dst))
        found = (list(graph[pair[0]][pair[1]].values())
                 if graph.has_edge(*pair) else [])
        moves = [d["edge"] for d in found if d["kind"] is EdgeKind.MOVEMENT]
        if not moves:
            missing.append(Edge(source=src, target=dst))
            reasons.append(
                f"Only failed attempts were observed from {src} to {dst}; a failure is not "
                "movement." if found else
                f"No successful authentication from {src} to {dst} was observed in these logs.")
        layers.append(sorted(moves, key=lambda e: (e.timestamp, e.event_id)))
    if missing:
        return _not_validated(hypothesis_id, proposed,
                              [*reasons, *([truncated] if truncated else [])], missing)
    sequence = _best_sequence(layers, evidence.config.max_link_gap_seconds)
    if sequence is None:
        return _not_validated(hypothesis_id, proposed, [
            "Every hop was observed, but no time-ordered sequence within the link limit joins "
            "them.", *([truncated] if truncated else [])])
    ids = [e.event_id for e in sequence]
    try:
        verify_chain(ids, evidence.events, evidence.detection_config, evidence.config)
    except StructuralVerificationError:
        return _not_validated(hypothesis_id, proposed, [
            "The selected events failed independent verification against the original logs."])
    conditions = [
        _clip(f"Requires that {a.account} and {b.account} were operated by the same party on "
              f"{b.src_host}; the logs do not show this.")
        for a, b in itertools.pairwise(sequence)
        if account_name(a.account) != account_name(b.account)
    ]
    return PathValidation(
        hypothesis_id=hypothesis_id,
        verdict=Feasibility.CONDITIONALLY_FEASIBLE if conditions else Feasibility.FEASIBLE,
        checked_path=list(proposed), conditions=conditions, evidence_event_ids=ids,
        reasons=[("Every hop is backed by original events, but joining them assumes an account "
                  "switch." if conditions else
                  "Every hop is backed by original successful authentications in time order. "
                  "This does not show compromise.")],
    )
