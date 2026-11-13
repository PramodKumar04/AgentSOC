"""Structural Simulation Engine (SSE) output.

Everything here is validated against OBSERVED authentication logs only; no enterprise
topology is assumed. A verdict is about that evidence:

  FEASIBLE                observed evidence supports every link.
  CONDITIONALLY_FEASIBLE  every hop was observed, but linking them needs an assumption,
                          such as two accounts being operated by the same party.
  INFEASIBLE              required evidence is missing or a claimed link is unsupported.

FEASIBLE does not prove an attack happened, and INFEASIBLE does not prove movement was
impossible or the environment clean: it only means these logs do not show it.
"""

from __future__ import annotations

import itertools
from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from agentsoc.schemas.audit import Sha256Hex
from agentsoc.schemas.common import Contract, Identifier, ShortText
from agentsoc.schemas.events import DatasetSource, RawRef


class Feasibility(StrEnum):
    FEASIBLE = "FEASIBLE"
    CONDITIONALLY_FEASIBLE = "CONDITIONALLY_FEASIBLE"
    INFEASIBLE = "INFEASIBLE"


class Edge(Contract):
    source: Identifier
    target: Identifier


class PathValidation(Contract):
    hypothesis_id: Identifier
    verdict: Feasibility
    checked_path: list[Identifier] = Field(default_factory=list)
    missing_edges: list[Edge] = Field(default_factory=list)
    conditions: list[ShortText] = Field(default_factory=list)
    reasons: list[ShortText] = Field(min_length=1)
    evidence_event_ids: list[Identifier] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_verdict(self) -> PathValidation:
        if self.verdict is Feasibility.FEASIBLE and (self.missing_edges or self.conditions):
            raise ValueError("FEASIBLE verdict cannot have missing edges or conditions")
        if self.verdict is Feasibility.CONDITIONALLY_FEASIBLE and not self.conditions:
            raise ValueError("CONDITIONALLY_FEASIBLE verdict must state its conditions")
        return self


class EdgeKind(StrEnum):
    MOVEMENT = "MOVEMENT"  # successful remote access: the only kind that can form a path
    ATTEMPT = "ATTEMPT"  # failed authentication: reported, never part of a path
    LOCAL = "LOCAL"  # successful logon with source = destination


class GraphEdge(Contract):
    """One original authentication event in an incident's graph."""

    event_id: Identifier
    duplicate_event_ids: list[Identifier] = Field(default_factory=list)
    timestamp: AwareDatetime
    account: Identifier
    src_host: Identifier
    dst_host: Identifier
    kind: EdgeKind
    auth_type: Identifier | None = None
    logon_type: Identifier | None = None
    dataset: DatasetSource
    raw_ref: RawRef
    rule_ids: list[Identifier] = Field(default_factory=list)  # empty = surrounding context event


class PathKind(StrEnum):
    OBSERVED = "OBSERVED"  # one account throughout
    INFERRED = "INFERRED"  # hops were observed; joining them assumes an account switch


class LinkBasis(StrEnum):
    SAME_ACCOUNT = "SAME_ACCOUNT"
    ACCOUNT_SWITCH = "ACCOUNT_SWITCH"


class HopLink(Contract):
    from_event_id: Identifier
    to_event_id: Identifier
    host: Identifier
    gap_seconds: float = Field(gt=0)
    basis: LinkBasis
    # Distinct other accounts arriving on the host in the window, counted up to the
    # ambiguity threshold + 1.
    other_accounts_arriving: int = Field(ge=0)
    ambiguous: bool = False  # a busy shared host makes this account switch weak evidence

    @model_validator(mode="after")
    def _check(self) -> HopLink:
        if self.ambiguous and self.basis is not LinkBasis.ACCOUNT_SWITCH:
            raise ValueError("only account-switch links can be ambiguous")
        return self


class StructuralPath(Contract):
    path_id: Identifier
    kind: PathKind
    verdict: Feasibility
    event_ids: list[Identifier] = Field(min_length=1)  # ordered hops, each one a graph edge
    hosts: list[Identifier] = Field(min_length=2)  # the walk; hosts may repeat
    accounts: list[Identifier] = Field(min_length=1)
    links: list[HopLink] = Field(default_factory=list)
    finding_ids: list[Identifier] = Field(default_factory=list)
    anchor_event_ids: list[Identifier] = Field(default_factory=list)  # cited by detection rules
    context_event_ids: list[Identifier] = Field(default_factory=list)  # found only by the SSE
    revisited_hosts: list[Identifier] = Field(default_factory=list)
    conditions: list[ShortText] = Field(default_factory=list)
    reasons: list[ShortText] = Field(min_length=1)
    is_proof_of_compromise: Literal[False] = False

    @model_validator(mode="after")
    def _check(self) -> StructuralPath:
        if len(self.hosts) != len(self.event_ids) + 1:
            raise ValueError("a path of N hops must list N + 1 hosts")
        if len(self.links) != len(self.event_ids) - 1:
            raise ValueError("a path of N hops must have N - 1 links")
        switched = any(k.basis is LinkBasis.ACCOUNT_SWITCH for k in self.links)
        if switched != (self.kind is PathKind.INFERRED):
            raise ValueError("a path is INFERRED exactly when a link switches account")
        expected = (Feasibility.CONDITIONALLY_FEASIBLE if switched else Feasibility.FEASIBLE)
        if self.verdict is not expected:
            raise ValueError(f"{self.kind} paths must have verdict {expected}")
        if switched and not self.conditions:
            raise ValueError("INFERRED paths must state their conditions")
        if not switched and self.conditions:
            raise ValueError("OBSERVED paths have no conditions")
        return self


class FindingValidation(Contract):
    """Edge-by-edge re-check of a LATERAL_CHAIN or CROSS_ACCOUNT_PIVOT finding."""

    finding_id: Identifier
    rule_id: Identifier
    verdict: Feasibility
    checked_path: list[Identifier] = Field(default_factory=list)
    event_ids: list[Identifier] = Field(default_factory=list)
    missing_event_ids: list[Identifier] = Field(default_factory=list)
    missing_edges: list[Edge] = Field(default_factory=list)
    conditions: list[ShortText] = Field(default_factory=list)
    reasons: list[ShortText] = Field(min_length=1)
    extended_by: list[Identifier] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> FindingValidation:
        problems = self.missing_edges or self.missing_event_ids
        if self.verdict is Feasibility.FEASIBLE and (problems or self.conditions):
            raise ValueError("FEASIBLE verdict cannot have missing evidence or conditions")
        if self.verdict is Feasibility.CONDITIONALLY_FEASIBLE and (
            problems or not self.conditions
        ):
            raise ValueError("CONDITIONALLY_FEASIBLE needs conditions and complete evidence")
        return self


class DisconnectReason(StrEnum):
    NO_SHARED_HOST = "NO_SHARED_HOST"
    TIME_ORDER = "TIME_ORDER"  # shares a host, but the order does not allow a continuation
    GAP_EXCEEDED = "GAP_EXCEEDED"
    FAILED_LINK_ONLY = "FAILED_LINK_ONLY"  # only a failed attempt would have joined them


class DisconnectedEvent(Contract):
    event_id: Identifier
    reason: DisconnectReason
    detail: ShortText
    nearest_event_id: Identifier | None = None


class MovementSequence(Contract):
    """Suspicious movement events joined by time-respecting links."""

    sequence_id: Identifier
    event_ids: list[Identifier] = Field(min_length=1)
    hosts: list[Identifier]
    requires_account_switch: bool


class ChokePoint(Contract):
    """Every observed route traced back to these entry hosts passes through `via_hosts`."""

    target_event_id: Identifier
    target_host: Identifier
    entry_hosts: list[Identifier]
    via_hosts: list[Identifier] = Field(min_length=1)


class AccountBridge(Contract):
    """An account seen on host groups that no observed movement connects."""

    account: Identifier
    host_groups: list[list[Identifier]] = Field(min_length=2)


class AssessmentStats(Contract):
    anchors: int
    context_events: int
    movement_edges: int
    attempt_edges: int
    local_edges: int
    event_graph_nodes: int
    event_graph_arcs: int
    account_switch_arcs: int
    depth_reached: int
    truncated: bool
    truncation_reasons: list[ShortText] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> AssessmentStats:
        if self.truncated != bool(self.truncation_reasons):
            raise ValueError("truncated must be true exactly when reasons are given")
        return self


class StructuralAssessment(Contract):
    """Pre-LLM structural evidence for one incident. Untrusted input to the investigator."""

    incident_id: Identifier
    incident_sha256: Sha256Hex
    datasets: list[DatasetSource] = Field(min_length=1)
    edges: list[GraphEdge] = Field(default_factory=list)
    paths: list[StructuralPath] = Field(default_factory=list)
    finding_validations: list[FindingValidation] = Field(default_factory=list)
    sequences: list[MovementSequence] = Field(default_factory=list)
    disconnected: list[DisconnectedEvent] = Field(default_factory=list)
    choke_points: list[ChokePoint] = Field(default_factory=list)
    cyclic_host_groups: list[list[Identifier]] = Field(default_factory=list)
    account_bridges: list[AccountBridge] = Field(default_factory=list)
    non_movement_anchors: dict[EdgeKind, int] = Field(default_factory=dict)
    missing_event_ids: list[Identifier] = Field(default_factory=list)
    stats: AssessmentStats
    limitations: list[ShortText] = Field(min_length=1)
    is_proof_of_compromise: Literal[False] = False

    @model_validator(mode="after")
    def _check(self) -> StructuralAssessment:
        by_id = {e.event_id: e for e in self.edges}
        if len(by_id) != len(self.edges):
            raise ValueError("edges must reference unique events")
        for path in self.paths:
            hops = [by_id.get(e) for e in path.event_ids]
            if None in hops:
                raise ValueError(f"{path.path_id} uses an event that is not a graph edge")
            if any(h.kind is not EdgeKind.MOVEMENT for h in hops):
                raise ValueError(f"{path.path_id} uses a non-movement edge")
            for a, b in itertools.pairwise(hops):
                if a.dst_host != b.src_host or a.timestamp >= b.timestamp:
                    raise ValueError(f"{path.path_id} is not continuous in host and time")
        return self
