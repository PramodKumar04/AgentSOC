"""Display form of an incident's structural assessment, for the attack graph.

Derived entirely from one `StructuralAssessment`. It contains no edge that is not an
original authentication event and no path the Structural Simulation Engine did not report.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, Field

from agentsoc.schemas.common import Contract
from agentsoc.schemas.events import DatasetSource
from agentsoc.schemas.graph import (
    AccountBridge,
    AssessmentStats,
    ChokePoint,
    DisconnectedEvent,
    EdgeKind,
    Feasibility,
    FindingValidation,
    PathKind,
)


class NodeRole(StrEnum):
    PRINCIPAL = "PRINCIPAL"  # the incident's principal account
    ADMIN = "ADMIN"  # a configured administrative account
    SENSITIVE = "SENSITIVE"  # a configured sensitive host
    JUMP_HOST = "JUMP_HOST"  # a configured jump host
    CHOKE_POINT = "CHOKE_POINT"  # every observed route traced back passes through it
    ACCOUNT_SWITCH = "ACCOUNT_SWITCH"  # an inferred path changes account here
    AMBIGUOUS_SWITCH = "AMBIGUOUS_SWITCH"  # ... on a host too busy for that to mean much


class GraphNode(Contract):
    node_id: str
    kind: Literal["host", "user"]
    label: str
    roles: list[NodeRole] = Field(default_factory=list)
    event_count: int = Field(ge=0)


class LinkKind(StrEnum):
    MOVEMENT = "MOVEMENT"
    ATTEMPT = "ATTEMPT"
    LOCAL = "LOCAL"
    ACCOUNT = "ACCOUNT"  # an account seen acting from or reaching a host


class GraphLink(Contract):
    """All events sharing a source, a target and a kind."""

    link_id: str
    source: str
    target: str
    kind: LinkKind
    event_ids: list[str] = Field(min_length=1)  # chronological
    accounts: list[str] = Field(min_length=1)
    relations: list[Literal["ACTED_FROM", "REACHED"]] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    first_seen_label: str
    last_seen_label: str
    path_ids: list[str] = Field(default_factory=list)


class GraphEvent(Contract):
    event_id: str
    duplicate_event_ids: list[str] = Field(default_factory=list)
    timestamp: AwareDatetime
    time_label: str
    account: str
    src_host: str
    dst_host: str
    kind: EdgeKind
    auth_type: str | None = None
    logon_type: str | None = None
    dataset: DatasetSource
    raw_file: str
    raw_line: int
    rule_ids: list[str] = Field(default_factory=list)  # empty = surrounding context event
    path_ids: list[str] = Field(default_factory=list)


class AccountSwitch(Contract):
    """Where an inferred path joins two accounts' observed activity. Not an edge."""

    host: str
    from_event_id: str
    to_event_id: str
    gap_seconds: float
    other_accounts_arriving: int
    ambiguous: bool


class GraphPath(Contract):
    path_id: str
    kind: PathKind
    verdict: Feasibility
    event_ids: list[str] = Field(min_length=1)
    link_ids: list[str] = Field(min_length=1)
    hosts: list[str]
    accounts: list[str]
    switches: list[AccountSwitch] = Field(default_factory=list)
    ambiguous: bool = False
    finding_ids: list[str] = Field(default_factory=list)
    anchor_event_ids: list[str] = Field(default_factory=list)
    context_event_ids: list[str] = Field(default_factory=list)
    revisited_hosts: list[str] = Field(default_factory=list)
    conditions: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(min_length=1)
    is_proof_of_compromise: Literal[False] = False


class IncidentGraph(Contract):
    incident_id: str
    incident_sha256: str
    datasets: list[DatasetSource]
    nodes: list[GraphNode] = Field(default_factory=list)
    links: list[GraphLink] = Field(default_factory=list)
    events: list[GraphEvent] = Field(default_factory=list)
    paths: list[GraphPath] = Field(default_factory=list)
    finding_validations: list[FindingValidation] = Field(default_factory=list)
    disconnected: list[DisconnectedEvent] = Field(default_factory=list)
    choke_points: list[ChokePoint] = Field(default_factory=list)
    cyclic_host_groups: list[list[str]] = Field(default_factory=list)
    account_bridges: list[AccountBridge] = Field(default_factory=list)
    missing_event_ids: list[str] = Field(default_factory=list)
    stats: AssessmentStats
    limitations: list[str] = Field(min_length=1)
    is_proof_of_compromise: Literal[False] = False
