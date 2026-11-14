"""Shared types for the specialised investigation agents.

Each agent examines one aspect of an incident (identity, network/host, threat intelligence,
endpoint) and returns an `AgentReport`: what it looked at, what it found, and what it could not
see. Agents are deterministic and read-only; they never call a language model or any external
service. An agent without data for its aspect says so (status `unavailable`) rather than
guessing.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum

from agentsoc.detection.config import DetectionConfig
from agentsoc.schemas import AuthEvent, Incident
from agentsoc.schemas.graph import StructuralAssessment


class Stance(StrEnum):
    SUSPICIOUS = "suspicious"    # points towards malicious activity
    BENIGN = "benign"            # points towards an innocent explanation
    CONTEXT = "context"          # relevant, but points neither way


class Strength(StrEnum):
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"


class AgentStatus(StrEnum):
    COMPLETED = "completed"
    NO_FINDINGS = "no_findings"
    UNAVAILABLE = "unavailable"   # the data this agent needs is not available to AgentSOC
    FAILED = "failed"             # an internal error; the other agents are unaffected


@dataclass(frozen=True)
class AgentFinding:
    statement: str
    stance: Stance
    strength: Strength
    accounts: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    event_ids: tuple[str, ...] = ()      # events in this data source that back the statement
    techniques: tuple[str, ...] = ()     # MITRE ATT&CK IDs (threat-intelligence agent only)
    expanded: bool = False               # found only in the analyst-requested wider window


@dataclass(frozen=True)
class AgentReport:
    agent: str
    title: str
    purpose: str
    status: AgentStatus
    examined: list[str]                  # what the agent looked at
    findings: list[AgentFinding]
    gaps: list[str]                      # what it could not see or check
    duration_ms: float = 0.0


@dataclass(frozen=True)
class InvestigationTask:
    """What the orchestrator hands to every agent."""

    incident: Incident
    events: Sequence[AuthEvent]          # the whole verified dataset, sorted by time
    incidents: Sequence[Incident]        # every incident in the same detection run
    detection: DetectionConfig
    structural: StructuralAssessment | None
    label: Callable[[datetime], str]
    relative_time: bool                  # anonymised offsets (LANL, synthetic), not clock time
    window_hours: int | None = None      # None: standard run; set: analyst asked for more
    _cache: dict = field(default_factory=dict, repr=False, compare=False)

    @property
    def expanded(self) -> bool:
        return self.window_hours is not None

    @property
    def window(self) -> tuple[datetime, datetime]:
        hours = self.window_hours or 0
        return (self.incident.first_seen - timedelta(hours=hours),
                self.incident.last_seen + timedelta(hours=hours))

    def incident_events(self) -> list[AuthEvent]:
        if "own" not in self._cache:
            ids = set(self.incident.event_ids)
            self._cache["own"] = [e for e in self.events if e.event_id in ids]
        return self._cache["own"]

    def window_events(self) -> list[AuthEvent]:
        key = ("window", self.window_hours)
        if key not in self._cache:
            start, end = self.window
            self._cache[key] = [e for e in self.events if start <= e.timestamp <= end]
        return self._cache[key]


def touches(event: AuthEvent, account: str) -> bool:
    return event.src_user == account or event.dst_user == account


def status_for(findings: list[AgentFinding]) -> AgentStatus:
    return AgentStatus.COMPLETED if findings else AgentStatus.NO_FINDINGS
