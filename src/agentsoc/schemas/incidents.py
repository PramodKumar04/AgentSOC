"""Detection findings and correlated incidents (Layer 1 → Layers 2–5).

A Finding separates raw observations (`metrics`, `event_ids`) from the rule's
interpretation (`description`). An Incident is suspicious activity awaiting
investigation — never a confirmed compromise.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import AwareDatetime, Field, model_validator

from agentsoc.schemas.common import Contract, Identifier, LongText, Severity, ShortText
from agentsoc.schemas.events import DatasetSource

MetricValue = bool | int | float | str


class Finding(Contract):
    """One detection rule firing over one or more events."""

    finding_id: Identifier
    rule_id: Identifier
    severity: Severity
    user: Identifier
    event_ids: list[Identifier] = Field(min_length=1)
    hosts: list[Identifier] = Field(default_factory=list)
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    metrics: dict[str, MetricValue] = Field(default_factory=dict)
    description: LongText

    @model_validator(mode="after")
    def _check_window(self) -> Finding:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen precedes first_seen")
        return self


class IncidentStatus(StrEnum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Incident(Contract):
    """Correlated findings about one principal within one time window.

    `event_ids` is the evidence set: downstream components (including the LLM)
    may only cite events from this list.
    """

    incident_id: Identifier
    principal_user: Identifier
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    findings: list[Finding] = Field(min_length=1)
    event_ids: list[Identifier] = Field(min_length=1)
    rule_ids: list[Identifier] = Field(min_length=1)
    involved_users: list[Identifier] = Field(default_factory=list)
    involved_hosts: list[Identifier] = Field(default_factory=list)
    datasets: list[DatasetSource] = Field(min_length=1)
    severity: Severity
    severity_rationale: LongText
    benign_explanations: list[ShortText] = Field(default_factory=list)
    limitations: list[ShortText] = Field(default_factory=list)
    missing_information: list[ShortText] = Field(default_factory=list)
    flags: list[Identifier] = Field(default_factory=list)
    status: IncidentStatus = IncidentStatus.OPEN

    @model_validator(mode="after")
    def _check_consistency(self) -> Incident:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen precedes first_seen")
        if len(set(self.event_ids)) != len(self.event_ids):
            raise ValueError("event_ids contains duplicates")
        known = set(self.event_ids)
        for finding in self.findings:
            missing = set(finding.event_ids) - known
            if missing:
                raise ValueError(
                    f"finding {finding.finding_id} cites events not in incident: {sorted(missing)}"
                )
            if finding.first_seen < self.first_seen or finding.last_seen > self.last_seen:
                raise ValueError(f"finding {finding.finding_id} lies outside the incident window")
        if sorted(set(self.rule_ids)) != sorted({f.rule_id for f in self.findings}):
            raise ValueError("rule_ids must equal the distinct rule_ids of the findings")
        return self
