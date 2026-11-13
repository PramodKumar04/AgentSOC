"""Helpers for SSE tests on SYNTHETIC fixtures (not real-world attack data)."""

from __future__ import annotations

from typing import Any

from agentsoc.detection.config import DetectionConfig
from agentsoc.detection.engine import run_detection
from agentsoc.detection.lateral import account_name
from agentsoc.graph.config import StructuralConfig
from agentsoc.graph.index import EventIndex, IndexedEvent
from agentsoc.graph.proposed import StructuralEvidence
from agentsoc.graph.validate import assess_incident
from agentsoc.schemas import AuthEvent
from agentsoc.schemas.graph import EdgeKind, StructuralAssessment
from tests.detection_support import config as detection_config


def kind_of(event: AuthEvent) -> EdgeKind:
    if event.outcome.value == "Success":
        return EdgeKind.LOCAL if event.src_host == event.dst_host else EdgeKind.MOVEMENT
    return EdgeKind.ATTEMPT


def indexed(event: AuthEvent) -> IndexedEvent:
    return IndexedEvent(
        event_id=event.event_id, timestamp=event.timestamp, t=event.timestamp.timestamp(),
        account=event.src_user, account_key=account_name(event.src_user),
        src_host=event.src_host, dst_host=event.dst_host, kind=kind_of(event),
        auth_type=event.auth_type, logon_type=event.logon_type, dataset=event.dataset.value,
        raw_file=event.raw_ref.file, raw_line=event.raw_ref.line,
    )


def index_of(events: list[AuthEvent]) -> EventIndex:
    return EventIndex(indexed(e) for e in events)


class Assessed:
    """Detection then structural assessment over one SYNTHETIC event list."""

    def __init__(
        self, events: list[AuthEvent], *, detection: dict[str, Any] | None = None,
        **structural: Any,
    ) -> None:
        self.events = {e.event_id: e for e in events}
        self.detection: DetectionConfig = detection_config(**(detection or {}))
        self.config = StructuralConfig(**structural)
        self.index = index_of(events)
        self.result = run_detection(events, self.detection)
        self.by_user: dict[str, StructuralAssessment] = {
            i.principal_user: assess_incident(i, self.index, self.config)
            for i in self.result.incidents
        }
        self.incidents = {i.principal_user: i for i in self.result.incidents}

    def __getitem__(self, user: str) -> StructuralAssessment:
        return self.by_user[user]

    def evidence(self, user: str) -> StructuralEvidence:
        return StructuralEvidence(self.by_user[user], self.events, self.detection, self.config)

