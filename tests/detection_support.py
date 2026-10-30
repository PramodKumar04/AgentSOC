"""Builders for SYNTHETIC detection fixtures (not real-world attack data)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from agentsoc.detection.config import DetectionConfig
from agentsoc.schemas import AuthEvent

BASE = datetime(2026, 1, 1, tzinfo=UTC)
BASELINE_S = 1000  # tests use a short baseline: [first event, first event + 1000 s)


class Stream:
    """Accumulates events with unique IDs and source line numbers."""

    def __init__(self, dataset: str = "synthetic", prefix: str = "E") -> None:
        self.dataset = dataset
        self.prefix = prefix
        self.events: list[AuthEvent] = []

    def add(
        self,
        t: int,
        user: str = "u1@D",
        src: str = "WS1",
        dst: str = "WS1",
        outcome: str = "Success",
        orientation: str = "LogOn",
        **overrides: Any,
    ) -> AuthEvent:
        n = len(self.events) + 1
        data: dict[str, Any] = {
            "event_id": f"{self.prefix}{n}",
            "timestamp": BASE + timedelta(seconds=t),
            "src_user": user,
            "dst_user": user,
            "src_host": src,
            "dst_host": dst,
            "auth_type": "Kerberos",
            "logon_type": "Network",
            "orientation": orientation,
            "outcome": outcome,
            "dataset": self.dataset,
            "raw_ref": {"file": f"{self.prefix}.txt", "line": n},
        }
        data.update(overrides)
        event = AuthEvent(**data)
        self.events.append(event)
        return event

    def fails(self, times: list[int], user: str = "u1@D", src: str = "WS1", dst: str = "WS1"):
        return [self.add(t, user, src, dst, outcome="Fail") for t in times]

    def baseline(self, user: str = "u1@D", src: str = "WS1", dsts: tuple[str, ...] = ("SRV1",)):
        """Familiar access at t=0..; keeps the baseline window anchored at t=0."""
        for k, dst in enumerate(dsts):
            self.add(k, user, src, dst)


def config(**overrides: Any) -> DetectionConfig:
    return DetectionConfig(**{"baseline_seconds": BASELINE_S, **overrides})


def rules_of(result) -> list[str]:
    return [f.rule_id for f in result.findings]
