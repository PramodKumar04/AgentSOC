"""Analyst decisions on incidents (human in the loop).

Every decision is a new row; nothing is updated or deleted, so the history is the record. A
decision is bound to the incident's content hash. Incident numbers are per detection run, so a
decision recorded for a different version of an incident is reported as such and the incident
counts as open again.

Decisions never execute anything: accepting an incident marks it as confirmed for follow-up.
Proposed response actions stay dry-run proposals for people to carry out.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from agentsoc.store import appdb


class Decision(StrEnum):
    ACCEPTED = "accepted"            # confirmed: needs follow-up
    DISMISSED = "dismissed"          # not a concern (reason required)
    MORE_EVIDENCE = "more_evidence"  # analyst asked AgentSOC for wider context
    REOPENED = "reopened"            # back to open


class DismissReason(StrEnum):
    EXPECTED_ACTIVITY = "expected_activity"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    AUTHORISED_TEST = "authorised_test"
    OTHER = "other"


class ReviewStatus(StrEnum):
    OPEN = "open"
    ACCEPTED = "accepted"
    DISMISSED = "dismissed"
    MORE_EVIDENCE = "more_evidence"


CONTEXT_WINDOWS = (1, 6, 24, 72)


@dataclass(frozen=True)
class ReviewEntry:
    id: int
    source_key: str
    incident_id: str
    incident_sha256: str
    decision: Decision
    reason: str | None
    note: str | None
    window_hours: int | None
    analyst: str
    created_at: str


def status_of(latest: ReviewEntry | None, current_sha256: str) -> ReviewStatus:
    if latest is None or latest.incident_sha256 != current_sha256:
        return ReviewStatus.OPEN
    if latest.decision is Decision.REOPENED:
        return ReviewStatus.OPEN
    return ReviewStatus(latest.decision.value)


def _entry(row) -> ReviewEntry:
    return ReviewEntry(row["id"], row["source_key"], row["incident_id"], row["incident_sha256"],
                       Decision(row["decision"]), row["reason"], row["note"],
                       row["window_hours"], row["analyst"], row["created_at"])


class ReviewStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        appdb.migrate(self.db_path)

    def add(self, *, source_key: str, incident_id: str, incident_sha256: str,
            decision: Decision, reason: str | None, note: str | None,
            window_hours: int | None, analyst: str) -> ReviewEntry:
        now = datetime.now(UTC).isoformat(timespec="seconds")
        with appdb.transaction(self.db_path) as conn:
            row_id = conn.execute(
                "INSERT INTO incident_reviews (source_key, incident_id, incident_sha256, "
                "decision, reason, note, window_hours, analyst, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (source_key, incident_id, incident_sha256, decision.value, reason, note,
                 window_hours, analyst, now)).lastrowid
            row = conn.execute("SELECT * FROM incident_reviews WHERE id = ?",
                               (row_id,)).fetchone()
        return _entry(row)

    def history(self, source_key: str, incident_id: str) -> list[ReviewEntry]:
        """Oldest first."""
        with appdb.reader(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM incident_reviews WHERE source_key = ? AND incident_id = ? "
                "ORDER BY id", (source_key, incident_id)).fetchall()
        return [_entry(r) for r in rows]

    def latest_by_incident(self, source_key: str) -> dict[str, ReviewEntry]:
        with appdb.reader(self.db_path) as conn:
            rows = conn.execute(
                "SELECT r.* FROM incident_reviews r JOIN (SELECT incident_id, MAX(id) AS id "
                "FROM incident_reviews WHERE source_key = ? GROUP BY incident_id) l "
                "ON r.id = l.id", (source_key,)).fetchall()
        return {r["incident_id"]: _entry(r) for r in rows}
