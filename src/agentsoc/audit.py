"""The hash-chained activity log, shared by the API, authentication and the CLIs.

One `AuditLog` per file. Writes take an in-process lock and a cross-process file lock, so
the server and a command-line tool appending at the same time cannot break the chain.
Event types come from a fixed catalogue; details must never contain secrets.

The actor is the signed-in user for the current request (set by the authentication layer
through `acting_as`), or "system" for work no user started.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from agentsoc.logging_setup import get_logger
from agentsoc.schemas import AuditRecord

logger = get_logger(__name__)

SYSTEM_ACTOR = "system"
_actor: ContextVar[str] = ContextVar("agentsoc_actor", default=SYSTEM_ACTOR)


class AuditEventType(StrEnum):
    DATASET_VERIFIED = "dataset.verified"
    INVESTIGATION_COMPLETED = "investigation.completed"
    INVESTIGATION_COMPLETED_LIMITED = "investigation.completed_limited"
    INVESTIGATION_FAILED = "investigation.failed"
    LOGIN_SUCCEEDED = "auth.login.succeeded"
    LOGIN_FAILED = "auth.login.failed"
    LOGOUT = "auth.logout"
    PASSWORD_CHANGED = "auth.password.changed"  # noqa: S105 — an event name
    USER_CREATED = "user.created"
    USER_ROLE_CHANGED = "user.role_changed"
    USER_DISABLED = "user.disabled"
    USER_ENABLED = "user.enabled"
    USER_PASSWORD_RESET = "user.password_reset"  # noqa: S105 — an event name
    CREDENTIAL_STORED = "credential.stored"
    CREDENTIAL_DELETED = "credential.deleted"
    CREDENTIAL_KEYS_ROTATED = "credential.keys_rotated"
    CONFIG_CHANGED = "config.changed"
    # Organisational data sources.
    DATASOURCE_CONNECTION_TESTED = "datasource.connection_tested"
    DATASOURCE_SAVED = "datasource.saved"
    DATASOURCE_DELETED = "datasource.deleted"
    DATASOURCE_SYNC_SETTINGS_CHANGED = "datasource.sync_settings_changed"
    DATASOURCE_AI_PERMISSION_CHANGED = "datasource.ai_permission_changed"
    SNAPSHOT_CREATED = "snapshot.created"
    SNAPSHOT_FAILED = "snapshot.failed"
    # Analyst decisions on incidents.
    INCIDENT_ACCEPTED = "incident.accepted"
    INCIDENT_DISMISSED = "incident.dismissed"
    INCIDENT_EVIDENCE_REQUESTED = "incident.evidence_requested"
    INCIDENT_REOPENED = "incident.reopened"
    INCIDENT_REPORT_EXPORTED = "incident.report_exported"
    SYNC_STARTED = "sync.started"
    SYNC_COMPLETED = "sync.completed"
    SYNC_FAILED = "sync.failed"
    ASSESSMENT_CREATED = "assessment.created"


def current_actor() -> str:
    return _actor.get()


def set_actor(username: str) -> None:
    """Bind the actor for the rest of the current context (one API request)."""
    _actor.set(username)


@contextmanager
def acting_as(username: str) -> Iterator[None]:
    token = _actor.set(username)
    try:
        yield
    finally:
        _actor.reset(token)


@contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    """Exclusive lock on a side file, held across processes. Waits up to 10 s."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.01)
        try:
            yield
        finally:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def append(self, event_type: AuditEventType | str, subject: str,
               details: dict | None = None, *, actor: str | None = None) -> bool:
        """Best effort: a logging failure must never fail the request. Returns success."""
        try:
            kind = AuditEventType(event_type)
            with self._lock, _file_lock(self.path.with_suffix(".lock")):
                records = self.read()
                record = AuditRecord.create(
                    records[-1] if records else None, timestamp=datetime.now(UTC),
                    actor=actor or current_actor(), event_type=kind.value, subject_id=subject,
                    details=details or {})
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(record.model_dump_json() + "\n")
            return True
        except Exception:
            logger.exception("activity log write failed", extra={"context": {
                "event_type": str(event_type)}})
            return False

    def read(self) -> list[AuditRecord]:
        if not self.path.is_file():
            return []
        return [AuditRecord.model_validate_json(line)
                for line in self.path.read_text(encoding="utf-8").splitlines() if line]
