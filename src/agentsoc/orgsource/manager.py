"""Everything an administrator does with an organisational data source, in one place,
each action audited. Passwords pass through here only on their way to the credential store
or to a connector; they are never returned, logged or written anywhere else.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import SecretStr

from agentsoc.audit import AuditEventType, AuditLog
from agentsoc.connectors.base import (
    MAX_BATCH,
    Column,
    ConnectionReport,
    ConnectorError,
    SourceConnector,
    TableRef,
)
from agentsoc.connectors.postgres import PostgresConnector, PostgresSettings
from agentsoc.credentials import CredentialStore
from agentsoc.ingest.mapping import MappingSpec, map_record
from agentsoc.logging_setup import get_logger, register_secret
from agentsoc.orgsource.registry import (
    DataSource,
    DataSourceConfig,
    DataSourceError,
    DataSourceRegistry,
    credential_ref,
)
from agentsoc.orgsource.snapshot import (
    SnapshotError,
    SnapshotInfo,
    build_snapshot,
    read_current,
    source_dir,
    withdraw,
)
from agentsoc.orgsource.staging import RunRecord, StagingStats, StagingStore
from agentsoc.orgsource.sync import sync_once
from agentsoc.perception.records import RejectedRecord
from agentsoc.schemas import AuthEvent, DatasetSource
from agentsoc.schemas.events import RawRef

logger = get_logger(__name__)

ConnectorFactory = Callable[[PostgresSettings, SecretStr], SourceConnector]
PREVIEW_ROWS = 50


@dataclass(frozen=True)
class Preview:
    rows_read: int
    events: list[AuthEvent]
    rejected: list[RejectedRecord]
    disclosures: list[str]


@dataclass(frozen=True)
class SourceStatus:
    source: DataSource
    stats: StagingStats
    runs: list[RunRecord]
    snapshot: dict | None
    has_password: bool


class DataSourceManager:
    def __init__(self, registry: DataSourceRegistry, credentials: CredentialStore,
                 audit: AuditLog, data_root: Path, *,
                 connector_factory: ConnectorFactory | None = None,
                 on_snapshot: Callable[[], None] | None = None) -> None:
        self.registry = registry
        self.credentials = credentials
        self.audit = audit
        self.data_root = Path(data_root)
        self.connector_factory = connector_factory or PostgresConnector
        self.on_snapshot = on_snapshot or (lambda: None)
        self._snapshot_lock = threading.Lock()

    # -- connections -------------------------------------------------------------------------
    def _password(self, password: SecretStr | None, key: str | None) -> SecretStr:
        if password is not None and password.get_secret_value():
            register_secret(password.get_secret_value())
            return password
        if key is None:
            raise DataSourceError("Enter the database password.")
        return self.credentials.get(self.registry.get(key).credential_ref)

    def connector(self, connection: PostgresSettings, password: SecretStr | None = None,
                  key: str | None = None) -> SourceConnector:
        return self.connector_factory(connection, self._password(password, key))

    def test(self, connection: PostgresSettings, password: SecretStr | None,
             key: str | None) -> ConnectionReport:
        subject = key or f"{connection.host}/{connection.database}"
        try:
            report = self.connector(connection, password, key).test()
        except ConnectorError as exc:
            self.audit.append(AuditEventType.DATASOURCE_CONNECTION_TESTED, subject,
                              {"result": "failed", "code": exc.code})
            raise
        self.audit.append(AuditEventType.DATASOURCE_CONNECTION_TESTED, subject,
                          {"result": "ok", "read_only_session": report.read_only_session,
                           "warnings": len(report.warnings)})
        return report

    def tables(self, connection: PostgresSettings, password: SecretStr | None,
               key: str | None) -> list[TableRef]:
        return self.connector(connection, password, key).list_tables()

    def columns(self, connection: PostgresSettings, password: SecretStr | None,
                key: str | None, table: TableRef) -> list[Column]:
        return self.connector(connection, password, key).list_columns(table)

    def preview(self, connection: PostgresSettings, password: SecretStr | None,
                key: str | None, table: TableRef, cursor_column: str,
                mapping: MappingSpec) -> Preview:
        """Map the first rows without storing anything, to check a mapping before saving."""
        connector = self.connector(connection, password, key)
        columns = sorted(mapping.columns | {cursor_column})
        rows = connector.fetch(table, columns, cursor_column=cursor_column,
                               key_column=mapping.record_id, after=None, since=None,
                               limit=PREVIEW_ROWS)
        events, rejected = [], []
        for line, row in enumerate(rows, start=1):
            result = map_record(row, mapping, ref=RawRef(file="preview", line=line),
                                prefix=key or "preview", dataset=DatasetSource.ORGANIZATION)
            (rejected if isinstance(result, RejectedRecord) else events).append(result)
        return Preview(len(rows), events, rejected, mapping.disclosures())

    # -- configuration -----------------------------------------------------------------------
    def create(self, key: str, name: str, config: DataSourceConfig, password: SecretStr, *,
               actor: str) -> DataSource:
        if not password.get_secret_value():
            raise DataSourceError("Enter the database password.")
        if config.batch_size > MAX_BATCH:
            raise DataSourceError(f"batch size must be at most {MAX_BATCH}")
        try:
            self.registry.get(key)
        except DataSourceError:
            pass
        else:
            raise DataSourceError(f"a data source named '{key}' already exists")
        # Credential first: a source never exists without its password.
        self.credentials.put(credential_ref(key), password, actor=actor)
        try:
            source = self.registry.create(key, name, config, actor=actor)
        except Exception:
            self.credentials.delete(credential_ref(key), actor=actor)
            raise
        self.audit.append(AuditEventType.DATASOURCE_SAVED, key, {
            "kind": config.kind, "table": f"{config.table.schema_name}.{config.table.name}",
            "mapping_sha256": config.mapping.sha256(),
            "constants": ",".join(sorted(config.mapping.confirmed_constants)) or "none",
            "sync_interval_seconds": config.sync_interval_seconds, "ai_enabled": False})
        return source

    def update(self, key: str, *, name: str | None = None, sync_enabled: bool | None = None,
               sync_interval_seconds: int | None = None, ai_enabled: bool | None = None,
               actor: str) -> DataSource:
        source, changes = self.registry.update(
            key, name=name, sync_enabled=sync_enabled,
            sync_interval_seconds=sync_interval_seconds, ai_enabled=ai_enabled, actor=actor)
        if "ai_enabled" in changes:
            self.audit.append(AuditEventType.DATASOURCE_AI_PERMISSION_CHANGED, key,
                              {"ai_enabled": changes.pop("ai_enabled")})
        if changes:
            self.audit.append(AuditEventType.DATASOURCE_SYNC_SETTINGS_CHANGED, key, changes)
        return source

    def set_password(self, key: str, password: SecretStr, *, actor: str) -> None:
        if not password.get_secret_value():
            raise DataSourceError("Enter the database password.")
        self.credentials.put(self.registry.get(key).credential_ref, password, actor=actor)

    def delete(self, key: str, *, actor: str) -> None:
        source = self.registry.get(key)
        self.registry.delete(key)
        self.credentials.delete(source.credential_ref, actor=actor)
        withdraw(source_dir(self.data_root, key))
        self.audit.append(AuditEventType.DATASOURCE_DELETED, key,
                          {"stored_data": "kept on disk, no longer shown"})
        self.on_snapshot()

    # -- sync and snapshots ------------------------------------------------------------------
    def store(self, key: str) -> StagingStore:
        return StagingStore(source_dir(self.data_root, key))

    def sync(self, key: str, *, trigger: str = "manual") -> RunRecord:
        source = self.registry.get(key)
        connector = self.connector(source.config.connection, None, key)
        self.audit.append(AuditEventType.SYNC_STARTED, key, {"trigger": trigger})
        run = sync_once(source, connector, self.store(key), trigger=trigger)
        details = {"trigger": trigger, "run": run.id, "fetched": run.fetched, "new": run.new,
                   "duplicates": run.duplicates, "changed": run.changed,
                   "rejected": run.rejected, "more_available": run.more_available}
        if run.status == "completed":
            self.audit.append(AuditEventType.SYNC_COMPLETED, key, details)
        else:
            self.audit.append(AuditEventType.SYNC_FAILED, key, {**details, "error": run.error})
        return run

    def snapshot(self, key: str) -> SnapshotInfo:
        source = self.registry.get(key)
        with self._snapshot_lock:
            try:
                info = build_snapshot(source, self.store(key), self.data_root)
            except SnapshotError:
                raise
            except Exception:
                logger.exception("snapshot failed", extra={"context": {"source": key}})
                self.audit.append(AuditEventType.SNAPSHOT_FAILED, key, {})
                raise SnapshotError("The snapshot could not be built; see the server log."
                                    ) from None
        self.audit.append(AuditEventType.SNAPSHOT_CREATED, source.dashboard_key, {
            "snapshot": info.stamp, "events": info.event_count,
            "incidents": info.incident_count, "first_event": info.first_event,
            "last_event": info.last_event, "mapping_sha256": source.config.mapping.sha256()})
        self.on_snapshot()
        return info

    def status(self, key: str) -> SourceStatus:
        source = self.registry.get(key)
        store = self.store(key)
        refs = {c.ref for c in self.credentials.list()}
        return SourceStatus(source, store.stats(), store.runs(10),
                            read_current(source_dir(self.data_root, key)),
                            source.credential_ref in refs)


class SyncScheduler:
    """Polls each enabled source on its interval and rebuilds its snapshot when new rows
    arrived (at most once per `snapshot.min_interval_seconds`). Not real-time: the delay is
    up to one sync interval plus the snapshot interval and the time a snapshot takes."""

    def __init__(self, manager: DataSourceManager, *, tick_seconds: float = 5.0,
                 clock: Callable[[], datetime] | None = None) -> None:
        self.manager = manager
        self.tick_seconds = tick_seconds
        self.clock = clock or (lambda: datetime.now(UTC))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def tick(self) -> None:
        now = self.clock()
        for source in self.manager.registry.list():
            if not source.sync_enabled:
                continue
            try:
                self._tick_source(source, now)
            except Exception:
                logger.exception("scheduled sync failed", extra={"context": {
                    "source": source.key}})

    def _tick_source(self, source: DataSource, now: datetime) -> None:
        store = self.manager.store(source.key)
        runs = store.runs(1)
        last = runs[0] if runs else None
        due = last is None or last.finished_at is None or (
            datetime.fromisoformat(last.finished_at)
            + timedelta(seconds=source.config.sync_interval_seconds) <= now)
        if due and (last is None or last.status != "running"):
            try:
                last = self.manager.sync(source.key, trigger="scheduled")
            except ConnectorError:
                return
        current = read_current(source_dir(self.manager.data_root, source.key))
        stats = store.stats()
        if stats.accepted == 0:
            return
        if current is not None:
            made = datetime.fromisoformat(current["created_at"])
            interval = timedelta(seconds=source.config.snapshot.min_interval_seconds)
            newer = stats.last_event is not None and (
                stats.last_event.isoformat() != current["last_event"]
                or stats.accepted != current.get("accepted_total", -1))
            if made + interval > now or not newer:
                return
        self.manager.snapshot(source.key)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="agentsoc-sync", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self.tick_seconds):
            self.tick()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=30)
            self._thread = None
