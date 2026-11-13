"""Configured organisational data sources, kept in the application database.

A source's configuration holds no secret: the password lives in the credential store under
`credential_ref`. AI investigation starts disabled for every source and only an
administrator can enable it, which is recorded with who and when.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, ValidationError

from agentsoc.connectors.postgres import Name, PostgresSettings
from agentsoc.exceptions import AgentSOCError
from agentsoc.ingest.mapping import ColumnName, MappingSpec
from agentsoc.schemas.common import Contract
from agentsoc.store import appdb

SourceKey = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9\-]{1,30}$")]
SOURCE_KEY_PREFIX = "org-"  # key shown to the dashboard, apart from the built-in sources
MIN_SYNC_INTERVAL = 30


class DataSourceError(AgentSOCError):
    pass


class TableName(Contract):
    schema_name: Name = Field(alias="schema")
    name: Name

    model_config = Contract.model_config | {"populate_by_name": True}


class SnapshotPolicy(Contract):
    # The newest `window_hours` of data, at most `max_events` events, go into each snapshot
    # that detection, SSE and RSEM process. Those engines hold a snapshot in memory.
    window_hours: int = Field(default=168, ge=1, le=2160)
    max_events: int = Field(default=200_000, ge=100, le=500_000)
    min_interval_seconds: int = Field(default=300, ge=60, le=86_400)


class DataSourceConfig(Contract):
    kind: Literal["postgresql"] = "postgresql"
    connection: PostgresSettings
    table: TableName
    # Rows are read in (cursor, record id) order. The cursor should only grow for new rows:
    # an insert sequence or an "ingested at" time, not the time the event happened.
    cursor_column: ColumnName
    # Re-read this far behind the checkpoint on every sync (seconds for a time cursor, units
    # for a number cursor) to catch rows committed late. Already-stored rows are skipped.
    lookback: int = Field(default=0, ge=0, le=86_400)
    batch_size: int = Field(default=1000, ge=1, le=5000)
    max_rows_per_sync: int = Field(default=50_000, ge=1, le=1_000_000)
    sync_interval_seconds: int = Field(default=60, ge=MIN_SYNC_INTERVAL, le=86_400)
    snapshot: SnapshotPolicy = Field(default_factory=SnapshotPolicy)
    mapping: MappingSpec

    @property
    def key_column(self) -> str:
        return self.mapping.record_id

    @property
    def columns(self) -> list[str]:
        return sorted(self.mapping.columns | {self.cursor_column})


@dataclass(frozen=True)
class DataSource:
    key: str
    name: str
    config: DataSourceConfig
    credential_ref: str
    sync_enabled: bool
    ai_enabled: bool
    ai_changed_by: str | None
    ai_changed_at: str | None
    created_by: str
    created_at: str
    updated_at: str

    @property
    def dashboard_key(self) -> str:
        return SOURCE_KEY_PREFIX + self.key


def credential_ref(key: str) -> str:
    return f"datasource.{key}"


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _row(row) -> DataSource:
    try:
        config = DataSourceConfig.model_validate_json(row["config"])
    except ValidationError:
        raise DataSourceError(f"stored configuration of '{row['key']}' is invalid") from None
    return DataSource(row["key"], row["name"], config, row["credential_ref"],
                      bool(row["sync_enabled"]), bool(row["ai_enabled"]), row["ai_changed_by"],
                      row["ai_changed_at"], row["created_by"], row["created_at"],
                      row["updated_at"])


class DataSourceRegistry:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        appdb.migrate(self.db_path)

    def list(self) -> list[DataSource]:
        with appdb.reader(self.db_path) as conn:
            return [_row(r) for r in conn.execute("SELECT * FROM data_sources ORDER BY key")]

    def get(self, key: str) -> DataSource:
        with appdb.reader(self.db_path) as conn:
            row = conn.execute("SELECT * FROM data_sources WHERE key = ?", (key,)).fetchone()
        if row is None:
            raise DataSourceError(f"unknown data source '{key}'")
        return _row(row)

    def find_by_dashboard_key(self, dashboard_key: str) -> DataSource | None:
        if not dashboard_key.startswith(SOURCE_KEY_PREFIX):
            return None
        try:
            return self.get(dashboard_key.removeprefix(SOURCE_KEY_PREFIX))
        except DataSourceError:
            return None

    def create(self, key: str, name: str, config: DataSourceConfig, *, actor: str) -> DataSource:
        now = _now()
        try:
            with appdb.transaction(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO data_sources (key, name, kind, config, credential_ref, "
                    "created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (key, name, config.kind, config.model_dump_json(by_alias=True),
                     credential_ref(key), actor, now, now))
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise DataSourceError(f"a data source named '{key}' already exists") from None
            raise
        return self.get(key)

    def update(self, key: str, *, name: str | None = None, sync_enabled: bool | None = None,
               sync_interval_seconds: int | None = None, ai_enabled: bool | None = None,
               actor: str) -> tuple[DataSource, dict[str, object]]:
        """Returns the source and the fields that actually changed."""
        current = self.get(key)
        changes: dict[str, object] = {}
        config = current.config
        if name is not None and name != current.name:
            changes["name"] = name
        if sync_enabled is not None and sync_enabled != current.sync_enabled:
            changes["sync_enabled"] = sync_enabled
        if sync_interval_seconds is not None and (
                sync_interval_seconds != config.sync_interval_seconds):
            config = DataSourceConfig.model_validate(
                {**config.model_dump(by_alias=True),
                 "sync_interval_seconds": sync_interval_seconds})
            changes["sync_interval_seconds"] = sync_interval_seconds
        if ai_enabled is not None and ai_enabled != current.ai_enabled:
            changes["ai_enabled"] = ai_enabled
        if not changes:
            return current, {}
        now = _now()
        with appdb.transaction(self.db_path) as conn:
            conn.execute(
                "UPDATE data_sources SET name = ?, config = ?, sync_enabled = ?, "
                "updated_at = ? WHERE key = ?",
                (changes.get("name", current.name), config.model_dump_json(by_alias=True),
                 int(changes.get("sync_enabled", current.sync_enabled)), now, key))
            if "ai_enabled" in changes:
                conn.execute("UPDATE data_sources SET ai_enabled = ?, ai_changed_by = ?, "
                             "ai_changed_at = ? WHERE key = ?",
                             (int(bool(changes["ai_enabled"])), actor, now, key))
        return self.get(key), changes

    def delete(self, key: str) -> bool:
        with appdb.transaction(self.db_path) as conn:
            return conn.execute("DELETE FROM data_sources WHERE key = ?", (key,)).rowcount > 0

    def ai_allowed(self, dashboard_key: str) -> bool:
        """False for every organisational source unless an administrator enabled it."""
        source = self.find_by_dashboard_key(dashboard_key)
        return bool(source and source.ai_enabled)


def describe(config: DataSourceConfig) -> dict[str, object]:
    """Configuration safe to show any signed-in user: no host, account or secret."""
    return json.loads(json.dumps({
        "kind": config.kind, "table": f"{config.table.schema_name}.{config.table.name}",
        "sync_interval_seconds": config.sync_interval_seconds,
        "disclosures": config.mapping.disclosures()}))
