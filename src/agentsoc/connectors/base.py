"""What every organisational database connector provides.

Connectors only read. They are given a table and the columns a mapping needs, check both
against what the server reports, and fetch bounded batches in (cursor, key) order so a sync
can stop at any batch and resume from its checkpoint.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Protocol

from agentsoc.exceptions import AgentSOCError

MAX_BATCH = 5000


class ConnectorError(AgentSOCError):
    """Safe to show: never contains a password, connection string, or server message text."""

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class TableRef:
    schema: str
    name: str

    def __str__(self) -> str:
        return f"{self.schema}.{self.name}"


@dataclass(frozen=True)
class Column:
    name: str
    data_type: str
    nullable: bool


@dataclass(frozen=True)
class ConnectionReport:
    server_version: str
    account: str
    read_only_session: bool
    warnings: list[str] = field(default_factory=list)


CursorValue = int | Decimal | datetime | str


@dataclass(frozen=True)
class Position:
    """The last (cursor, key) a sync has fully stored. Rows after it are new."""

    cursor: CursorValue
    key: CursorValue


class SourceConnector(Protocol):
    def test(self) -> ConnectionReport: ...

    def list_tables(self) -> list[TableRef]: ...

    def list_columns(self, table: TableRef) -> list[Column]: ...

    def fetch(self, table: TableRef, columns: list[str], *, cursor_column: str,
              key_column: str, after: Position | None, since: CursorValue | None,
              limit: int) -> list[dict[str, object]]: ...


def encode_cursor(value: CursorValue) -> dict[str, str]:
    """Checkpoints keep the cursor's type so the next query compares like with like."""
    if isinstance(value, bool):
        raise ConnectorError("a true/false column cannot be a sync cursor")
    if isinstance(value, int):
        return {"type": "int", "value": str(value)}
    if isinstance(value, Decimal):
        return {"type": "decimal", "value": str(value)}
    if isinstance(value, datetime):
        return {"type": "datetime", "value": value.isoformat()}
    if isinstance(value, str):
        return {"type": "text", "value": value}
    raise ConnectorError(f"{type(value).__name__} columns cannot be a sync cursor")


def decode_cursor(data: dict[str, str]) -> CursorValue:
    kind, value = data["type"], data["value"]
    if kind == "int":
        return int(value)
    if kind == "decimal":
        return Decimal(value)
    if kind == "datetime":
        return datetime.fromisoformat(value)
    if kind == "text":
        return value
    raise ConnectorError("checkpoint has an unknown cursor type")
