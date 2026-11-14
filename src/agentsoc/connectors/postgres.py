"""Read-only PostgreSQL connector (psycopg 3).

Safety measures, each enforced here rather than left to the account's configuration:
  * Every session is read-only (`default_transaction_read_only`, and the connection's own
    read-only flag), with a statement timeout and an idle-in-transaction timeout.
  * Table and column names are used only after they are found in the server's catalogue,
    and are quoted by psycopg; every value is a bound parameter.
  * Batches are bounded; results are fetched in (cursor, key) order for keyset paging.
  * Errors are reduced to a fixed message and the SQLSTATE code. Server message text, which
    can echo host, account or query details, is never passed on.
The account should still be granted SELECT only; `test()` warns when it can do more.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Annotated, Any, Literal

from pydantic import Field, SecretStr, StringConstraints

from agentsoc.connectors.base import (
    MAX_BATCH,
    Column,
    ConnectionReport,
    ConnectorError,
    CursorValue,
    Position,
    TableRef,
)
from agentsoc.logging_setup import get_logger, register_secret
from agentsoc.schemas.common import Contract

logger = get_logger(__name__)

Host = Annotated[str, StringConstraints(min_length=1, max_length=253,
                                        pattern=r"^[A-Za-z0-9][A-Za-z0-9.\-:]*$")]
Name = Annotated[str, StringConstraints(min_length=1, max_length=63,
                                        pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.\-@]*$")]
SslMode = Literal["verify-full", "verify-ca", "require", "prefer", "disable"]
_SYSTEM_SCHEMAS = ("pg_catalog", "information_schema", "pg_toast")


class PostgresSettings(Contract):
    engine: Literal["postgresql"] = "postgresql"
    host: Host
    port: int = Field(default=5432, ge=1, le=65535)
    database: Name
    username: Name
    # "require" encrypts but does not check the server's certificate; "verify-full" does.
    sslmode: SslMode = "require"
    connect_timeout_seconds: int = Field(default=10, ge=1, le=60)
    statement_timeout_ms: int = Field(default=30_000, ge=1000, le=300_000)

    def warnings(self) -> list[str]:
        out = []
        if self.sslmode in ("disable", "prefer"):
            out.append("The connection may not be encrypted (TLS mode "
                       f"'{self.sslmode}'). Use 'verify-full' outside a test network.")
        elif self.sslmode == "require":
            out.append("TLS is used but the server certificate is not verified; "
                       "'verify-full' also checks the server's identity.")
        return out


_MESSAGES = {
    "28P01": "Authentication failed: check the account name and password.",
    "28000": "The server refused this account or connection (check pg_hba.conf and TLS).",
    "3D000": "The database does not exist.",
    "42501": "Permission denied: grant this account SELECT on the table.",
    "42P01": "The table does not exist or is not visible to this account.",
    "42703": "A mapped column does not exist.",
    "57014": "The query took longer than the statement timeout.",
    "53300": "The server has too many connections.",
}


def _safe(exc: Exception) -> ConnectorError:
    code = getattr(exc, "sqlstate", None)
    if code in _MESSAGES:
        return ConnectorError(_MESSAGES[code], code=code)
    import psycopg

    if isinstance(exc, psycopg.OperationalError):
        return ConnectorError("Could not connect: check host, port, network, TLS mode and "
                              "credentials.", code=code)
    return ConnectorError("The database reported an error.", code=code)


class PostgresConnector:
    def __init__(self, settings: PostgresSettings, password: SecretStr, *,
                 connect: Callable[..., Any] | None = None) -> None:
        self.settings = settings
        self._password = password
        register_secret(password.get_secret_value())
        if connect is None:
            import psycopg

            connect = psycopg.connect
        self._connect = connect

    @contextmanager
    def _session(self) -> Iterator[Any]:
        s = self.settings
        options = (f"-c default_transaction_read_only=on -c statement_timeout="
                   f"{s.statement_timeout_ms} -c idle_in_transaction_session_timeout=60000")
        try:
            conn = self._connect(
                host=s.host, port=s.port, dbname=s.database, user=s.username,
                password=self._password.get_secret_value(), sslmode=s.sslmode,
                connect_timeout=s.connect_timeout_seconds,
                application_name="agentsoc-readonly", options=options)
        except Exception as exc:
            raise _safe(exc) from None
        try:
            conn.read_only = True
            yield conn
        except ConnectorError:
            raise
        except Exception as exc:
            raise _safe(exc) from None
        finally:
            try:
                conn.rollback()
            finally:
                conn.close()

    @staticmethod
    def _rows(conn: Any, query: Any, params: tuple = ()) -> list[tuple]:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchall()

    def test(self) -> ConnectionReport:
        with self._session() as conn:
            version, account, read_only, superuser, can_create = self._rows(conn, """
                SELECT current_setting('server_version'), current_user,
                       current_setting('transaction_read_only'),
                       (SELECT rolsuper FROM pg_roles WHERE rolname = current_user),
                       has_database_privilege(current_user, current_database(), 'CREATE')
            """)[0]
        warnings = self.settings.warnings()
        if superuser:
            warnings.append("This account is a superuser. Use an account granted SELECT only.")
        elif can_create:
            warnings.append("This account can create objects in the database. An account "
                            "with SELECT only is safer.")
        return ConnectionReport(server_version=str(version), account=str(account),
                                read_only_session=read_only == "on", warnings=warnings)

    def list_tables(self) -> list[TableRef]:
        with self._session() as conn:
            rows = self._rows(conn, """
                SELECT table_schema, table_name FROM information_schema.tables
                WHERE table_type IN ('BASE TABLE', 'VIEW')
                  AND table_schema <> ALL(%s)
                ORDER BY table_schema, table_name LIMIT 1000
            """, (list(_SYSTEM_SCHEMAS),))
        return [TableRef(schema, name) for schema, name in rows]

    def list_columns(self, table: TableRef) -> list[Column]:
        with self._session() as conn:
            return self._columns(conn, table)

    def _columns(self, conn: Any, table: TableRef) -> list[Column]:
        rows = self._rows(conn, """
            SELECT column_name, data_type, is_nullable = 'YES'
            FROM information_schema.columns
            WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position
        """, (table.schema, table.name))
        if not rows:
            raise ConnectorError(_MESSAGES["42P01"], code="42P01")
        return [Column(name, data_type, bool(nullable)) for name, data_type, nullable in rows]

    def fetch(self, table: TableRef, columns: list[str], *, cursor_column: str,
              key_column: str, after: Position | None, since: CursorValue | None,
              limit: int) -> list[dict[str, object]]:
        """Rows ordered by (cursor, key): after `after` when given, else from `since` on."""
        from psycopg import sql

        if not 1 <= limit <= MAX_BATCH:
            raise ConnectorError(f"batch size must be 1-{MAX_BATCH}")
        wanted = list(dict.fromkeys([*columns, cursor_column, key_column]))
        with self._session() as conn:
            known = {c.name for c in self._columns(conn, table)}
            unknown = sorted(set(wanted) - known)
            if unknown:
                raise ConnectorError(f"Columns not in {table}: {', '.join(unknown)}",
                                     code="42703")
            cursor, key = sql.Identifier(cursor_column), sql.Identifier(key_column)
            query = sql.SQL("SELECT {cols} FROM {schema}.{table}").format(
                cols=sql.SQL(", ").join(sql.Identifier(c) for c in wanted),
                schema=sql.Identifier(table.schema), table=sql.Identifier(table.name))
            params: tuple = ()
            if after is not None:
                query += sql.SQL(" WHERE ({c}, {k}) > (%s, %s)").format(c=cursor, k=key)
                params = (after.cursor, after.key)
            elif since is not None:
                query += sql.SQL(" WHERE {c} >= %s").format(c=cursor)
                params = (since,)
            else:
                query += sql.SQL(" WHERE {c} IS NOT NULL").format(c=cursor)
            query += sql.SQL(" ORDER BY {c}, {k} LIMIT %s").format(c=cursor, k=key)
            with conn.cursor() as cur:
                cur.execute(query, (*params, limit))
                names = [d.name for d in cur.description]
                return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]
