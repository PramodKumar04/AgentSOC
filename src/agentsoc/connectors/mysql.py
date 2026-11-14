"""Read-only MySQL connector (PyMySQL).

Safety measures, each enforced here rather than left to the account's configuration:
  * Every session is read-only (`SET SESSION TRANSACTION READ ONLY`) and checked afterwards
    with `@@transaction_read_only`. A client-side read timeout and, on MySQL 5.7.8 or later,
    `max_execution_time` bound every query.
  * Only the configured database is listed or read. Table and column names are used only
    after they are found in the catalogue, and are quoted with backticks; every value is a
    bound parameter.
  * Batches are bounded; results are fetched in (cursor, key) order for keyset paging.
  * Errors are reduced to a fixed message and the MySQL error number. Server message text,
    which can echo host, account or query details, is never passed on.
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
Name = Annotated[str, StringConstraints(min_length=1, max_length=64,
                                        pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.\-@]*$")]
SslMode = Literal["verify-full", "verify-ca", "require", "disable"]
_SYSTEM_SCHEMAS = ("mysql", "information_schema", "performance_schema", "sys")
# Privileges that let an account change data or schema; SELECT and USAGE are expected.
_WRITE_PRIVILEGES = ("INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER", "INDEX",
                     "GRANT OPTION", "ALL PRIVILEGES", "SUPER", "FILE", "PROCESS")


class MySQLSettings(Contract):
    engine: Literal["mysql"] = "mysql"
    host: Host
    port: int = Field(default=3306, ge=1, le=65535)
    database: Name
    username: Name
    # "require" encrypts but does not check the server's certificate; "verify-full" does.
    sslmode: SslMode = "require"
    connect_timeout_seconds: int = Field(default=10, ge=1, le=60)
    statement_timeout_ms: int = Field(default=30_000, ge=1000, le=300_000)

    def warnings(self) -> list[str]:
        out = []
        if self.sslmode == "disable":
            out.append("The connection is not encrypted (TLS mode 'disable'). Use "
                       "'verify-full' outside a test network.")
        elif self.sslmode == "require":
            out.append("TLS is used but the server certificate is not verified; "
                       "'verify-full' also checks the server's identity.")
        return out


_MESSAGES = {
    1045: "Authentication failed: check the account name and password.",
    1044: "The server refused this account for this database (check the grants).",
    1049: "The database does not exist.",
    1142: "Permission denied: grant this account SELECT on the table.",
    1143: "Permission denied: grant this account SELECT on the column.",
    1227: "Permission denied: this account lacks the privilege needed.",
    1146: "The table does not exist or is not visible to this account.",
    1054: "A mapped column does not exist.",
    3024: "The query took longer than the statement timeout.",
    1040: "The server has too many connections.",
    2003: "Could not connect: check host, port, network, TLS mode and credentials.",
    2013: "Could not connect: check host, port, network, TLS mode and credentials.",
    2026: "Could not connect: check host, port, network, TLS mode and credentials.",
}


def _safe(exc: Exception) -> ConnectorError:
    import pymysql

    if isinstance(exc, pymysql.MySQLError) and exc.args and isinstance(exc.args[0], int):
        code = exc.args[0]
        if code in _MESSAGES:
            return ConnectorError(_MESSAGES[code], code=str(code))
        return ConnectorError("The database reported an error.", code=str(code))
    if isinstance(exc, pymysql.err.InterfaceError):
        return ConnectorError("Could not connect: check host, port, network, TLS mode and "
                              "credentials.")
    return ConnectorError("The database reported an error.")


def _ident(name: str) -> str:
    """Quote an identifier that has already been found in the catalogue."""
    return "`" + name.replace("`", "``") + "`"


class MySQLConnector:
    def __init__(self, settings: MySQLSettings, password: SecretStr, *,
                 connect: Callable[..., Any] | None = None) -> None:
        self.settings = settings
        self._password = password
        register_secret(password.get_secret_value())
        if connect is None:
            import pymysql

            connect = pymysql.connect
        self._connect = connect

    def _tls_options(self) -> dict[str, Any]:
        mode = self.settings.sslmode
        if mode == "disable":
            return {"ssl_disabled": True}
        options: dict[str, Any] = {"ssl": {}}
        if mode == "verify-full":
            options.update(ssl_verify_cert=True, ssl_verify_identity=True)
        elif mode == "verify-ca":
            options.update(ssl_verify_cert=True, ssl_verify_identity=False)
        else:  # require: encrypt, do not verify
            options.update(ssl_verify_cert=False, ssl_verify_identity=False)
        return options

    @contextmanager
    def _session(self) -> Iterator[Any]:
        s = self.settings
        timeout = s.statement_timeout_ms / 1000
        try:
            conn = self._connect(
                host=s.host, port=s.port, database=s.database, user=s.username,
                password=self._password.get_secret_value(),
                connect_timeout=s.connect_timeout_seconds,
                read_timeout=timeout, write_timeout=timeout, autocommit=True,
                charset="utf8mb4", **self._tls_options())
        except Exception as exc:
            raise _safe(exc) from None
        try:
            with conn.cursor() as cur:
                cur.execute("SET SESSION TRANSACTION READ ONLY")
                try:  # MySQL 5.7.8+; MariaDB and older servers use the client timeout only
                    cur.execute(f"SET SESSION max_execution_time = {s.statement_timeout_ms}")
                except Exception:
                    logger.info("server has no max_execution_time; client timeout applies")
            yield conn
        except ConnectorError:
            raise
        except Exception as exc:
            raise _safe(exc) from None
        finally:
            conn.close()

    @staticmethod
    def _rows(conn: Any, query: str, params: tuple = ()) -> list[tuple]:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return list(cur.fetchall())

    def test(self) -> ConnectionReport:
        with self._session() as conn:
            version, account, read_only = self._rows(conn, """
                SELECT VERSION(), CURRENT_USER(), @@SESSION.transaction_read_only
            """)[0]
            grants = [str(row[0]) for row in self._rows(conn, "SHOW GRANTS FOR CURRENT_USER()")]
        warnings = self.settings.warnings()
        granted = " ".join(grants).upper()
        if any(f" {p}" in granted or f"{p} ON" in granted for p in _WRITE_PRIVILEGES):
            warnings.append("This account has privileges beyond SELECT. An account with "
                            "SELECT only is safer.")
        return ConnectionReport(server_version=str(version), account=str(account),
                                read_only_session=int(read_only) == 1, warnings=warnings)

    def list_tables(self) -> list[TableRef]:
        """Tables and views of the configured database only (never other databases)."""
        with self._session() as conn:
            rows = self._rows(conn, """
                SELECT table_schema, table_name FROM information_schema.tables
                WHERE table_schema = %s AND table_type IN ('BASE TABLE', 'VIEW')
                  AND table_schema NOT IN %s
                ORDER BY table_name LIMIT 1000
            """, (self.settings.database, _SYSTEM_SCHEMAS))
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
            raise ConnectorError(_MESSAGES[1146], code="1146")
        return [Column(name, data_type, bool(nullable)) for name, data_type, nullable in rows]

    def fetch(self, table: TableRef, columns: list[str], *, cursor_column: str,
              key_column: str, after: Position | None, since: CursorValue | None,
              limit: int) -> list[dict[str, object]]:
        """Rows ordered by (cursor, key): after `after` when given, else from `since` on."""
        if not 1 <= limit <= MAX_BATCH:
            raise ConnectorError(f"batch size must be 1-{MAX_BATCH}")
        if table.schema != self.settings.database:
            raise ConnectorError("The table is not in the configured database.")
        wanted = list(dict.fromkeys([*columns, cursor_column, key_column]))
        with self._session() as conn:
            known = {c.name for c in self._columns(conn, table)}
            unknown = sorted(set(wanted) - known)
            if unknown:
                raise ConnectorError(f"Columns not in {table}: {', '.join(unknown)}",
                                     code="1054")
            cursor, key = _ident(cursor_column), _ident(key_column)
            # Identifiers were found in the catalogue above and are quoted by _ident().
            query = (f"SELECT {', '.join(_ident(c) for c in wanted)} "  # noqa: S608
                     f"FROM {_ident(table.schema)}.{_ident(table.name)}")
            params: tuple = ()
            if after is not None:
                query += f" WHERE ({cursor}, {key}) > (%s, %s)"
                params = (after.cursor, after.key)
            elif since is not None:
                query += f" WHERE {cursor} >= %s"
                params = (since,)
            else:
                query += f" WHERE {cursor} IS NOT NULL"
            query += f" ORDER BY {cursor}, {key} LIMIT %s"
            with conn.cursor() as cur:
                cur.execute(query, (*params, limit))
                names = [d[0] for d in cur.description]
                return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]
