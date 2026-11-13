"""PostgreSQL connector against a SIMULATED driver.

These tests check what AgentSOC sends (read-only session, timeouts, quoted identifiers,
bound values, bounded batches) and how it reports errors. They do not show that the
connector works with a real PostgreSQL server: see tests/integration/test_postgres_real.py.
"""

from datetime import UTC, datetime

import psycopg
import pytest
from pydantic import SecretStr, ValidationError

from agentsoc.connectors.base import (
    ConnectorError,
    Position,
    TableRef,
    decode_cursor,
    encode_cursor,
)
from agentsoc.connectors.postgres import PostgresConnector, PostgresSettings

PASSWORD = "S3cret-db-passw0rd"
COLUMNS = [("id", "bigint", False), ("ts", "timestamp with time zone", False),
           ("user", "text", True), ("weird\"col", "text", True)]


class FakeCursor:
    def __init__(self, conn):
        self.conn, self.description, self._rows = conn, [], []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, query, params=()):
        text = query if isinstance(query, str) else query.as_string(None)
        self.conn.executed.append((text, params))
        if self.conn.fail:
            raise self.conn.fail
        if "information_schema.columns" in text:
            self._rows = COLUMNS
        elif "information_schema.tables" in text:
            self._rows = [("public", "auth_log")]
        elif "current_setting('server_version')" in text:
            self._rows = [("16.4", "agentsoc_reader", "on", self.conn.superuser, False)]
        else:
            self.description = [type("D", (), {"name": n}) for n in ("id", "ts", "user")]
            self._rows = [(1, datetime(2026, 11, 13, tzinfo=UTC), "alice")]

    def fetchall(self):
        return self._rows


class FakeConnection:
    def __init__(self, fail=None, superuser=False):
        self.executed, self.fail, self.superuser = [], fail, superuser
        self.read_only, self.closed, self.rolled_back = False, False, False

    def cursor(self):
        return FakeCursor(self)

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def make(fail=None, connect_error=None, superuser=False, **settings):
    calls, conns = [], []

    def connect(**kwargs):
        calls.append(kwargs)
        if connect_error:
            raise connect_error
        conns.append(FakeConnection(fail, superuser))
        return conns[-1]

    s = PostgresSettings(host="db.example.test", database="security", username="agentsoc_reader",
                         **settings)
    return PostgresConnector(s, SecretStr(PASSWORD), connect=connect), calls, conns


def test_sessions_are_read_only_bounded_and_closed():
    connector, calls, conns = make(statement_timeout_ms=5000)
    report = connector.test()
    options = calls[0]["options"]
    assert "default_transaction_read_only=on" in options
    assert "statement_timeout=5000" in options and "idle_in_transaction_session_timeout" in options
    assert calls[0]["sslmode"] == "require" and calls[0]["connect_timeout"] == 10
    assert calls[0]["application_name"] == "agentsoc-readonly"
    assert conns[0].read_only and conns[0].closed and conns[0].rolled_back
    assert report.read_only_session and report.account == "agentsoc_reader"


def test_superuser_and_unencrypted_connections_are_warned_about():
    connector, *_ = make(superuser=True, sslmode="disable")
    warnings = " ".join(make(superuser=True, sslmode="disable")[0].test().warnings)
    assert "superuser" in warnings and "may not be encrypted" in warnings
    assert connector.settings.warnings()


def test_fetch_quotes_names_binds_values_and_bounds_the_batch():
    connector, _, conns = make()
    after = Position(datetime(2026, 11, 13, tzinfo=UTC), 41)
    rows = connector.fetch(TableRef("public", "auth_log"), ["user", 'weird"col'],
                           cursor_column="ts", key_column="id", after=after, since=None,
                           limit=500)
    sql, params = conns[0].executed[-1]
    assert sql == ('SELECT "user", "weird""col", "ts", "id" FROM "public"."auth_log" '
                   'WHERE ("ts", "id") > (%s, %s) ORDER BY "ts", "id" LIMIT %s')
    assert params == (after.cursor, 41, 500)
    assert rows == [{"id": 1, "ts": datetime(2026, 11, 13, tzinfo=UTC), "user": "alice"}]


def test_first_and_lookback_reads():
    connector, _, conns = make()
    table = TableRef("public", "auth_log")
    connector.fetch(table, ["user"], cursor_column="ts", key_column="id", after=None,
                    since=None, limit=10)
    assert 'WHERE "ts" IS NOT NULL ORDER BY' in conns[-1].executed[-1][0]
    connector.fetch(table, ["user"], cursor_column="ts", key_column="id", after=None,
                    since=5, limit=10)
    assert 'WHERE "ts" >= %s' in conns[-1].executed[-1][0]


def test_columns_must_exist_before_any_query_uses_them():
    connector, _, conns = make()
    with pytest.raises(ConnectorError, match=r"Columns not in public.auth_log: password"):
        connector.fetch(TableRef("public", "auth_log"), ["password"], cursor_column="ts",
                        key_column="id", after=None, since=None, limit=10)
    assert not any("auth_log\"" in sql for sql, _ in conns[0].executed)


@pytest.mark.parametrize("limit", [0, 5001])
def test_batch_size_is_bounded(limit):
    connector, *_ = make()
    with pytest.raises(ConnectorError, match="batch size"):
        connector.fetch(TableRef("public", "t"), [], cursor_column="ts", key_column="id",
                        after=None, since=None, limit=limit)


@pytest.mark.parametrize(("error", "message"), [
    (psycopg.errors.InvalidPassword(f"password authentication failed; password={PASSWORD}"),
     "Authentication failed"),
    (psycopg.OperationalError(f"connection to server at db.example.test failed {PASSWORD}"),
     "Could not connect"),
])
def test_connect_errors_never_echo_server_text(error, message, caplog):
    connector, *_ = make(connect_error=error)
    with pytest.raises(ConnectorError) as raised:
        connector.test()
    text = str(raised.value)
    assert message in text and PASSWORD not in text and "db.example.test" not in text
    assert raised.value.__cause__ is None and raised.value.__suppress_context__
    assert PASSWORD not in caplog.text


def test_query_errors_are_reduced_to_a_code():
    connector, _, conns = make(fail=psycopg.errors.InsufficientPrivilege("permission denied "
                                                                         "for table secret"))
    with pytest.raises(ConnectorError, match="grant this account SELECT") as raised:
        connector.list_tables()
    assert raised.value.code == "42501" and "secret" not in str(raised.value)
    assert conns[0].closed


def test_password_is_registered_for_log_redaction():
    from agentsoc.logging_setup import _RUNTIME_SECRETS

    make()
    assert PASSWORD in _RUNTIME_SECRETS


@pytest.mark.parametrize("field", [{"host": "db;rm -rf"}, {"database": "x' OR 1=1"},
                                   {"username": "a b"}, {"port": 0}, {"sslmode": "allow"},
                                   {"statement_timeout_ms": 10}])
def test_settings_are_validated(field):
    base = {"host": "db", "database": "d", "username": "u"}
    with pytest.raises(ValidationError):
        PostgresSettings(**{**base, **field})


@pytest.mark.parametrize("value", [42, datetime(2026, 1, 1, tzinfo=UTC), "abc"])
def test_cursor_round_trip(value):
    assert decode_cursor(encode_cursor(value)) == value


def test_boolean_cursor_is_refused():
    with pytest.raises(ConnectorError):
        encode_cursor(True)
