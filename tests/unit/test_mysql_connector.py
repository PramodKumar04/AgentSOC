"""MySQL connector against a SIMULATED driver.

These tests check what AgentSOC sends (read-only session, timeouts, quoted identifiers, bound
values, bounded batches, TLS options) and how it reports errors. They do not show that the
connector works with a real MySQL server; that needs a server and a read-only account.
"""

import re
from datetime import datetime

import pymysql
import pytest
from pydantic import SecretStr, TypeAdapter, ValidationError

from agentsoc.connectors.base import ConnectorError, Position, TableRef
from agentsoc.connectors.mysql import MySQLConnector, MySQLSettings
from agentsoc.connectors.postgres import PostgresConnector, PostgresSettings
from agentsoc.connectors.settings import ConnectionSettings, connector_for, with_engine

PASSWORD = "My-S3cret-passw0rd"
TABLE = TableRef("security", "auth_events")
COLUMNS = [("id", "bigint", "NO"), ("ts", "datetime", "NO"), ("account", "varchar", "YES"),
           ("we`ird", "varchar", "YES")]


class FakeCursor:
    def __init__(self, conn):
        self.conn, self.description, self._rows = conn, None, []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, query, params=()):
        q = " ".join(query.split())
        self.conn.executed.append((q, tuple(params)))
        if self.conn.fail_on and self.conn.fail_on in q:
            raise self.conn.fail_on_exc
        if "information_schema.columns" in q:
            self._rows = [(n, t, nullable == "YES") for n, t, nullable in COLUMNS]
        elif "information_schema.tables" in q:
            self._rows = [("security", "auth_events"), ("security", "vw_logons")]
        elif "VERSION()" in q:
            self._rows = [("8.0.36", "reader@%", 1)]
        elif "SHOW GRANTS" in q:
            self._rows = [(self.conn.grants,)]
        elif q.startswith("SELECT ") and "FROM `security`.`auth_events`" in q:
            head = q.split(" FROM ")[0][len("SELECT "):]
            names = [m.replace("``", "`") for m in re.findall(r"`((?:[^`]|``)*)`", head)]
            self.description = [(n,) for n in names]
            sample = {"id": 1, "ts": datetime(2026, 11, 13, 9), "account": "alice", "we`ird": "x"}
            self._rows = [tuple(sample[n] for n in names)]
        else:
            self._rows = []

    def fetchall(self):
        return list(self._rows)


class FakeConn:
    def __init__(self, grants="GRANT SELECT ON `security`.* TO `reader`@`%`", fail_on=None,
                 fail_on_exc=None):
        self.executed, self.closed = [], False
        self.grants, self.fail_on, self.fail_on_exc = grants, fail_on, fail_on_exc

    def cursor(self):
        return FakeCursor(self)

    def close(self):
        self.closed = True


def settings(**kw) -> MySQLSettings:
    base = dict(host="db.example.test", port=3306, database="security", username="reader",
                sslmode="verify-full")
    return MySQLSettings(**(base | kw))


def connector(conn: FakeConn, **kw) -> tuple[MySQLConnector, dict]:
    seen: dict = {}

    def connect(**args):
        seen.update(args)
        return conn
    return MySQLConnector(settings(**kw), SecretStr(PASSWORD), connect=connect), seen


class TestSessionSafety:
    def test_every_session_is_read_only_and_bounded(self):
        conn = FakeConn()
        c, seen = connector(conn)
        c.test()
        sql = [q for q, _ in conn.executed]
        assert "SET SESSION TRANSACTION READ ONLY" in sql
        assert any(q.startswith("SET SESSION max_execution_time = 30000") for q in sql)
        assert seen["read_timeout"] == 30 and seen["autocommit"] is True
        assert conn.closed

    def test_tls_modes_map_to_driver_options(self):
        expected = {
            "verify-full": {"ssl": {}, "ssl_verify_cert": True, "ssl_verify_identity": True},
            "verify-ca": {"ssl": {}, "ssl_verify_cert": True, "ssl_verify_identity": False},
            "require": {"ssl": {}, "ssl_verify_cert": False, "ssl_verify_identity": False},
            "disable": {"ssl_disabled": True},
        }
        for mode, options in expected.items():
            c = MySQLConnector(settings(sslmode=mode), SecretStr(PASSWORD),
                               connect=lambda **_: FakeConn())
            assert c._tls_options() == options, mode

    def test_test_reports_version_account_and_read_only_session(self):
        c, _ = connector(FakeConn())
        report = c.test()
        assert report.server_version == "8.0.36" and report.account == "reader@%"
        assert report.read_only_session is True
        assert report.warnings == []

    def test_write_privileges_are_warned_about(self):
        c, _ = connector(FakeConn(grants="GRANT ALL PRIVILEGES ON `security`.* TO `reader`@`%`"))
        assert any("beyond SELECT" in w for w in c.test().warnings)

    def test_unencrypted_mode_is_warned_about(self):
        c, _ = connector(FakeConn(), sslmode="disable")
        assert any("not encrypted" in w for w in c.test().warnings)

    def test_unverified_tls_is_warned_about_for_require(self):
        c, _ = connector(FakeConn(), sslmode="require")
        assert any("not verified" in w for w in c.test().warnings)


class TestErrors:
    @pytest.mark.parametrize("code, text", [
        (1045, "Authentication failed"), (1049, "does not exist"),
        (1142, "Permission denied"), (2003, "Could not connect"),
    ])
    def test_errors_are_fixed_messages_with_no_server_text(self, code, text):
        exc = pymysql.err.OperationalError(code, "secret host db.internal user admin")

        def connect(**_):
            raise exc
        c = MySQLConnector(settings(), SecretStr(PASSWORD), connect=connect)
        with pytest.raises(ConnectorError) as info:
            c.test()
        assert text in str(info.value)
        assert "db.internal" not in str(info.value) and PASSWORD not in str(info.value)

    def test_unknown_error_numbers_use_a_generic_message(self):
        conn = FakeConn(fail_on="VERSION()", fail_on_exc=pymysql.err.ProgrammingError(
            9999, "internal detail with " + PASSWORD))
        c, _ = connector(conn)
        with pytest.raises(ConnectorError) as info:
            c.test()
        assert str(info.value) == "The database reported an error."
        assert PASSWORD not in str(info.value)


class TestCatalogueAndFetch:
    def test_tables_are_listed_only_from_the_configured_database(self):
        conn = FakeConn()
        c, _ = connector(conn)
        assert [str(t) for t in c.list_tables()] == ["security.auth_events", "security.vw_logons"]
        sql = next(q for q, _ in conn.executed if "information_schema.tables" in q)
        assert "table_schema = %s" in sql

    def test_fetch_quotes_identifiers_binds_values_and_orders_by_cursor(self):
        conn = FakeConn()
        c, _ = connector(conn)
        rows = c.fetch(TABLE, ["account"], cursor_column="id", key_column="id",
                       after=Position(cursor=10, key=10), since=None, limit=50)
        assert rows[0]["account"] == "alice"
        query, params = next((q, p) for q, p in conn.executed if q.startswith("SELECT `account`"))
        assert "FROM `security`.`auth_events`" in query
        assert "WHERE (`id`, `id`) > (%s, %s) ORDER BY `id`, `id` LIMIT %s" in query
        assert params == (10, 10, 50)

    def test_identifiers_with_backticks_are_escaped(self):
        conn = FakeConn()
        c, _ = connector(conn)
        c.fetch(TABLE, ["we`ird"], cursor_column="id", key_column="id", after=None,
                since=None, limit=5)
        query = next(q for q, _ in conn.executed if q.startswith("SELECT `we"))
        assert "`we``ird`" in query

    def test_unknown_column_and_foreign_database_are_refused(self):
        c, _ = connector(FakeConn())
        with pytest.raises(ConnectorError, match="Columns not in"):
            c.fetch(TABLE, ["nope"], cursor_column="id", key_column="id", after=None,
                    since=None, limit=5)
        with pytest.raises(ConnectorError, match="not in the configured database"):
            c.fetch(TableRef("mysql", "user"), ["id"], cursor_column="id", key_column="id",
                    after=None, since=None, limit=5)

    def test_batch_size_is_bounded(self):
        c, _ = connector(FakeConn())
        with pytest.raises(ConnectorError):
            c.fetch(TABLE, ["account"], cursor_column="id", key_column="id", after=None,
                    since=None, limit=5001)


class TestSettings:
    def test_defaults_and_engine(self):
        s = MySQLSettings(host="h", database="d", username="u")
        assert s.port == 3306 and s.engine == "mysql" and s.sslmode == "require"

    def test_password_is_never_part_of_settings(self):
        assert "password" not in MySQLSettings.model_fields

    def test_unknown_fields_and_bad_modes_are_refused(self):
        with pytest.raises(ValidationError):
            MySQLSettings(host="h", database="d", username="u", sslmode="prefer")
        with pytest.raises(ValidationError):
            MySQLSettings(host="h", database="d", username="u", password="x")

    def test_connection_union_picks_the_engine(self):
        adapter = TypeAdapter(ConnectionSettings)
        mysql = adapter.validate_python({"engine": "mysql", "host": "h", "database": "d",
                                         "username": "u"})
        pg = adapter.validate_python({"engine": "postgresql", "host": "h", "database": "d",
                                      "username": "u"})
        assert isinstance(mysql, MySQLSettings) and isinstance(pg, PostgresSettings)

    def test_old_connections_without_an_engine_are_postgresql(self):
        legacy = with_engine({"host": "h", "database": "d", "username": "u"})
        assert legacy["engine"] == "postgresql"
        assert with_engine({"engine": "mysql"})["engine"] == "mysql"

    def test_factory_chooses_the_connector_by_engine(self):
        pg = PostgresSettings(host="h", database="d", username="u")
        assert isinstance(connector_for(settings(), SecretStr(PASSWORD)), MySQLConnector)
        assert isinstance(connector_for(pg, SecretStr(PASSWORD)), PostgresConnector)
