"""Against a REAL PostgreSQL server. Skipped unless one is configured, in which case the
PostgreSQL connector must be reported as NOT verified.

Prepare a test server with scripts/postgres_test_fixture.sql, then set:
    AGENTSOC_TEST_PG_HOST, AGENTSOC_TEST_PG_PORT (default 5432), AGENTSOC_TEST_PG_DATABASE,
    AGENTSOC_TEST_PG_USER (default agentsoc_reader), AGENTSOC_TEST_PG_PASSWORD,
    AGENTSOC_TEST_PG_SSLMODE (default prefer, for a local test server only)
"""

import os

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from agentsoc.api.service import Service
from agentsoc.connectors.base import ConnectorError, Position, TableRef
from agentsoc.connectors.postgres import PostgresConnector, PostgresSettings
from agentsoc.credentials import EncryptedCredentialStore
from agentsoc.orgsource.manager import DataSourceManager
from agentsoc.orgsource.registry import DataSourceConfig

ENV = os.environ
pytestmark = pytest.mark.skipif(
    not ENV.get("AGENTSOC_TEST_PG_HOST"),
    reason="no real PostgreSQL test server configured (AGENTSOC_TEST_PG_*): "
           "PostgreSQL connector NOT verified against a real server")
TABLE = TableRef("agentsoc_fixture", "auth_events")


@pytest.fixture(scope="module")
def settings():
    return PostgresSettings(host=ENV["AGENTSOC_TEST_PG_HOST"],
                            port=int(ENV.get("AGENTSOC_TEST_PG_PORT", "5432")),
                            database=ENV["AGENTSOC_TEST_PG_DATABASE"],
                            username=ENV.get("AGENTSOC_TEST_PG_USER", "agentsoc_reader"),
                            sslmode=ENV.get("AGENTSOC_TEST_PG_SSLMODE", "prefer"))


@pytest.fixture(scope="module")
def password():
    return SecretStr(ENV["AGENTSOC_TEST_PG_PASSWORD"])


def test_connection_is_read_only(settings, password):
    report = PostgresConnector(settings, password).test()
    assert report.read_only_session


def test_writes_are_refused_by_the_server(settings, password):
    import psycopg

    connector = PostgresConnector(settings, password)
    with connector._session() as conn, conn.cursor() as cur, pytest.raises(
            psycopg.errors.ReadOnlySqlTransaction):
        cur.execute("CREATE TEMP TABLE agentsoc_should_fail (x int)")


def test_catalogue_and_keyset_paging(settings, password):
    connector = PostgresConnector(settings, password)
    assert TABLE in connector.list_tables()
    names = {c.name for c in connector.list_columns(TABLE)}
    assert {"id", "ingested_at", "note"} <= names
    seen, keys, after = [], set(), None
    while True:
        rows = connector.fetch(TABLE, ["account"], cursor_column="ingested_at",
                               key_column="id", after=after, since=None, limit=137)
        if not rows:
            break
        seen += [r["id"] for r in rows]
        keys |= {k for r in rows for k in r}
        after = Position(rows[-1]["ingested_at"], rows[-1]["id"])
    assert seen == list(range(1, 1001))
    assert keys == {"account", "ingested_at", "id"}  # unmapped columns are never read


def test_wrong_password_is_reported_without_details(settings):
    with pytest.raises(ConnectorError) as raised:
        PostgresConnector(settings, SecretStr("definitely-wrong-password")).test()
    assert "definitely-wrong-password" not in str(raised.value)
    assert settings.host not in str(raised.value)


def test_full_sync_and_snapshot(settings, password, tmp_path):
    service = Service(root=tmp_path / "root", provider_factory=lambda: (None, "off"))
    creds = EncryptedCredentialStore(service.app_db, SecretStr(Fernet.generate_key().decode()),
                                     service.audit)
    manager = DataSourceManager(service.datasources, creds, service.audit, service.root)
    config = DataSourceConfig.model_validate({
        "connection": settings.model_dump(), "table": {"schema": TABLE.schema,
                                                       "name": TABLE.name},
        "cursor_column": "ingested_at", "batch_size": 250,
        "mapping": {"record_id": "id", "timestamp": {"column": "event_time"},
                    "fields": {"src_user": {"column": "account"},
                               "src_host": {"column": "client"},
                               "dst_host": {"column": "server"},
                               "orientation": {"column": "action"},
                               "outcome": {"column": "result",
                                           "values": {"true": "Success", "false": "Fail"}}}}})
    manager.create("pg-fixture", "PostgreSQL fixture (SYNTHETIC)", config, password,
                   actor="test")
    run = manager.sync("pg-fixture")
    assert (run.status, run.fetched, run.new, run.rejected) == ("completed", 1000, 980, 20)
    assert manager.sync("pg-fixture").fetched == 0
    info = manager.snapshot("pg-fixture")
    assert info.event_count == 980
