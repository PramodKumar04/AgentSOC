"""Schema 4 lets a data source be MySQL. Existing rows must survive the table rebuild."""

import sqlite3

import pytest

from agentsoc.store import appdb


def _schema_3_database(path):
    conn = sqlite3.connect(path, isolation_level=None)
    for statement in [s for part in appdb.MIGRATIONS[:3] for s in part.split(";") if s.strip()]:
        conn.execute(statement)
    conn.execute("INSERT INTO data_sources (key, name, kind, config, credential_ref, "
                 "created_by, created_at, updated_at) VALUES ('hr', 'HR', 'postgresql', "
                 "'{\"kind\": \"postgresql\"}', 'cred-1', 'boss', 'x', 'x')")
    conn.execute("PRAGMA user_version = 3")
    conn.close()


def test_migration_four_keeps_existing_sources_and_allows_mysql(tmp_path):
    path = tmp_path / "app.db"
    _schema_3_database(path)
    assert appdb.migrate(path) == appdb.SCHEMA_VERSION == 4
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT key, name, kind, config FROM data_sources").fetchall() == [
        ("hr", "HR", "postgresql", '{"kind": "postgresql"}')]
    conn.execute("INSERT INTO data_sources (key, name, kind, config, credential_ref, "
                 "created_by, created_at, updated_at) VALUES ('sql', 'SQL', 'mysql', '{}', "
                 "'cred-2', 'boss', 'x', 'x')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO data_sources (key, name, kind, config, credential_ref, "
                     "created_by, created_at, updated_at) VALUES ('bad', 'x', 'oracle', '{}', "
                     "'cred-3', 'boss', 'x', 'x')")
    conn.close()


def test_migration_four_is_idempotent_on_a_fresh_database(tmp_path):
    path = tmp_path / "fresh.db"
    assert appdb.migrate(path) == 4
    assert appdb.migrate(path) == 4
