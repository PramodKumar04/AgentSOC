"""Application database migrations and the shared, locked audit log."""

import sqlite3
import subprocess
import sys
import textwrap

import pytest

from agentsoc.audit import SYSTEM_ACTOR, AuditEventType, AuditLog, acting_as, current_actor
from agentsoc.exceptions import ConfigurationError
from agentsoc.schemas import verify_chain
from agentsoc.store import appdb


class TestMigrations:
    def test_creates_the_current_schema(self, tmp_path):
        path = tmp_path / "app.db"
        assert appdb.migrate(path) == appdb.SCHEMA_VERSION
        with appdb.reader(path) as conn:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"users", "sessions", "credentials"} <= tables

    def test_is_idempotent(self, tmp_path):
        path = tmp_path / "app.db"
        appdb.migrate(path)
        assert appdb.migrate(path) == appdb.SCHEMA_VERSION

    def test_refuses_a_newer_schema(self, tmp_path):
        path = tmp_path / "app.db"
        appdb.migrate(path)
        with appdb.reader(path) as conn:
            conn.execute(f"PRAGMA user_version = {appdb.SCHEMA_VERSION + 1}")
        with pytest.raises(ConfigurationError):
            appdb.migrate(path)

    def test_foreign_keys_are_enforced(self, tmp_path):
        path = tmp_path / "app.db"
        appdb.migrate(path)
        with pytest.raises(sqlite3.IntegrityError), appdb.transaction(path) as conn:
            conn.execute("INSERT INTO sessions VALUES ('h', 999, 'c', 'a', 'b', 'c')")

    def test_failed_transaction_is_rolled_back(self, tmp_path):
        path = tmp_path / "app.db"
        appdb.migrate(path)
        with pytest.raises(RuntimeError), appdb.transaction(path) as conn:
            conn.execute("INSERT INTO credentials VALUES ('r', x'00', 'a', 'b', 'c')")
            raise RuntimeError("boom")
        with appdb.reader(path) as conn:
            assert conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 0


class TestAuditLog:
    def test_records_the_bound_actor(self, tmp_path):
        log = AuditLog(tmp_path / "activity.jsonl")
        assert current_actor() == SYSTEM_ACTOR
        log.append(AuditEventType.DATASET_VERIFIED, "demo")
        with acting_as("alice"):
            log.append(AuditEventType.LOGOUT, "alice")
        assert current_actor() == SYSTEM_ACTOR
        assert [r.actor for r in log.read()] == [SYSTEM_ACTOR, "alice"]

    def test_unknown_event_type_is_refused_without_raising(self, tmp_path):
        log = AuditLog(tmp_path / "activity.jsonl")
        assert log.append("made.up", "x") is False
        assert log.read() == []

    def test_existing_event_names_are_unchanged(self):
        for name in ("dataset.verified", "investigation.completed",
                     "investigation.completed_limited", "investigation.failed"):
            assert AuditEventType(name)

    def test_concurrent_processes_keep_the_chain_intact(self, tmp_path):
        path = tmp_path / "activity.jsonl"
        script = textwrap.dedent(f"""
            from agentsoc.audit import AuditLog
            log = AuditLog(r"{path}")
            for _ in range(25):
                assert log.append("config.changed", "x", {{"n": 1}})
        """)
        procs = [subprocess.Popen([sys.executable, "-c", script])  # noqa: S603 — fixed script
                 for _ in range(3)]
        assert [p.wait(timeout=120) for p in procs] == [0, 0, 0]
        records = AuditLog(path).read()
        assert len(records) == 75 and verify_chain(records) is None


def test_upgrade_from_phase_a_keeps_accounts(tmp_path):
    """A version-1 database (Phase A) gains data_sources without losing anything."""
    import sqlite3

    path = tmp_path / "v1.db"
    conn = sqlite3.connect(path)
    for statement in filter(str.strip, appdb.MIGRATIONS[0].split(";")):
        conn.execute(statement)
    conn.execute("INSERT INTO users (username, password_hash, role, created_at, updated_at, "
                 "password_changed_at) VALUES ('alice', 'h', 'admin', 'x', 'x', 'x')")
    conn.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()
    assert appdb.migrate(path) == appdb.SCHEMA_VERSION == 4
    with appdb.reader(path) as c:
        assert [r[0] for r in c.execute("SELECT username FROM users")] == ["alice"]
        assert c.execute("SELECT COUNT(*) FROM data_sources").fetchone()[0] == 0
