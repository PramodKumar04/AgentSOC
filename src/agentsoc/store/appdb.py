"""Application database (SQLite): users, sessions, encrypted credentials, data sources.

Separate from the event data. The schema is versioned with `PRAGMA user_version` and
upgraded by numbered, forward-only migrations. A database written by a newer version of
AgentSOC is refused rather than guessed at.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from agentsoc.exceptions import ConfigurationError

MIGRATIONS: list[str] = [
    # 1: accounts, sessions, encrypted credentials
    """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin', 'analyst')),
        disabled INTEGER NOT NULL DEFAULT 0,
        failed_logins INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        password_changed_at TEXT NOT NULL
    );
    CREATE TABLE sessions (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        csrf_token TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        expires_at TEXT NOT NULL
    );
    CREATE INDEX sessions_user ON sessions(user_id);
    CREATE TABLE credentials (
        ref TEXT PRIMARY KEY,
        ciphertext BLOB NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL
    );
    """,
    # 2: organisational data sources (connection settings without secrets, mapping, policy)
    """
    CREATE TABLE data_sources (
        key TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('postgresql')),
        config TEXT NOT NULL,
        credential_ref TEXT NOT NULL,
        sync_enabled INTEGER NOT NULL DEFAULT 0,
        ai_enabled INTEGER NOT NULL DEFAULT 0,
        ai_changed_by TEXT,
        ai_changed_at TEXT,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """,
    # 3: analyst decisions on incidents (append-only; the latest row is the current state)
    """
    CREATE TABLE incident_reviews (
        id INTEGER PRIMARY KEY,
        source_key TEXT NOT NULL,
        incident_id TEXT NOT NULL,
        incident_sha256 TEXT NOT NULL,
        decision TEXT NOT NULL
            CHECK (decision IN ('accepted', 'dismissed', 'more_evidence', 'reopened')),
        reason TEXT,
        note TEXT,
        window_hours INTEGER,
        analyst TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX incident_reviews_lookup ON incident_reviews(source_key, incident_id, id);
    """,
]
# 4: allow MySQL sources. SQLite cannot change a CHECK constraint, so the table is rebuilt; no
# other table refers to data_sources, and every existing row is copied unchanged.
MIGRATIONS.append(
    """
    CREATE TABLE data_sources_v4 (
        key TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('postgresql', 'mysql')),
        config TEXT NOT NULL,
        credential_ref TEXT NOT NULL,
        sync_enabled INTEGER NOT NULL DEFAULT 0,
        ai_enabled INTEGER NOT NULL DEFAULT 0,
        ai_changed_by TEXT,
        ai_changed_at TEXT,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    INSERT INTO data_sources_v4 SELECT * FROM data_sources;
    DROP TABLE data_sources;
    ALTER TABLE data_sources_v4 RENAME TO data_sources;
    """
)
SCHEMA_VERSION = len(MIGRATIONS)


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def migrate(path: str | Path) -> int:
    """Create or upgrade the database. Returns the schema version now in place."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = _connect(path)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        current = conn.execute("PRAGMA user_version").fetchone()[0]
        if current > SCHEMA_VERSION:
            raise ConfigurationError(
                f"Application database schema {current} is newer than this version supports "
                f"({SCHEMA_VERSION}).")
        for version in range(current, SCHEMA_VERSION):
            conn.execute("BEGIN IMMEDIATE")
            try:
                for statement in filter(str.strip, MIGRATIONS[version].split(";")):
                    conn.execute(statement)
                conn.execute(f"PRAGMA user_version = {version + 1}")
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return conn.execute("PRAGMA user_version").fetchone()[0]
    finally:
        conn.close()


@contextmanager
def transaction(path: str | Path) -> Iterator[sqlite3.Connection]:
    """One write transaction (BEGIN IMMEDIATE), committed on success, rolled back on error."""
    conn = _connect(Path(path))
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")
    finally:
        conn.close()


@contextmanager
def reader(path: str | Path) -> Iterator[sqlite3.Connection]:
    conn = _connect(Path(path))
    try:
        yield conn
    finally:
        conn.close()
