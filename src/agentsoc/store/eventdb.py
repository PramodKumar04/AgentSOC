"""Queryable SQLite copy of one verified event dataset.

The dataset directory stays the source of truth and is never written. An index is built
by streaming `events.jsonl` while re-hashing it; if the hash does not match the manifest
the build fails and leaves nothing behind (it is written to a temporary file and renamed
only on success). Each index records the dataset hash it was built from, so a changed
dataset is reported as stale instead of being served.

`export_jsonl` writes the events back in their original order and serialisation; for a
UTC dataset the result is byte-identical to the source file, which is checked.

Indexes are per source, so events from different sources are never mixed in one query.
Timestamps are stored as integer microseconds since the epoch and must be UTC.

This makes searching and counting cheap. It does not change how the detection, graph and
risk engines work: they still load a whole dataset into memory.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import ValidationError

from agentsoc.exceptions import AgentSOCError
from agentsoc.schemas import AuthEvent, RawRef
from agentsoc.store.datasets import EVENTS_FILE, load_manifest

SCHEMA_VERSION = 1
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MICRO = timedelta(microseconds=1)
BATCH = 5_000
COLUMNS = ("event_id", "ts_us", "src_user", "dst_user", "src_host", "dst_host", "auth_type",
           "logon_type", "orientation", "outcome", "dataset", "raw_file", "raw_line")
DISTINCT_COLUMNS = {"auth_type", "logon_type", "orientation", "outcome"}

_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE events (
    seq INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    ts_us INTEGER NOT NULL,
    src_user TEXT NOT NULL, dst_user TEXT,
    src_host TEXT NOT NULL, dst_host TEXT NOT NULL,
    auth_type TEXT, logon_type TEXT,
    orientation TEXT NOT NULL, outcome TEXT NOT NULL, dataset TEXT NOT NULL,
    raw_file TEXT NOT NULL, raw_line INTEGER NOT NULL
);
-- Original record identities for database sources (empty for file datasets).
CREATE TABLE record_keys (
    event_id TEXT PRIMARY KEY REFERENCES events(event_id),
    record_key TEXT NOT NULL
);
"""
_INDEXES = """
CREATE INDEX events_ts ON events(ts_us);
CREATE INDEX events_src_user ON events(src_user COLLATE NOCASE);
CREATE INDEX events_dst_user ON events(dst_user COLLATE NOCASE);
CREATE INDEX events_src_host ON events(src_host COLLATE NOCASE);
CREATE INDEX events_dst_host ON events(dst_host COLLATE NOCASE);
CREATE INDEX events_outcome_ts ON events(outcome, ts_us);
CREATE INDEX events_auth_type ON events(auth_type);
"""


class EventStoreError(AgentSOCError):
    pass


class EventIndexStaleError(EventStoreError):
    """The dataset changed after the index was built."""


@dataclass(frozen=True)
class IndexInfo:
    source_key: str
    provenance: str
    events_sha256: str
    event_count: int
    built_at: str


@dataclass(frozen=True)
class EventQuery:
    """All filters combine with AND. Text filters are case-insensitive substrings."""

    event_id: str | None = None
    user: str | None = None  # source or destination account
    host: str | None = None  # source or destination host
    src_host: str | None = None
    dst_host: str | None = None
    outcome: str | None = None  # "Success" | "Fail"
    auth_type: str | None = None  # exact
    start: datetime | None = None  # inclusive
    end: datetime | None = None  # exclusive


def to_micros(moment: datetime) -> int:
    if moment.utcoffset() != timedelta(0):
        raise EventStoreError("Event timestamps must be UTC.")
    return (moment - EPOCH) // _MICRO


def from_micros(value: int) -> datetime:
    return EPOCH + value * _MICRO


def _row(event: AuthEvent) -> tuple:
    return (event.event_id, to_micros(event.timestamp), event.src_user, event.dst_user,
            event.src_host, event.dst_host, event.auth_type, event.logon_type,
            event.orientation.value, event.outcome.value, event.dataset.value,
            event.raw_ref.file, event.raw_ref.line)


def _event(row: sqlite3.Row) -> AuthEvent:
    return AuthEvent(
        event_id=row["event_id"], timestamp=from_micros(row["ts_us"]), src_user=row["src_user"],
        dst_user=row["dst_user"], src_host=row["src_host"], dst_host=row["dst_host"],
        auth_type=row["auth_type"], logon_type=row["logon_type"],
        orientation=row["orientation"], outcome=row["outcome"], dataset=row["dataset"],
        raw_ref=RawRef(file=row["raw_file"], line=row["raw_line"]))


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def _reader(path: Path) -> Iterator[sqlite3.Connection]:
    """Read-only connection that is always closed (sqlite3's own `with` only commits)."""
    if not path.is_file():
        raise EventStoreError("event index has not been built")
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def build_index(dataset_dir: str | Path, index_path: str | Path, *, source_key: str) -> IndexInfo:
    """Stream the dataset into a new index. Never modifies the dataset directory."""
    dataset_dir, index_path = Path(dataset_dir), Path(index_path)
    manifest = load_manifest(dataset_dir)
    index_path.parent.mkdir(parents=True, exist_ok=True)
    temp = index_path.with_name(index_path.name + ".building")
    temp.unlink(missing_ok=True)
    conn = _connect(temp)
    try:
        conn.execute("PRAGMA journal_mode = OFF")  # the temp file is discarded on failure
        conn.execute("PRAGMA synchronous = OFF")
        conn.executescript(_SCHEMA)
        digest, count, batch = hashlib.sha256(), 0, []
        insert = (f"INSERT INTO events ({', '.join(COLUMNS)}) "  # noqa: S608 — fixed columns
                  f"VALUES ({', '.join('?' * len(COLUMNS))})")
        conn.execute("BEGIN")
        with (dataset_dir / EVENTS_FILE).open("rb") as handle:
            for line_no, raw in enumerate(handle, start=1):
                digest.update(raw)
                try:
                    batch.append(_row(AuthEvent.model_validate_json(raw)))
                except ValidationError:
                    raise EventStoreError(f"{EVENTS_FILE}:{line_no} is not a valid event") from None
                if len(batch) >= BATCH:
                    conn.executemany(insert, batch)
                    count += len(batch)
                    batch.clear()
        conn.executemany(insert, batch)
        count += len(batch)
        if digest.hexdigest() != manifest.events_sha256 or count != manifest.event_count:
            raise EventStoreError("events file does not match its manifest; index not built")
        built_at = datetime.now(UTC).isoformat()
        info = IndexInfo(source_key, manifest.dataset.value, manifest.events_sha256, count,
                         built_at)
        conn.executemany("INSERT INTO meta VALUES (?, ?)", [
            ("schema_version", str(SCHEMA_VERSION)), ("source_key", source_key),
            ("provenance", info.provenance), ("events_sha256", info.events_sha256),
            ("event_count", str(count)), ("built_at", built_at)])
        conn.execute("COMMIT")
        conn.executescript(_INDEXES)
        conn.execute("ANALYZE")
    except BaseException:
        conn.close()
        temp.unlink(missing_ok=True)
        raise
    conn.close()
    os.replace(temp, index_path)
    return info


def read_info(index_path: str | Path) -> IndexInfo:
    path = Path(index_path)
    if not path.is_file():
        raise EventStoreError("event index has not been built")
    with _reader(path) as conn:
        meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
    if meta.get("schema_version") != str(SCHEMA_VERSION):
        raise EventIndexStaleError("event index was built by another version")
    return IndexInfo(meta["source_key"], meta["provenance"], meta["events_sha256"],
                     int(meta["event_count"]), meta["built_at"])


def check_current(index_path: str | Path, dataset_dir: str | Path) -> IndexInfo:
    info = read_info(index_path)
    if load_manifest(dataset_dir).events_sha256 != info.events_sha256:
        raise EventIndexStaleError("dataset changed since the event index was built")
    return info


def _like(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _where(query: EventQuery) -> tuple[str, list]:
    clauses, params = [], []
    text = "LIKE ? ESCAPE '\\'"
    if query.event_id:
        clauses.append(f"event_id {text}")
        params.append(_like(query.event_id))
    if query.user:
        clauses.append(f"(src_user {text} OR dst_user {text})")
        params += [_like(query.user)] * 2
    if query.host:
        clauses.append(f"(src_host {text} OR dst_host {text})")
        params += [_like(query.host)] * 2
    if query.src_host:
        clauses.append(f"src_host {text}")
        params.append(_like(query.src_host))
    if query.dst_host:
        clauses.append(f"dst_host {text}")
        params.append(_like(query.dst_host))
    if query.outcome:
        clauses.append("outcome = ?")
        params.append(query.outcome)
    if query.auth_type:
        clauses.append("auth_type = ?")
        params.append(query.auth_type)
    if query.start:
        clauses.append("ts_us >= ?")
        params.append(to_micros(query.start))
    if query.end:
        clauses.append("ts_us < ?")
        params.append(to_micros(query.end))
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def search(index_path: str | Path, query: EventQuery, *, page: int = 1,
           page_size: int = 50) -> tuple[list[AuthEvent], int]:
    """One page in dataset order (time, then original position), plus the total count."""
    if page < 1 or not 1 <= page_size <= 1000:
        raise EventStoreError("invalid page")
    where, params = _where(query)
    with _reader(Path(index_path)) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM events{where}", params).fetchone()[0]  # noqa: S608 — clauses are fixed text
        rows = conn.execute(
            f"SELECT * FROM events{where} ORDER BY seq LIMIT ? OFFSET ?",  # noqa: S608
            [*params, page_size, (page - 1) * page_size]).fetchall()
    return [_event(r) for r in rows], total


def outcome_histogram(index_path: str | Path, bucket_seconds: int,
                      query: EventQuery | None = None) -> list[tuple[datetime, int, int]]:
    """(bucket start, successes, failures) per time bucket that has events."""
    if bucket_seconds < 1:
        raise EventStoreError("bucket must be at least one second")
    where, params = _where(query or EventQuery())
    width = bucket_seconds * 1_000_000
    with _reader(Path(index_path)) as conn:
        sql = ("SELECT (ts_us / ?) * ? AS bucket, SUM(outcome = 'Success'), "  # noqa: S608
               "SUM(outcome = 'Fail') FROM events" + where + " GROUP BY bucket ORDER BY bucket")
        rows = conn.execute(sql, [width, width, *params]).fetchall()
    return [(from_micros(b), s, f) for b, s, f in rows]


def distinct_values(index_path: str | Path, column: str, limit: int = 50) -> list[str]:
    if column not in DISTINCT_COLUMNS:
        raise EventStoreError(f"cannot list values of '{column}'")
    with _reader(Path(index_path)) as conn:
        return [r[0] for r in conn.execute(
            f"SELECT {column} FROM events WHERE {column} IS NOT NULL "  # noqa: S608 — allow-listed
            f"GROUP BY {column} ORDER BY COUNT(*) DESC LIMIT ?", (limit,))]


def iter_events(index_path: str | Path) -> Iterator[AuthEvent]:
    with _reader(Path(index_path)) as conn:
        for row in conn.execute("SELECT * FROM events ORDER BY seq"):
            yield _event(row)


def export_jsonl(index_path: str | Path, out_path: str | Path) -> str:
    """Write events in original order and serialisation; returns the file's SHA-256."""
    digest = hashlib.sha256()
    with Path(out_path).open("wb") as handle:
        for event in iter_events(index_path):
            line = (event.model_dump_json() + "\n").encode("utf-8")
            digest.update(line)
            handle.write(line)
    return digest.hexdigest()
