"""Per-source staging store: every row read from an organisational database, once.

Layout under `<data root>/org/<key>/`:
    staging.sqlite       rows (keyed by the source's own record id), checkpoint, sync runs
    capture/NNNNNN.jsonl the mapped columns of each row exactly as read, one file per sync
                         run; `RawRef` of every event points to its line here
    snapshots/<stamp>/   immutable datasets and detection outputs (see snapshot.py)
    current.json         the snapshot the dashboard shows

A batch is written to its capture file and fsynced, then stored together with the advanced
checkpoint in one transaction. A crash between the two leaves an unreferenced capture line;
the next sync reads the same rows again and stores them then. Rows already stored are
skipped (counted as duplicates); a row whose content differs from the stored one under the
same record id is counted as changed and the first version is kept.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID

from agentsoc.connectors.base import Position, decode_cursor, encode_cursor
from agentsoc.exceptions import AgentSOCError
from agentsoc.schemas import AuthEvent

CAPTURE_DIR = "capture"
STAGING_FILE = "staging.sqlite"
_SCHEMA = """
CREATE TABLE IF NOT EXISTS rows (
    record_id TEXT PRIMARY KEY,
    content_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('accepted', 'rejected')),
    ts_us INTEGER,
    event TEXT,
    reject_reason TEXT,
    reject_field TEXT,
    capture_file TEXT NOT NULL,
    capture_line INTEGER NOT NULL,
    first_run INTEGER NOT NULL,
    changed_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS rows_accepted_ts ON rows(status, ts_us);
CREATE TABLE IF NOT EXISTS checkpoint (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    cursor TEXT NOT NULL,
    key TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    trigger TEXT NOT NULL CHECK (trigger IN ('manual', 'scheduled')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'interrupted')),
    fetched INTEGER NOT NULL DEFAULT 0,
    new INTEGER NOT NULL DEFAULT 0,
    duplicates INTEGER NOT NULL DEFAULT 0,
    changed INTEGER NOT NULL DEFAULT 0,
    rejected INTEGER NOT NULL DEFAULT 0,
    batches INTEGER NOT NULL DEFAULT 0,
    more_available INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
"""


class SyncBusyError(AgentSOCError):
    """Another sync of the same source is running (in this or another process)."""


def _iso(moment: datetime | None = None) -> str:
    return (moment or datetime.now(UTC)).isoformat(timespec="seconds")


def json_safe(value: object) -> object:
    """Capture values as text that round-trips for every type a mapping accepts."""
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, Decimal | UUID):
        return str(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return f"<binary value, {len(bytes(value))} bytes, not stored>"
    return f"<{type(value).__name__} value, not stored>"


def content_sha256(row: dict[str, object]) -> str:
    text = json.dumps({k: json_safe(v) for k, v in row.items()}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class StagedItem:
    record_id: str
    content_sha256: str
    event: AuthEvent | None
    reject_reason: str | None
    reject_field: str | None
    capture_line: int


@dataclass(frozen=True)
class BatchCounts:
    new: int
    duplicates: int
    changed: int
    rejected: int


@dataclass(frozen=True)
class RunRecord:
    id: int
    trigger: str
    started_at: str
    finished_at: str | None
    status: str
    fetched: int
    new: int
    duplicates: int
    changed: int
    rejected: int
    batches: int
    more_available: bool
    error: str | None


@dataclass(frozen=True)
class StagingStats:
    accepted: int
    rejected: int
    changed: int
    rejected_by_reason: dict[str, int]
    first_event: datetime | None
    last_event: datetime | None


class CaptureWriter:
    """Append-only capture file for one sync run."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = path.open("a", encoding="utf-8", newline="\n")
        with path.open(encoding="utf-8") as existing:
            self._lines = sum(1 for _ in existing)

    def append(self, record_id: str | None, row: dict[str, object]) -> int:
        payload = {"record_id": record_id, "row": {k: json_safe(v) for k, v in row.items()}}
        self._handle.write(json.dumps(payload, sort_keys=True, ensure_ascii=False) + "\n")
        self._lines += 1
        return self._lines

    def sync(self) -> None:
        self._handle.flush()
        os.fsync(self._handle.fileno())

    def close(self) -> None:
        self._handle.close()


class StagingStore:
    def __init__(self, source_dir: str | Path) -> None:
        self.dir = Path(source_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / STAGING_FILE
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA busy_timeout = 10000")
            yield conn
        finally:
            conn.close()

    # -- runs ----------------------------------------------------------------------------
    def start_run(self, trigger: str) -> int:
        with self._conn() as conn:
            # A run left 'running' by a crashed process is marked as interrupted.
            conn.execute("UPDATE runs SET status = 'interrupted', finished_at = ? "
                         "WHERE status = 'running'", (_iso(),))
            return conn.execute("INSERT INTO runs (trigger, started_at, status) "
                                "VALUES (?, ?, 'running')", (trigger, _iso())).lastrowid

    def finish_run(self, run_id: int, *, status: str, more_available: bool = False,
                   error: str | None = None) -> RunRecord:
        with self._conn() as conn:
            conn.execute("UPDATE runs SET status = ?, finished_at = ?, more_available = ?, "
                         "error = ? WHERE id = ?",
                         (status, _iso(), int(more_available), error, run_id))
        return self.run(run_id)

    def run(self, run_id: int) -> RunRecord:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return _run(row)

    def runs(self, limit: int = 20) -> list[RunRecord]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,))
            return [_run(r) for r in rows]

    def capture_path(self, run_id: int) -> Path:
        return self.dir / CAPTURE_DIR / f"{run_id:06d}.jsonl"

    # -- checkpoint ------------------------------------------------------------------------
    def checkpoint(self) -> Position | None:
        with self._conn() as conn:
            row = conn.execute("SELECT cursor, key FROM checkpoint WHERE id = 1").fetchone()
        if row is None:
            return None
        return Position(decode_cursor(json.loads(row["cursor"])),
                        decode_cursor(json.loads(row["key"])))

    def reset(self) -> None:
        """Forget the checkpoint; stored rows stay, so a re-read only adds what is new."""
        with self._conn() as conn:
            conn.execute("DELETE FROM checkpoint")

    # -- batches ---------------------------------------------------------------------------
    def apply_batch(self, run_id: int, capture_file: str, items: list[StagedItem],
                    position: Position, fetched: int) -> BatchCounts:
        """Store a batch and advance the checkpoint in one transaction (never backwards)."""
        new = duplicates = changed = rejected = 0
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                for item in items:
                    existing = conn.execute("SELECT content_sha256 FROM rows WHERE record_id = ?",
                                            (item.record_id,)).fetchone()
                    if existing is not None:
                        if existing["content_sha256"] == item.content_sha256:
                            duplicates += 1
                        else:
                            changed += 1
                            conn.execute("UPDATE rows SET changed_count = changed_count + 1 "
                                         "WHERE record_id = ?", (item.record_id,))
                        continue
                    event = item.event
                    conn.execute(
                        "INSERT INTO rows (record_id, content_sha256, status, ts_us, event, "
                        "reject_reason, reject_field, capture_file, capture_line, first_run) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (item.record_id, item.content_sha256,
                         "accepted" if event else "rejected",
                         _micros(event.timestamp) if event else None,
                         event.model_dump_json() if event else None, item.reject_reason,
                         item.reject_field, capture_file, item.capture_line, run_id))
                    if event:
                        new += 1
                    else:
                        rejected += 1
                old = conn.execute("SELECT cursor, key FROM checkpoint WHERE id = 1").fetchone()
                advance = old is None or _later(
                    position, Position(decode_cursor(json.loads(old["cursor"])),
                                       decode_cursor(json.loads(old["key"]))))
                if advance:
                    conn.execute(
                        "INSERT INTO checkpoint (id, cursor, key, updated_at) "
                        "VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
                        "cursor = excluded.cursor, key = excluded.key, "
                        "updated_at = excluded.updated_at",
                        (json.dumps(encode_cursor(position.cursor)),
                         json.dumps(encode_cursor(position.key)), _iso()))
                conn.execute(
                    "UPDATE runs SET fetched = fetched + ?, new = new + ?, duplicates = "
                    "duplicates + ?, changed = changed + ?, rejected = rejected + ?, "
                    "batches = batches + 1 WHERE id = ?",
                    (fetched, new, duplicates, changed, rejected, run_id))
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return BatchCounts(new, duplicates, changed, rejected)

    # -- reading ---------------------------------------------------------------------------
    def stats(self) -> StagingStats:
        with self._conn() as conn:
            counts = dict(conn.execute(
                "SELECT status, COUNT(*) FROM rows GROUP BY status").fetchall())
            reasons = dict(conn.execute(
                "SELECT reject_reason, COUNT(*) FROM rows WHERE status = 'rejected' "
                "GROUP BY reject_reason ORDER BY 2 DESC, 1").fetchall())
            changed = conn.execute("SELECT COALESCE(SUM(changed_count), 0) FROM rows"
                                   ).fetchone()[0]
            first, last = conn.execute("SELECT MIN(ts_us), MAX(ts_us) FROM rows "
                                       "WHERE status = 'accepted'").fetchone()
        return StagingStats(counts.get("accepted", 0), counts.get("rejected", 0), changed,
                            reasons, _from_micros(first), _from_micros(last))

    def window(self, hours: int, max_events: int) -> list[AuthEvent]:
        """The newest events: within `hours` of the latest one, at most `max_events`."""
        with self._conn() as conn:
            latest = conn.execute("SELECT MAX(ts_us) FROM rows WHERE status = 'accepted'"
                                  ).fetchone()[0]
            if latest is None:
                return []
            rows = conn.execute(
                "SELECT event FROM rows WHERE status = 'accepted' AND ts_us >= ? "
                "ORDER BY ts_us DESC, record_id DESC LIMIT ?",
                (latest - hours * 3_600_000_000, max_events)).fetchall()
        events = [AuthEvent.model_validate_json(r["event"]) for r in rows]
        events.sort(key=lambda e: (e.timestamp, e.raw_ref.file, e.raw_ref.line))
        return events

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        """Held for the whole sync; a second sync of this source is refused, not queued."""
        lock = self.dir / "sync.lock"
        handle = lock.open("a+b")
        try:
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise SyncBusyError("a sync of this source is already running") from None
            try:
                yield
            finally:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def _later(a: Position, b: Position) -> bool:
    try:
        return (a.cursor, a.key) > (b.cursor, b.key)
    except TypeError:  # types changed (e.g. the cursor column was altered): keep the newer
        return True


def _micros(moment: datetime) -> int:
    delta = moment.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def _from_micros(value: int | None) -> datetime | None:
    if value is None:
        return None
    return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=value)


def _run(row: sqlite3.Row) -> RunRecord:
    return RunRecord(row["id"], row["trigger"], row["started_at"], row["finished_at"],
                     row["status"], row["fetched"], row["new"], row["duplicates"],
                     row["changed"], row["rejected"], row["batches"],
                     bool(row["more_available"]), row["error"])
