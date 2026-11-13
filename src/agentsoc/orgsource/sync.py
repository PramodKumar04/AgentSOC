"""One sync run: read new rows in bounded batches, map them, store them with a checkpoint.

This is polling ("near real-time"), not streaming: rows appear in AgentSOC at the next sync
after they are committed in the source, and in the dashboard at the next snapshot.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from agentsoc.connectors.base import ConnectorError, Position, SourceConnector, TableRef
from agentsoc.ingest.mapping import map_record, usable_record_id
from agentsoc.logging_setup import get_logger
from agentsoc.orgsource.registry import DataSource
from agentsoc.orgsource.staging import (
    CAPTURE_DIR,
    CaptureWriter,
    RunRecord,
    StagedItem,
    StagingStore,
    content_sha256,
)
from agentsoc.perception.records import RejectedRecord
from agentsoc.schemas import DatasetSource
from agentsoc.schemas.events import RawRef

logger = get_logger(__name__)


def _start(store: StagingStore, source: DataSource) -> tuple[Position | None, object]:
    """Where to read from: after the checkpoint, or `lookback` before it."""
    checkpoint = store.checkpoint()
    lookback = source.config.lookback
    if checkpoint is None or not lookback:
        return checkpoint, None
    if isinstance(checkpoint.cursor, datetime):
        return None, checkpoint.cursor - timedelta(seconds=lookback)
    if isinstance(checkpoint.cursor, int):
        return None, checkpoint.cursor - lookback
    return checkpoint, None


def _stage(source: DataSource, capture: CaptureWriter, capture_name: str,
           rows: list[dict[str, object]]) -> list[StagedItem]:
    config = source.config
    items = []
    for row in rows:
        sha = content_sha256(row)
        record_id = usable_record_id(row.get(config.key_column))
        line = capture.append(record_id, row)
        result = map_record(row, config.mapping, ref=RawRef(file=capture_name, line=line),
                            prefix=source.key, dataset=DatasetSource.ORGANIZATION)
        if isinstance(result, RejectedRecord):
            items.append(StagedItem(record_id or f"invalid.{sha[:32]}", sha, None,
                                    result.reason.value, result.field, line))
        else:
            items.append(StagedItem(record_id, sha, result, None, None, line))
    return items


def sync_once(source: DataSource, connector: SourceConnector, store: StagingStore, *,
              trigger: str = "manual") -> RunRecord:
    """Never raises for source problems: the run is recorded as failed with a safe reason.

    Progress up to the last stored batch is kept, so a failed run resumes from there.
    """
    config = source.config
    with store.exclusive():
        run_id = store.start_run(trigger)
        capture_path = store.capture_path(run_id)
        capture_name = f"{CAPTURE_DIR}/{capture_path.name}"
        capture = CaptureWriter(capture_path)
        table = TableRef(config.table.schema_name, config.table.name)
        start_checkpoint = store.checkpoint()
        after, since = _start(store, source)
        total, more = 0, False
        try:
            while True:
                remaining = config.max_rows_per_sync - total
                if remaining <= 0:
                    more = True
                    break
                limit = min(config.batch_size, remaining)
                rows = connector.fetch(table, config.columns, cursor_column=config.cursor_column,
                                       key_column=config.key_column, after=after, since=since,
                                       limit=limit)
                if not rows:
                    break
                items = _stage(source, capture, capture_name, rows)
                capture.sync()
                last = rows[-1]
                position = Position(last[config.cursor_column], last[config.key_column])
                store.apply_batch(run_id, capture_name, items, position, len(rows))
                total += len(rows)
                after, since = position, None
                if len(rows) < limit:
                    break
        except ConnectorError as exc:
            capture.close()
            logger.warning("sync failed", extra={"context": {
                "source": source.key, "code": exc.code}})
            return store.finish_run(run_id, status="failed", error=str(exc))
        except Exception:
            capture.close()
            logger.exception("sync failed unexpectedly", extra={"context": {
                "source": source.key}})
            return store.finish_run(run_id, status="failed",
                                    error="Internal error; see the server log.")
        capture.close()
        if total == 0 and capture_path.stat().st_size == 0:
            capture_path.unlink()
        if more and store.checkpoint() == start_checkpoint:
            # Every row read was inside the look-back window: the run made no progress.
            return store.finish_run(run_id, status="failed", error=(
                "The look-back window holds more rows than one sync may read. Reduce the "
                "look-back or raise the rows per sync."))
        return store.finish_run(run_id, status="completed", more_available=more)
