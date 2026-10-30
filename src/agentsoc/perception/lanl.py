"""Parser for the LANL "Comprehensive, Multi-Source Cyber-Security Events"
authentication log (`auth.txt` / `auth.txt.gz`, https://csr.lanl.gov/data/cyber1/).

Format: headerless CSV, 9 fields per line:
    time,source user@domain,destination user@domain,source computer,
    destination computer,authentication type,logon type,
    authentication orientation,success/failure

`time` is an integer number of seconds from an anonymised start, not a real
date. We map it to `base_time + time` (default: Unix epoch) and record the
base in the dataset manifest so the original offset is always recoverable.

Policy: records are validated, never repaired. The only normalisation is that
LANL's unknown marker `?` and empty optional fields become None.
"""

from __future__ import annotations

import gzip
import hashlib
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import BinaryIO

from pydantic import ValidationError

from agentsoc.exceptions import IngestionError
from agentsoc.logging_setup import get_logger
from agentsoc.perception.records import IngestionResult, RejectedRecord, RejectReason
from agentsoc.schemas import AuthEvent, AuthOrientation, AuthOutcome, DatasetSource

PARSER_VERSION = "lanl-auth/1.0"
DEFAULT_BASE_TIME = datetime(1970, 1, 1, tzinfo=UTC)

LANL_FIELDS = (
    "time", "src_user", "dst_user", "src_host", "dst_host",
    "auth_type", "logon_type", "orientation", "outcome",
)
REQUIRED_FIELDS = ("time", "src_user", "src_host", "dst_host", "orientation", "outcome")
OPTIONAL_FIELDS = ("dst_user", "auth_type", "logon_type")
UNKNOWN_MARKER = "?"

MAX_LINE_LENGTH = 1024
MAX_OFFSET_SECONDS = 10**10  # ~317 years; anything larger is not a plausible offset
_OFFSET_PATTERN = re.compile(r"[0-9]{1,11}")  # ASCII digits only (int() accepts e.g. "٥")
_EXCERPT_LEN = 200

logger = get_logger(__name__)


def event_id_prefix(source_name: str) -> str:
    """Stable, identifier-safe prefix derived from the source file name."""
    stem = source_name.removesuffix(".gz")
    return re.sub(r"[^A-Za-z0-9_.\-]", "_", stem)[:64] or "src"


def _optional(value: str) -> str | None:
    return None if value in ("", UNKNOWN_MARKER) else value


def parse_lanl_line(
    line: str,
    *,
    line_no: int,
    source_name: str,
    base_time: datetime = DEFAULT_BASE_TIME,
    dataset: DatasetSource = DatasetSource.LANL,
) -> AuthEvent | RejectedRecord:
    """Parse one LANL-format auth line. Never raises for bad content — returns a RejectedRecord.

    `dataset` records true provenance: a synthetic file in LANL format is SYNTHETIC, not LANL.
    """
    text = line.rstrip("\r\n")

    def reject(reason: RejectReason, detail: str, field: str | None = None) -> RejectedRecord:
        return RejectedRecord(
            line=line_no, reason=reason, field=field,
            detail=detail[:300], raw_excerpt=text[:_EXCERPT_LEN],
        )

    if len(text) > MAX_LINE_LENGTH:
        return reject(RejectReason.LINE_TOO_LONG, f"{len(text)} chars > {MAX_LINE_LENGTH}")
    if "�" in text:
        return reject(RejectReason.ENCODING_ERROR, "line contains bytes that are not valid UTF-8")

    parts = [p.strip() for p in text.split(",")]
    if len(parts) != len(LANL_FIELDS):
        return reject(
            RejectReason.WRONG_FIELD_COUNT, f"expected {len(LANL_FIELDS)} fields, got {len(parts)}"
        )
    raw = dict(zip(LANL_FIELDS, parts, strict=True))

    for name in REQUIRED_FIELDS:
        if not raw[name]:
            return reject(RejectReason.MISSING_REQUIRED_FIELD, f"{name} is empty", name)

    if not _OFFSET_PATTERN.fullmatch(raw["time"]) or int(raw["time"]) > MAX_OFFSET_SECONDS:
        return reject(
            RejectReason.INVALID_TIMESTAMP,
            "time must be a non-negative integer number of seconds",
            "time",
        )
    try:
        timestamp = base_time + timedelta(seconds=int(raw["time"]))
    except OverflowError:
        return reject(RejectReason.INVALID_TIMESTAMP, "time overflows the base time", "time")

    try:
        orientation = AuthOrientation(raw["orientation"])
    except ValueError:
        return reject(
            RejectReason.INVALID_ORIENTATION, "unknown authentication orientation", "orientation"
        )
    try:
        outcome = AuthOutcome(raw["outcome"])
    except ValueError:
        return reject(RejectReason.INVALID_OUTCOME, "outcome must be Success or Fail", "outcome")

    try:
        return AuthEvent(
            event_id=f"{event_id_prefix(source_name)}-{line_no}",
            timestamp=timestamp,
            src_user=raw["src_user"],
            dst_user=_optional(raw["dst_user"]),
            src_host=raw["src_host"],
            dst_host=raw["dst_host"],
            auth_type=_optional(raw["auth_type"]),
            logon_type=_optional(raw["logon_type"]),
            orientation=orientation,
            outcome=outcome,
            dataset=dataset,
            raw_ref={"file": source_name, "line": line_no},
        )
    except ValidationError as exc:
        err = exc.errors()[0]
        field = str(err["loc"][0]) if err["loc"] else None
        msg = (
            "contains characters outside the allowed identifier set"
            if err["type"] == "string_pattern_mismatch"
            else err["msg"]
        )
        return reject(RejectReason.INVALID_FIELD, f"{field}: {msg}", field)


def _open_binary(path: Path) -> BinaryIO:
    return gzip.open(path, "rb") if path.suffix == ".gz" else path.open("rb")


def _iter_lines(path: Path, skip: int, limit: int | None, digest) -> Iterator[tuple[int, str]]:
    """Yield (1-based line number, decoded line) for the consumed window; hash consumed bytes."""
    consumed = 0
    with _open_binary(path) as handle:
        for line_no, raw in enumerate(handle, start=1):
            if line_no <= skip:
                continue
            if limit is not None and consumed >= limit:
                break
            consumed += 1
            digest.update(raw)
            yield line_no, raw.decode("utf-8", errors="replace")


def ingest_lanl_file(
    path: str | Path,
    *,
    limit: int | None = None,
    skip: int = 0,
    base_time: datetime = DEFAULT_BASE_TIME,
    dataset: DatasetSource = DatasetSource.LANL,
) -> IngestionResult:
    """Stream a LANL auth file (plain or .gz) into validated events and rejections.

    `skip` lines are passed over, then at most `limit` lines are consumed.
    Raises IngestionError only if the file itself cannot be read.
    """
    path = Path(path)
    if limit is not None and limit < 1:
        raise IngestionError("limit must be >= 1")
    if skip < 0:
        raise IngestionError("skip must be >= 0")
    if base_time.tzinfo is None:
        raise IngestionError("base_time must be timezone-aware")
    if not path.is_file():
        raise IngestionError(f"input file not found: {path.name}")

    source_name = path.name
    digest = hashlib.sha256()
    events: list[AuthEvent] = []
    rejected: list[RejectedRecord] = []
    seen: set[tuple] = set()
    lines_read = blank = out_of_order = duplicates = 0
    latest: datetime | None = None

    try:
        for line_no, line in _iter_lines(path, skip, limit, digest):
            lines_read += 1
            if not line.strip():
                blank += 1
                continue
            result = parse_lanl_line(
                line, line_no=line_no, source_name=source_name,
                base_time=base_time, dataset=dataset,
            )
            if isinstance(result, RejectedRecord):
                rejected.append(result)
                continue
            if latest is not None and result.timestamp < latest:
                out_of_order += 1
            latest = result.timestamp if latest is None else max(latest, result.timestamp)
            key = tuple(result.model_dump(exclude={"event_id", "raw_ref"}).values())
            if key in seen:
                duplicates += 1
            seen.add(key)
            events.append(result)
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        raise IngestionError(f"cannot read {source_name}: {type(exc).__name__}") from exc

    events.sort(key=lambda e: (e.timestamp, e.raw_ref.line))
    logger.info(
        "ingested LANL-format auth file",
        extra={"context": {
            "file": source_name, "dataset": dataset.value, "lines_read": lines_read,
            "accepted": len(events),
            "rejected": len(rejected), "blank": blank,
        }},
    )
    return IngestionResult(
        source_file=source_name,
        dataset=dataset,
        parser_version=PARSER_VERSION,
        base_time=base_time,
        skip=skip,
        limit=limit,
        input_sha256=digest.hexdigest(),
        lines_read=lines_read,
        blank_lines=blank,
        out_of_order=out_of_order,
        exact_duplicates=duplicates,
        events=events,
        rejected=rejected,
    )
