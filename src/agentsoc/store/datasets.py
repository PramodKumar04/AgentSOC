"""Reproducible on-disk format for processed event datasets.

A dataset directory contains:
    events.jsonl          one AuthEvent JSON per line, sorted by (timestamp, source line)
    rejected.jsonl        one RejectedRecord JSON per line
    quality_report.json   DataQualityReport
    quality_report.md     human-readable report
    manifest.json         provenance + SHA-256 of events.jsonl

Re-running ingestion with the same input and parameters produces byte-identical
events.jsonl; `manifest.created_at` is the only field that varies between runs.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import AwareDatetime, ValidationError

from agentsoc.exceptions import DatasetIntegrityError, IngestionError
from agentsoc.perception.quality import DataQualityReport, render_markdown
from agentsoc.perception.records import IngestionResult
from agentsoc.schemas import AuthEvent, DatasetSource
from agentsoc.schemas.common import Contract

EVENTS_FILE = "events.jsonl"
REJECTED_FILE = "rejected.jsonl"
REPORT_JSON = "quality_report.json"
REPORT_MD = "quality_report.md"
MANIFEST_FILE = "manifest.json"


class DatasetManifest(Contract):
    format_version: Literal[1] = 1
    dataset: DatasetSource
    dataset_label: str
    source_file: str
    parser_version: str
    base_time: AwareDatetime
    skip: int
    limit: int | None
    input_sha256: str
    events_sha256: str
    event_count: int
    rejected_count: int
    created_at: AwareDatetime


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_text(path: Path, text: str) -> None:
    # Fixed encoding and "\n" line endings so output bytes are platform-independent.
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def write_processed_dataset(
    result: IngestionResult,
    report: DataQualityReport,
    out_dir: str | Path,
    *,
    dataset_label: str,
    overwrite: bool = False,
) -> DatasetManifest:
    out = Path(out_dir)
    if out.exists() and any(out.iterdir()) and not overwrite:
        raise IngestionError(f"output directory is not empty: {out} (use overwrite)")
    out.mkdir(parents=True, exist_ok=True)

    _write_text(out / EVENTS_FILE, "".join(e.model_dump_json() + "\n" for e in result.events))
    _write_text(out / REJECTED_FILE, "".join(r.model_dump_json() + "\n" for r in result.rejected))
    _write_text(out / REPORT_JSON, report.model_dump_json(indent=2) + "\n")
    _write_text(out / REPORT_MD, render_markdown(report, dataset_label=dataset_label))

    manifest = DatasetManifest(
        dataset=result.dataset,
        dataset_label=dataset_label,
        source_file=result.source_file,
        parser_version=result.parser_version,
        base_time=result.base_time,
        skip=result.skip,
        limit=result.limit,
        input_sha256=result.input_sha256,
        events_sha256=_sha256_file(out / EVENTS_FILE),
        event_count=len(result.events),
        rejected_count=len(result.rejected),
        created_at=datetime.now(UTC),
    )
    _write_text(out / MANIFEST_FILE, manifest.model_dump_json(indent=2) + "\n")
    return manifest


def load_manifest(dataset_dir: str | Path) -> DatasetManifest:
    path = Path(dataset_dir) / MANIFEST_FILE
    try:
        return DatasetManifest.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise DatasetIntegrityError(f"manifest not found in {dataset_dir}") from None
    except ValidationError:
        raise DatasetIntegrityError(f"manifest in {dataset_dir} is invalid") from None


def load_events(dataset_dir: str | Path, *, verify: bool = True) -> list[AuthEvent]:
    """Load events, re-validating every record. With `verify`, the file hash and
    count must match the manifest — guarding against edits after ingestion."""
    directory = Path(dataset_dir)
    manifest = load_manifest(directory)
    events_path = directory / EVENTS_FILE
    if not events_path.is_file():
        raise DatasetIntegrityError(f"{EVENTS_FILE} not found in {directory}")
    if verify and _sha256_file(events_path) != manifest.events_sha256:
        raise DatasetIntegrityError(f"{EVENTS_FILE} hash does not match manifest")

    events: list[AuthEvent] = []
    with events_path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            try:
                events.append(AuthEvent.model_validate_json(line))
            except ValidationError:
                raise DatasetIntegrityError(
                    f"{EVENTS_FILE}:{line_no} is not a valid AuthEvent"
                ) from None
    if verify and len(events) != manifest.event_count:
        raise DatasetIntegrityError("event count does not match manifest")
    return events
