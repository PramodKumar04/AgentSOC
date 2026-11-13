"""Import a CSV file with a header row through a column mapping.

The result is an ordinary verified dataset (events.jsonl + manifest), so the unchanged
detection, SSE and RSEM pipeline reads it like any other. The mapping is saved next to it
(`mapping.json`) with its SHA-256, which is also part of the parser version in the manifest.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from agentsoc.exceptions import IngestionError
from agentsoc.ingest.mapping import PREFIX_PATTERN, MappingSpec, map_record
from agentsoc.perception.quality import DataQualityReport, build_quality_report
from agentsoc.perception.records import IngestionResult, RejectedRecord, RejectReason
from agentsoc.schemas import AuthEvent, DatasetSource
from agentsoc.schemas.events import RawRef
from agentsoc.store.datasets import DatasetManifest, write_processed_dataset

MAPPING_FILE = "mapping.json"
MAX_ROW_CHARS = 8192
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)  # unused offset base: mapped times are absolute


def parser_version(spec: MappingSpec) -> str:
    return f"mapping/{spec.version}:{spec.sha256()[:16]}"


def _header(row: list[str], spec: MappingSpec) -> list[str]:
    names = [c.strip() for c in row]
    if len(set(names)) != len(names):
        raise IngestionError("the header repeats a column name")
    missing = sorted(spec.columns - set(names))
    if missing:
        raise IngestionError(f"mapped columns are not in the header: {', '.join(missing)}")
    return names


def ingest_csv(path: str | Path, spec: MappingSpec, *, prefix: str,
               dataset: DatasetSource = DatasetSource.UPLOAD,
               max_rows: int | None = None) -> IngestionResult:
    """Read every row; return accepted events sorted by (time, line) and rejected rows."""
    if not re.fullmatch(PREFIX_PATTERN, prefix):
        raise IngestionError("event prefix must be 1-31 of a-z 0-9 _ -")
    source = Path(path)
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)

    events: list[AuthEvent] = []
    rejected: list[RejectedRecord] = []
    seen_ids: set[str] = set()
    signatures: set[tuple] = set()
    duplicates = out_of_order = lines = blank = 0
    last = None
    with source.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.reader(handle)
        try:
            header = _header(next(reader), spec)
        except StopIteration:
            raise IngestionError("the file is empty") from None
        for row in reader:
            lines += 1
            if max_rows is not None and lines > max_rows:
                raise IngestionError(f"more than {max_rows} rows")
            line = reader.line_num
            if not any(cell.strip() for cell in row):
                blank += 1
                continue
            if sum(len(c) for c in row) > MAX_ROW_CHARS:
                rejected.append(RejectedRecord(line=line, reason=RejectReason.LINE_TOO_LONG,
                                               detail=f"row is longer than {MAX_ROW_CHARS}",
                                               raw_excerpt=",".join(row)[:200]))
                continue
            if len(row) != len(header):
                rejected.append(RejectedRecord(
                    line=line, reason=RejectReason.WRONG_FIELD_COUNT,
                    detail=f"expected {len(header)} fields, got {len(row)}",
                    raw_excerpt=",".join(row)[:200]))
                continue
            record = dict(zip(header, row, strict=True))
            result = map_record(record, spec, ref=RawRef(file=source.name, line=line),
                                prefix=prefix, dataset=dataset)
            if isinstance(result, RejectedRecord):
                rejected.append(result)
                continue
            if result.event_id in seen_ids:
                rejected.append(RejectedRecord(
                    line=line, reason=RejectReason.DUPLICATE_RECORD_ID, field="record_id",
                    detail="record identifier already used by an earlier row",
                    raw_excerpt=",".join(row)[:200]))
                continue
            seen_ids.add(result.event_id)
            signature = result.model_dump(exclude={"event_id", "raw_ref"})
            key = tuple(sorted((k, str(v)) for k, v in signature.items()))
            if key in signatures:
                duplicates += 1
            signatures.add(key)
            if last is not None and result.timestamp < last:
                out_of_order += 1
            last = result.timestamp
            events.append(result)
    events.sort(key=lambda e: (e.timestamp, e.raw_ref.line))
    return IngestionResult(
        source_file=source.name, dataset=dataset, parser_version=parser_version(spec),
        base_time=EPOCH, skip=0, limit=max_rows,
        input_sha256=digest.hexdigest(), lines_read=lines, blank_lines=blank,
        out_of_order=out_of_order, exact_duplicates=duplicates, events=events,
        rejected=rejected)


def write_mapped_dataset(result: IngestionResult, spec: MappingSpec, out_dir: str | Path, *,
                         dataset_label: str, overwrite: bool = False
                         ) -> tuple[DatasetManifest, DataQualityReport]:
    report = build_quality_report(result)
    manifest = write_processed_dataset(result, report, out_dir, dataset_label=dataset_label,
                                       overwrite=overwrite)
    record = {"mapping": spec.model_dump(mode="json"), "mapping_sha256": spec.sha256(),
              "disclosures": spec.disclosures()}
    with (Path(out_dir) / MAPPING_FILE).open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return manifest, report
