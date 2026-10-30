"""Reproducible on-disk format for detection results.

    detections.jsonl         one Finding per line (sorted by finding_id)
    incidents.jsonl          one Incident per line (sorted by incident_id)
    detection_summary.json   provenance, config, stats, output hashes, generated_at
    detection_report.md      human-readable report (no wall-clock content)

For identical inputs and config, every file except `detection_summary.json`
(`generated_at`) is byte-identical across runs.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from agentsoc.detection.config import DetectionConfig
from agentsoc.detection.engine import DetectionResult, verify_evidence
from agentsoc.detection.inputs import VerifiedInput
from agentsoc.detection.report import DetectionSummary, build_summary, render_report
from agentsoc.exceptions import DatasetIntegrityError, DetectionError
from agentsoc.schemas import Finding, Incident

DETECTIONS_FILE = "detections.jsonl"
INCIDENTS_FILE = "incidents.jsonl"
SUMMARY_FILE = "detection_summary.json"
REPORT_FILE = "detection_report.md"


def _write(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_detection_outputs(
    result: DetectionResult,
    inputs: list[VerifiedInput],
    config: DetectionConfig,
    out_dir: str | Path,
    *,
    overwrite: bool = False,
    generated_at: datetime | None = None,
) -> DetectionSummary:
    out = Path(out_dir)
    if out.exists() and any(out.iterdir()) and not overwrite:
        raise DetectionError(f"output directory is not empty: {out} (use overwrite)")
    events_by_id = {e.event_id: e for i in inputs for e in i.events}
    # Re-check evidence against exactly the inputs being recorded as provenance.
    verify_evidence(result.findings, result.incidents, set(events_by_id))

    detections_text = "".join(f.model_dump_json() + "\n" for f in result.findings)
    incidents_text = "".join(i.model_dump_json() + "\n" for i in result.incidents)
    summary = build_summary(
        result, inputs, config,
        detections_sha256=_sha256(detections_text),
        incidents_sha256=_sha256(incidents_text),
        generated_at=generated_at or datetime.now(UTC),
    )
    out.mkdir(parents=True, exist_ok=True)
    _write(out / DETECTIONS_FILE, detections_text)
    _write(out / INCIDENTS_FILE, incidents_text)
    _write(out / SUMMARY_FILE, summary.model_dump_json(indent=2) + "\n")
    _write(out / REPORT_FILE, render_report(summary, result, events_by_id))
    return summary


def load_detection_summary(out_dir: str | Path) -> DetectionSummary:
    path = Path(out_dir) / SUMMARY_FILE
    try:
        return DetectionSummary.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise DatasetIntegrityError(f"{SUMMARY_FILE} not found in {out_dir}") from None
    except ValidationError:
        raise DatasetIntegrityError(f"{SUMMARY_FILE} in {out_dir} is invalid") from None


def _load_jsonl(path: Path, expected_sha: str, model: type, verify: bool) -> list:
    if not path.is_file():
        raise DatasetIntegrityError(f"{path.name} not found")
    text = path.read_text(encoding="utf-8")
    if verify and _sha256(text) != expected_sha:
        raise DatasetIntegrityError(f"{path.name} hash does not match {SUMMARY_FILE}")
    items = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        try:
            items.append(model.model_validate_json(line))
        except ValidationError:
            raise DatasetIntegrityError(f"{path.name}:{line_no} is invalid") from None
    return items


def load_incidents(out_dir: str | Path, *, verify: bool = True) -> list[Incident]:
    summary = load_detection_summary(out_dir)
    return _load_jsonl(Path(out_dir) / INCIDENTS_FILE, summary.incidents_sha256, Incident, verify)


def load_findings(out_dir: str | Path, *, verify: bool = True) -> list[Finding]:
    summary = load_detection_summary(out_dir)
    return _load_jsonl(Path(out_dir) / DETECTIONS_FILE, summary.detections_sha256, Finding, verify)
