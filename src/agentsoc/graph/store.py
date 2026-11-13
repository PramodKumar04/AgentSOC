"""Persist structural assessments beside the detection run they belong to.

    <detection dir>/structural/assessments.jsonl       one StructuralAssessment per line
    <detection dir>/structural/structural_summary.json hashes, config and timing

A separate directory: detection files are never rewritten. For identical inputs and
config `assessments.jsonl` is byte-identical across runs. A stored assessment only loads
if its detection run is still the one it was computed from.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from pathlib import Path

from pydantic import AwareDatetime, ValidationError

from agentsoc.exceptions import DatasetIntegrityError
from agentsoc.graph.config import StructuralConfig
from agentsoc.schemas.common import Contract
from agentsoc.schemas.graph import StructuralAssessment
from agentsoc.store.detections import load_detection_summary

STRUCTURAL_DIR = "structural"
ASSESSMENTS_FILE = "assessments.jsonl"
SUMMARY_FILE = "structural_summary.json"


class StructuralTiming(Contract):
    index_seconds: float
    assess_seconds: float
    verify_seconds: float
    per_incident_ms_p50: float
    per_incident_ms_p95: float
    per_incident_ms_max: float


class StructuralSummary(Contract):
    engine_version: str
    structural_config_sha256: str
    structural_config: StructuralConfig
    detection_engine_version: str
    detection_config_sha256: str
    detection_incidents_sha256: str
    dataset_events_sha256: list[str]
    assessments_sha256: str
    incidents_assessed: int
    events_indexed: int
    paths_by_kind: dict[str, int]
    finding_verdicts: dict[str, int]
    truncated_incidents: int
    timing: StructuralTiming
    generated_at: AwareDatetime


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def serialise_assessments(assessments: Sequence[StructuralAssessment]) -> str:
    return "".join(a.model_dump_json() + "\n" for a in assessments)


def write_structural_outputs(
    assessments_text: str, summary: StructuralSummary, detection_dir: str | Path,
    *, overwrite: bool = False,
) -> Path:
    out = Path(detection_dir) / STRUCTURAL_DIR
    if out.exists() and any(out.iterdir()) and not overwrite:
        raise DatasetIntegrityError(f"output directory is not empty: {out} (use overwrite)")
    out.mkdir(parents=True, exist_ok=True)
    _write(out / ASSESSMENTS_FILE, assessments_text)
    _write(out / SUMMARY_FILE, summary.model_dump_json(indent=2) + "\n")
    return out


def load_structural_summary(detection_dir: str | Path) -> StructuralSummary:
    path = Path(detection_dir) / STRUCTURAL_DIR / SUMMARY_FILE
    try:
        return StructuralSummary.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise DatasetIntegrityError(f"{SUMMARY_FILE} not found in {path.parent}") from None
    except ValidationError:
        raise DatasetIntegrityError(f"{SUMMARY_FILE} in {path.parent} is invalid") from None


def load_assessments(detection_dir: str | Path) -> list[StructuralAssessment]:
    """Hash-verified assessments, or DatasetIntegrityError if tampered with or out of date."""
    summary = load_structural_summary(detection_dir)
    current = load_detection_summary(detection_dir)
    if current.incidents_sha256 != summary.detection_incidents_sha256:
        raise DatasetIntegrityError("structural assessments belong to a different detection run")
    path = Path(detection_dir) / STRUCTURAL_DIR / ASSESSMENTS_FILE
    if not path.is_file():
        raise DatasetIntegrityError(f"{ASSESSMENTS_FILE} not found")
    text = path.read_text(encoding="utf-8")
    if _sha256(text) != summary.assessments_sha256:
        raise DatasetIntegrityError(f"{ASSESSMENTS_FILE} hash does not match {SUMMARY_FILE}")
    items = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        try:
            items.append(StructuralAssessment.model_validate_json(line))
        except ValidationError:
            raise DatasetIntegrityError(f"{ASSESSMENTS_FILE}:{line_no} is invalid") from None
    return items
