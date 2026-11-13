"""Persist risk records beside the detection run they belong to.

    <detection dir>/risk/risk_records.jsonl   one IncidentRiskRecord per line
    <detection dir>/risk/risk_summary.json    hashes, config and timing

A separate directory: detection and structural files are never rewritten. A record loads
only if the detection run and structural assessment it was computed from are unchanged.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from pathlib import Path

from pydantic import AwareDatetime, ValidationError

from agentsoc.exceptions import DatasetIntegrityError
from agentsoc.graph.store import load_structural_summary
from agentsoc.risk.config import RiskConfig
from agentsoc.schemas.common import Contract
from agentsoc.schemas.rsem import IncidentRiskRecord
from agentsoc.store.detections import load_detection_summary

RISK_DIR = "risk"
RECORDS_FILE = "risk_records.jsonl"
SUMMARY_FILE = "risk_summary.json"


class RiskTiming(Contract):
    assess_seconds: float
    verify_seconds: float
    per_incident_ms_p50: float
    per_incident_ms_p95: float
    per_incident_ms_max: float


class RiskSummary(Contract):
    engine_version: str
    risk_config_sha256: str
    risk_config: RiskConfig
    detection_incidents_sha256: str
    structural_assessments_sha256: str
    records_sha256: str
    incidents_scored: int
    bands: dict[str, int]
    severity_vs_risk: dict[str, int]
    confidence_levels: dict[str, int]
    actions_withheld: int
    timing: RiskTiming
    generated_at: AwareDatetime


def serialise_records(records: Sequence[IncidentRiskRecord]) -> str:
    return "".join(r.model_dump_json() + "\n" for r in records)


def _write(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def write_risk_outputs(
    records_text: str, summary: RiskSummary, detection_dir: str | Path, *, overwrite: bool = False,
) -> Path:
    out = Path(detection_dir) / RISK_DIR
    if out.exists() and any(out.iterdir()) and not overwrite:
        raise DatasetIntegrityError(f"output directory is not empty: {out} (use overwrite)")
    out.mkdir(parents=True, exist_ok=True)
    _write(out / RECORDS_FILE, records_text)
    _write(out / SUMMARY_FILE, summary.model_dump_json(indent=2) + "\n")
    return out


def load_risk_summary(detection_dir: str | Path) -> RiskSummary:
    path = Path(detection_dir) / RISK_DIR / SUMMARY_FILE
    try:
        return RiskSummary.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise DatasetIntegrityError(f"{SUMMARY_FILE} not found in {path.parent}") from None
    except ValidationError:
        raise DatasetIntegrityError(f"{SUMMARY_FILE} in {path.parent} is invalid") from None


def load_risk_records(detection_dir: str | Path) -> list[IncidentRiskRecord]:
    """Hash-verified records, or DatasetIntegrityError if tampered with or out of date."""
    summary = load_risk_summary(detection_dir)
    if load_detection_summary(detection_dir).incidents_sha256 != (
        summary.detection_incidents_sha256
    ):
        raise DatasetIntegrityError("risk records belong to a different detection run")
    if load_structural_summary(detection_dir).assessments_sha256 != (
        summary.structural_assessments_sha256
    ):
        raise DatasetIntegrityError("risk records belong to a different structural assessment")
    path = Path(detection_dir) / RISK_DIR / RECORDS_FILE
    if not path.is_file():
        raise DatasetIntegrityError(f"{RECORDS_FILE} not found")
    text = path.read_text(encoding="utf-8")
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != summary.records_sha256:
        raise DatasetIntegrityError(f"{RECORDS_FILE} hash does not match {SUMMARY_FILE}")
    items = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        try:
            items.append(IncidentRiskRecord.model_validate_json(line))
        except ValidationError:
            raise DatasetIntegrityError(f"{RECORDS_FILE}:{line_no} is invalid") from None
    return items
