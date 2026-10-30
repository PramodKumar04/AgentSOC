"""Persist investigation results next to the detection run they belong to.

File name = incident_id + first 16 hex of the incident's SHA-256, so a result can
only be reloaded for the exact incident content it investigated.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from agentsoc.investigator.agent import incident_sha256
from agentsoc.schemas import Incident, InvestigationResult

INVESTIGATIONS_DIR = "investigations"


def _path(detection_dir: Path, incident: Incident) -> Path:
    return (Path(detection_dir) / INVESTIGATIONS_DIR
            / f"{incident.incident_id}-{incident_sha256(incident)[:16]}.json")


def save_investigation(detection_dir: Path, incident: Incident,
                       result: InvestigationResult) -> Path:
    if result.incident_sha256 != incident_sha256(incident):
        raise ValueError("result does not belong to this incident")
    path = _path(detection_dir, incident)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(result.model_dump_json(indent=2) + "\n")
    return path


def load_investigation(detection_dir: Path, incident: Incident) -> InvestigationResult | None:
    """The saved result for exactly this incident, or None (missing, corrupt or mismatched)."""
    path = _path(detection_dir, incident)
    if not path.is_file():
        return None
    try:
        result = InvestigationResult.model_validate_json(path.read_text(encoding="utf-8"))
    except ValidationError:
        return None
    return result if result.incident_sha256 == incident_sha256(incident) else None


def count_investigations(detection_dir: Path) -> int:
    directory = Path(detection_dir) / INVESTIGATIONS_DIR
    return sum(1 for _ in directory.glob("*.json")) if directory.is_dir() else 0
