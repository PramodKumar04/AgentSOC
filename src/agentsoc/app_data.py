"""Data access for the SOC dashboard (no Streamlit imports, so it is unit-testable).

Sources:
  * demo — the deterministic SYNTHETIC 4-day scenario, built on demand with the
    existing Phase 1/2 pipeline into <root>/demo/{dataset,detection}.
  * LANL validation runs — REAL (sampled, anonymised) data produced by
    scripts/validate_lanl.py, if present under <root>/lanl_validation.

Evidence is always read from the verified dataset: the events file's SHA-256 must
match its manifest, and only events cited by incidents are parsed (streaming), so
large LANL datasets do not need to fit in memory.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from agentsoc.config import PROJECT_ROOT
from agentsoc.detection.config import load_detection_config
from agentsoc.detection.engine import run_detection
from agentsoc.detection.inputs import load_verified_inputs
from agentsoc.exceptions import DatasetIntegrityError
from agentsoc.perception.lanl import ingest_lanl_file
from agentsoc.perception.quality import build_quality_report
from agentsoc.schemas import AuthEvent, DatasetSource, Finding, Incident
from agentsoc.store.datasets import (
    EVENTS_FILE,
    DatasetManifest,
    load_manifest,
    write_processed_dataset,
)
from agentsoc.store.detections import (
    SUMMARY_FILE,
    load_detection_summary,
    load_findings,
    load_incidents,
    write_detection_outputs,
)

DEMO_INPUT = PROJECT_ROOT / "data" / "samples" / "auth_scenarios_synthetic.txt"
DEMO_CONFIG = PROJECT_ROOT / "data" / "samples" / "scenarios_detection_config.json"
DEMO_LABEL = "SYNTHETIC 4-day enterprise scenario in LANL format (generated, not real activity)"


def data_root() -> Path:
    """`AGENTSOC_DATA_ROOT` overrides the default <project>/data/processed (used by tests)."""
    return Path(os.environ.get("AGENTSOC_DATA_ROOT", PROJECT_ROOT / "data" / "processed"))


@dataclass(frozen=True)
class Source:
    key: str
    label: str
    provenance: DatasetSource
    dataset_dir: Path
    detection_dir: Path


def ensure_demo(root: Path | None = None) -> Source:
    """Build the synthetic demo with the existing pipeline if it is missing or invalid."""
    base = (root or data_root()) / "demo"
    dataset_dir, detection_dir = base / "dataset", base / "detection"
    try:
        load_manifest(dataset_dir)
        load_incidents(detection_dir)
    except DatasetIntegrityError:
        result = ingest_lanl_file(DEMO_INPUT, dataset=DatasetSource.SYNTHETIC)
        write_processed_dataset(result, build_quality_report(result), dataset_dir,
                                dataset_label=DEMO_LABEL, overwrite=True)
        config = load_detection_config(DEMO_CONFIG)
        inputs = load_verified_inputs([dataset_dir])
        detection = run_detection([e for i in inputs for e in i.events], config)
        write_detection_outputs(detection, inputs, config, detection_dir, overwrite=True)
    return Source("demo", "Synthetic demo scenario (4 days)", DatasetSource.SYNTHETIC,
                  dataset_dir, detection_dir)


def discover_sources(root: Path | None = None) -> list[Source]:
    root = root or data_root()
    sources = [ensure_demo(root)]
    summary_path = root / "lanl_validation" / "detection_summary.json"
    if summary_path.is_file():
        runs = json.loads(summary_path.read_text(encoding="utf-8")).get("runs", {})
        for name, run in runs.items():
            dataset_dir = root / "lanl_validation" / "datasets" / run["spec"]["dataset_dir"]
            detection_dir = root / "lanl_validation" / "runs" / name / "detection"
            if (dataset_dir / EVENTS_FILE).is_file() and (detection_dir / SUMMARY_FILE).is_file():
                mode = run["spec"]["baseline_mode"]
                suffix = " — sensitivity run (short baseline)" if mode == "half_window" else ""
                sources.append(Source(f"lanl:{name}", f"LANL 2015 (real, sampled): {name}{suffix}",
                                      DatasetSource.LANL, dataset_dir, detection_dir))
    return sources


@dataclass(frozen=True)
class LoadedSource:
    source: Source
    manifest: DatasetManifest
    summary: dict
    incidents: list[Incident]
    findings: list[Finding]
    admin_users: frozenset[str]


def load_source(source: Source) -> LoadedSource:
    """Hash-verified incidents/findings plus the dataset manifest."""
    summary = load_detection_summary(source.detection_dir).model_dump(mode="json")
    return LoadedSource(
        source=source,
        manifest=load_manifest(source.dataset_dir),
        summary=summary,
        incidents=load_incidents(source.detection_dir),
        findings=load_findings(source.detection_dir),
        admin_users=frozenset(summary["config"]["admin_users"]),
    )


def load_evidence(dataset_dir: Path, event_ids: set[str]) -> dict[str, AuthEvent]:
    """Stream the verified events file; return only the requested events.

    Raises DatasetIntegrityError if the file no longer matches its manifest.
    Missing IDs are simply absent from the result (callers report them).
    """
    manifest = load_manifest(dataset_dir)
    digest = hashlib.sha256()
    found: dict[str, AuthEvent] = {}
    with (Path(dataset_dir) / EVENTS_FILE).open("rb") as handle:
        for raw in handle:
            digest.update(raw)
            if len(found) < len(event_ids) and b'"event_id"' in raw:
                eid = json.loads(raw)["event_id"]
                if eid in event_ids:
                    found[eid] = AuthEvent.model_validate_json(raw)
    if digest.hexdigest() != manifest.events_sha256:
        raise DatasetIntegrityError("events file hash does not match its manifest")
    return found


def relative_time(ts) -> str:
    """LANL-style time is an offset from an anonymised start; show it as Day N HH:MM:SS."""
    seconds = int(ts.timestamp())
    hours, minutes = seconds % 86400 // 3600, seconds % 3600 // 60
    return f"Day {seconds // 86400} {hours:02d}:{minutes:02d}:{seconds % 60:02d}"
