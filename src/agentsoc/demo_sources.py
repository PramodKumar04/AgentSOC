"""Register additional, clearly labelled data sources for the dashboard.

    python scripts/prepare_demo_sources.py

Synthetic risk scenarios are built into `<root>/demo_sources/` with the normal pipeline.
LANL runs that already have structural and risk assessments are only referenced: nothing
under `lanl_validation*` is written. The sole shared file written is the registry
`<root>/demo_sources.json`. Without it the dashboard shows only its default sources.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from agentsoc.app_data import REGISTRY_FILE, data_root
from agentsoc.config import PROJECT_ROOT
from agentsoc.detection.config import load_detection_config
from agentsoc.detection.engine import run_detection
from agentsoc.detection.inputs import load_verified_inputs
from agentsoc.exceptions import DatasetIntegrityError
from agentsoc.graph.assess import run_structural_assessment
from agentsoc.graph.store import load_structural_summary
from agentsoc.perception.lanl import ingest_lanl_file
from agentsoc.perception.quality import build_quality_report
from agentsoc.risk.assess import run_risk_assessment
from agentsoc.risk.store import load_risk_records
from agentsoc.schemas import DatasetSource
from agentsoc.store.datasets import load_manifest, write_processed_dataset
from agentsoc.store.detections import write_detection_outputs

SAMPLES = PROJECT_ROOT / "data" / "samples"
SYNTHETIC_INPUT = SAMPLES / "auth_risk_scenarios_synthetic.txt"
SYNTHETIC_CONFIG = SAMPLES / "risk_scenarios_detection_config.json"
SYNTHETIC_KEY = "synthetic-risk"
SYNTHETIC_LABEL = "SYNTHETIC risk scenarios (constructed test cases, not real activity)"
LANL_DATASET = Path("lanl_validation") / "datasets" / "lines_29400001_29800000"
LANL_RUNS = (
    ("lanl-assessed-redteam_window", "redteam_window",
     "LANL 2015 (real, sampled): red-team window, full assessment"),
    ("lanl-assessed-redteam_window_half_baseline", "redteam_window_half_baseline",
     "LANL 2015 (real, sampled): red-team window, full assessment — sensitivity run "
     "(short baseline)"),
)


@dataclass(frozen=True)
class Prepared:
    key: str
    status: str  # built, reused, referenced or skipped
    detail: str = ""


def _assessed(detection_dir: Path) -> bool:
    try:
        return bool(load_risk_records(detection_dir))
    except DatasetIntegrityError:
        return False


def _build_synthetic(root: Path) -> tuple[Prepared, dict]:
    base = Path("demo_sources") / SYNTHETIC_KEY
    dataset_dir, detection_dir = root / base / "dataset", root / base / "detection"
    entry = {"key": SYNTHETIC_KEY, "label": SYNTHETIC_LABEL, "provenance": "synthetic",
             "dataset_dir": (base / "dataset").as_posix(),
             "detection_dir": (base / "detection").as_posix()}
    if _assessed(detection_dir):
        return Prepared(SYNTHETIC_KEY, "reused"), entry
    result = ingest_lanl_file(SYNTHETIC_INPUT, dataset=DatasetSource.SYNTHETIC)
    write_processed_dataset(result, build_quality_report(result), dataset_dir,
                            dataset_label=SYNTHETIC_LABEL, overwrite=True)
    config = load_detection_config(SYNTHETIC_CONFIG)
    inputs = load_verified_inputs([dataset_dir])
    detection = run_detection([e for i in inputs for e in i.events], config)
    write_detection_outputs(detection, inputs, config, detection_dir, overwrite=True)
    run_structural_assessment([dataset_dir], detection_dir, overwrite=True)
    run_risk_assessment(detection_dir, overwrite=True)
    return Prepared(SYNTHETIC_KEY, "built"), entry


def _reference_lanl(root: Path, key: str, run: str, label: str) -> tuple[Prepared, dict | None]:
    detection = Path("lanl_validation_target1") / run / "detection"
    if not (root / detection).is_dir():
        return Prepared(key, "skipped", "run not found"), None
    if not _assessed(root / detection):
        return Prepared(key, "skipped", "no valid structural and risk assessment"), None
    try:
        manifest = load_manifest(root / LANL_DATASET)
        hashes = load_structural_summary(root / detection).dataset_events_sha256
    except DatasetIntegrityError:
        return Prepared(key, "skipped", "dataset not available"), None
    if manifest.events_sha256 not in hashes:
        return Prepared(key, "skipped", "dataset does not match the assessment"), None
    return Prepared(key, "referenced"), {
        "key": key, "label": label, "provenance": "lanl",
        "dataset_dir": LANL_DATASET.as_posix(), "detection_dir": detection.as_posix(),
    }


def prepare_demo_sources(root: Path | None = None) -> list[Prepared]:
    root = Path(root) if root else data_root()
    root.mkdir(parents=True, exist_ok=True)
    report, entries = [], []
    prepared, entry = _build_synthetic(root)
    report.append(prepared)
    entries.append(entry)
    for key, run, label in LANL_RUNS:
        prepared, entry = _reference_lanl(root, key, run, label)
        report.append(prepared)
        if entry:
            entries.append(entry)
    with (root / REGISTRY_FILE).open("w", encoding="utf-8", newline="\n") as handle:
        json.dump({"sources": entries}, handle, indent=2)
        handle.write("\n")
    return report
