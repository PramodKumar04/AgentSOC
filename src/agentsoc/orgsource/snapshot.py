"""Snapshots: the newest synced events, frozen into a verified dataset and analysed.

Each snapshot is a new directory and is never changed afterwards. Detection, SSE and RSEM
run on it unchanged, exactly as on any other dataset. Incident IDs are numbered per snapshot,
so INC-00003 in one snapshot is not the same incident as INC-00003 in the next.

The baseline is the first `baseline_seconds` of each snapshot (48 h by default), so a
snapshot window shorter than that finds no novelty-based activity.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from agentsoc.config import PROJECT_ROOT
from agentsoc.detection.config import load_detection_config
from agentsoc.detection.engine import run_detection
from agentsoc.detection.inputs import load_verified_inputs
from agentsoc.exceptions import AgentSOCError
from agentsoc.graph.assess import run_structural_assessment
from agentsoc.ingest.csv_import import EPOCH, parser_version, write_mapped_dataset
from agentsoc.orgsource.registry import DataSource
from agentsoc.orgsource.staging import StagingStore
from agentsoc.perception.records import IngestionResult
from agentsoc.risk.assess import run_risk_assessment
from agentsoc.schemas import DatasetSource
from agentsoc.store.detections import write_detection_outputs

SNAPSHOT_DIR = "snapshots"
CURRENT_FILE = "current.json"
DETECTION_CONFIG = PROJECT_ROOT / "config" / "detection.json"


class SnapshotError(AgentSOCError):
    pass


@dataclass(frozen=True)
class SnapshotInfo:
    stamp: str
    created_at: str
    event_count: int
    incident_count: int
    first_event: str
    last_event: str
    dataset_dir: Path
    detection_dir: Path


def org_root(data_root: Path) -> Path:
    return data_root / "org"


def source_dir(data_root: Path, key: str) -> Path:
    return org_root(data_root) / key


def build_snapshot(source: DataSource, store: StagingStore, data_root: Path, *,
                   now: datetime | None = None) -> SnapshotInfo:
    policy = source.config.snapshot
    accepted_total = store.stats().accepted
    events = store.window(policy.window_hours, policy.max_events)
    if not events:
        raise SnapshotError("No accepted events have been synced yet.")
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    stamp = moment.strftime("%Y%m%dT%H%M%S%fZ")
    base = source_dir(data_root, source.key) / SNAPSHOT_DIR / stamp
    if base.exists():
        raise SnapshotError("A snapshot with this time stamp already exists.")
    dataset_dir, detection_dir = base / "dataset", base / "detection"

    # The input hash covers exactly the stored events chosen for this snapshot.
    digest = hashlib.sha256()
    for event in events:
        digest.update(event.model_dump_json().encode("utf-8") + b"\n")
    mapping = source.config.mapping
    result = IngestionResult(
        source_file=f"{source.config.kind}:{source.key}", dataset=DatasetSource.ORGANIZATION,
        parser_version=parser_version(mapping), base_time=EPOCH, skip=0,
        limit=policy.max_events, input_sha256=digest.hexdigest(), lines_read=len(events),
        blank_lines=0, out_of_order=0, exact_duplicates=0, events=events, rejected=[])
    label = f"{source.name} (organisation database, snapshot {moment:%Y-%m-%d %H:%M} UTC)"
    write_mapped_dataset(result, mapping, dataset_dir, dataset_label=label)

    config = load_detection_config(DETECTION_CONFIG)
    inputs = load_verified_inputs([dataset_dir])
    detection = run_detection([e for i in inputs for e in i.events], config)
    write_detection_outputs(detection, inputs, config, detection_dir)
    run_structural_assessment([dataset_dir], detection_dir)
    run_risk_assessment(detection_dir)

    info = SnapshotInfo(stamp, moment.isoformat(timespec="seconds"), len(events),
                        len(detection.incidents), events[0].timestamp.isoformat(),
                        events[-1].timestamp.isoformat(), dataset_dir, detection_dir)
    _write_current(source_dir(data_root, source.key), source, info, label, accepted_total)
    return info


def _write_current(directory: Path, source: DataSource, info: SnapshotInfo, label: str,
                   accepted_total: int) -> None:
    record = {"key": source.dashboard_key, "label": label, "snapshot": info.stamp,
              "created_at": info.created_at, "event_count": info.event_count,
              "incident_count": info.incident_count, "first_event": info.first_event,
              "last_event": info.last_event, "accepted_total": accepted_total}
    temp = directory / (CURRENT_FILE + ".tmp")
    temp.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temp, directory / CURRENT_FILE)


def read_current(directory: Path) -> dict | None:
    try:
        record = json.loads((directory / CURRENT_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return record if isinstance(record, dict) else None


def withdraw(directory: Path) -> None:
    """Stop offering a source's snapshots; the files stay on disk."""
    (directory / CURRENT_FILE).unlink(missing_ok=True)
