"""Run the SSE over one detection run: index, assess, verify independently, persist."""

from __future__ import annotations

import hashlib
import statistics
import time
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from agentsoc.graph.config import StructuralConfig
from agentsoc.graph.index import build_event_index, read_evidence
from agentsoc.graph.store import (
    StructuralSummary,
    StructuralTiming,
    serialise_assessments,
    write_structural_outputs,
)
from agentsoc.graph.validate import assess_incident
from agentsoc.graph.verify import verify_assessment
from agentsoc.logging_setup import get_logger
from agentsoc.store.datasets import load_manifest
from agentsoc.store.detections import load_detection_summary, load_incidents

ENGINE_VERSION = "sse/1.0"
logger = get_logger(__name__)


def run_structural_assessment(
    dataset_dirs: Sequence[str | Path],
    detection_dir: str | Path,
    config: StructuralConfig | None = None,
    *,
    overwrite: bool = False,
) -> StructuralSummary:
    config = config or StructuralConfig()
    detection = load_detection_summary(detection_dir)
    incidents = load_incidents(detection_dir)

    start = time.perf_counter()
    indexes = build_event_index(dataset_dirs, incidents, detection.config, config)
    index_seconds = time.perf_counter() - start

    start = time.perf_counter()
    assessments = []
    per_incident_ms: list[float] = []
    for incident in incidents:
        began = time.perf_counter()
        assessments.append(assess_incident(incident, indexes[incident.datasets[0]], config))
        per_incident_ms.append((time.perf_counter() - began) * 1000)
    assess_seconds = time.perf_counter() - start

    start = time.perf_counter()
    needed = {i for a in assessments for e in a.edges for i in (e.event_id, *e.duplicate_event_ids)}
    originals = read_evidence(dataset_dirs, needed)
    for assessment in assessments:
        verify_assessment(assessment, originals, detection.config, config)
    verify_seconds = time.perf_counter() - start

    text = serialise_assessments(assessments)
    ordered_ms = sorted(per_incident_ms)
    summary = StructuralSummary(
        engine_version=ENGINE_VERSION,
        structural_config_sha256=config.sha256(), structural_config=config,
        detection_engine_version=detection.engine_version,
        detection_config_sha256=detection.config_sha256,
        detection_incidents_sha256=detection.incidents_sha256,
        dataset_events_sha256=[load_manifest(d).events_sha256 for d in dataset_dirs],
        assessments_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        incidents_assessed=len(assessments),
        events_indexed=sum(len(i) for i in indexes.values()),
        paths_by_kind=dict(Counter(p.kind.value for a in assessments for p in a.paths)),
        finding_verdicts=dict(Counter(
            v.verdict.value for a in assessments for v in a.finding_validations)),
        truncated_incidents=sum(a.stats.truncated for a in assessments),
        timing=StructuralTiming(
            index_seconds=round(index_seconds, 3), assess_seconds=round(assess_seconds, 3),
            verify_seconds=round(verify_seconds, 3),
            per_incident_ms_p50=round(statistics.median(ordered_ms), 3) if ordered_ms else 0.0,
            per_incident_ms_p95=(round(ordered_ms[int(0.95 * (len(ordered_ms) - 1))], 3)
                                 if ordered_ms else 0.0),
            per_incident_ms_max=round(max(ordered_ms), 3) if ordered_ms else 0.0,
        ),
        generated_at=datetime.now(UTC),
    )
    write_structural_outputs(text, summary, detection_dir, overwrite=overwrite)
    logger.info("structural assessment complete", extra={"context": {
        "incidents": len(assessments), "paths": dict(summary.paths_by_kind)}})
    return summary
