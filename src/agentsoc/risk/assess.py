"""Run RSEM over one detection run: score, verify independently, persist.

Needs a stored structural assessment. Reads only hash-verified detection and structural
outputs, and does not call the LLM.
"""

from __future__ import annotations

import hashlib
import statistics
import time
from collections import Counter
from collections.abc import Collection
from datetime import UTC, datetime
from pathlib import Path

from agentsoc.detection.config import DetectionConfig
from agentsoc.exceptions import DatasetIntegrityError
from agentsoc.graph.proposed import assessment_sha256
from agentsoc.graph.store import load_assessments, load_structural_summary
from agentsoc.logging_setup import get_logger
from agentsoc.risk.actions import propose_actions
from agentsoc.risk.confidence import assess_confidence
from agentsoc.risk.config import RiskConfig
from agentsoc.risk.score import compare_with_severity, score_incident
from agentsoc.risk.store import (
    RiskSummary,
    RiskTiming,
    serialise_records,
    write_risk_outputs,
)
from agentsoc.risk.verify import verify_record
from agentsoc.schemas import Incident, Severity
from agentsoc.schemas.graph import StructuralAssessment
from agentsoc.schemas.incidents import incident_sha256
from agentsoc.schemas.rsem import IncidentRiskRecord, SeverityComparison
from agentsoc.store.detections import load_detection_summary, load_incidents

ENGINE_VERSION = "rsem/1.0"
_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
LIMITATIONS = (
    "Risk is an evidence-weighted heuristic score, not a calibrated probability of compromise.",
    "Weights and bands are starting defaults; they have not been validated against ground truth.",
    "Connected authentication events do not establish compromise.",
    "Actions are proposals only: none has been or can be executed by this system.",
)
logger = get_logger(__name__)


def assess_incident_risk(
    incident: Incident, assessment: StructuralAssessment, detection_config: DetectionConfig,
    users_without_baseline: Collection[str], config: RiskConfig,
) -> IncidentRiskRecord:
    result = score_incident(incident, assessment, detection_config, config)
    confidence = assess_confidence(incident, assessment, detection_config,
                                   users_without_baseline, config)
    actions, withheld = propose_actions(incident, result, confidence, assessment,
                                        detection_config, config)
    relation, text = compare_with_severity(incident.severity, result.assessment.band, _ORDER)
    route = result.selection.route
    return IncidentRiskRecord(
        incident_id=incident.incident_id, incident_sha256=incident_sha256(incident),
        structural_sha256=assessment_sha256(assessment), risk=result.assessment,
        base_score=result.base_score, adjustments=result.adjustments,
        route=None if route is None else {
            "event_ids": list(route.event_ids), "hosts": list(route.hosts), "kind": route.kind,
            "effective_hops": route.effective_hops, "source_path_id": route.source_path_id,
            "reduced_jump_route": route.reduced_jump_route,
        },
        attributions=result.attributions, confidence=confidence,
        severity_comparison=SeverityComparison(
            detection_severity=incident.severity, risk_band=result.assessment.band,
            relation=relation, explanation=text,
        ),
        actions=actions, withheld_actions=withheld, limitations=list(LIMITATIONS),
    )


def run_risk_assessment(
    detection_dir: str | Path, config: RiskConfig | None = None, *, overwrite: bool = False,
) -> RiskSummary:
    config = config or RiskConfig()
    detection = load_detection_summary(detection_dir)
    incidents = {i.incident_id: i for i in load_incidents(detection_dir)}
    assessments = load_assessments(detection_dir)
    structural = load_structural_summary(detection_dir)
    if {a.incident_id for a in assessments} != set(incidents):
        raise DatasetIntegrityError("structural assessments do not cover every incident")
    no_baseline = {u for p in detection.partitions.values() for u in p.users_without_baseline}

    start = time.perf_counter()
    records: list[IncidentRiskRecord] = []
    per_incident_ms: list[float] = []
    for assessment in assessments:
        began = time.perf_counter()
        records.append(assess_incident_risk(incidents[assessment.incident_id], assessment,
                                            detection.config, no_baseline, config))
        per_incident_ms.append((time.perf_counter() - began) * 1000)
    assess_seconds = time.perf_counter() - start

    start = time.perf_counter()
    for record, assessment in zip(records, assessments, strict=True):
        verify_record(record, incidents[record.incident_id], assessment, detection.config, config)
    verify_seconds = time.perf_counter() - start

    text = serialise_records(records)
    ordered = sorted(per_incident_ms)
    summary = RiskSummary(
        engine_version=ENGINE_VERSION, risk_config_sha256=config.sha256(), risk_config=config,
        detection_incidents_sha256=detection.incidents_sha256,
        structural_assessments_sha256=structural.assessments_sha256,
        records_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        incidents_scored=len(records),
        bands=dict(Counter(r.risk.band.value for r in records)),
        severity_vs_risk=dict(Counter(
            f"{r.severity_comparison.detection_severity.value}->{r.risk.band.value}"
            for r in records)),
        confidence_levels=dict(Counter(r.confidence.level.value for r in records)),
        actions_withheld=sum(len(r.withheld_actions) for r in records),
        timing=RiskTiming(
            assess_seconds=round(assess_seconds, 3), verify_seconds=round(verify_seconds, 3),
            per_incident_ms_p50=round(statistics.median(ordered), 3) if ordered else 0.0,
            per_incident_ms_p95=(round(ordered[int(0.95 * (len(ordered) - 1))], 3)
                                 if ordered else 0.0),
            per_incident_ms_max=round(max(ordered), 3) if ordered else 0.0,
        ),
        generated_at=datetime.now(UTC),
    )
    write_risk_outputs(text, summary, detection_dir, overwrite=overwrite)
    logger.info("risk assessment complete", extra={"context": {
        "incidents": len(records), "bands": dict(summary.bands)}})
    return summary
