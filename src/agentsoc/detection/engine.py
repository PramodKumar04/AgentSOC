"""Detection engine: provenance partitioning, pre-processing, rules, correlation,
and a final evidence check against the input events."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from agentsoc.detection import rules
from agentsoc.detection.baseline import annotate_novelty, build_profiles, split_baseline
from agentsoc.detection.config import DetectionConfig
from agentsoc.detection.correlate import correlate
from agentsoc.exceptions import DetectionError
from agentsoc.logging_setup import get_logger
from agentsoc.schemas import AuthEvent, DatasetSource, Finding, Incident
from agentsoc.schemas.common import Contract

ENGINE_VERSION = "auth-detect/1.0"
logger = get_logger(__name__)


class PartitionStats(Contract):
    """Pre-processing and baseline facts for one provenance partition."""

    input_events: int
    excluded_events: int
    collapsed_duplicates: int
    analysed_events: int
    baseline_events: int
    evaluated_events: int
    baseline_end: datetime | None
    users_with_baseline: int
    users_without_baseline: list[str]


@dataclass(frozen=True)
class DetectionResult:
    findings: list[Finding]
    incidents: list[Incident]
    partitions: dict[DatasetSource, PartitionStats]


def _preprocess(
    events: Sequence[AuthEvent], config: DetectionConfig
) -> tuple[list[AuthEvent], int, int]:
    ordered = sorted(events, key=lambda e: (e.timestamp, e.raw_ref.file, e.raw_ref.line))
    kept = [e for e in ordered if not config.is_excluded(e.src_user)]
    excluded = len(ordered) - len(kept)
    if not config.collapse_exact_duplicates:
        return kept, excluded, 0
    seen: set[tuple] = set()
    unique: list[AuthEvent] = []
    for event in kept:
        key = tuple(event.model_dump(exclude={"event_id", "raw_ref"}).values())
        if key not in seen:
            seen.add(key)
            unique.append(event)
    return unique, excluded, len(kept) - len(unique)


def _detect_partition(
    events: Sequence[AuthEvent], config: DetectionConfig
) -> tuple[list[rules.Detection], PartitionStats]:
    analysed, excluded, collapsed = _preprocess(events, config)
    split = split_baseline(analysed, config)
    profiles = build_profiles(split.baseline_events, config)
    novelty = annotate_novelty(split.evaluated_events, profiles, config)

    found: list[rules.Detection] = []
    # Failure rules need no baseline and evaluate the full time range.
    if config.failure_burst.enabled:
        found += rules.failure_bursts(analysed, config)
    if config.fail_then_success.enabled:
        found += rules.fail_then_success(analysed, config)
    # Novelty-based rules evaluate post-baseline events of users with a baseline.
    if config.new_src_host.enabled:
        found += rules.new_src_hosts(novelty, profiles, config)
    if config.new_dst_host.enabled:
        found += rules.new_dst_hosts(novelty, profiles, config)
    if config.multi_host_spread.enabled:
        found += rules.multi_host_spread(novelty, config)
    if config.lateral_chain.enabled:
        found += rules.lateral_chains(split.evaluated_events, novelty, profiles, config)
    if config.sensitive_host_access.enabled:
        found += rules.sensitive_access(novelty, config)

    stats = PartitionStats(
        input_events=len(events),
        excluded_events=excluded,
        collapsed_duplicates=collapsed,
        analysed_events=len(analysed),
        baseline_events=len(split.baseline_events),
        evaluated_events=len(split.evaluated_events),
        baseline_end=split.baseline_end,
        users_with_baseline=len(profiles),
        users_without_baseline=sorted(novelty.users_without_baseline),
    )
    return found, stats


def _to_findings(detections: list[rules.Detection]) -> list[Finding]:
    ordered = sorted(
        detections,
        key=lambda d: (d.events[0].timestamp, d.rule_id, d.user, d.events[0].event_id),
    )
    return [
        Finding(
            finding_id=f"FND-{n:05d}",
            rule_id=d.rule_id,
            severity=d.severity,
            user=d.user,
            event_ids=[e.event_id for e in d.events],
            hosts=sorted({h for e in d.events for h in (e.src_host, e.dst_host)}),
            first_seen=d.events[0].timestamp,
            last_seen=d.events[-1].timestamp,
            metrics=d.metrics,
            description=d.description,
        )
        for n, d in enumerate(ordered, start=1)
    ]


def verify_evidence(
    findings: Sequence[Finding], incidents: Sequence[Incident], known_event_ids: set[str]
) -> None:
    """Every cited event must exist in the verified input, and every finding must
    belong to exactly one incident. Raises DetectionError otherwise."""
    for item in (*findings, *incidents):
        unknown = set(item.event_ids) - known_event_ids
        if unknown:
            label = getattr(item, "incident_id", None) or item.finding_id
            raise DetectionError(f"{label} cites unknown events: {sorted(unknown)[:5]}")
    in_incidents = [f.finding_id for i in incidents for f in i.findings]
    if sorted(in_incidents) != sorted(f.finding_id for f in findings):
        raise DetectionError("findings and incidents are inconsistent")


def run_detection(events: Sequence[AuthEvent], config: DetectionConfig) -> DetectionResult:
    """Detect and correlate. Events of different provenance are never correlated."""
    ids = [e.event_id for e in events]
    if len(set(ids)) != len(ids):
        raise DetectionError("input contains duplicate event_ids")
    events_by_id = {e.event_id: e for e in events}

    partitions: dict[DatasetSource, list[AuthEvent]] = {}
    for event in events:
        partitions.setdefault(event.dataset, []).append(event)

    detections: list[rules.Detection] = []
    stats: dict[DatasetSource, PartitionStats] = {}
    for dataset in sorted(partitions):
        found, stats[dataset] = _detect_partition(partitions[dataset], config)
        detections += found

    findings = _to_findings(detections)
    incidents = correlate(findings, events_by_id, config)
    verify_evidence(findings, incidents, set(events_by_id))
    logger.info(
        "detection complete",
        extra={"context": {
            "events": len(events), "findings": len(findings), "incidents": len(incidents),
        }},
    )
    return DetectionResult(findings=findings, incidents=incidents, partitions=stats)
