"""Correlate findings into incidents and compute incident severity.

Correlation key: (provenance, principal user). Within a key, findings sorted by
first_seen are merged while each starts no later than `correlation_gap_seconds`
after the current incident's last event, or shares an evidence event with it.
Cross-user correlation (e.g. by shared host) is not performed.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta

from agentsoc.detection.catalog import (
    ADMIN_EXPLANATION,
    CATALOG,
    DATASET_FLAGS,
    DATASET_LIMITATIONS,
    GENERIC_LIMITATION,
    GENERIC_MISSING,
    RuleId,
)
from agentsoc.detection.config import DetectionConfig, SeverityPolicy
from agentsoc.schemas import AuthEvent, DatasetSource, Finding, Incident, Severity

SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def incident_severity(
    rule_ids: Sequence[RuleId], *, is_admin: bool, policy: SeverityPolicy
) -> tuple[Severity, str]:
    """Band the sum of points over DISTINCT rules; optionally lower one band for admins.

    This is a triage priority for a human analyst, not a probability of compromise.
    """
    distinct = sorted(set(rule_ids))
    total = sum(policy.points[r] for r in distinct)
    if total >= policy.critical_at:
        band = Severity.CRITICAL
    elif total >= policy.high_at:
        band = Severity.HIGH
    elif total >= policy.medium_at:
        band = Severity.MEDIUM
    else:
        band = Severity.LOW
    terms = " + ".join(f"{r}={policy.points[r]}" for r in distinct)
    rationale = (
        f"Points over distinct rules: {terms} = {total}. Bands: MEDIUM>={policy.medium_at}, "
        f"HIGH>={policy.high_at}, CRITICAL>={policy.critical_at} -> {band}."
    )
    if is_admin and policy.downgrade_admin_users and band is not Severity.LOW:
        band = SEVERITY_ORDER[SEVERITY_ORDER.index(band) - 1]
        rationale += f" Lowered one band to {band}: principal is a configured admin account."
    return band, rationale


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _build_incident(
    incident_id: str,
    findings: list[Finding],
    events_by_id: dict[str, AuthEvent],
    config: DetectionConfig,
) -> Incident:
    evidence = sorted(
        {eid for f in findings for eid in f.event_ids},
        key=lambda eid: (events_by_id[eid].timestamp, eid),
    )
    events = [events_by_id[eid] for eid in evidence]
    principal = findings[0].user
    rule_ids = sorted({RuleId(f.rule_id) for f in findings})
    datasets = sorted({e.dataset for e in events})
    is_admin = principal in config.admin_users
    severity, rationale = incident_severity(
        rule_ids, is_admin=is_admin, policy=config.severity_policy
    )

    benign = [ADMIN_EXPLANATION] if is_admin else []
    limitations = [GENERIC_LIMITATION]
    missing: list[str] = []
    for rule in rule_ids:
        info = CATALOG[rule]
        benign += info.benign_explanations
        limitations += info.limitations
        missing += info.missing_information
    for dataset in datasets:
        limitations += DATASET_LIMITATIONS[dataset]
    missing.append(GENERIC_MISSING)

    flags = [DATASET_FLAGS[d] for d in datasets]
    if is_admin:
        flags.append("known-admin-account")
    if DatasetSource.LANL in datasets:
        flags.append("relative-timestamps")

    return Incident(
        incident_id=incident_id,
        principal_user=principal,
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        findings=findings,
        event_ids=evidence,
        rule_ids=[str(r) for r in rule_ids],
        involved_users=sorted(
            {e.src_user for e in events} | {e.dst_user for e in events if e.dst_user}
        ),
        involved_hosts=sorted({e.src_host for e in events} | {e.dst_host for e in events}),
        datasets=datasets,
        severity=severity,
        severity_rationale=rationale,
        benign_explanations=_dedupe(benign),
        limitations=_dedupe(limitations),
        missing_information=_dedupe(missing),
        flags=flags,
    )


def correlate(
    findings: Sequence[Finding], events_by_id: dict[str, AuthEvent], config: DetectionConfig
) -> list[Incident]:
    gap = timedelta(seconds=config.correlation_gap_seconds)
    groups: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        dataset = events_by_id[finding.event_ids[0]].dataset
        groups.setdefault((dataset.value, finding.user), []).append(finding)

    clusters: list[list[Finding]] = []
    for key in sorted(groups):
        current: list[Finding] = []
        last_seen = None
        evidence: set[str] = set()
        for finding in sorted(groups[key], key=lambda f: (f.first_seen, f.finding_id)):
            joins = current and (
                finding.first_seen <= last_seen + gap or evidence & set(finding.event_ids)
            )
            if current and not joins:
                clusters.append(current)
                current, evidence = [], set()
            current.append(finding)
            evidence |= set(finding.event_ids)
            last_seen = max(f.last_seen for f in current)
        if current:
            clusters.append(current)

    clusters.sort(key=lambda c: (min(f.first_seen for f in c), c[0].user, c[0].finding_id))
    return [
        _build_incident(f"INC-{n:05d}", cluster, events_by_id, config)
        for n, cluster in enumerate(clusters, start=1)
    ]
