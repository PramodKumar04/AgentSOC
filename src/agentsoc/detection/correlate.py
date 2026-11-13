"""Correlate findings into incidents and compute incident severity.

Correlation key: (provenance, principal user). Within a key, findings sorted by
first_seen are merged while each starts no later than `correlation_gap_seconds`
after the current incident's last event, or shares an evidence event with it.
Cross-user correlation (e.g. by shared host) is not performed.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
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
_UNSCORED_REASON = {
    RuleId.NEW_SRC_HOST: "its events are departures already counted by CROSS_ACCOUNT_PIVOT",
    RuleId.CROSS_ACCOUNT_PIVOT: "its departure events are already counted by NEW_SRC_HOST",
}


def incident_severity(
    rule_ids: Sequence[RuleId],
    *,
    is_admin: bool,
    policy: SeverityPolicy,
    reduced_rules: Collection[RuleId] = (),
    unscored_rules: Collection[RuleId] = (),
) -> tuple[Severity, str]:
    """Band the sum of points over DISTINCT rules; optionally lower one band for admins.

    `reduced_rules` lose `jump_host_point_reduction` points, never below 1. `unscored_rules`
    add nothing because another rule already scored the same events.

    This is a triage priority for a human analyst, not a probability of compromise.
    """
    distinct = sorted(set(rule_ids) - set(unscored_rules))

    def points(rule: RuleId) -> int:
        base = policy.points[rule]
        if rule not in reduced_rules:
            return base
        return max(min(1, base), base - policy.jump_host_point_reduction)

    def term(rule: RuleId) -> str:
        if points(rule) == policy.points[rule]:
            return f"{rule}={points(rule)}"
        return f"{rule}={points(rule)} (base {policy.points[rule]}, configured jump host path)"

    total = sum(points(r) for r in distinct)
    if total >= policy.critical_at:
        band = Severity.CRITICAL
    elif total >= policy.high_at:
        band = Severity.HIGH
    elif total >= policy.medium_at:
        band = Severity.MEDIUM
    else:
        band = Severity.LOW
    terms = " + ".join(term(r) for r in distinct)
    rationale = (
        f"Points over distinct rules: {terms} = {total}. Bands: MEDIUM>={policy.medium_at}, "
        f"HIGH>={policy.high_at}, CRITICAL>={policy.critical_at} -> {band}."
    )
    for rule in sorted(unscored_rules):
        rationale += f" {rule} not scored: {_UNSCORED_REASON[rule]}."
    if is_admin and policy.downgrade_admin_users and band is not Severity.LOW:
        band = SEVERITY_ORDER[SEVERITY_ORDER.index(band) - 1]
        rationale += f" Lowered one band to {band}: principal is a configured admin account."
    return band, rationale


def severity_for_findings(
    findings: Sequence[Finding], *, is_admin: bool, policy: SeverityPolicy
) -> tuple[Severity, str]:
    """Incident severity from its findings, without scoring the same evidence twice.

    A rule is reduced only if ALL its findings carry a jump-host adjustment. A pivot's
    departure is also a NEW_SRC_HOST event, so the two rules count once: NEW_SRC_HOST is
    dropped if pivots cover all of its events, otherwise the pivot is.
    """
    by_rule: dict[RuleId, list[Finding]] = {}
    for finding in findings:
        by_rule.setdefault(RuleId(finding.rule_id), []).append(finding)
    reduced = {rule for rule, group in by_rule.items()
               if all("severity_adjustment" in f.metrics for f in group)}
    departures = {f.metrics["departure_event_id"]
                  for f in by_rule.get(RuleId.CROSS_ACCOUNT_PIVOT, [])}
    new_source_events = {e for f in by_rule.get(RuleId.NEW_SRC_HOST, []) for e in f.event_ids}
    unscored: set[RuleId] = set()
    if departures & new_source_events:
        unscored.add(RuleId.NEW_SRC_HOST if new_source_events <= departures
                     else RuleId.CROSS_ACCOUNT_PIVOT)
    return incident_severity(
        list(by_rule), is_admin=is_admin, policy=policy, reduced_rules=reduced,
        unscored_rules=unscored,
    )


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
    severity, rationale = severity_for_findings(
        findings, is_admin=is_admin, policy=config.severity_policy
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
