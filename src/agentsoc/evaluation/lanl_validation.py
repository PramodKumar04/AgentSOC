"""Analysis of a LANL validation run: ingestion, baseline coverage, per-rule results,
evidence integrity, severity inflation, identity splitting and a SEPARATE Red Team
comparison.

Red Team labels are only read here, after detection has finished. Nothing in this
module influences detection. No precision/recall/F1 is computed: the matching
methodology below does not justify them (see `redteam_comparison`).
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from agentsoc.detection.catalog import CATALOG, RuleId
from agentsoc.detection.config import DetectionConfig
from agentsoc.detection.correlate import incident_severity
from agentsoc.schemas import Finding, Incident
from agentsoc.store.datasets import EVENTS_FILE, DatasetManifest

COMPUTER_PATTERN = re.compile(r"C\d+")  # LANL's anonymised computer names
NOVELTY_RULES = {
    RuleId.NEW_SRC_HOST, RuleId.NEW_DST_HOST, RuleId.MULTI_HOST_SPREAD,
    RuleId.LATERAL_CHAIN, RuleId.SENSITIVE_HOST_ACCESS,
}
DISCLAIMER = (
    "This is an evaluation on SAMPLED windows of the LANL 2015 authentication dataset. "
    "It characterises how the Phase 2 rules behave on real authentication logs; it is not "
    "proof of production detection accuracy, and findings are suspicious-activity "
    "indicators, not confirmed compromises."
)


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def lines_per_day(archive: str | Path, days: int) -> dict[str, int]:
    """Stream the archive's time column and count lines per LANL day for the first `days`
    days (stops reading after that). Used to size what a full baseline would require."""
    counts: Counter = Counter()
    limit = days * 86_400
    with gzip.open(archive, "rb") if str(archive).endswith(".gz") else open(archive, "rb") as fh:
        for raw in fh:
            t = int(raw[: raw.index(b",")])
            if t >= limit:
                break
            counts[t // 86_400] += 1
    return {f"day_{d}": counts[d] for d in range(days)}


# ---------------------------------------------------------------- Red Team labels

@dataclass(frozen=True)
class RedTeamEvent:
    """One line of LANL redteam.txt: time,user@domain,source computer,destination computer."""

    t: int
    user: str
    src: str
    dst: str

    @property
    def key(self) -> tuple[int, str, str, str]:
        return (self.t, self.user, self.src, self.dst)


def load_redteam(path: str | Path) -> list[RedTeamEvent]:
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    events = []
    with opener(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            parts = line.strip().split(",")
            if len(parts) == 4 and parts[0].isdigit():
                events.append(RedTeamEvent(int(parts[0]), parts[1], parts[2], parts[3]))
    return events


# ---------------------------------------------------------------- streaming event scan

@dataclass
class EventScan:
    """Facts gathered in ONE streaming pass over events.jsonl (no full in-memory load)."""

    events: int = 0
    events_sha256: str = ""
    by_dataset: Counter = field(default_factory=Counter)
    min_offset: int | None = None
    max_offset: int | None = None
    non_computer_dst: Counter = field(default_factory=Counter)
    non_computer_src: Counter = field(default_factory=Counter)
    user_domains: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    excluded_by_pattern: Counter = field(default_factory=Counter)
    cited: dict[str, dict[str, Any]] = field(default_factory=dict)
    redteam_matches: dict[tuple, list[str]] = field(default_factory=lambda: defaultdict(list))


def scan_events(
    dataset_dir: str | Path,
    base_time: datetime,
    *,
    cited_ids: set[str],
    redteam_keys: set[tuple] = frozenset(),
    config: DetectionConfig | None = None,
) -> EventScan:
    scan = EventScan()
    digest = hashlib.sha256()
    patterns = [(p, re.compile(p)) for p in (config.excluded_user_patterns if config else [])]
    with (Path(dataset_dir) / EVENTS_FILE).open("rb") as handle:
        for raw in handle:
            digest.update(raw)
            e = json.loads(raw)
            scan.events += 1
            scan.by_dataset[e["dataset"]] += 1
            offset = int(
                (datetime.fromisoformat(e["timestamp"]) - base_time).total_seconds()
            )
            scan.min_offset = offset if scan.min_offset is None else min(scan.min_offset, offset)
            scan.max_offset = offset if scan.max_offset is None else max(scan.max_offset, offset)
            if not COMPUTER_PATTERN.fullmatch(e["dst_host"]):
                scan.non_computer_dst[e["dst_host"]] += 1
            if not COMPUTER_PATTERN.fullmatch(e["src_host"]):
                scan.non_computer_src[e["src_host"]] += 1
            local, _, domain = e["src_user"].partition("@")
            scan.user_domains[local].add(domain)
            for label, regex in patterns:
                if regex.fullmatch(e["src_user"]):
                    scan.excluded_by_pattern[label] += 1
                    break
            if e["event_id"] in cited_ids:
                scan.cited[e["event_id"]] = {**e, "offset": offset}
            key = (offset, e["src_user"], e["src_host"], e["dst_host"])
            if key in redteam_keys:
                scan.redteam_matches[key].append(e["event_id"])
    scan.events_sha256 = digest.hexdigest()
    return scan


# ---------------------------------------------------------------- sections

def ingestion_section(manifest: DatasetManifest, quality: dict, scan: EventScan) -> dict:
    span = (scan.max_offset - scan.min_offset) if scan.events else 0
    return {
        "provenance": manifest.dataset.value,
        "label": manifest.dataset_label,
        "source_file": manifest.source_file,
        "parser_version": manifest.parser_version,
        "skip": manifest.skip,
        "limit": manifest.limit,
        "first_line": manifest.skip + 1,
        "last_line": manifest.skip + quality["lines_read"],
        "input_sha256": manifest.input_sha256,
        "events_sha256": manifest.events_sha256,
        "events_sha256_recomputed_matches": scan.events_sha256 == manifest.events_sha256,
        "manifest_event_count_matches": scan.events == manifest.event_count,
        "all_events_have_manifest_provenance": set(scan.by_dataset) == {manifest.dataset.value},
        **{k: quality[k] for k in (
            "lines_read", "blank_lines", "accepted", "rejected", "rejection_rate",
            "rejected_by_reason", "exact_duplicates", "out_of_order", "missing_optional",
            "outcome_counts", "orientation_counts", "auth_type_top", "logon_type_top",
            "failure_rate", "unique_users", "unique_hosts", "time_start", "time_end",
        )},
        "lanl_offset_start_s": scan.min_offset,
        "lanl_offset_end_s": scan.max_offset,
        "time_coverage_s": span,
        "non_computer_dst_host_values": dict(scan.non_computer_dst.most_common(10)),
        "non_computer_dst_host_events": sum(scan.non_computer_dst.values()),
        "non_computer_src_host_events": sum(scan.non_computer_src.values()),
        "users_with_multiple_domains": sum(len(d) > 1 for d in scan.user_domains.values()),
    }


def baseline_section(detection_summary: dict, config: DetectionConfig, scan: EventScan) -> dict:
    out = {}
    span = (scan.max_offset - scan.min_offset) if scan.events else 0
    for dataset, p in detection_summary["partitions"].items():
        out[dataset] = {
            "baseline_seconds": config.baseline_seconds,
            "sample_span_seconds": span,
            "baseline_coverage_fraction": round(min(1.0, span / config.baseline_seconds), 6)
            if config.baseline_seconds else 1.0,
            "baseline_complete": span >= config.baseline_seconds,
            "input_events": p["input_events"],
            "excluded_events": p["excluded_events"],
            "excluded_fraction": round(p["excluded_events"] / p["input_events"], 4)
            if p["input_events"] else 0.0,
            "excluded_by_pattern": dict(scan.excluded_by_pattern),
            "collapsed_duplicates": p["collapsed_duplicates"],
            "baseline_events": p["baseline_events"],
            "evaluated_events": p["evaluated_events"],
            "baseline_end": p["baseline_end"],
            "users_with_baseline": p["users_with_baseline"],
            "users_without_baseline": len(p["users_without_baseline"]),
        }
    return {"computed_per_provenance": sorted(out), "partitions": out}


def _zero_reason(rule: RuleId, baseline: dict, config: DetectionConfig, novelty_fired: bool) -> str:
    parts = list(baseline["partitions"].values())
    evaluated = sum(p["evaluated_events"] for p in parts)
    if rule in NOVELTY_RULES and evaluated == 0:
        cov = parts[0]["baseline_coverage_fraction"] if parts else 0
        return (f"Not evaluable: the sample covers {cov:.2%} of the {config.baseline_seconds} s "
                "baseline, so no events fall after the baseline window.")
    if rule is RuleId.SENSITIVE_HOST_ACCESS and not config.sensitive_host_access.hosts:
        return ("Inert: no sensitive hosts are configured (LANL hosts are anonymised and carry "
                "no criticality data).")
    if rule in (RuleId.MULTI_HOST_SPREAD, RuleId.LATERAL_CHAIN) and not novelty_fired:
        return "No first-seen access occurred after the baseline, so this rule had no input."
    return ("Evaluated; no activity met the configured thresholds in this sample. Zero findings "
            "is not evidence that the rule works or fails.")


def rule_section(
    findings: list[Finding], incidents: list[Incident], baseline: dict,
    config: DetectionConfig, *, examples: int = 3,
) -> dict:
    novelty_fired = any(f.rule_id in (RuleId.NEW_DST_HOST, RuleId.NEW_SRC_HOST) for f in findings)
    out = {}
    for rule in RuleId:
        mine = [f for f in findings if f.rule_id == rule]
        info = CATALOG[rule]
        entry: dict[str, Any] = {
            "title": info.title,
            "findings": len(mine),
            "distinct_users": len({f.user for f in mine}),
            "distinct_hosts": len({h for f in mine for h in f.hosts}),
            "incidents_containing_rule": sum(rule in i.rule_ids for i in incidents),
            "benign_explanations": list(info.benign_explanations),
            "limitations": list(info.limitations),
        }
        if mine:
            ranked = sorted(mine, key=lambda f: (-len(f.event_ids), f.finding_id))[:examples]
            entry["examples"] = [
                {"finding_id": f.finding_id, "user": f.user, "description": f.description,
                 "metrics": f.metrics, "evidence_event_ids": f.event_ids[:10],
                 "evidence_count": len(f.event_ids)}
                for f in ranked
            ]
        else:
            entry["zero_findings_explanation"] = _zero_reason(rule, baseline, config, novelty_fired)
        out[rule.value] = entry
    return out


def integrity_section(
    incidents: list[Incident], findings: list[Finding], scan: EventScan,
    manifest: DatasetManifest, config: DetectionConfig,
) -> dict:
    gap = timedelta(seconds=config.correlation_gap_seconds)
    failures: list[str] = []
    valid_rules = {r.value for r in RuleId}

    def ts(eid: str) -> datetime:
        return datetime.fromisoformat(scan.cited[eid]["timestamp"])

    cited = {e for i in incidents for e in i.event_ids} | {e for f in findings for e in f.event_ids}
    missing = cited - set(scan.cited)
    if missing:
        failures.append(f"{len(missing)} cited event IDs not in verified input")
    for f in findings:
        if set(f.event_ids) & missing:
            continue
        times = [ts(e) for e in f.event_ids]
        if (min(times), max(times)) != (f.first_seen, f.last_seen):
            failures.append(f"{f.finding_id}: window does not match evidence timestamps")
    for i in incidents:
        label = i.incident_id
        if set(i.event_ids) & missing:
            continue
        if {scan.cited[e]["dataset"] for e in i.event_ids} != {d.value for d in i.datasets}:
            failures.append(f"{label}: evidence provenance differs from incident provenance")
        if {d.value for d in i.datasets} != {manifest.dataset.value}:
            failures.append(f"{label}: provenance differs from dataset manifest")
        times = [ts(e) for e in i.event_ids]
        if (min(times), max(times)) != (i.first_seen, i.last_seen):
            failures.append(f"{label}: window does not match evidence timestamps")
        if not set(i.rule_ids) <= valid_rules:
            failures.append(f"{label}: unknown rule ids")
        if not (i.benign_explanations and i.limitations and i.missing_information):
            failures.append(f"{label}: missing benign explanations/limitations/missing info")
        if {f.user for f in i.findings} != {i.principal_user}:
            failures.append(f"{label}: findings of different users grouped together")
        ordered = sorted(i.findings, key=lambda f: (f.first_seen, f.finding_id))
        latest, evidence = ordered[0].last_seen, set(ordered[0].event_ids)
        for f in ordered[1:]:
            if not (f.first_seen <= latest + gap or evidence & set(f.event_ids)):
                failures.append(f"{label}: {f.finding_id} joined without time proximity or "
                                "shared evidence")
            latest, evidence = max(latest, f.last_seen), evidence | set(f.event_ids)
        severity, rationale = incident_severity(
            [RuleId(r) for r in i.rule_ids],
            is_admin=i.principal_user in config.admin_users,
            policy=config.severity_policy,
        )
        if (severity, rationale) != (i.severity, i.severity_rationale):
            failures.append(f"{label}: severity not reproducible from its rules")
    return {
        "incidents_checked": len(incidents),
        "findings_checked": len(findings),
        "cited_event_ids": len(cited),
        "cited_event_ids_found_in_verified_input": len(cited) - len(missing),
        "checks": [
            "evidence IDs exist in verified input", "evidence provenance = incident provenance",
            "incident provenance = manifest provenance", "incident/finding windows = evidence "
            "timestamps", "rule IDs valid", "benign explanations, limitations and missing "
            "information present", "one principal per incident", "grouping explained by time "
            "gap or shared evidence", "severity recomputed from rules equals stored severity",
        ],
        "failures": failures,
        "passed": not failures,
    }


def severity_inflation_section(incidents: list[Incident]) -> dict:
    """Events cited by findings of two or more DIFFERENT rules in the same incident."""
    affected = []
    for i in incidents:
        rules_per_event: dict[str, set[str]] = defaultdict(set)
        for f in i.findings:
            for e in f.event_ids:
                rules_per_event[e].add(f.rule_id)
        shared = {e: sorted(r) for e, r in rules_per_event.items() if len(r) > 1}
        if shared:
            affected.append({
                "incident_id": i.incident_id,
                "severity": i.severity.value,
                "rules": i.rule_ids,
                "events_shared_by_multiple_rules": len(shared),
                "example": next(iter(shared.items())),
            })
    return {
        "incidents": len(incidents),
        "incidents_with_cross_rule_shared_evidence": len(affected),
        "details": affected[:20],
    }


def identity_section(incidents: list[Incident], scan: EventScan) -> dict:
    by_local: dict[str, set[str]] = defaultdict(set)
    for i in incidents:
        by_local[i.principal_user.partition("@")[0]].add(i.principal_user)
    split = {k: sorted(v) for k, v in by_local.items() if len(v) > 1}
    return {
        "dataset_users_with_multiple_domains": sum(len(d) > 1 for d in scan.user_domains.values()),
        "incident_principals_split_across_domains": split,
    }


def _uncited_reason(
    r: RedTeamEvent, in_baseline: bool, users_without_baseline: set[str],
    first_flagged: dict[tuple[str, str, str], int],
) -> str:
    if in_baseline:
        return "inside the baseline window; novelty rules do not evaluate it"
    if r.user in users_without_baseline:
        return "user had no baseline activity; novelty rules do not evaluate this user"
    notes = []
    for kind, host in (("src", r.src), ("dst", r.dst)):
        earlier = first_flagged.get((r.user, kind, host))
        if earlier is not None and earlier < r.t:
            notes.append(f"{kind} host {host} already flagged as first-seen at t={earlier}")
    if notes:
        return "; ".join(notes) + " (repeats are not re-flagged)"
    return "no rule condition met (hosts familiar from baseline, or thresholds not reached)"


def redteam_comparison(
    redteam: list[RedTeamEvent], scan: EventScan, findings: list[Finding],
    incidents: list[Incident], baseline_end_offset: int | None,
    users_without_baseline: set[str] = frozenset(),
) -> dict:
    """Exact-match comparison. A Red Team record is 'matched' only if an ingested event
    has the same LANL offset, source user, source host and destination host. Matched
    events are then checked against finding evidence. Because LANL labels are a sparse,
    incomplete list of red-team authentications (not a labelling of every event), the
    absence of a label does not make an event benign, so no precision/recall is reported."""
    if not scan.events:
        return {"labels_total": len(redteam), "labels_in_sample_time_range": 0}
    in_range = [r for r in redteam if scan.min_offset <= r.t <= scan.max_offset]
    cited_by: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        for e in f.event_ids:
            cited_by[e].add(f.rule_id)
    principals = Counter(i.principal_user for i in incidents)
    first_flagged: dict[tuple[str, str, str], int] = {}
    for f in findings:
        kind = {"NEW_SRC_HOST": "src", "NEW_DST_HOST": "dst"}.get(f.rule_id)
        if kind and f.event_ids[0] in scan.cited:
            host = f.metrics[f"{kind}_host"]
            offset = scan.cited[f.event_ids[0]]["offset"]
            key = (f.user, kind, str(host))
            first_flagged[key] = min(offset, first_flagged.get(key, offset))
    rows = []
    for r in in_range:
        ids = scan.redteam_matches.get(r.key, [])
        rules = sorted({rule for e in ids for rule in cited_by.get(e, ())})
        in_baseline = baseline_end_offset is not None and r.t < baseline_end_offset
        rows.append({
            "t": r.t, "user": r.user, "src": r.src, "dst": r.dst,
            "matched_event_ids": ids,
            "in_baseline_window": in_baseline,
            "cited_by_rules": rules,
            "not_cited_reason": None if rules or not ids else _uncited_reason(
                r, in_baseline, users_without_baseline, first_flagged),
            "user_has_incident_in_sample": principals.get(r.user, 0) > 0,
        })
    matched = [x for x in rows if x["matched_event_ids"]]
    return {
        "labels_total": len(redteam),
        "labels_in_sample_time_range": len(in_range),
        "labels_matched_to_events": len(matched),
        "labels_unmatched_in_range": len(rows) - len(matched),
        "matched_after_baseline": sum(not x["in_baseline_window"] for x in matched),
        "matched_cited_by_any_finding": sum(bool(x["cited_by_rules"]) for x in matched),
        "matched_user_has_any_incident": sum(x["user_has_incident_in_sample"] for x in matched),
        "methodology": " ".join(redteam_comparison.__doc__.split()),
        "why_no_precision_recall": (
            "Red Team labels list compromise authentications only; unlabelled events are not "
            "known to be benign, sample windows contain few labels, and most rules cannot be "
            "evaluated without a complete baseline."
        ),
        "events": rows,
    }


def output_sizes(directory: Path) -> dict[str, int]:
    return {p.name: p.stat().st_size for p in sorted(directory.iterdir()) if p.is_file()}
