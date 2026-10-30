"""Detection summary (JSON) and human-readable report (Markdown)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from pydantic import AwareDatetime

from agentsoc.detection.catalog import CATALOG, RuleId
from agentsoc.detection.config import DetectionConfig
from agentsoc.detection.correlate import SEVERITY_ORDER
from agentsoc.detection.engine import ENGINE_VERSION, DetectionResult, PartitionStats
from agentsoc.detection.inputs import VerifiedInput
from agentsoc.schemas import AuthEvent, DatasetSource, Incident
from agentsoc.schemas.common import Contract

MAX_EVIDENCE_ROWS = 25


class InputDatasetRef(Contract):
    directory: str
    dataset: DatasetSource
    dataset_label: str
    source_file: str
    parser_version: str
    input_sha256: str
    events_sha256: str
    event_count: int


class DetectionSummary(Contract):
    engine_version: str
    config_sha256: str
    config: DetectionConfig
    inputs: list[InputDatasetRef]
    partitions: dict[DatasetSource, PartitionStats]
    findings_total: int
    findings_by_rule: dict[str, int]
    incidents_total: int
    incidents_by_severity: dict[str, int]
    detections_sha256: str
    incidents_sha256: str
    generated_at: AwareDatetime


def build_summary(
    result: DetectionResult,
    inputs: list[VerifiedInput],
    config: DetectionConfig,
    *,
    detections_sha256: str,
    incidents_sha256: str,
    generated_at: datetime,
) -> DetectionSummary:
    by_rule = Counter(f.rule_id for f in result.findings)
    by_severity = Counter(i.severity.value for i in result.incidents)
    return DetectionSummary(
        engine_version=ENGINE_VERSION,
        config_sha256=config.sha256(),
        config=config,
        inputs=[
            InputDatasetRef(
                directory=i.directory.name,
                dataset=i.manifest.dataset,
                dataset_label=i.manifest.dataset_label,
                source_file=i.manifest.source_file,
                parser_version=i.manifest.parser_version,
                input_sha256=i.manifest.input_sha256,
                events_sha256=i.manifest.events_sha256,
                event_count=i.manifest.event_count,
            )
            for i in inputs
        ],
        partitions=result.partitions,
        findings_total=len(result.findings),
        findings_by_rule={r.value: by_rule.get(r.value, 0) for r in RuleId},
        incidents_total=len(result.incidents),
        incidents_by_severity={s.value: by_severity.get(s.value, 0) for s in SEVERITY_ORDER},
        detections_sha256=detections_sha256,
        incidents_sha256=incidents_sha256,
        generated_at=generated_at,
    )


def _incident_section(incident: Incident, events_by_id: dict[str, AuthEvent]) -> list[str]:
    lines = [
        f"### {incident.incident_id} — {incident.principal_user} — {incident.severity}",
        "",
        f"- **Window:** {incident.first_seen.isoformat()} → {incident.last_seen.isoformat()}",
        f"- **Provenance:** {', '.join(d.value for d in incident.datasets)}",
        f"- **Rules:** {', '.join(f'`{r}`' for r in incident.rule_ids)}",
        f"- **Users:** {', '.join(incident.involved_users)}",
        f"- **Hosts:** {', '.join(incident.involved_hosts)}",
        f"- **Severity rationale:** {incident.severity_rationale}",
        "",
        "**Detection reasons (inferences)**",
        "",
        *[f"- `{f.finding_id}` `{f.rule_id}` ({f.severity}): {f.description}"
          for f in incident.findings],
        "",
        f"**Evidence events (raw observations, {len(incident.event_ids)} total)**",
        "",
        "| Event ID | Time | User | Source → Destination | Orientation | Outcome |",
        "|---|---|---|---|---|---|",
    ]
    for eid in incident.event_ids[:MAX_EVIDENCE_ROWS]:
        e = events_by_id[eid]
        lines.append(
            f"| `{e.event_id}` | {e.timestamp.isoformat()} | {e.src_user} | "
            f"{e.src_host} → {e.dst_host} | {e.orientation.value} | {e.outcome.value} |"
        )
    if len(incident.event_ids) > MAX_EVIDENCE_ROWS:
        hidden = len(incident.event_ids) - MAX_EVIDENCE_ROWS
        lines.append(f"| … | {hidden} more in incidents.jsonl | | | | |")
    for title, items in (
        ("Possible benign explanations", incident.benign_explanations),
        ("Limitations", incident.limitations),
        ("Missing information", incident.missing_information),
    ):
        lines += ["", f"**{title}**", "", *[f"- {item}" for item in items]]
    return [*lines, ""]


def render_report(
    summary: DetectionSummary, result: DetectionResult, events_by_id: dict[str, AuthEvent]
) -> str:
    """Deterministic: contains no wall-clock time (see detection_summary.json)."""
    s = summary
    lines = [
        "# Detection Report",
        "",
        "> Detections are heuristic indicators of suspicious authentication behaviour, **not**",
        "> confirmation of compromise. Thresholds are configurable heuristics. Results on",
        "> synthetic data do not measure real-world detection accuracy.",
        "",
        f"**Engine:** `{s.engine_version}`  ",
        f"**Config SHA-256:** `{s.config_sha256}`  ",
        f"**detections.jsonl SHA-256:** `{s.detections_sha256}`  ",
        f"**incidents.jsonl SHA-256:** `{s.incidents_sha256}`",
        "",
        "## Inputs (verified against manifests)",
        "",
        "| Directory | Provenance | Label | Events | events.jsonl SHA-256 |",
        "|---|---|---|---:|---|",
        *[f"| {i.directory} | `{i.dataset.value}` | {i.dataset_label} | {i.event_count} | "
          f"`{i.events_sha256[:16]}…` |" for i in s.inputs],
        "",
        "## Pre-processing and baseline",
        "",
        "| Provenance | Input | Excluded accounts | Duplicates collapsed | Baseline events | "
        "Evaluated events | Baseline ends | Users with baseline | Users without baseline |",
        "|---|---:|---:|---:|---:|---:|---|---:|---:|",
    ]
    for dataset, p in s.partitions.items():
        end = p.baseline_end.isoformat() if p.baseline_end else "n/a"
        lines.append(
            f"| `{dataset.value}` | {p.input_events} | {p.excluded_events} | "
            f"{p.collapsed_duplicates} | {p.baseline_events} | {p.evaluated_events} | {end} | "
            f"{p.users_with_baseline} | {len(p.users_without_baseline)} |"
        )
    lines += [
        "",
        "Novelty rules (`NEW_*`, `MULTI_HOST_SPREAD`, `LATERAL_CHAIN`, `SENSITIVE_HOST_ACCESS`) "
        "only evaluate events after the baseline, for users with baseline activity.",
        "",
        "## Findings by rule",
        "",
        "| Rule | Description | Findings |",
        "|---|---|---:|",
        *[f"| `{rule}` | {CATALOG[RuleId(rule)].title} | {count} |"
          for rule, count in s.findings_by_rule.items()],
        "",
        "## Incidents",
        "",
    ]
    if not result.incidents:
        lines += ["No incidents were produced.", ""]
        return "\n".join(lines)
    lines += [
        "| Incident | Principal | Severity | Rules | First seen | Last seen | Evidence |",
        "|---|---|---|---|---|---|---:|",
        *[f"| {i.incident_id} | {i.principal_user} | {i.severity} | {', '.join(i.rule_ids)} | "
          f"{i.first_seen.isoformat()} | {i.last_seen.isoformat()} | {len(i.event_ids)} |"
          for i in result.incidents],
        "",
    ]
    for incident in result.incidents:
        lines += _incident_section(incident, events_by_id)
    return "\n".join(lines)
