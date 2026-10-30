"""Data-quality report for one ingestion run (JSON model + Markdown rendering)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from pydantic import AwareDatetime, Field

from agentsoc.perception.records import IngestionResult
from agentsoc.schemas import AuthOutcome, DatasetSource
from agentsoc.schemas.common import Contract

TOP_N = 10


class DataQualityReport(Contract):
    source_file: str
    dataset: DatasetSource
    parser_version: str
    input_sha256: str
    base_time: AwareDatetime
    skip: int
    limit: int | None
    lines_read: int
    blank_lines: int
    accepted: int
    rejected: int
    rejection_rate: float = Field(ge=0, le=1)  # rejected / non-blank lines
    rejected_by_reason: dict[str, int]
    rejected_by_field: dict[str, int]
    exact_duplicates: int
    out_of_order: int
    missing_optional: dict[str, int]
    outcome_counts: dict[str, int]
    orientation_counts: dict[str, int]
    auth_type_top: dict[str, int]
    logon_type_top: dict[str, int]
    failure_rate: float = Field(ge=0, le=1)
    unique_users: int
    unique_hosts: int
    time_start: AwareDatetime | None
    time_end: AwareDatetime | None


def _sorted_counts(counter: Counter, top: int | None = None) -> dict[str, int]:
    # Sort by count desc, then key, so reports are byte-for-byte reproducible.
    items = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    return dict(items[:top] if top else items)


def build_quality_report(result: IngestionResult) -> DataQualityReport:
    events = result.events
    non_blank = result.lines_read - result.blank_lines
    fails = sum(e.outcome is AuthOutcome.FAILURE for e in events)
    users = {e.src_user for e in events} | {e.dst_user for e in events if e.dst_user}
    hosts = {e.src_host for e in events} | {e.dst_host for e in events}

    return DataQualityReport(
        source_file=result.source_file,
        dataset=result.dataset,
        parser_version=result.parser_version,
        input_sha256=result.input_sha256,
        base_time=result.base_time,
        skip=result.skip,
        limit=result.limit,
        lines_read=result.lines_read,
        blank_lines=result.blank_lines,
        accepted=len(events),
        rejected=len(result.rejected),
        rejection_rate=len(result.rejected) / non_blank if non_blank else 0.0,
        rejected_by_reason=_sorted_counts(Counter(r.reason.value for r in result.rejected)),
        rejected_by_field=_sorted_counts(
            Counter(r.field for r in result.rejected if r.field is not None)
        ),
        exact_duplicates=result.exact_duplicates,
        out_of_order=result.out_of_order,
        missing_optional={
            name: sum(getattr(e, name) is None for e in events)
            for name in ("dst_user", "auth_type", "logon_type")
        },
        outcome_counts=_sorted_counts(Counter(e.outcome.value for e in events)),
        orientation_counts=_sorted_counts(Counter(e.orientation.value for e in events)),
        auth_type_top=_sorted_counts(Counter(e.auth_type or "(missing)" for e in events), TOP_N),
        logon_type_top=_sorted_counts(Counter(e.logon_type or "(missing)" for e in events), TOP_N),
        failure_rate=fails / len(events) if events else 0.0,
        unique_users=len(users),
        unique_hosts=len(hosts),
        time_start=events[0].timestamp if events else None,
        time_end=events[-1].timestamp if events else None,
    )


def _table(title: str, counts: dict[str, int]) -> list[str]:
    if not counts:
        return [f"**{title}:** none", ""]
    rows = [f"**{title}**", "", "| Value | Count |", "|---|---:|"]
    rows += [f"| `{k}` | {v} |" for k, v in counts.items()]
    return [*rows, ""]


def _fmt_time(value: datetime | None) -> str:
    return value.isoformat() if value else "n/a"


def render_markdown(report: DataQualityReport, *, dataset_label: str) -> str:
    """Human-readable report. `dataset_label` must state the true provenance
    (e.g. 'SYNTHETIC sample in LANL format' or 'LANL auth.txt, lines 1-5000')."""
    r = report
    lines = [
        f"# Data Quality Report — {r.source_file}",
        "",
        f"**Dataset:** {dataset_label} (source: `{r.dataset.value}`)  ",
        f"**Parser:** `{r.parser_version}`  ",
        f"**Input SHA-256 (consumed lines):** `{r.input_sha256}`  ",
        f"**Window:** skip={r.skip}, limit={r.limit}  ",
        f"**Time base:** offset 0 = {r.base_time.isoformat()} (LANL times are relative)",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Lines read | {r.lines_read} |",
        f"| Blank lines skipped | {r.blank_lines} |",
        f"| Accepted events | {r.accepted} |",
        f"| Rejected records | {r.rejected} |",
        f"| Rejection rate (of non-blank) | {r.rejection_rate:.2%} |",
        f"| Exact duplicates (kept) | {r.exact_duplicates} |",
        f"| Out-of-order events (output re-sorted) | {r.out_of_order} |",
        f"| Authentication failure rate | {r.failure_rate:.2%} |",
        f"| Unique users | {r.unique_users} |",
        f"| Unique hosts | {r.unique_hosts} |",
        f"| First event | {_fmt_time(r.time_start)} |",
        f"| Last event | {_fmt_time(r.time_end)} |",
        "",
        "## Rejections",
        "",
        *_table("By reason", r.rejected_by_reason),
        *_table("By field", r.rejected_by_field),
        "## Field completeness (accepted events)",
        "",
        *_table("Missing optional values (`?` or empty)", r.missing_optional),
        "## Distributions",
        "",
        *_table("Outcome", r.outcome_counts),
        *_table("Orientation", r.orientation_counts),
        *_table(f"Authentication type (top {TOP_N})", r.auth_type_top),
        *_table(f"Logon type (top {TOP_N})", r.logon_type_top),
        "## Notes",
        "",
        "- Malformed records are rejected, never repaired; see `rejected.jsonl` for reasons.",
        "- Exact duplicates are kept: LANL can log identical authentications within one second.",
        "- Rejected raw excerpts are untrusted text and are never passed to detection or the LLM.",
        "",
    ]
    return "\n".join(lines)
