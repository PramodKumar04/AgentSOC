"""Markdown rendering for the LANL validation report."""

from __future__ import annotations

from typing import Any

MB = 2**20
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def _manifest_ok(ingestion: dict[str, Any]) -> bool:
    return bool(ingestion["events_sha256_recomputed_matches"]
                and ingestion["manifest_event_count_matches"]
                and ingestion["all_events_have_manifest_provenance"])


def _mb(value: int | None) -> str:
    return f"{value / MB:,.0f} MB" if value else "n/a"


def _table(header: list[str], rows: list[list[Any]]) -> list[str]:
    return [
        "| " + " | ".join(header) + " |",
        "|" + "|".join("---" for _ in header) + "|",
        *["| " + " | ".join(str(c) for c in row) + " |" for row in rows],
        "",
    ]


def _baseline_lines(ctx: dict[str, Any], seconds: int) -> int | None:
    per_day = ctx["archive"].get("lines_per_day")
    days = seconds // 86_400
    if not per_day or days == 0 or len(per_day) < days:
        return None
    return sum(per_day[f"day_{d}"] for d in range(days))


def _recommendations(ctx: dict[str, Any]) -> list[str]:
    runs: dict[str, dict] = ctx["runs"]
    recs: list[str] = []
    first = next(iter(runs.values()))
    if any(not p["baseline_complete"] for r in runs.values()
           for p in r["baseline"]["partitions"].values()):
        needed = _baseline_lines(ctx, first["spec"]["baseline_seconds"])
        per_event = [r["performance"]["bytes_per_event_peak_ingest"] for r in runs.values()
                     if r["performance"]["bytes_per_event_peak_ingest"]]
        recs.append(
            "**Baseline needs a streaming design.** A complete default baseline spans "
            f"{f'{needed:,} lines' if needed else 'tens of millions of lines'}; the current "
            "pipeline holds every event in memory"
            f"{f' (~{max(per_event) / 1024:.1f} KB/event measured at ingest)' if per_event else ''}"
            ", which exceeds this machine. Build per-user host profiles incrementally from the "
            "stream (only sets of hosts per user are needed), then evaluate later windows "
            "against them."
        )
    if any(r["baseline"]["partitions"] and next(iter(r["baseline"]["partitions"].values()))
           ["excluded_fraction"] > 0.5 for r in runs.values()):
        recs.append(
            "**Review account exclusion.** Most LANL events come from machine/system "
            "accounts. Excluding them is a deliberate noise trade-off, but attacks using those "
            "principals are invisible; consider a separate, coarser rule set for them."
        )
    if any(r["identity"]["incident_principals_split_across_domains"] for r in runs.values()):
        recs.append(
            "**Normalise identities.** LANL records the same user under different domains "
            "(e.g. `U73@DOM1` and `U73@?`), splitting one user across incidents. Add an explicit, "
            "documented identity-normalisation step (keep the raw value as evidence)."
        )
    if first["ingestion"]["non_computer_dst_host_events"]:
        recs.append(
            "**Treat non-computer destination values explicitly.** LANL destination fields "
            "contain `TGT` and user-like values (`U22`) on Kerberos events. They are accepted as "
            "hosts today; tag or exclude them from host-based rules."
        )
    if any(r["severity_inflation"]["incidents_with_cross_rule_shared_evidence"]
           for r in runs.values()):
        recs.append(
            "**Fix severity inflation.** Several rules score the same events (e.g. "
            "FAILURE_BURST and FAIL_THEN_SUCCESS share failures; novelty rules share one logon). "
            "Phase 5 should score evidence once rather than summing correlated rules."
        )
    longest = max(
        ((x["metrics"]["span_seconds"], x["metrics"]["failure_count"],
          x["metrics"]["threshold_window_seconds"])
         for r in runs.values() for x in r["rules"]["FAILURE_BURST"].get("examples", [])),
        default=None,
    )
    if longest and longest[0] > longest[2]:
        recs.append(
            "**Long merged bursts.** Overlapping qualifying windows merge into one finding whose "
            f"span can far exceed the window (largest example: {longest[1]} failures over "
            f"{longest[0]} s). This is by design but should be stated in analyst-facing text."
        )
    recs.append(
        "**Red Team evaluation needs a complete baseline** before any coverage figure is "
        "meaningful; until then report only matched/unmatched counts, never precision/recall."
    )
    return recs


def render_validation_report(ctx: dict[str, Any]) -> str:
    runs: dict[str, dict] = ctx["runs"]
    a = ctx["archive"]
    lines = [
        "# LANL 2015 Validation Report — Phases 1 & 2",
        "",
        f"> {ctx['disclaimer']}",
        "",
        f"Generated: {ctx['generated_at']}",
        "",
        "## 1. Dataset description and provenance",
        "",
        "- Source: Los Alamos National Laboratory, *Comprehensive, Multi-Source Cyber-Security "
        "Events* (2015), authentication log `auth.txt.gz` (A. D. Kent, csr.lanl.gov/data/cyber1).",
        f"- Archive used: `{a['path_name']}`, {a['size_bytes']:,} bytes, "
        f"SHA-256 `{a['sha256']}` (read-only; never modified).",
        "- Provenance recorded on every event and manifest: `lanl`. LANL users and hosts are "
        "anonymised; time is seconds from an anonymised start (mapped to 1970-01-01 + offset).",
    ]
    if ctx.get("redteam_archive"):
        r = ctx["redteam_archive"]
        lines.append(f"- Red Team labels: `{r['path_name']}`, {r['records']} records, SHA-256 "
                     f"`{r['sha256']}` — used only for the separate comparison in §7.")
    lines += ["", "## 2. Sampling methodology", ""]
    lines += _table(
        ["Run", "Lines", "Skip", "Limit", "Baseline config", "Purpose"],
        [[n, f"{r['ingestion']['first_line']:,}–{r['ingestion']['last_line']:,}",
          f"{r['spec']['skip']:,}", f"{r['spec']['limit']:,}",
          f"{r['spec']['baseline_mode']} ({r['spec']['baseline_seconds']:,} s)",
          _purpose(n, r)] for n, r in runs.items()],
    )
    lines += [
        "Samples are contiguous windows read by streaming (the archive is never fully loaded). "
        "`half_window` runs are **sensitivity runs**: baseline = half of the window's observed "
        "span, a rule fixed before results were seen. They are not the project default.",
        "",
        "## 3. Ingestion results and data quality",
        "",
    ]
    lines += _table(
        ["Run", "Lines read", "Accepted", "Rejected", "Blank", "Duplicates", "Out of order",
         "Users", "Hosts", "LANL time (s)", "Coverage"],
        [[n, f"{i['lines_read']:,}", f"{i['accepted']:,}", i["rejected"], i["blank_lines"],
          i["exact_duplicates"], i["out_of_order"], f"{i['unique_users']:,}",
          f"{i['unique_hosts']:,}", f"{i['lanl_offset_start_s']:,}–{i['lanl_offset_end_s']:,}",
          f"{i['time_coverage_s']:,} s ({i['time_coverage_s'] / 3600:.2f} h)"]
         for n, r in runs.items() for i in [r["ingestion"]]],
    )
    i0 = next(iter(runs.values()))["ingestion"]
    lines += [
        "- Integrity: every manifest re-verified (events hash recomputed, count, provenance): "
        + ", ".join(f"{n}: {'OK' if _manifest_ok(x['ingestion']) else 'FAILED'}"
                    for n, x in runs.items()) + ".",
        f"- Missing optional values ({next(iter(runs))}): {i0['missing_optional']} — LANL `?` "
        "markers, kept as missing (not repaired).",
        f"- Orientation: {i0['orientation_counts']}; outcome: {i0['outcome_counts']} "
        f"(failure rate {i0['failure_rate']:.2%}).",
        f"- Authentication types (top): {i0['auth_type_top']} — note truncated LANL values such "
        "as `MICROSOFT_AUTHENTICATION_PAC`, accepted as-is.",
        f"- Non-computer destination values: {i0['non_computer_dst_host_events']:,} events "
        f"({i0['non_computer_dst_host_values']}).",
        f"- Users appearing under more than one domain: {i0['users_with_multiple_domains']:,}.",
        "",
        "## 4. Baseline coverage",
        "",
    ]
    lines += _table(
        ["Run", "Baseline (s)", "Sample span (s)", "Coverage", "Excluded events",
         "Analysed baseline events", "Evaluated events", "Users w/ baseline",
         "Users w/o baseline"],
        [[n, f"{p['baseline_seconds']:,}", f"{p['sample_span_seconds']:,}",
          f"{p['baseline_coverage_fraction']:.2%}",
          f"{p['excluded_events']:,} ({p['excluded_fraction']:.1%})", f"{p['baseline_events']:,}",
          f"{p['evaluated_events']:,}", p["users_with_baseline"], p["users_without_baseline"]]
         for n, r in runs.items() for p in r["baseline"]["partitions"].values()],
    )
    lines += [
        "Baselines are computed independently per provenance partition (only `lanl` present).",
        _baseline_sizing(ctx),
        "",
        "## 5. Detection results by rule",
        "",
    ]
    rule_names = list(next(iter(runs.values()))["rules"])
    lines += _table(
        ["Rule", *[f"{n}: findings / users / hosts / incidents" for n in runs]],
        [[f"`{rule}`", *[f"{x['findings']} / {x['distinct_users']} / {x['distinct_hosts']} / "
                         f"{x['incidents_containing_rule']}" for r in runs.values()
                         for x in [r["rules"][rule]]]] for rule in rule_names],
    )
    for n, r in runs.items():
        lines += [f"### {n}", ""]
        for rule, x in r["rules"].items():
            if x["findings"]:
                ex = x["examples"][0]
                lines.append(f"- `{rule}` — e.g. `{ex['finding_id']}`: {ex['description']} "
                             f"(evidence: {ex['evidence_count']} events, first "
                             f"`{ex['evidence_event_ids'][0]}`)")
            else:
                lines.append(f"- `{rule}` — 0 findings. {x['zero_findings_explanation']}")
        lines.append("")
    lines += ["Benign explanations and limitations per rule are listed in `rule_analysis.json` "
              "and ARCHITECTURE.md §9.", "", "## 6. Incident analysis", ""]
    lines += _table(
        ["Run", "Incidents", "LOW", "MEDIUM", "HIGH", "CRITICAL",
         "Incidents with cross-rule shared evidence", "Principals split across domains"],
        [[n, r["detection"]["incidents_total"],
          *[r["detection"]["incidents_by_severity"][s] for s in SEVERITIES],
          r["severity_inflation"]["incidents_with_cross_rule_shared_evidence"],
          len(r["identity"]["incident_principals_split_across_domains"])]
         for n, r in runs.items()],
    )
    for n, r in runs.items():
        if not r["incident_examples"]:
            continue
        lines += [f"**{n} — examples (largest rule sets first)**", ""]
        for ex in r["incident_examples"][:3]:
            lines += [
                f"- `{ex['incident_id']}` {ex['principal']} — **{ex['severity']}** — "
                f"{', '.join(ex['rules'])}; {ex['evidence_events']} evidence events, "
                f"{ex['first_seen']} → {ex['last_seen']}.",
                f"  - Reason: {ex['reasons'][0]}",
                f"  - Severity: {ex['severity_rationale']}",
                f"  - Possible benign explanation: {ex['benign_explanations'][0]}",
            ]
        split = r["identity"]["incident_principals_split_across_domains"]
        if split:
            lines.append(f"- Same user split across incidents by domain: "
                         f"{dict(list(split.items())[:5])}")
        lines.append("")
    lines += [
        "No incident is a confirmed compromise. LANL authentication logs contain no malware, "
        "PowerShell, credential-dumping, geolocation or endpoint telemetry, and none is claimed.",
        "",
        "## 7. Red Team comparison (separate from detection)",
        "",
    ]
    rt_rows = [[n, x["labels_in_sample_time_range"], x.get("labels_matched_to_events", 0),
                x.get("labels_unmatched_in_range", 0), x.get("matched_after_baseline", 0),
                x.get("matched_cited_by_any_finding", 0), x.get("matched_user_has_any_incident", 0)]
               for n, r in runs.items() if (x := r["redteam"])]
    if rt_rows:
        lines += _table(["Run", "Labels in time range", "Matched to events", "Unmatched",
                         "Matched after baseline", "Cited by a finding", "User has an incident"],
                        rt_rows)
        any_rt = next(r["redteam"] for r in runs.values() if r["redteam"])
        lines += [f"- Method: {any_rt['methodology']}",
                  f"- No precision/recall/F1: {any_rt['why_no_precision_recall']}",
                  "- Labels were read only after detection finished; rules and thresholds were "
                  "not changed in response to them.", ""]
        for n, r in runs.items():
            for ev in (r["redteam"] or {}).get("events", []):
                lines.append(
                    f"- {n}: t={ev['t']} {ev['user']} {ev['src']}→{ev['dst']} — matched "
                    f"{len(ev['matched_event_ids'])} event(s); in baseline: "
                    f"{ev['in_baseline_window']}; cited by: {ev['cited_by_rules'] or 'none'}"
                    + (f" — not cited because: {ev['not_cited_reason']}"
                       if ev.get("not_cited_reason") else "")
                    + f"; user has incident: {ev['user_has_incident_in_sample']}")
        lines.append("")
    else:
        lines += ["Red Team file not provided.", ""]
    lines += ["## 8. Evidence integrity verification", ""]
    lines += _table(
        ["Run", "Incidents", "Findings", "Cited IDs", "Found in verified input", "Result"],
        [[n, x["incidents_checked"], x["findings_checked"], x["cited_event_ids"],
          x["cited_event_ids_found_in_verified_input"],
          "PASSED" if x["passed"] else f"FAILED: {x['failures'][:3]}"]
         for n, r in runs.items() for x in [r["integrity"]]],
    )
    lines += ["Checks: " + "; ".join(next(iter(runs.values()))["integrity"]["checks"]) + ".", "",
              "## 9. Performance", ""]
    m = ctx["machine"]
    lines.append(f"Machine: {m.get('platform')}, Python {m.get('python')}, "
                 f"{m.get('logical_cpus')} logical CPUs, RAM {_mb(m.get('ram_total_bytes'))} "
                 f"(available at start {_mb(m.get('ram_available_bytes_at_start'))}).")
    lines.append("")
    lines += _table(
        ["Run", "Ingest time", "Ingest peak", "Lines/s", "Detect time", "Detect peak",
         "Events/s", "events.jsonl", "incidents.jsonl"],
        [[n, f"{p['ingest']['wall_seconds']:.1f} s", _mb(p["ingest"]["peak_memory_bytes"]),
          f"{p['ingest']['lines_per_second']:,.0f}", f"{p['detect']['wall_seconds']:.1f} s",
          _mb(p["detect"]["peak_memory_bytes"]), f"{p['detect']['events_per_second']:,.0f}",
          _mb(p["dataset_file_bytes"].get("events.jsonl")),
          f"{p['detection_file_bytes'].get('incidents.jsonl', 0):,} B"]
         for n, r in runs.items() for p in [r["performance"]]],
    )
    lines += [
        "Ingest time includes decompressing and skipping lines before the window. Each stage ran "
        "in its own process; peak = peak working set of that process. Detection time includes "
        "verified loading (hash check, re-validation of every event) and writing outputs.",
        "",
        "## 10. Limitations and known gaps",
        "",
        "- The default 2-day baseline is not covered by any sample that fits in memory here, so "
        "novelty rules (`NEW_*`, `MULTI_HOST_SPREAD`, `LATERAL_CHAIN`) were only exercised in the "
        "short-baseline sensitivity run, whose baseline (minutes) is far too short to represent "
        "normal behaviour; its novelty findings are expected to be dominated by benign activity.",
        "- `SENSITIVE_HOST_ACCESS` is inert on LANL: no host criticality data exists.",
        "- Samples are contiguous windows from specific times; they are not random and do not "
        "represent the full 58-day dataset.",
        "- Red Team labels are sparse; matched counts are not detection accuracy.",
        "- Machine/system accounts are excluded by default (most LANL events).",
        "",
        "## 11. Recommendations",
        "",
        *[f"{k}. {rec}" for k, rec in enumerate(_recommendations(ctx), start=1)],
        "",
    ]
    return "\n".join(lines)


def _baseline_sizing(ctx: dict[str, Any]) -> str:
    per_day = ctx["archive"].get("lines_per_day")
    if not per_day:
        return "Archive line counts per day were not scanned for this report."
    seconds = next(iter(ctx["runs"].values()))["spec"]["baseline_seconds"]
    needed = _baseline_lines(ctx, seconds)
    days = ", ".join(f"{k.replace('_', ' ')}: {v:,}" for k, v in per_day.items())
    return (f"Archive lines per LANL day (streamed count of the time column): {days}. "
            f"A complete {seconds:,} s baseline therefore needs "
            f"{f'{needed:,}' if needed else 'more than the scanned'} lines.")


def _purpose(name: str, run: dict) -> str:
    if run["spec"]["baseline_mode"] == "half_window":
        return "sensitivity: exercise novelty rules on real data"
    if run["redteam"] and run["redteam"].get("labels_in_sample_time_range"):
        return "window containing Red Team labels, default config"
    return "default config" if run["spec"]["limit"] <= 100_000 else "scale test, default config"
