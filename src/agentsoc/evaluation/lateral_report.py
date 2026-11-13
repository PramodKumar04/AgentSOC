"""Target 1 result reports, generated from actual runs so nothing is hand-copied.

`synthetic`  committed SYNTHETIC scenarios: input, expected and actual, plus scale runs.
`lanl`       sensitivity runs on stored real LANL windows, written to a NEW directory so
             the Phase 2 validation outputs are never touched. Red Team labels are read
             only after detection has finished, and only for a separate comparison.

The two reports are separate files and never share figures.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from agentsoc.cli import detect_main, ingest_main
from agentsoc.config import PROJECT_ROOT
from agentsoc.data_gen.lateral_scenarios import SCENARIOS, Scenario, generate_large_batch_text
from agentsoc.detection.config import DetectionConfig, load_detection_config
from agentsoc.detection.engine import ENGINE_VERSION
from agentsoc.evaluation import lanl_validation as lv
from agentsoc.evaluation.validate import _machine, _run_stage
from agentsoc.schemas import Finding, Incident
from agentsoc.store.datasets import load_manifest
from agentsoc.store.detections import load_detection_summary, load_findings, load_incidents

SAMPLES = PROJECT_ROOT / "data" / "samples"
SCENARIO_INPUT = SAMPLES / "auth_lateral_scenarios_synthetic.txt"
SCENARIO_CONFIG = SAMPLES / "lateral_scenarios_detection_config.json"
DOCS = PROJECT_ROOT / "docs"
LANL_ROOT = PROJECT_ROOT / "data" / "processed" / "lanl_validation"
LANL_DATASET = LANL_ROOT / "datasets" / "lines_29400001_29800000"
PIVOT, CHAIN = "CROSS_ACCOUNT_PIVOT", "LATERAL_CHAIN"
SCALE_ACCOUNTS = (1000, 5000, 10000)


def _accounts(scenario: Scenario) -> set[str]:
    return ({a.user for a in scenario.accounts} | set(scenario.expected.findings)
            | set(scenario.expected.without_baseline))


def _actual(scenario: Scenario, findings: list[Finding], incidents: list[Incident]) -> dict:
    names = _accounts(scenario)
    mine = [f for f in findings if f.user in names]
    counts: dict[str, Counter] = {}
    for finding in mine:
        counts.setdefault(finding.user, Counter())[finding.rule_id] += 1
    return {
        "findings": {u: dict(c) for u, c in counts.items()},
        "severity": {i.principal_user: i.severity.value for i in incidents
                     if i.principal_user in names},
        "chain_paths": sorted(f.metrics["path"] for f in mine if f.rule_id == CHAIN),
        "pivots": sorted((f.user, f.metrics["arriving_account"], f.metrics["pivot_host"])
                         for f in mine if f.rule_id == PIVOT),
        "benign_context": sorted({f.user for f in mine if "benign_context" in f.metrics}),
        "severity_adjusted": sorted({f.user for f in mine if "severity_adjustment" in f.metrics}),
    }


def _expected(scenario: Scenario) -> dict:
    e = scenario.expected
    return {
        "findings": {u: dict(c) for u, c in e.findings.items()},
        "severity": dict(e.severity),
        "chain_paths": sorted(e.chain_paths),
        "pivots": sorted(e.pivots),
        "benign_context": sorted(e.benign_context),
        "severity_adjusted": sorted(e.severity_adjusted),
    }


def _fmt_counts(counts: dict[str, dict[str, int]]) -> str:
    if not counts:
        return "none"
    return "; ".join(
        f"`{user}`: " + ", ".join(f"{rule}×{n}" for rule, n in sorted(rules.items()))
        for user, rules in sorted(counts.items())
    )


def _scenario_section(
    scenario: Scenario, findings: list[Finding], incidents: list[Incident]
) -> tuple[list[str], bool]:
    expected, actual = _expected(scenario), _actual(scenario, findings, incidents)
    passed = expected == actual
    names = _accounts(scenario)
    case = f"case {scenario.case}" if scenario.case != "extra" else "additional case"
    lines = [
        f"### {scenario.key} — {scenario.title}",
        "",
        f"Brief {case}. **Result: {'as expected' if passed else 'DIFFERS FROM EXPECTED'}.**",
        "",
        "Input events (LANL format: time, source user, destination user, source host, "
        "destination host, auth type, logon type, orientation, outcome):",
        "",
        "```",
        *[line for _, line in sorted(scenario.rows, key=lambda r: r[0])],
        "```",
        "",
    ]
    baseline = ", ".join(f"`{a.user}` on {a.workstation}" for a in scenario.accounts)
    lines += [f"Baseline (days 0–1): {baseline or 'none, deliberately'}.", "",
              "| | Expected | Actual |", "|---|---|---|"]
    lines.append(f"| Findings | {_fmt_counts(expected['findings'])} | "
                 f"{_fmt_counts(actual['findings'])} |")
    for label, key in (("Severity", "severity"), ("Chain paths", "chain_paths"),
                       ("Pivots (departing, arriving, host)", "pivots"),
                       ("Benign context", "benign_context"),
                       ("Severity adjusted", "severity_adjusted")):
        lines.append(f"| {label} | {expected[key] or 'none'} | {actual[key] or 'none'} |")
    lines.append("")
    for incident in incidents:
        if incident.principal_user in names:
            lines.append(f"- `{incident.principal_user}` — **{incident.severity.value}**: "
                         f"{incident.severity_rationale}")
    for finding in findings:
        if finding.user in names and "benign_context" in finding.metrics:
            lines.append(f"- `{finding.finding_id}` context: {finding.metrics['benign_context']}")
    lines.append("")
    return lines, passed


def _scale_rows(work: Path) -> list[str]:
    off = work / "pivot_off.json"
    off.write_text(json.dumps({"cross_account_pivot": {"enabled": False}}), encoding="utf-8")
    rows = ["| Accounts | Events | Detect (rule on) | Peak memory | Detect (rule off) | Chains "
            "found / planted | Pivots found / planted |", "|---|---:|---:|---:|---:|---:|---:|"]
    for accounts in SCALE_ACCOUNTS:
        text, chains, pivots = generate_large_batch_text(accounts)
        source = work / f"bulk_{accounts}.txt"
        source.write_text(text, encoding="utf-8", newline="\n")
        dataset = work / f"dataset_{accounts}"
        _run_stage("ingest", [str(source), "--out", str(dataset), "--source", "synthetic",
                              "--label", "SYNTHETIC large batch", "--overwrite"])
        on_dir, off_dir = work / f"on_{accounts}", work / f"off_{accounts}"
        on = _run_stage("detect", [str(dataset), "--out", str(on_dir), "--overwrite"])
        without = _run_stage("detect", [str(dataset), "--out", str(off_dir), "--config", str(off),
                                        "--overwrite"])
        by_rule = load_detection_summary(on_dir).findings_by_rule
        events = load_manifest(dataset).event_count
        rows.append(
            f"| {accounts:,} | {events:,} | {on['wall_seconds']:.2f} s | "
            f"{on['peak_memory_bytes'] / 2**20:,.0f} MB | {without['wall_seconds']:.2f} s | "
            f"{by_rule[CHAIN]} / {chains} | {by_rule[PIVOT]} / {pivots} |"
        )
    return rows


def write_synthetic_report(work: Path, out: Path) -> bool:
    dataset, detection = work / "dataset", work / "detection"
    if ingest_main([str(SCENARIO_INPUT), "--out", str(dataset), "--source", "synthetic",
                    "--label", "SYNTHETIC lateral scenarios", "--overwrite"]):
        raise RuntimeError("ingest failed")
    if detect_main([str(dataset), "--config", str(SCENARIO_CONFIG), "--out", str(detection),
                    "--overwrite"]):
        raise RuntimeError("detection failed")
    findings, incidents = load_findings(detection), load_incidents(detection)
    sections: list[str] = []
    verdicts: list[tuple[Scenario, bool]] = []
    for scenario in SCENARIOS:
        lines, passed = _scenario_section(scenario, findings, incidents)
        sections += lines
        verdicts.append((scenario, passed))
    machine = _machine()
    partition = load_detection_summary(detection).partitions["synthetic"]
    doc = [
        "# Target 1 — synthetic scenario results",
        "",
        "> **All data here is SYNTHETIC.** These results show that the rules behave as designed "
        "on constructed inputs. They do not measure real-world detection accuracy. LANL results "
        "are in a separate file, [target1_lanl_sensitivity.md](target1_lanl_sensitivity.md).",
        "",
        f"Generated by `python scripts/evaluate_lateral.py synthetic`. Engine `{ENGINE_VERSION}`. "
        "Expected values are hand-written in `src/agentsoc/data_gen/lateral_scenarios.py`.",
        "",
        "Graph paths and 0–100 risk scores belong to Targets 2 and 3 and are not implemented. "
        "This report shows detected chain and pivot paths and the current triage severity.",
        "",
        "## Summary",
        "",
        "| Scenario | Brief case | Title | Result |",
        "|---|---|---|---|",
        *[f"| {s.key} | {s.case} | {s.title} | {'as expected' if ok else '**DIFFERS**'} |"
          for s, ok in verdicts],
        "",
        f"Duplicates collapsed: {partition.collapsed_duplicates} (expected 2, scenario S09). "
        f"Accounts without a baseline: {', '.join(partition.users_without_baseline) or 'none'}.",
        "",
        "## Brief case 10 — large batches and performance",
        "",
        "One shared server for all accounts, the worst case for cross-account lookups. Each "
        "figure is one run of the full detect stage in its own process, including verified "
        "loading and writing outputs; single runs on a busy desktop, so small differences "
        "between rows are noise.",
        "",
        *_scale_rows(work),
        "",
        f"Machine: {machine['platform']}, Python {machine['python']}, "
        f"{machine['logical_cpus']} logical CPUs, "
        f"RAM {machine.get('ram_total_bytes', 0) / 2**20:,.0f} MB.",
        "",
        "## Scenario detail",
        "",
        *sections,
    ]
    out.write_text("\n".join(doc), encoding="utf-8", newline="\n")
    return all(ok for _, ok in verdicts)


def _lanl_run(name: str, config_path: Path | None, stored: Path, out_root: Path) -> dict[str, Any]:
    detection = out_root / name / "detection"
    args = [str(LANL_DATASET), "--out", str(detection), "--overwrite"]
    if config_path:
        args += ["--config", str(config_path)]
    metrics = _run_stage("detect", args)
    config = load_detection_config(config_path) if config_path else DetectionConfig()
    return {
        "name": name, "config": config, "metrics": metrics, "detection": detection,
        "findings": load_findings(detection), "incidents": load_incidents(detection),
        "stored_findings": load_findings(stored), "stored_incidents": load_incidents(stored),
    }


def _key(finding: Finding) -> tuple:
    return (finding.rule_id, finding.user, tuple(finding.event_ids))


def _lanl_section(run: dict[str, Any], manifest: Any) -> tuple[list[str], Any]:
    findings: list[Finding] = run["findings"]
    incidents: list[Incident] = run["incidents"]
    stored = {_key(f) for f in run["stored_findings"]}
    kept = {_key(f) for f in findings if f.rule_id != PIVOT}
    severity = Counter(i.severity.value for i in incidents)
    before = Counter(i.severity.value for i in run["stored_incidents"])
    scan = lv.scan_events(LANL_DATASET, manifest.base_time,
                          cited_ids={e for f in findings for e in f.event_ids},
                          config=run["config"])
    integrity = lv.integrity_section(incidents, findings, scan, manifest, run["config"])
    pivots = [f for f in findings if f.rule_id == PIVOT]
    chains = [f for f in findings if f.rule_id == CHAIN]
    lines = [
        f"### `{run['name']}`",
        "",
        f"Baseline: {run['config'].baseline_seconds:,} s. "
        f"Detect stage: {run['metrics']['wall_seconds']:.1f} s, peak "
        f"{run['metrics']['peak_memory_bytes'] / 2**20:,.0f} MB.",
        "",
        f"- Findings: {len(findings):,} ({len(pivots)} `{PIVOT}`, {len(chains)} `{CHAIN}`).",
        f"- Original seven rules reproduce the stored Phase 2 findings: **{kept == stored}**.",
        f"- Incident severity, stored → now: {dict(sorted(before.items()))} → "
        f"{dict(sorted(severity.items()))}.",
        f"- Evidence integrity: **{'PASSED' if integrity['passed'] else 'FAILED'}** "
        f"({integrity['cited_event_ids_found_in_verified_input']:,} of "
        f"{integrity['cited_event_ids']:,} cited events found).",
        "",
    ]
    if chains:
        lines += ["| Account | Path | Hops | Distinct hosts | Longest gap (s) |",
                  "|---|---|---:|---:|---:|"]
        lines += [f"| `{f.user}` | {f.metrics['path']} | {f.metrics['hops']} | "
                  f"{f.metrics['distinct_hosts']} | {f.metrics['longest_hop_gap_seconds']} |"
                  for f in chains]
        lines.append("")
    if pivots:
        lines += ["| Departing | Arriving | Path | Gap (s) | Other accounts on host |",
                  "|---|---|---|---:|---:|"]
        lines += [f"| `{f.user}` | `{f.metrics['arriving_account']}` | {f.metrics['path']} | "
                  f"{f.metrics['seconds_after_arrival']} | {f.metrics['other_accounts_on_host']} |"
                  for f in pivots]
        lines.append("")
    return lines, scan


def write_lanl_report(redteam_path: Path, out_root: Path, out: Path) -> None:
    half = LANL_ROOT / "configs" / "redteam_window_half_baseline.json"
    runs = [
        _lanl_run("redteam_window", None, LANL_ROOT / "runs" / "redteam_window" / "detection",
                  out_root),
        _lanl_run("redteam_window_half_baseline", half,
                  LANL_ROOT / "runs" / "redteam_window_half_baseline" / "detection", out_root),
    ]
    manifest = load_manifest(LANL_DATASET)
    detection_lines: list[str] = []
    for run in runs:
        lines, _ = _lanl_section(run, manifest)
        detection_lines += lines

    # Evaluation starts here: detection above has finished and cannot see these labels.
    redteam = lv.load_redteam(redteam_path)
    evaluation = ["| Run | Labels in window | Matched to events | Cited by a finding | "
                  "Cited by the new pivot rule |", "|---|---:|---:|---:|---:|"]
    rows: list[str] = []
    for run in runs:
        scan = lv.scan_events(LANL_DATASET, manifest.base_time,
                              cited_ids={e for f in run["findings"] for e in f.event_ids},
                              redteam_keys={r.key for r in redteam}, config=run["config"])
        summary = load_detection_summary(run["detection"])
        partition = next(iter(summary.partitions.values()))
        end = (int((partition.baseline_end - manifest.base_time).total_seconds())
               if partition.baseline_end else None)
        result = lv.redteam_comparison(redteam, scan, run["findings"], run["incidents"], end,
                                       set(partition.users_without_baseline))
        by_pivot = sum(PIVOT in x["cited_by_rules"] for x in result["events"])
        evaluation.append(
            f"| `{run['name']}` | {result['labels_in_sample_time_range']} | "
            f"{result['labels_matched_to_events']} | {result['matched_cited_by_any_finding']} | "
            f"{by_pivot} |"
        )
        rows += [f"- `{run['name']}` t={x['t']} {x['user']} {x['src']}→{x['dst']}: cited by "
                 f"{x['cited_by_rules'] or 'none'}"
                 + (f" ({x['not_cited_reason']})" if x["not_cited_reason"] else "")
                 for x in result["events"]]
    doc = [
        "# Target 1 — LANL sensitivity results",
        "",
        "> **Real, sampled LANL 2015 data** (one contiguous 400,000-line window). A sensitivity "
        "check of how the rules behave, not a measure of detection accuracy. Synthetic results "
        "are in a separate file, [target1_synthetic_results.md](target1_synthetic_results.md).",
        "",
        f"Generated by `python scripts/evaluate_lateral.py lanl`. Engine `{ENGINE_VERSION}`. "
        f"Outputs are in `{out_root.relative_to(PROJECT_ROOT).as_posix()}`; the stored Phase 2 "
        "outputs are read only.",
        "",
        "The default 2-day baseline needs about 33.3M lines and does not fit in memory here, so "
        "under default settings the novelty-based rules have nothing to evaluate. The "
        "half-window run uses a baseline of 1,027 s, far too short to represent normal "
        "behaviour; its novelty findings are expected to be dominated by benign activity.",
        "",
        "## Part A — detection results",
        "",
        *detection_lines,
        "## Part B — Red Team comparison (evaluation only)",
        "",
        "Red Team labels were loaded after detection finished and are not an input to any rule. "
        "Exact match on offset, user, source and destination. No precision, recall or accuracy "
        "is reported: labels are sparse, unlabelled events are not known to be benign, and this "
        "window holds very few labels.",
        "",
        *evaluation,
        "",
        *rows,
        "",
    ]
    out.write_text("\n".join(doc), encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    syn = commands.add_parser("synthetic")
    syn.add_argument("--work", type=Path, required=True, help="scratch directory for this run")
    syn.add_argument("--out", type=Path, default=DOCS / "target1_synthetic_results.md")
    lanl = commands.add_parser("lanl")
    lanl.add_argument("--redteam", type=Path, required=True)
    lanl.add_argument("--work", type=Path,
                      default=PROJECT_ROOT / "data" / "processed" / "lanl_validation_target1")
    lanl.add_argument("--out", type=Path, default=DOCS / "target1_lanl_sensitivity.md")
    args = parser.parse_args(argv)
    args.work.mkdir(parents=True, exist_ok=True)
    if args.command == "synthetic":
        ok = write_synthetic_report(args.work, args.out)
        print(f"[{' OK ' if ok else 'FAIL'}] {args.out}")
        return 0 if ok else 1
    write_lanl_report(args.redteam, args.work, args.out)
    print(f"[ OK ] {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
