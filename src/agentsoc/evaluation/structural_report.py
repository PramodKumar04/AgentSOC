"""Target 2 result reports, generated from actual runs so nothing is hand-copied.

`synthetic`  committed SYNTHETIC scenarios plus scale runs, compared with a naive graph.
`lanl`       real LANL windows, on the Target 1 detection outputs. Red Team labels are
             read only after the assessment has finished, for a separate comparison.

The two reports are separate files and never share figures.
"""

from __future__ import annotations

import argparse
import itertools
import sys
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import networkx as nx

from agentsoc.cli import assess_structure_main, detect_main, ingest_main
from agentsoc.config import PROJECT_ROOT
from agentsoc.data_gen.lateral_scenarios import generate_large_batch_text
from agentsoc.data_gen.structural_scenarios import (
    SCENARIOS,
    ExpectedPath,
    StructuralScenario,
)
from agentsoc.evaluation import lanl_validation as lv
from agentsoc.evaluation.validate import _machine, _run_stage
from agentsoc.graph.assess import ENGINE_VERSION
from agentsoc.graph.store import load_assessments, load_structural_summary
from agentsoc.schemas import AuthEvent, Incident
from agentsoc.schemas.graph import PathKind, StructuralAssessment
from agentsoc.store.datasets import load_manifest
from agentsoc.store.detections import load_detection_summary, load_incidents

SAMPLES = PROJECT_ROOT / "data" / "samples"
SCENARIO_INPUT = SAMPLES / "auth_structural_scenarios_synthetic.txt"
DOCS = PROJECT_ROOT / "docs"
LANL_ROOT = PROJECT_ROOT / "data" / "processed"
LANL_DATASET = LANL_ROOT / "lanl_validation" / "datasets" / "lines_29400001_29800000"
LANL_RUNS = LANL_ROOT / "lanl_validation_target1"
RUN_NAMES = ("redteam_window", "redteam_window_half_baseline")
SCALE_ACCOUNTS = (1000, 5000, 10000)


def naive_findings_graph(incident: Incident, events: Mapping[str, AuthEvent]) -> nx.DiGraph:
    """The comparison baseline: one host edge per event cited by a finding, nothing more."""
    graph = nx.DiGraph()
    for finding in incident.findings:
        for event_id in finding.event_ids:
            event = events.get(event_id)
            if event is not None and event.src_host != event.dst_host:
                graph.add_edge(event.src_host, event.dst_host)
    return graph


def naive_has_walk(graph: nx.DiGraph, walk: Iterable[str]) -> bool:
    hosts = list(walk)
    return all(graph.has_edge(a, b) for a, b in itertools.pairwise(hosts))


def naive_longest_hops(graph: nx.DiGraph) -> int:
    best = 0
    for source in graph.nodes:
        for target in graph.nodes:
            if source != target:
                for path in nx.all_simple_paths(graph, source, target):
                    best = max(best, len(path) - 1)
    return best


def check_scenario(
    scenario: StructuralScenario, assessments: Mapping[str, StructuralAssessment]
) -> list[str]:
    """Differences from the hand-written expectation; empty means it matched."""
    expected = scenario.expected
    if expected.principal is None:
        names = {a.user for a in scenario.accounts}
        return [f"unexpected incident for {n}" for n in names if n in assessments]
    assessment = assessments.get(expected.principal)
    if assessment is None:
        return [f"no assessment for {expected.principal}"]
    problems: list[str] = []
    for want in expected.paths:
        if not _has_path(assessment, want):
            problems.append(f"missing path {want}")
    for walk in expected.forbidden_walks:
        for path in assessment.paths:
            hosts = path.hosts
            if any(hosts[k:k + len(walk)] == list(walk) for k in range(len(hosts))):
                problems.append(f"forbidden walk {walk} on {path.path_id}")
    verdicts: dict[str, list[str]] = {}
    for item in assessment.finding_validations:
        verdicts.setdefault(item.rule_id, []).append(item.verdict.value)
    if {k: sorted(v) for k, v in verdicts.items()} != {
        k: sorted(v) for k, v in expected.finding_verdicts.items()
    }:
        problems.append(f"finding verdicts {verdicts}")
    for rule in expected.extended_rules:
        if not any(v.rule_id == rule and v.extended_by for v in assessment.finding_validations):
            problems.append(f"{rule} was not extended")
    reasons = dict(Counter(d.reason.value for d in assessment.disconnected))
    if reasons != dict(expected.disconnected):
        problems.append(f"disconnected {reasons}")
    if expected.choke_via and not any(
        tuple(c.via_hosts) == expected.choke_via for c in assessment.choke_points
    ):
        problems.append(f"choke points {assessment.choke_points}")
    if expected.cyclic_hosts and list(expected.cyclic_hosts) not in assessment.cyclic_host_groups:
        problems.append(f"cycles {assessment.cyclic_host_groups}")
    if expected.account_bridge and not assessment.account_bridges:
        problems.append("no account bridge")
    attempts = assessment.non_movement_anchors.get("ATTEMPT", 0)
    if attempts != expected.failed_anchors:
        problems.append(f"failed anchors {attempts}")
    duplicated = sum(bool(e.duplicate_event_ids) for e in assessment.edges)
    if duplicated != expected.duplicate_edges:
        problems.append(f"duplicate edges {duplicated}")
    return problems


def _has_path(assessment: StructuralAssessment, want: ExpectedPath) -> bool:
    return any(
        p.kind.value == want.kind and p.verdict.value == want.verdict
        and tuple(p.hosts) == want.hosts and len(p.context_event_ids) == want.context_events
        and any(k.ambiguous for k in p.links) == want.ambiguous
        for p in assessment.paths
    )


def _scenario_section(
    scenario: StructuralScenario, assessments: Mapping[str, StructuralAssessment],
    problems: list[str],
) -> list[str]:
    principal = scenario.expected.principal
    assessment = assessments.get(principal) if principal else None
    lines = [
        f"### {scenario.key} — {scenario.title}", "",
        f"Case: {scenario.case}. **Result: "
        f"{'as expected' if not problems else 'DIFFERS: ' + '; '.join(problems)}.**", "",
        "Input (LANL format):", "", "```",
        *[line for _, line in sorted(scenario.rows, key=lambda r: r[0])], "```", "",
    ]
    if scenario.beyond_naive:
        lines += [f"A naive findings-to-edges graph: {scenario.beyond_naive}", ""]
    if assessment is None:
        return [*lines, "No incident, so nothing to assess.", ""]
    lines += ["| Path | Kind | Verdict | Hosts | Context events | Ambiguous link |",
              "|---|---|---|---|---:|---|"]
    lines += [f"| {p.path_id} | {p.kind.value} | {p.verdict.value} | {' > '.join(p.hosts)} | "
              f"{len(p.context_event_ids)} | {any(k.ambiguous for k in p.links)} |"
              for p in assessment.paths] or ["| none | | | | | |"]
    lines.append("")
    for item in assessment.finding_validations:
        lines.append(f"- `{item.rule_id}` {item.finding_id}: **{item.verdict.value}**. "
                     f"{item.reasons[0]}" + (f" Extended by {', '.join(item.extended_by)}."
                                             if item.extended_by else ""))
    for item in assessment.disconnected:
        lines.append(f"- Disconnected `{item.event_id}` ({item.reason.value}): {item.detail}")
    for item in assessment.choke_points:
        lines.append(f"- Routes to `{item.target_host}` must cross "
                     f"{', '.join(item.via_hosts)}.")
    lines.append("")
    return lines


def _scale_rows(work: Path) -> list[str]:
    rows = ["| Accounts | Events | Indexed | Assess | Index | Verify | Whole stage | Peak memory | "
            "p50 / p95 / max per incident (ms) | Paths | Incidents |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|"]
    for accounts in SCALE_ACCOUNTS:
        text, _, _ = generate_large_batch_text(accounts)
        source = work / f"bulk_{accounts}.txt"
        source.write_text(text, encoding="utf-8", newline="\n")
        dataset, detection = work / f"bulk_ds_{accounts}", work / f"bulk_det_{accounts}"
        _run_stage("ingest", [str(source), "--out", str(dataset), "--source", "synthetic",
                              "--label", "SYNTHETIC large batch", "--overwrite"])
        _run_stage("detect", [str(dataset), "--out", str(detection), "--overwrite"])
        metrics = _run_stage("structure", [str(dataset), "--detection", str(detection),
                                           "--overwrite"])
        summary = load_structural_summary(detection)
        t = summary.timing
        rows.append(
            f"| {accounts:,} | {load_manifest(dataset).event_count:,} | "
            f"{summary.events_indexed:,} | {t.assess_seconds:.2f} s | {t.index_seconds:.2f} s | "
            f"{t.verify_seconds:.2f} s | {metrics['wall_seconds']:.2f} s | "
            f"{metrics['peak_memory_bytes'] / 2**20:,.0f} MB | "
            f"{t.per_incident_ms_p50:.1f} / {t.per_incident_ms_p95:.1f} / "
            f"{t.per_incident_ms_max:.1f} | {sum(summary.paths_by_kind.values()):,} | "
            f"{summary.incidents_assessed:,} |"
        )
    return rows


def write_synthetic_report(work: Path, out: Path) -> bool:
    dataset, detection = work / "dataset", work / "detection"
    if ingest_main([str(SCENARIO_INPUT), "--out", str(dataset), "--source", "synthetic",
                    "--label", "SYNTHETIC structural scenarios", "--overwrite"]):
        raise RuntimeError("ingest failed")
    if detect_main([str(dataset), "--out", str(detection), "--overwrite"]):
        raise RuntimeError("detection failed")
    if assess_structure_main([str(dataset), "--detection", str(detection), "--overwrite"]):
        raise RuntimeError("assessment failed")
    incidents = {i.incident_id: i.principal_user for i in load_incidents(detection)}
    assessments = {incidents[a.incident_id]: a for a in load_assessments(detection)}
    sections: list[str] = []
    verdicts: list[tuple[StructuralScenario, bool]] = []
    for scenario in SCENARIOS:
        problems = check_scenario(scenario, assessments)
        sections += _scenario_section(scenario, assessments, problems)
        verdicts.append((scenario, not problems))
    machine = _machine()
    summary = load_structural_summary(detection)
    doc = [
        "# Target 2 — SSE synthetic scenario results", "",
        "> **All data here is SYNTHETIC.** These results show the SSE behaves as designed on "
        "constructed inputs. They do not measure real-world detection accuracy. LANL results "
        "are in a separate file, [target2_lanl_results.md](target2_lanl_results.md).", "",
        f"Generated by `python scripts/evaluate_structure.py synthetic`. Engine "
        f"`{ENGINE_VERSION}`. Structural config SHA-256 `{summary.structural_config_sha256}`. "
        "Expected values are hand-written in `src/agentsoc/data_gen/structural_scenarios.py`. "
        "A connected path is not evidence of compromise; `INFEASIBLE` means not observed.", "",
        "## Summary", "",
        "| Scenario | Case | Title | Result |", "|---|---|---|---|",
        *[f"| {s.key} | {s.case} | {s.title} | {'as expected' if ok else '**DIFFERS**'} |"
          for s, ok in verdicts],
        "",
        "## Large batches and performance", "",
        "All accounts share one server, the worst case for link lookups. Each row is one run of "
        "the structure stage in its own process; single runs on a busy desktop.", "",
        *_scale_rows(work), "",
        f"Machine: {machine['platform']}, Python {machine['python']}, "
        f"{machine['logical_cpus']} logical CPUs, "
        f"RAM {machine.get('ram_total_bytes', 0) / 2**20:,.0f} MB.", "",
        "## Scenario detail", "", *sections,
    ]
    out.write_text("\n".join(doc), encoding="utf-8", newline="\n")
    return all(ok for _, ok in verdicts)


def _rule_gain(incident: Incident, assessment: StructuralAssessment) -> dict[str, Any]:
    rule_hops = max((int(f.metrics["hops"]) for f in incident.findings
                     if f.rule_id == "LATERAL_CHAIN"), default=0)
    observed = [p for p in assessment.paths if p.kind is PathKind.OBSERVED]
    longest_observed = max((len(p.event_ids) for p in observed), default=0)
    return {
        "rule_hops": rule_hops,
        "longer_observed": longest_observed > rule_hops and longest_observed >= 2,
        "has_context_path": any(p.context_event_ids for p in assessment.paths),
        "inferred": any(p.kind is PathKind.INFERRED for p in assessment.paths),
        "strong_inferred": any(
            p.kind is PathKind.INFERRED and not any(k.ambiguous for k in p.links)
            for p in assessment.paths),
    }


def _lanl_section(name: str, detection: Path, metrics: dict) -> tuple[list[str], dict]:
    incidents = {i.incident_id: i for i in load_incidents(detection)}
    assessments = load_assessments(detection)
    summary = load_structural_summary(detection)
    gains = [_rule_gain(incidents[a.incident_id], a) for a in assessments]
    verdicts = Counter(v.verdict.value for a in assessments for v in a.finding_validations)
    reasons = Counter(d.reason.value for a in assessments for d in a.disconnected)
    t = summary.timing
    paths = [p for a in assessments for p in a.paths]
    samples = sorted(
        ((a, p) for a in assessments for p in a.paths if p.context_event_ids),
        key=lambda x: (-len(x[1].event_ids), x[1].path_id, x[0].incident_id),
    )[:8]
    lines = [
        f"### `{name}`", "",
        f"Incidents assessed: {summary.incidents_assessed:,}. Events indexed: "
        f"{summary.events_indexed:,}. Detection engine: `{summary.detection_engine_version}`.",
        "",
        f"- Paths: {len(paths):,} ({sum(p.kind is PathKind.OBSERVED for p in paths):,} observed, "
        f"{sum(p.kind is PathKind.INFERRED for p in paths):,} inferred).",
        f"- Finding validation: {dict(sorted(verdicts.items()))}.",
        f"- Disconnected suspicious events: {dict(sorted(reasons.items()))}.",
        f"- Incidents whose context was truncated: {summary.truncated_incidents:,}.",
        f"- Incidents with a path through an event no rule cited: "
        f"{sum(g['has_context_path'] for g in gains):,}.",
        f"- Incidents with an observed path longer than any rule chain: "
        f"{sum(g['longer_observed'] for g in gains):,}.",
        f"- Incidents with an inferred path: {sum(g['inferred'] for g in gains):,}, of which "
        f"not flagged ambiguous: {sum(g['strong_inferred'] for g in gains):,}.",
        f"- Time: index {t.index_seconds:.1f} s, assess {t.assess_seconds:.2f} s, verify "
        f"{t.verify_seconds:.1f} s; whole stage {metrics['wall_seconds']:.1f} s, peak "
        f"{metrics['peak_memory_bytes'] / 2**20:,.0f} MB. Per incident p50 "
        f"{t.per_incident_ms_p50:.1f} ms, p95 {t.per_incident_ms_p95:.1f} ms, max "
        f"{t.per_incident_ms_max:.1f} ms.", "",
    ]
    if samples:
        lines += ["| Incident | Kind | Hosts | Accounts | Context events |",
                  "|---|---|---|---|---:|"]
        lines += [f"| {a.incident_id} | {p.kind.value} | {' > '.join(p.hosts)} | "
                  f"{', '.join(p.accounts)} | {len(p.context_event_ids)} |" for a, p in samples]
        lines.append("")
    return lines, {"assessments": assessments}


def _place(ids: list[str], on_paths: set[str], edges: set[str]) -> str:
    if set(ids) & on_paths:
        return "on a reported path"
    return "on a graph edge only" if set(ids) & edges else "not in any incident graph"


def write_lanl_report(redteam_path: Path, out: Path) -> None:
    manifest = load_manifest(LANL_DATASET)
    part_a: list[str] = []
    runs: dict[str, dict] = {}
    for name in RUN_NAMES:
        detection = LANL_RUNS / name / "detection"
        metrics = _run_stage("structure", [str(LANL_DATASET), "--detection", str(detection),
                                           "--overwrite"])
        lines, runs[name] = _lanl_section(name, detection, metrics)
        part_a += lines
    # Evaluation starts here: the assessments above are finished and cannot see these labels.
    redteam = lv.load_redteam(redteam_path)
    table = ["| Run | Labels in window | Matched to events | On a graph edge | "
             "On a reported path |", "|---|---:|---:|---:|---:|"]
    notes: list[str] = []
    for name in RUN_NAMES:
        assessments: list[StructuralAssessment] = runs[name]["assessments"]
        scan = lv.scan_events(LANL_DATASET, manifest.base_time, cited_ids=set(),
                              redteam_keys={r.key for r in redteam})
        in_range = [r for r in redteam if scan.min_offset <= r.t <= scan.max_offset]
        edges = {e.event_id for a in assessments for e in a.edges}
        on_paths = {e for a in assessments for p in a.paths for e in p.event_ids}
        matched = {r: scan.redteam_matches.get(r.key, []) for r in in_range}
        table.append(f"| `{name}` | {len(in_range)} | {sum(bool(v) for v in matched.values())} | "
                     f"{sum(bool(set(v) & edges) for v in matched.values())} | "
                     f"{sum(bool(set(v) & on_paths) for v in matched.values())} |")
        notes += [f"- `{name}` t={r.t} {r.user} {r.src}→{r.dst}: {_place(v, on_paths, edges)}"
                  for r, v in matched.items()]
    summary = load_detection_summary(LANL_RUNS / RUN_NAMES[1] / "detection")
    doc = [
        "# Target 2 — SSE results on LANL data", "",
        "> **Real, sampled LANL 2015 data** (one contiguous 400,000-line window). This shows how "
        "the SSE behaves on real logs. It does not measure detection accuracy, and a connected "
        "path is not evidence of compromise. Synthetic results are in a separate file, "
        "[target2_synthetic_results.md](target2_synthetic_results.md).", "",
        f"Generated by `python scripts/evaluate_structure.py lanl`. Engine `{ENGINE_VERSION}`, "
        f"detection engine `{summary.engine_version}`. Validated against observed logons only; "
        "LANL has no topology, so `INFEASIBLE` means not observed.", "",
        "The half-window run uses a 1,027 s baseline, far too short to represent normal "
        "behaviour, so its novelty-based incidents are expected to be dominated by benign "
        "activity. Inferred paths join different accounts by assumption.", "",
        "## Part A — structural results", "", *part_a,
        "## Part B — Red Team comparison (evaluation only)", "",
        "Red Team labels were loaded after the assessments finished and are not an input to "
        "any rule or graph. Exact match on offset, user, source and destination. No precision, "
        "recall or accuracy is reported: labels are sparse and unlabelled events are not known "
        "to be benign.", "",
        *table, "", *notes, "",
    ]
    out.write_text("\n".join(doc), encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    syn = commands.add_parser("synthetic")
    syn.add_argument("--work", type=Path, required=True, help="scratch directory for this run")
    syn.add_argument("--out", type=Path, default=DOCS / "target2_synthetic_results.md")
    lanl = commands.add_parser("lanl")
    lanl.add_argument("--redteam", type=Path, required=True)
    lanl.add_argument("--out", type=Path, default=DOCS / "target2_lanl_results.md")
    args = parser.parse_args(argv)
    if args.command == "synthetic":
        args.work.mkdir(parents=True, exist_ok=True)
        ok = write_synthetic_report(args.work, args.out)
        print(f"[{' OK ' if ok else 'FAIL'}] {args.out}")
        return 0 if ok else 1
    write_lanl_report(args.redteam, args.out)
    print(f"[ OK ] {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
