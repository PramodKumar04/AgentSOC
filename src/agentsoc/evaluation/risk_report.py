"""Target 3 result reports, generated from actual runs so nothing is hand-copied.

`synthetic`  committed SYNTHETIC scenarios against hand-worked expected scores, plus scale.
`lanl`       real LANL windows, on stored Target 1 and 2 outputs. Red Team labels are read
             only after scoring has finished, for a separate comparison.

The two reports are separate files and never share figures. Stability under changed weights
is reported as a property of the arithmetic; it is not calibration or evidence of accuracy.
"""

from __future__ import annotations

import argparse
import hashlib
import random
import sys
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from agentsoc.cli import (
    assess_risk_main,
    assess_structure_main,
    detect_main,
    ingest_main,
)
from agentsoc.config import PROJECT_ROOT
from agentsoc.data_gen.lateral_scenarios import generate_large_batch_text
from agentsoc.data_gen.risk_scenarios import SCENARIOS, RiskScenario
from agentsoc.detection.config import DetectionConfig
from agentsoc.evaluation import lanl_validation as lv
from agentsoc.evaluation.validate import _machine, _run_stage
from agentsoc.graph.store import load_assessments
from agentsoc.risk.actions import DESTRUCTIVE
from agentsoc.risk.assess import ENGINE_VERSION
from agentsoc.risk.config import RiskConfig, RiskWeights
from agentsoc.risk.score import score_incident
from agentsoc.risk.store import RECORDS_FILE, RISK_DIR, load_risk_records, load_risk_summary
from agentsoc.schemas import Incident
from agentsoc.schemas.graph import StructuralAssessment
from agentsoc.schemas.rsem import IncidentRiskRecord
from agentsoc.store.datasets import load_manifest
from agentsoc.store.detections import load_detection_summary, load_incidents

SAMPLES = PROJECT_ROOT / "data" / "samples"
SCENARIO_INPUT = SAMPLES / "auth_risk_scenarios_synthetic.txt"
SCENARIO_CONFIG = SAMPLES / "risk_scenarios_detection_config.json"
DOCS = PROJECT_ROOT / "docs"
LANL_ROOT = PROJECT_ROOT / "data" / "processed"
LANL_DATASET = LANL_ROOT / "lanl_validation" / "datasets" / "lines_29400001_29800000"
LANL_RUNS = LANL_ROOT / "lanl_validation_target1"
RUN_NAMES = ("redteam_window", "redteam_window_half_baseline")
SCALE_ACCOUNTS = (1000, 5000, 10000)
PERTURBATIONS = 50
PERTURBATION_RANGE = 0.2


def band_stability(
    incidents: Mapping[str, Incident], assessments: list[StructuralAssessment],
    detection_config: DetectionConfig, config: RiskConfig,
) -> float:
    """Share of incidents keeping their band when each weight varies by up to 20%."""
    rng = random.Random(7)  # noqa: S311 - a reproducible perturbation, not security
    base = config.weights.model_dump()
    bands = {a.incident_id: score_incident(incidents[a.incident_id], a, detection_config,
                                           config).assessment.band for a in assessments}
    same = total = 0
    for _ in range(PERTURBATIONS):
        varied = {k: v * rng.uniform(1 - PERTURBATION_RANGE, 1 + PERTURBATION_RANGE)
                  for k, v in base.items()}
        scale = sum(varied.values())
        changed = config.model_copy(update={"weights": RiskWeights(
            **{k: v / scale for k, v in varied.items()})})
        for assessment in assessments:
            result = score_incident(incidents[assessment.incident_id], assessment,
                                    detection_config, changed)
            total += 1
            same += result.assessment.band is bands[assessment.incident_id]
    return same / total if total else 1.0


def _breakdown(record: IncidentRiskRecord) -> list[str]:
    lines = ["| Component | Value | Weight | Points |", "|---|---:|---:|---:|"]
    lines += [f"| {c.name} | {c.value:.3f} | {c.weight:.2f} | {100 * c.contribution:.2f} |"
              for c in record.risk.components]
    lines.append("")
    lines += [f"- {s.name}: {s.before:.2f} → {s.after:.2f}. {s.explanation}"
              for s in record.adjustments]
    return lines


def _scenario_section(
    scenario: RiskScenario, record: IncidentRiskRecord | None, ok: bool
) -> list[str]:
    expected = scenario.expected
    lines = [f"### {scenario.key} — {scenario.title}", "",
             f"**Result: {'as expected' if ok else 'DIFFERS'}.** Hand calculation: "
             f"{scenario.working}.", "", "Input (LANL format):", "", "```",
             *[line for _, line in sorted(scenario.rows, key=lambda r: r[0])], "```", ""]
    if record is None:
        return [*lines, "No incident produced.", ""]
    lines += [
        f"Expected {expected.score:g} ({expected.band}); got **{record.risk.score:g} "
        f"({record.risk.band.value})**. Detection severity stays "
        f"**{record.severity_comparison.detection_severity.value}**. Investigation confidence "
        f"(before any investigation) {record.confidence.score:g} "
        f"({record.confidence.level.value}).", "", *_breakdown(record), "",
        "Proposed actions, none executed (priority is separate from the risk): "
        + (", ".join(f"{a.action_type.value} on {a.target} ({a.score.composite:.3f})"
                     for a in record.actions)) + ".", "",
    ]
    if record.withheld_actions:
        lines += [f"Withheld: {', '.join(w.action_type.value for w in record.withheld_actions)} "
                  f"({record.withheld_actions[0].reasons[0]})", ""]
    return lines


def _scale_rows(work: Path) -> list[str]:
    rows = ["| Accounts | Events | Incidents | Risk stage | Score | Verify | Peak memory | "
            "p50 / p95 / max per incident (ms) |", "|---|---:|---:|---:|---:|---:|---:|---|"]
    for accounts in SCALE_ACCOUNTS:
        text, _, _ = generate_large_batch_text(accounts)
        source = work / f"bulk_{accounts}.txt"
        source.write_text(text, encoding="utf-8", newline="\n")
        dataset, detection = work / f"bulk_ds_{accounts}", work / f"bulk_det_{accounts}"
        _run_stage("ingest", [str(source), "--out", str(dataset), "--source", "synthetic",
                              "--label", "SYNTHETIC large batch", "--overwrite"])
        _run_stage("detect", [str(dataset), "--out", str(detection), "--overwrite"])
        _run_stage("structure", [str(dataset), "--detection", str(detection), "--overwrite"])
        metrics = _run_stage("risk", ["--detection", str(detection), "--overwrite"])
        summary = load_risk_summary(detection)
        t = summary.timing
        rows.append(
            f"| {accounts:,} | {load_manifest(dataset).event_count:,} | "
            f"{summary.incidents_scored:,} | {metrics['wall_seconds']:.2f} s | "
            f"{t.assess_seconds:.3f} s | {t.verify_seconds:.3f} s | "
            f"{metrics['peak_memory_bytes'] / 2**20:,.0f} MB | "
            f"{t.per_incident_ms_p50:.2f} / {t.per_incident_ms_p95:.2f} / "
            f"{t.per_incident_ms_max:.2f} |"
        )
    return rows


def write_synthetic_report(work: Path, out: Path) -> bool:
    dataset, detection = work / "dataset", work / "detection"
    if ingest_main([str(SCENARIO_INPUT), "--out", str(dataset), "--source", "synthetic",
                    "--label", "SYNTHETIC risk scenarios", "--overwrite"]):
        raise RuntimeError("ingest failed")
    if detect_main([str(dataset), "--config", str(SCENARIO_CONFIG), "--out", str(detection),
                    "--overwrite"]):
        raise RuntimeError("detection failed")
    if assess_structure_main([str(dataset), "--detection", str(detection), "--overwrite"]):
        raise RuntimeError("assessment failed")
    if assess_risk_main(["--detection", str(detection), "--overwrite"]):
        raise RuntimeError("risk assessment failed")
    incidents = {i.incident_id: i for i in load_incidents(detection)}
    records = {incidents[r.incident_id].principal_user: r for r in load_risk_records(detection)}
    sections: list[str] = []
    rows: list[str] = []
    all_ok = True
    for scenario in SCENARIOS:
        expected = scenario.expected
        record = records.get(expected.principal)
        ok = bool(record) and abs(record.risk.score - expected.score) <= 0.051 and (
            record.risk.band == expected.band
            and record.severity_comparison.detection_severity == expected.severity
            and any(a.action_type in DESTRUCTIVE for a in record.actions)
            == expected.destructive_allowed)
        all_ok = all_ok and ok
        rows.append(f"| {scenario.key} | {scenario.title} | {expected.score:g} | "
                    f"{record.risk.score if record else '-'} | "
                    f"{record.risk.band.value if record else '-'} | {expected.severity} | "
                    f"{record.confidence.score if record else '-'} | "
                    f"{'as expected' if ok else '**DIFFERS**'} |")
        sections += _scenario_section(scenario, record, ok)
    assessments = load_assessments(detection)
    detection_config = load_detection_summary(detection).config
    stability = band_stability(incidents, assessments, detection_config, RiskConfig())
    machine = _machine()
    doc = [
        "# Target 3 — RSEM synthetic scenario results", "",
        "> **All data here is SYNTHETIC.** These results show the arithmetic and safeguards "
        "behave as designed. They are not calibration and do not measure real-world accuracy. "
        "LANL results are in a separate file, [target3_lanl_results.md](target3_lanl_results.md).",
        "",
        f"Generated by `python scripts/evaluate_risk.py synthetic`. Engine `{ENGINE_VERSION}`. "
        f"Risk config SHA-256 `{RiskConfig().sha256()}`. Risk is a heuristic score, not a "
        "probability of compromise, and is reported beside detection severity, which it does "
        "not use.", "",
        "## Summary", "",
        "| Scenario | Title | Hand-worked | Score | Risk band | Detection severity | "
        "Confidence | Result |", "|---|---|---:|---:|---|---|---:|---|", *rows, "",
        f"Bands stayed the same for {stability:.1%} of synthetic incidents when each weight "
        f"varied by up to {PERTURBATION_RANGE:.0%}. This describes the arithmetic only; it is "
        "not calibration or evidence of accuracy.", "",
        "## Large batches and performance", "",
        "Each row is one run of the risk stage in its own process, on outputs of the earlier "
        "stages; single runs on a busy desktop.", "", *_scale_rows(work), "",
        f"Machine: {machine['platform']}, Python {machine['python']}, "
        f"{machine['logical_cpus']} logical CPUs, "
        f"RAM {machine.get('ram_total_bytes', 0) / 2**20:,.0f} MB.", "",
        "## Scenario detail", "", *sections,
    ]
    out.write_text("\n".join(doc), encoding="utf-8", newline="\n")
    return all_ok


def _lanl_section(name: str, detection: Path, metrics: dict) -> tuple[list[str], list, dict]:
    incidents = {i.incident_id: i for i in load_incidents(detection)}
    records = load_risk_records(detection)
    assessments = load_assessments(detection)
    summary = load_risk_summary(detection)
    config = load_detection_summary(detection).config
    stability = band_stability(incidents, assessments, config, RiskConfig())
    t = summary.timing
    top = sorted(records, key=lambda r: (-r.risk.score, r.incident_id))[:8]
    actions = Counter(a.action_type.value for r in records for a in r.actions)
    lines = [
        f"### `{name}`", "",
        f"Incidents scored: {summary.incidents_scored:,}. Baseline: "
        f"{config.baseline_seconds:,} s.", "",
        f"- Risk bands: {dict(sorted(summary.bands.items()))}.",
        f"- Severity → risk: {dict(sorted(summary.severity_vs_risk.items()))}.",
        f"- Confidence levels: {dict(sorted(summary.confidence_levels.items()))}.",
        f"- Actions proposed: {dict(sorted(actions.items()))}; destructive actions withheld: "
        f"{summary.actions_withheld:,}.",
        f"- Band stability when weights vary by up to {PERTURBATION_RANGE:.0%}: {stability:.1%}. "
        "Not calibration or evidence of accuracy.",
        f"- Time: score {t.assess_seconds:.3f} s, verify {t.verify_seconds:.3f} s; whole stage "
        f"{metrics['wall_seconds']:.1f} s, peak {metrics['peak_memory_bytes'] / 2**20:,.0f} MB.",
        "",
        "| Incident | Account | Risk | Band | Detection severity | Confidence | Route |",
        "|---|---|---:|---|---|---:|---|",
    ]
    lines += [f"| {r.incident_id} | {incidents[r.incident_id].principal_user} | {r.risk.score} | "
              f"{r.risk.band.value} | {r.severity_comparison.detection_severity.value} | "
              f"{r.confidence.score} | {' > '.join(r.route.hosts) if r.route else 'none'} |"
              for r in top]
    lines.append("")
    return lines, records, incidents


def write_lanl_report(redteam_path: Path, out: Path) -> None:
    manifest = load_manifest(LANL_DATASET)
    part_a: list[str] = []
    runs: dict[str, tuple[list, dict]] = {}
    for name in RUN_NAMES:
        detection = LANL_RUNS / name / "detection"
        metrics = _run_stage("risk", ["--detection", str(detection), "--overwrite"])
        lines, records, incidents = _lanl_section(name, detection, metrics)
        part_a += lines
        runs[name] = (records, incidents)
    # Evaluation starts here: scoring above is finished and cannot see these labels.
    redteam = lv.load_redteam(redteam_path)
    scan = lv.scan_events(LANL_DATASET, manifest.base_time, cited_ids=set(),
                          redteam_keys={r.key for r in redteam})
    in_range = [r for r in redteam if scan.min_offset <= r.t <= scan.max_offset]
    notes: list[str] = []
    for name, (records, incidents) in runs.items():
        for label in in_range:
            ids = set(scan.redteam_matches.get(label.key, []))
            hits = [r for r in records if ids & set(incidents[r.incident_id].event_ids)]
            where = ("; ".join(f"{r.incident_id} risk {r.risk.score} ({r.risk.band.value}), "
                               f"confidence {r.confidence.score}" for r in hits)
                     or "not cited by any incident")
            notes.append(f"- `{name}` t={label.t} {label.user} {label.src}→{label.dst}: {where}")
    summary = load_risk_summary(LANL_RUNS / RUN_NAMES[1] / "detection")
    records_hash = hashlib.sha256(
        (LANL_RUNS / RUN_NAMES[1] / "detection" / RISK_DIR / RECORDS_FILE).read_bytes()
    ).hexdigest()
    doc = [
        "# Target 3 — RSEM results on LANL data", "",
        "> **Real, sampled LANL 2015 data** (one contiguous 400,000-line window). This shows how "
        "the scoring behaves on real logs. It is not calibration and does not measure detection "
        "accuracy. Synthetic results are in a separate file, "
        "[target3_synthetic_results.md](target3_synthetic_results.md).", "",
        f"Generated by `python scripts/evaluate_risk.py lanl`. Engine `{ENGINE_VERSION}`. Risk "
        f"config SHA-256 `{summary.risk_config_sha256}`. Records SHA-256 `{records_hash}`.", "",
        "LANL has no host criticality data, so no sensitive hosts are configured and sensitive "
        "exposure contributes nothing: the highest reachable score is below the Critical band "
        "in practice. The half-window run uses a 1,027 s baseline, far too short to represent "
        "normal behaviour, which lowers investigation confidence and is not a measure of risk.",
        "",
        "## Part A — scoring results", "", *part_a,
        "## Part B — Red Team comparison (evaluation only)", "",
        "Red Team labels were loaded after scoring finished and are not an input to any score. "
        "Exact match on offset, user, source and destination. No precision, recall or accuracy "
        "is reported: labels are sparse and unlabelled events are not known to be benign.", "",
        *notes, "",
    ]
    out.write_text("\n".join(doc), encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    syn = commands.add_parser("synthetic")
    syn.add_argument("--work", type=Path, required=True, help="scratch directory for this run")
    syn.add_argument("--out", type=Path, default=DOCS / "target3_synthetic_results.md")
    lanl = commands.add_parser("lanl")
    lanl.add_argument("--redteam", type=Path, required=True)
    lanl.add_argument("--out", type=Path, default=DOCS / "target3_lanl_results.md")
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
