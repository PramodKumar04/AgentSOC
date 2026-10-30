"""LANL validation orchestrator.

Each run = (window of the original archive, detection configuration). Ingestion and
detection run as separate measured processes using the EXISTING Phase 1/2 CLIs; this
module only analyses their outputs. Red Team labels are read after detection.

    python scripts/validate_lanl.py --archive auth.txt.gz --redteam redteam.txt.gz \
        --out data/processed/lanl_validation \
        --run first_100k:0:100000 --run window:29400000:400000:half_window
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentsoc.detection.config import DetectionConfig, load_detection_config
from agentsoc.evaluation import lanl_validation as lv
from agentsoc.evaluation.measure import METRICS_PREFIX
from agentsoc.store.datasets import REPORT_JSON, load_manifest
from agentsoc.store.detections import SUMMARY_FILE, load_findings, load_incidents

BASELINE_MODES = ("default", "half_window")


@dataclass(frozen=True)
class RunSpec:
    name: str
    skip: int
    limit: int
    baseline: str = "default"

    @classmethod
    def parse(cls, text: str) -> RunSpec:
        parts = text.split(":")
        if len(parts) not in (3, 4) or (len(parts) == 4 and parts[3] not in BASELINE_MODES):
            raise argparse.ArgumentTypeError(
                f"expected NAME:SKIP:LIMIT[:{'|'.join(BASELINE_MODES)}], got {text!r}"
            )
        mode = parts[3] if len(parts) == 4 else "default"
        return cls(parts[0], int(parts[1]), int(parts[2]), mode)

    @property
    def dataset_name(self) -> str:
        return f"lines_{self.skip + 1}_{self.skip + self.limit}"


def _run_stage(stage: str, args: list[str]) -> dict[str, Any]:
    # Fixed interpreter and module; arguments are paths/numbers from our own CLI parsing.
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "agentsoc.evaluation.measure", stage, *args],
        capture_output=True, text=True, check=False,
    )
    lines = [x for x in proc.stdout.splitlines() if x.startswith(METRICS_PREFIX)]
    if proc.returncode != 0 or not lines:
        tail = "\n".join((proc.stdout + proc.stderr).splitlines()[-15:])
        raise RuntimeError(f"{stage} failed (exit {proc.returncode}):\n{tail}")
    return json.loads(lines[-1][len(METRICS_PREFIX):])


def _machine() -> dict[str, Any]:
    info: dict[str, Any] = {
        "platform": platform.platform(), "python": platform.python_version(),
        "logical_cpus": os.cpu_count(),
    }
    if sys.platform == "win32":
        import ctypes

        class MemoryStatus(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

        status = MemoryStatus()
        status.dwLength = ctypes.sizeof(status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            info["ram_total_bytes"] = status.ullTotalPhys
            info["ram_available_bytes_at_start"] = status.ullAvailPhys
    return info


def run_validation(
    archive: Path, redteam_path: Path | None, out: Path, runs: list[RunSpec],
    *, scan_days: int = 0,
) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    started = datetime.now(UTC)
    archive_info = {
        "path_name": archive.name,
        "size_bytes": archive.stat().st_size,
        "sha256": lv.file_sha256(archive),
    }
    if scan_days:
        archive_info["lines_per_day"] = lv.lines_per_day(archive, scan_days)
    redteam = lv.load_redteam(redteam_path) if redteam_path else []
    redteam_info = (
        {"path_name": redteam_path.name, "sha256": lv.file_sha256(redteam_path),
         "records": len(redteam)} if redteam_path else None
    )
    ingest_metrics: dict[str, dict] = {}
    results: dict[str, dict] = {}
    for spec in runs:
        ds_dir = out / "datasets" / spec.dataset_name
        if spec.dataset_name not in ingest_metrics:
            label = (f"LANL 2015 auth.txt.gz, lines {spec.skip + 1}-{spec.skip + spec.limit} "
                     f"(contiguous window, --skip {spec.skip} --limit {spec.limit})")
            ingest_metrics[spec.dataset_name] = _run_stage("ingest", [
                str(archive), "--out", str(ds_dir), "--source", "lanl", "--label", label,
                "--skip", str(spec.skip), "--limit", str(spec.limit), "--overwrite",
            ])
        manifest = load_manifest(ds_dir)
        quality = json.loads((ds_dir / REPORT_JSON).read_text(encoding="utf-8"))

        config_args: list[str] = []
        config = DetectionConfig()
        if spec.baseline == "half_window":
            span = int((datetime.fromisoformat(quality["time_end"])
                        - datetime.fromisoformat(quality["time_start"])).total_seconds())
            config = DetectionConfig(baseline_seconds=span // 2)
            config_path = out / "configs" / f"{spec.name}.json"
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(config.model_dump_json(indent=2) + "\n", encoding="utf-8")
            config = load_detection_config(config_path)
            config_args = ["--config", str(config_path)]

        det_dir = out / "runs" / spec.name / "detection"
        detect_metrics = _run_stage(
            "detect", [str(ds_dir), "--out", str(det_dir), *config_args, "--overwrite"]
        )
        summary = json.loads((det_dir / SUMMARY_FILE).read_text(encoding="utf-8"))
        findings, incidents = load_findings(det_dir), load_incidents(det_dir)
        scan = lv.scan_events(
            ds_dir, manifest.base_time,
            cited_ids={e for f in findings for e in f.event_ids},
            redteam_keys={r.key for r in redteam}, config=config,
        )
        baseline = lv.baseline_section(summary, config, scan)
        partition = next(iter(summary["partitions"].values()), None)
        baseline_end_offset = (
            int((datetime.fromisoformat(partition["baseline_end"]) - manifest.base_time)
                .total_seconds()) if partition and partition["baseline_end"] else None
        )
        ingest = ingest_metrics[spec.dataset_name]
        results[spec.name] = {
            "spec": {"skip": spec.skip, "limit": spec.limit, "baseline_mode": spec.baseline,
                     "dataset_dir": spec.dataset_name, "config_sha256": config.sha256(),
                     "baseline_seconds": config.baseline_seconds},
            "ingestion": lv.ingestion_section(manifest, quality, scan),
            "baseline": baseline,
            "detection": {k: summary[k] for k in (
                "engine_version", "config_sha256", "findings_total", "findings_by_rule",
                "incidents_total", "incidents_by_severity", "detections_sha256",
                "incidents_sha256")},
            "rules": lv.rule_section(findings, incidents, baseline, config),
            "integrity": lv.integrity_section(incidents, findings, scan, manifest, config),
            "severity_inflation": lv.severity_inflation_section(incidents),
            "identity": lv.identity_section(incidents, scan),
            "redteam": lv.redteam_comparison(
                redteam, scan, findings, incidents, baseline_end_offset,
                set(partition["users_without_baseline"]) if partition else set(),
            ) if redteam else None,
            "incident_examples": [
                {"incident_id": i.incident_id, "principal": i.principal_user,
                 "severity": i.severity.value, "rules": i.rule_ids,
                 "first_seen": i.first_seen.isoformat(), "last_seen": i.last_seen.isoformat(),
                 "evidence_events": len(i.event_ids), "severity_rationale": i.severity_rationale,
                 "reasons": [f.description for f in i.findings[:3]],
                 "benign_explanations": i.benign_explanations[:3]}
                for i in sorted(incidents, key=lambda i: (-len(i.rule_ids), -len(i.event_ids),
                                                         i.incident_id))[:5]
            ],
            "performance": {
                "ingest": {**ingest, "lines_per_second": round(
                    manifest.event_count / ingest["wall_seconds"], 1)},
                "detect": {**detect_metrics, "events_per_second": round(
                    manifest.event_count / detect_metrics["wall_seconds"], 1)},
                "dataset_file_bytes": lv.output_sizes(ds_dir),
                "detection_file_bytes": lv.output_sizes(det_dir),
                "bytes_per_event_peak_ingest": round(
                    ingest["peak_memory_bytes"] / manifest.event_count)
                if ingest.get("peak_memory_bytes") and manifest.event_count else None,
            },
        }

    context = {
        "disclaimer": lv.DISCLAIMER,
        "generated_at": datetime.now(UTC).isoformat(),
        "started_at": started.isoformat(),
        "archive": archive_info,
        "redteam_archive": redteam_info,
        "machine": _machine(),
        "runs": results,
    }
    _write_outputs(out, context)
    return context


def _dump(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(data, indent=2, default=str) + "\n")


def _write_outputs(out: Path, ctx: dict[str, Any]) -> None:
    from agentsoc.evaluation.report import render_validation_report

    head = {k: ctx[k] for k in ("disclaimer", "generated_at", "archive", "redteam_archive")}
    runs = ctx["runs"]
    _dump(out / "ingestion_summary.json",
          {**head, "runs": {n: {"spec": r["spec"], **r["ingestion"]} for n, r in runs.items()}})
    _dump(out / "detection_summary.json", {**head, "runs": {n: {
        "spec": r["spec"], **r["detection"], "baseline": r["baseline"],
        "integrity": r["integrity"], "severity_inflation": r["severity_inflation"],
        "identity": r["identity"], "incident_examples": r["incident_examples"],
        "redteam": r["redteam"]} for n, r in runs.items()}})
    _dump(out / "rule_analysis.json",
          {**head, "runs": {n: r["rules"] for n, r in runs.items()}})
    _dump(out / "performance_metrics.json", {**head, "machine": ctx["machine"],
          "runs": {n: r["performance"] for n, r in runs.items()}})
    (out / "validation_report.md").write_text(
        render_validation_report(ctx), encoding="utf-8", newline="\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Phase 1/2 on LANL windows.")
    parser.add_argument("--archive", type=Path, required=True, help="original auth.txt(.gz)")
    parser.add_argument("--redteam", type=Path, default=None, help="redteam.txt(.gz), optional")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--run", type=RunSpec.parse, action="append", required=True,
                        help="NAME:SKIP:LIMIT[:default|half_window]")
    parser.add_argument("--scan-days", type=int, default=0,
                        help="count archive lines for the first N days (sizes a full baseline)")
    args = parser.parse_args(argv)
    if len({r.name for r in args.run}) != len(args.run):
        parser.error("run names must be unique")
    try:
        ctx = run_validation(args.archive, args.redteam, args.out, args.run,
                             scan_days=args.scan_days)
    except (RuntimeError, OSError) as exc:
        print(f"[FAIL] {exc}")
        return 1
    for name, r in ctx["runs"].items():
        d = r["detection"]
        print(f"[ OK ] {name}: {r['ingestion']['accepted']} events, {d['findings_total']} "
              f"findings, {d['incidents_total']} incidents, integrity "
              f"{'passed' if r['integrity']['passed'] else 'FAILED'}")
    print(f"[INFO] report: {args.out / 'validation_report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
