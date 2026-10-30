"""Command-line entry points."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from agentsoc.config import get_settings
from agentsoc.data_gen.scenarios import generate_scenario_text
from agentsoc.detection.config import load_detection_config
from agentsoc.detection.engine import run_detection
from agentsoc.detection.inputs import load_verified_inputs
from agentsoc.exceptions import AgentSOCError
from agentsoc.logging_setup import configure_logging
from agentsoc.perception.lanl import DEFAULT_BASE_TIME, ingest_lanl_file
from agentsoc.perception.quality import build_quality_report
from agentsoc.schemas import DatasetSource
from agentsoc.store.datasets import REPORT_MD, write_processed_dataset
from agentsoc.store.detections import REPORT_FILE, write_detection_outputs


def _aware_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("base time must include a timezone, e.g. +00:00")
    return parsed


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


def ingest_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingest a LANL-format authentication file into a processed dataset."
    )
    parser.add_argument("input", type=Path, help="auth.txt, auth.txt.gz, or a LANL-format sample")
    parser.add_argument("--out", type=Path, required=True, help="output dataset directory")
    parser.add_argument(
        "--label", required=True,
        help="true provenance, e.g. 'LANL auth.txt lines 1-5000' or 'SYNTHETIC LANL-format sample'",
    )
    parser.add_argument(
        "--source", choices=[s.value for s in DatasetSource], default=DatasetSource.LANL.value,
        help="dataset provenance recorded in the manifest (use 'synthetic' for generated samples)",
    )
    parser.add_argument("--limit", type=_positive_int, default=None, help="max lines to consume")
    parser.add_argument("--skip", type=int, default=0, help="lines to skip before consuming")
    parser.add_argument(
        "--base-time", type=_aware_datetime, default=DEFAULT_BASE_TIME,
        help="ISO datetime that LANL offset 0 maps to (default 1970-01-01T00:00:00+00:00)",
    )
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)

    try:
        settings = get_settings()
        configure_logging(settings.log_level, settings.secret_values())
        result = ingest_lanl_file(
            args.input, limit=args.limit, skip=args.skip,
            base_time=args.base_time, dataset=DatasetSource(args.source),
        )
        report = build_quality_report(result)
        manifest = write_processed_dataset(
            result, report, args.out, dataset_label=args.label, overwrite=args.overwrite,
        )
    except AgentSOCError as exc:
        print(f"[FAIL] {exc}")
        return 1

    print(f"[ OK ] {manifest.event_count} events accepted, {manifest.rejected_count} rejected "
          f"({report.rejection_rate:.2%} of non-blank lines)")
    print(f"[ OK ] dataset written to {args.out}")
    print(f"[INFO] quality report: {args.out / REPORT_MD}")
    return 0


def detect_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run authentication threat detection on verified processed datasets."
    )
    parser.add_argument("datasets", nargs="+", type=Path, help="processed dataset directories")
    parser.add_argument("--out", type=Path, required=True, help="output directory")
    parser.add_argument("--config", type=Path, default=None, help="detection config JSON")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)

    try:
        settings = get_settings()
        configure_logging(settings.log_level, settings.secret_values())
        config = load_detection_config(args.config)
        inputs = load_verified_inputs(args.datasets)
        result = run_detection([e for i in inputs for e in i.events], config)
        summary = write_detection_outputs(
            result, inputs, config, args.out, overwrite=args.overwrite
        )
    except AgentSOCError as exc:
        print(f"[FAIL] {exc}")
        return 1

    severities = ", ".join(f"{k}={v}" for k, v in summary.incidents_by_severity.items())
    print(f"[ OK ] {summary.findings_total} findings, {summary.incidents_total} incidents "
          f"({severities})")
    print(f"[ OK ] results written to {args.out}")
    print(f"[INFO] report: {args.out / REPORT_FILE}")
    return 0


def generate_scenarios_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Write the deterministic SYNTHETIC LANL-format scenario file."
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(generate_scenario_text())
    print(f"[ OK ] synthetic scenarios written to {args.out}")
    return 0
