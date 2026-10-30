"""End-to-end: committed synthetic LANL-format sample → CLI → processed dataset.

Expected numbers are documented in data/samples/README.md.
"""

import json

from agentsoc.cli import ingest_main
from agentsoc.config import PROJECT_ROOT
from agentsoc.schemas import DatasetSource
from agentsoc.store.datasets import REJECTED_FILE, REPORT_JSON, load_events, load_manifest

SAMPLE = PROJECT_ROOT / "data" / "samples" / "lanl_format_synthetic_sample.txt"


def run(tmp_path, *extra):
    out = tmp_path / "ds"
    code = ingest_main(
        [str(SAMPLE), "--out", str(out), "--source", "synthetic",
         "--label", "SYNTHETIC sample in LANL format", *extra]
    )
    return code, out


def test_sample_produces_documented_results(tmp_path):
    code, out = run(tmp_path)
    assert code == 0

    report = json.loads((out / REPORT_JSON).read_text())
    assert report["lines_read"] == 25
    assert report["blank_lines"] == 1
    assert report["accepted"] == 16
    assert report["rejected"] == 8
    assert report["exact_duplicates"] == 2
    assert report["out_of_order"] == 1
    assert report["rejected_by_reason"] == {
        "INVALID_TIMESTAMP": 2, "WRONG_FIELD_COUNT": 2, "INVALID_FIELD": 1,
        "INVALID_ORIENTATION": 1, "INVALID_OUTCOME": 1, "MISSING_REQUIRED_FIELD": 1,
    }
    assert report["outcome_counts"] == {"Success": 13, "Fail": 3}

    manifest = load_manifest(out)
    assert manifest.dataset is DatasetSource.SYNTHETIC
    events = load_events(out)
    assert {e.dataset for e in events} == {DatasetSource.SYNTHETIC}

    # The prompt-injection line never becomes an event.
    assert all("ignore" not in e.model_dump_json() for e in events)
    rejected = [json.loads(x) for x in (out / REJECTED_FILE).read_text().splitlines()]
    assert {r["line"] for r in rejected} == {14, 15, 16, 17, 18, 19, 20, 21}


def test_limit_window(tmp_path):
    code, out = run(tmp_path, "--limit", "5")
    assert code == 0
    assert load_manifest(out).event_count == 5


def test_missing_input_returns_error_code(tmp_path, capsys):
    args = [str(tmp_path / "missing.txt"), "--out", str(tmp_path / "o"), "--label", "x"]
    code = ingest_main(args)
    assert code == 1
    assert "[FAIL]" in capsys.readouterr().out
