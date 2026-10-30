"""End-to-end on committed SYNTHETIC inputs: generate -> ingest (Phase 1) -> detect.

Expected outcomes are documented in data/samples/README.md. Passing these tests
shows the rules behave as designed on known scenarios; it is not evidence of
real-world detection accuracy.
"""

import json

import pytest

from agentsoc.cli import detect_main, ingest_main
from agentsoc.config import PROJECT_ROOT
from agentsoc.data_gen.scenarios import generate_scenario_text
from agentsoc.store.datasets import EVENTS_FILE, load_events
from agentsoc.store.detections import load_findings, load_incidents

SAMPLES = PROJECT_ROOT / "data" / "samples"
SCENARIOS = SAMPLES / "auth_scenarios_synthetic.txt"
SCENARIO_CONFIG = SAMPLES / "scenarios_detection_config.json"
PHASE1_SAMPLE = SAMPLES / "lanl_format_synthetic_sample.txt"


def ingest(tmp_path, source, name):
    out = tmp_path / name
    code = ingest_main([str(source), "--out", str(out), "--source", "synthetic",
                        "--label", f"SYNTHETIC {source.name}"])
    assert code == 0
    return out


def test_committed_scenarios_match_generator():
    assert SCENARIOS.read_bytes() == generate_scenario_text().encode("utf-8")


@pytest.fixture
def scenario_run(tmp_path):
    dataset = ingest(tmp_path, SCENARIOS, "scenarios")
    out = tmp_path / "detection"
    assert detect_main([str(dataset), "--config", str(SCENARIO_CONFIG), "--out", str(out)]) == 0
    return dataset, out


def test_scenarios_produce_documented_incidents(scenario_run):
    _, out = scenario_run
    incidents = {i.principal_user: i for i in load_incidents(out)}
    assert set(incidents) == {"alice.fin@CORP", "carol.fin@CORP", "dave.it@CORP"}

    alice = incidents["alice.fin@CORP"]
    assert alice.severity == "CRITICAL"
    assert set(alice.rule_ids) == {
        "FAILURE_BURST", "FAIL_THEN_SUCCESS", "NEW_SRC_HOST", "NEW_DST_HOST",
        "MULTI_HOST_SPREAD", "LATERAL_CHAIN", "SENSITIVE_HOST_ACCESS",
    }
    chain = next(f for f in alice.findings if f.rule_id == "LATERAL_CHAIN")
    assert chain.metrics["path"] == "WS-FIN-07 > SRV-APP-02 > DB-FIN-01"

    carol = incidents["carol.fin@CORP"]
    assert (carol.severity, carol.rule_ids) == ("MEDIUM", ["FAIL_THEN_SUCCESS"])
    assert any("typo" in b for b in carol.benign_explanations)

    dave = incidents["dave.it@CORP"]
    assert dave.severity == "LOW"  # MEDIUM by points, lowered for configured admin
    assert "known-admin-account" in dave.flags

    for incident in incidents.values():
        assert incident.datasets == ["synthetic"]
        assert "synthetic-data" in incident.flags


def test_benign_scenarios_produce_nothing(scenario_run):
    _, out = scenario_run
    users = {f.user for f in load_findings(out)}
    assert "bob.hr@CORP" not in users  # repeated familiar access; sub-threshold failures
    assert "erin.ops@CORP" not in users  # routine activity with a duplicate record


def test_every_evidence_id_exists_in_verified_dataset(scenario_run):
    dataset, out = scenario_run
    known = {e.event_id for e in load_events(dataset)}
    for incident in load_incidents(out):
        assert set(incident.event_ids) <= known
    for finding in load_findings(out):
        assert set(finding.event_ids) <= known


def test_summary_records_input_hashes(scenario_run):
    dataset, out = scenario_run
    summary = json.loads((out / "detection_summary.json").read_text())
    manifest = json.loads((dataset / "manifest.json").read_text())
    assert summary["inputs"][0]["events_sha256"] == manifest["events_sha256"]
    assert summary["inputs"][0]["dataset"] == "synthetic"
    assert summary["partitions"]["synthetic"]["collapsed_duplicates"] == 1


def test_phase1_sample_yields_no_incidents(tmp_path):
    dataset = ingest(tmp_path, PHASE1_SAMPLE, "p1")
    out = tmp_path / "det"
    assert detect_main([str(dataset), "--out", str(out)]) == 0
    assert load_incidents(out) == []


def test_tampered_dataset_fails_cli(tmp_path, capsys):
    dataset = ingest(tmp_path, PHASE1_SAMPLE, "p1")
    path = dataset / EVENTS_FILE
    path.write_text(path.read_text().replace("U22", "U23"), encoding="utf-8")
    assert detect_main([str(dataset), "--out", str(tmp_path / "det")]) == 1
    assert "hash does not match" in capsys.readouterr().out
