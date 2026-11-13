"""End-to-end on the committed SYNTHETIC lateral-movement scenarios: ingest -> detect.

Each scenario's expectation is written by hand in `data_gen/lateral_scenarios.py`.
Passing shows the rules behave as designed; it is not evidence of real-world accuracy.
"""

from collections import Counter

import pytest

from agentsoc import app_data
from agentsoc.api.service import Service
from agentsoc.cli import detect_main, generate_scenarios_main, ingest_main
from agentsoc.config import PROJECT_ROOT
from agentsoc.data_gen.lateral_scenarios import (
    SCENARIOS,
    generate_large_batch_text,
    generate_lateral_scenario_text,
)
from agentsoc.detection.config import load_detection_config
from agentsoc.detection.engine import run_detection
from agentsoc.detection.inputs import load_verified_inputs
from agentsoc.store.datasets import load_events
from agentsoc.store.detections import load_detection_summary, load_findings, load_incidents
from tests.support import signed_in_client

SAMPLES = PROJECT_ROOT / "data" / "samples"
INPUT = SAMPLES / "auth_lateral_scenarios_synthetic.txt"
CONFIG = SAMPLES / "lateral_scenarios_detection_config.json"


def test_committed_file_matches_generator():
    assert INPUT.read_bytes() == generate_lateral_scenario_text().encode("utf-8")


def test_generator_cli_writes_the_same_file(tmp_path):
    out = tmp_path / "x.txt"
    assert generate_scenarios_main(["--out", str(out), "--set", "lateral"]) == 0
    assert out.read_bytes() == INPUT.read_bytes()


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("lateral")
    dataset, out = tmp / "dataset", tmp / "detection"
    assert ingest_main([str(INPUT), "--out", str(dataset), "--source", "synthetic",
                        "--label", "SYNTHETIC lateral scenarios"]) == 0
    assert detect_main([str(dataset), "--config", str(CONFIG), "--out", str(out)]) == 0
    return dataset, out, load_findings(out), load_incidents(out)


def of(accounts, findings):
    return [f for f in findings if f.user in accounts]


def accounts_in(scenario):
    expected = scenario.expected
    named = {a.user for a in scenario.accounts} | set(expected.findings)
    named |= set(expected.without_baseline)
    return named


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.key)
def test_findings_per_account(run, scenario):
    _, _, findings, _ = run
    actual = {}
    for finding in of(accounts_in(scenario), findings):
        actual.setdefault(finding.user, Counter())[finding.rule_id] += 1
    assert {u: dict(c) for u, c in actual.items()} == {
        u: dict(c) for u, c in scenario.expected.findings.items()
    }


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.key)
def test_severity_per_account(run, scenario):
    _, _, _, incidents = run
    actual = {i.principal_user: i.severity.value for i in incidents
              if i.principal_user in accounts_in(scenario)}
    assert actual == dict(scenario.expected.severity)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.key)
def test_chain_paths(run, scenario):
    _, _, findings, _ = run
    paths = sorted(f.metrics["path"] for f in of(accounts_in(scenario), findings)
                   if f.rule_id == "LATERAL_CHAIN")
    assert paths == sorted(scenario.expected.chain_paths)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.key)
def test_pivots(run, scenario):
    _, _, findings, _ = run
    actual = sorted((f.user, f.metrics["arriving_account"], f.metrics["pivot_host"])
                    for f in of(accounts_in(scenario), findings)
                    if f.rule_id == "CROSS_ACCOUNT_PIVOT")
    assert actual == sorted(scenario.expected.pivots)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.key)
def test_jump_context(run, scenario):
    _, _, findings, _ = run
    mine = of(accounts_in(scenario), findings)
    assert {f.user for f in mine if "benign_context" in f.metrics} == set(
        scenario.expected.benign_context)
    assert {f.user for f in mine if "severity_adjustment" in f.metrics} == set(
        scenario.expected.severity_adjusted)


def test_accounts_without_baseline_are_reported(run):
    _, out, _, _ = run
    reported = set(load_detection_summary(out).partitions["synthetic"].users_without_baseline)
    expected = {u for s in SCENARIOS for u in s.expected.without_baseline}
    assert expected <= reported


def test_duplicates_collapse(run):
    _, out, _, _ = run
    assert load_detection_summary(out).partitions["synthetic"].collapsed_duplicates == 2


def test_every_evidence_id_exists_with_its_timestamp(run):
    dataset, _, findings, incidents = run
    events = {e.event_id: e for e in load_events(dataset)}
    for finding in findings:
        cited = [events[e] for e in finding.event_ids]
        assert finding.first_seen == min(e.timestamp for e in cited)
        assert finding.last_seen == max(e.timestamp for e in cited)
    for incident in incidents:
        assert set(incident.event_ids) <= set(events)
        assert incident.datasets == ["synthetic"]


def test_failed_events_are_never_movement_evidence(run):
    dataset, _, findings, _ = run
    events = {e.event_id: e for e in load_events(dataset)}
    for finding in findings:
        if finding.rule_id in ("LATERAL_CHAIN", "CROSS_ACCOUNT_PIVOT"):
            assert all(events[e].outcome.value == "Success" for e in finding.event_ids)


def test_rest_api_serves_a_pivot_incident(tmp_path, monkeypatch):
    monkeypatch.setattr(app_data, "DEMO_INPUT", INPUT)
    monkeypatch.setattr(app_data, "DEMO_CONFIG", CONFIG)
    service = Service(root=tmp_path, provider_factory=lambda: (None, "LLM disabled for test"))
    client = signed_in_client(service)

    listing = client.get("/api/incidents", params={"rule": "CROSS_ACCOUNT_PIVOT"}).json()
    assert {i["principal_user"] for i in listing["items"]} == {
        "s10.bob@CORP", "s15.bob@CORP",
    }
    incident_id = next(i["incident_id"] for i in listing["items"]
                       if i["principal_user"] == "s15.bob@CORP")
    detail = client.get(f"/api/incidents/{incident_id}").json()
    pivot = next(f for f in detail["findings"] if f["rule_id"] == "CROSS_ACCOUNT_PIVOT")
    assert pivot["metrics"]["pivot_host"] == "S15-JUMP-1"
    assert "benign_context" in pivot["metrics"]
    assert "s15.alice@CORP" in detail["involved_users"]

    investigated = client.post(f"/api/incidents/{incident_id}/investigate")
    assert investigated.status_code == 200
    assert investigated.json()["status"] == "completed_limited"


def test_large_batch_finds_exactly_the_planted_movement(tmp_path):
    text, chains, pivots = generate_large_batch_text(1000)
    source = tmp_path / "bulk.txt"
    source.write_text(text, encoding="utf-8", newline="\n")
    dataset = tmp_path / "dataset"
    assert ingest_main([str(source), "--out", str(dataset), "--source", "synthetic",
                        "--label", "SYNTHETIC large batch"]) == 0
    events = [e for i in load_verified_inputs([dataset]) for e in i.events]
    result = run_detection(events, load_detection_config(None))
    by_rule = Counter(f.rule_id for f in result.findings)
    assert (by_rule["LATERAL_CHAIN"], by_rule["CROSS_ACCOUNT_PIVOT"]) == (chains, pivots)
