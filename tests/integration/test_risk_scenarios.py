"""End-to-end on the committed SYNTHETIC risk scenarios: ingest -> detect -> SSE -> RSEM.

Expected scores are worked out by hand in `data_gen/risk_scenarios.py`. Passing shows the
arithmetic and safeguards behave as designed; it is not calibration or evidence of accuracy.
"""

import hashlib
import json

import pytest

from agentsoc import app_data
from agentsoc.api.service import Service
from agentsoc.cli import (
    assess_risk_main,
    assess_structure_main,
    detect_main,
    generate_scenarios_main,
    ingest_main,
)
from agentsoc.config import PROJECT_ROOT
from agentsoc.data_gen.lateral_scenarios import generate_large_batch_text
from agentsoc.data_gen.risk_scenarios import SCENARIOS, generate_risk_scenario_text
from agentsoc.exceptions import DatasetIntegrityError
from agentsoc.graph.store import ASSESSMENTS_FILE, STRUCTURAL_DIR
from agentsoc.graph.store import SUMMARY_FILE as STRUCTURAL_SUMMARY
from agentsoc.risk.actions import DESTRUCTIVE
from agentsoc.risk.assess import run_risk_assessment
from agentsoc.risk.config import RiskConfig
from agentsoc.risk.store import (
    RECORDS_FILE,
    RISK_DIR,
    SUMMARY_FILE,
    load_risk_records,
    load_risk_summary,
)
from agentsoc.store.detections import (
    DETECTIONS_FILE,
    INCIDENTS_FILE,
    REPORT_FILE,
    load_incidents,
)
from agentsoc.store.detections import SUMMARY_FILE as DETECTION_SUMMARY
from tests.support import signed_in_client

SAMPLES = PROJECT_ROOT / "data" / "samples"
INPUT = SAMPLES / "auth_risk_scenarios_synthetic.txt"
CONFIG = SAMPLES / "risk_scenarios_detection_config.json"


def test_committed_file_matches_generator():
    assert INPUT.read_bytes() == generate_risk_scenario_text().encode("utf-8")


def test_generator_cli_writes_the_same_file(tmp_path):
    out = tmp_path / "x.txt"
    assert generate_scenarios_main(["--out", str(out), "--set", "risk"]) == 0
    assert out.read_bytes() == INPUT.read_bytes()


def prepare(tmp, source=INPUT, config=CONFIG):
    dataset, detection = tmp / "dataset", tmp / "detection"
    assert ingest_main([str(source), "--out", str(dataset), "--source", "synthetic",
                        "--label", "SYNTHETIC risk"]) == 0
    args = [str(dataset), "--out", str(detection)]
    assert detect_main([*args, "--config", str(config)] if config else args) == 0
    assert assess_structure_main([str(dataset), "--detection", str(detection)]) == 0
    return detection


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    detection = prepare(tmp_path_factory.mktemp("risk"))
    assert assess_risk_main(["--detection", str(detection)]) == 0
    incidents = {i.incident_id: i for i in load_incidents(detection)}
    return detection, {incidents[r.incident_id].principal_user: r
                       for r in load_risk_records(detection)}


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.key)
def test_score_matches_the_hand_calculation(run, scenario):
    _, records = run
    expected = scenario.expected
    record = records[expected.principal]
    assert record.risk.score == pytest.approx(expected.score, abs=0.051), scenario.working
    assert record.risk.band == expected.band


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.key)
def test_detection_severity_stays_visible_and_unchanged(run, scenario):
    _, records = run
    expected = scenario.expected
    assert records[expected.principal].severity_comparison.detection_severity == expected.severity


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.key)
def test_destructive_actions_only_when_expected(run, scenario):
    _, records = run
    record = records[scenario.expected.principal]
    has_destructive = any(a.action_type in DESTRUCTIVE for a in record.actions)
    assert has_destructive == scenario.expected.destructive_allowed


def test_credential_only_stays_low_with_severity_visible(run):
    _, records = run
    record = records["r01.user@CORP"]
    assert record.risk.band == "LOW"
    assert record.severity_comparison.detection_severity == "MEDIUM"
    assert record.severity_comparison.relation == "RISK_LOWER"


def test_missing_baseline_does_not_raise_risk(run):
    _, records = run
    record = records["r18.new@CORP"]
    baseline = next(c for c in record.confidence.components if c.name == "baseline_coverage")
    assert baseline.value == 0
    assert record.risk.score == pytest.approx(33.0, abs=0.051)


def test_no_event_is_credited_twice_anywhere(run):
    _, records = run
    for record in records.values():
        ids = [a.event_id for a in record.attributions]
        assert len(ids) == len(set(ids))


def _hashes(detection):
    names = [detection / n for n in (DETECTIONS_FILE, INCIDENTS_FILE, DETECTION_SUMMARY,
                                     REPORT_FILE)]
    names += [detection / STRUCTURAL_DIR / n for n in (ASSESSMENTS_FILE, STRUCTURAL_SUMMARY)]
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in names}


class TestPersistence:
    def test_detection_and_structural_outputs_stay_byte_identical(self, tmp_path):
        detection = prepare(tmp_path)
        before = _hashes(detection)
        run_risk_assessment(detection)
        assert _hashes(detection) == before

    def test_output_is_byte_identical_across_runs(self, tmp_path):
        detection = prepare(tmp_path)
        run_risk_assessment(detection)
        path = detection / RISK_DIR / RECORDS_FILE
        first = path.read_bytes()
        run_risk_assessment(detection, overwrite=True)
        assert path.read_bytes() == first

    def test_records_its_own_config_hash(self, tmp_path):
        detection = prepare(tmp_path)
        config = RiskConfig(max_actions=2)
        assert run_risk_assessment(detection, config).risk_config_sha256 == config.sha256()

    def test_refuses_to_overwrite_unless_asked(self, tmp_path):
        detection = prepare(tmp_path)
        run_risk_assessment(detection)
        with pytest.raises(DatasetIntegrityError, match="not empty"):
            run_risk_assessment(detection)

    def test_needs_a_structural_assessment(self, tmp_path):
        dataset, detection = tmp_path / "d", tmp_path / "o"
        assert ingest_main([str(INPUT), "--out", str(dataset), "--source", "synthetic",
                            "--label", "SYNTHETIC risk"]) == 0
        assert detect_main([str(dataset), "--out", str(detection)]) == 0
        with pytest.raises(DatasetIntegrityError):
            run_risk_assessment(detection)

    def test_tampered_records_are_rejected(self, tmp_path):
        detection = prepare(tmp_path)
        run_risk_assessment(detection)
        path = detection / RISK_DIR / RECORDS_FILE
        path.write_text(path.read_text(encoding="utf-8").replace('"LOW"', '"HIGH"', 1),
                        encoding="utf-8")
        with pytest.raises(DatasetIntegrityError, match="hash does not match"):
            load_risk_records(detection)

    def test_changed_detection_run_is_rejected(self, tmp_path):
        detection = prepare(tmp_path)
        run_risk_assessment(detection)
        path = detection / DETECTION_SUMMARY
        data = json.loads(path.read_text(encoding="utf-8"))
        data["incidents_sha256"] = "b" * 64
        path.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(DatasetIntegrityError, match="detection run"):
            load_risk_records(detection)

    def test_changed_structural_assessment_is_rejected(self, tmp_path):
        detection = prepare(tmp_path)
        run_risk_assessment(detection)
        path = detection / STRUCTURAL_DIR / STRUCTURAL_SUMMARY
        data = json.loads(path.read_text(encoding="utf-8"))
        data["assessments_sha256"] = "c" * 64
        path.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(DatasetIntegrityError, match="structural"):
            load_risk_records(detection)

    def test_summary_counts(self, tmp_path):
        detection = prepare(tmp_path)
        run_risk_assessment(detection)
        summary = load_risk_summary(detection)
        assert sum(summary.bands.values()) == summary.incidents_scored > 0


class TestRestApi:
    @pytest.fixture
    def env(self, tmp_path, monkeypatch):
        monkeypatch.setattr(app_data, "DEMO_INPUT", INPUT)
        monkeypatch.setattr(app_data, "DEMO_CONFIG", CONFIG)
        service = Service(root=tmp_path, provider_factory=lambda: (None, "LLM disabled for test"))
        return signed_in_client(service), service, tmp_path

    def incident_of(self, client, user):
        items = client.get("/api/incidents", params={"page_size": 200}).json()["items"]
        return next(i["incident_id"] for i in items if i["principal_user"] == user)

    def test_risk_endpoint_keeps_the_three_numbers_separate(self, env):
        client, _, _ = env
        incident = self.incident_of(client, "r07.user@CORP")
        body = client.get(f"/api/incidents/{incident}/risk").json()
        assert body["detection_severity"] == "CRITICAL"
        assert body["record"]["risk"]["band"] == "HIGH"
        assert body["investigation_confidence"]["score"] != body["record"]["risk"]["score"]
        assert body["record"]["is_proof_of_compromise"] is False

    def test_investigation_raises_confidence_not_risk(self, env):
        client, _, _ = env
        incident = self.incident_of(client, "r05.user@CORP")
        before = client.get(f"/api/incidents/{incident}/risk").json()
        assert client.post(f"/api/incidents/{incident}/investigate").status_code == 200
        after = client.get(f"/api/incidents/{incident}/risk").json()
        assert after["record"] == before["record"]
        assert (after["investigation_confidence"]["score"]
                > before["investigation_confidence"]["score"])
        assert after["investigation_confidence"]["includes_investigation"] is True
        assert after["model_generated_estimates"]

    def fresh_client(self, root, monkeypatch):
        monkeypatch.setattr(app_data, "run_risk_assessment", lambda *a, **k: None)  # no rebuild
        service = Service(root=root, provider_factory=lambda: (None, "off"))
        return signed_in_client(service)

    def test_tampered_file_is_never_served(self, env, monkeypatch):
        client, service, root = env
        incident = self.incident_of(client, "r07.user@CORP")
        path = service.source(None).detection_dir / RISK_DIR / RECORDS_FILE
        path.write_text(path.read_text(encoding="utf-8").replace('"HIGH"', '"LOW"', 1),
                        encoding="utf-8")
        other = self.fresh_client(root, monkeypatch)
        assert other.get(f"/api/incidents/{incident}/risk").status_code == 404

    def test_record_with_valid_hashes_but_bad_content_is_never_served(self, env, monkeypatch):
        client, service, root = env
        incident = self.incident_of(client, "r07.user@CORP")
        directory = service.source(None).detection_dir / RISK_DIR
        lines = (directory / RECORDS_FILE).read_text(encoding="utf-8").splitlines()
        data = json.loads(lines[0])
        data["actions"][0]["target"] = "PAYROLL-DB"
        lines[0] = json.dumps(data, separators=(",", ":"))
        text = "\n".join(lines) + "\n"
        (directory / RECORDS_FILE).write_text(text, encoding="utf-8", newline="\n")
        summary_path = directory / SUMMARY_FILE
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["records_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
        other = self.fresh_client(root, monkeypatch)
        assert other.get(f"/api/incidents/{incident}/risk").status_code == 404

    def test_demo_rebuilds_a_tampered_file_rather_than_serving_it(self, env):
        client, service, root = env
        incident = self.incident_of(client, "r07.user@CORP")
        path = service.source(None).detection_dir / RISK_DIR / RECORDS_FILE
        path.write_text(path.read_text(encoding="utf-8").replace('"HIGH"', '"LOW"', 1),
                        encoding="utf-8")
        fresh = Service(root=root, provider_factory=lambda: (None, "off"))
        other = signed_in_client(fresh)
        assert other.get(f"/api/incidents/{incident}/risk").json()["record"]["risk"]["band"] == (
            "HIGH")

    def test_unknown_incident_is_404(self, env):
        client, _, _ = env
        assert client.get("/api/incidents/INC-99999/risk").status_code == 404

    def test_default_incident_sort_is_still_detection_severity(self, env):
        client, _, _ = env
        items = client.get("/api/incidents", params={"page_size": 200}).json()["items"]
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        severities = [rank[i["severity"]] for i in items]
        assert severities == sorted(severities)


def test_large_batch_is_scored_and_verified(tmp_path):
    text, _, _ = generate_large_batch_text(1000)
    source = tmp_path / "bulk.txt"
    source.write_text(text, encoding="utf-8", newline="\n")
    detection = prepare(tmp_path, source, None)
    summary = run_risk_assessment(detection)
    assert summary.incidents_scored == len(load_risk_records(detection)) > 0
