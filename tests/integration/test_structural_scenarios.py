"""End-to-end on the committed SYNTHETIC structural scenarios: ingest -> detect -> SSE.

Includes the Target 2 acceptance test: a naive findings-to-edges graph must fail where the
SSE succeeds. Passing shows designed behaviour; it is not evidence of real-world accuracy.
"""

import hashlib
import json
from collections import Counter

import pytest

from agentsoc import app_data
from agentsoc.api.service import Service
from agentsoc.cli import (
    assess_structure_main,
    detect_main,
    generate_scenarios_main,
    ingest_main,
)
from agentsoc.config import PROJECT_ROOT
from agentsoc.data_gen.lateral_scenarios import generate_large_batch_text
from agentsoc.data_gen.structural_scenarios import SCENARIOS, generate_structural_scenario_text
from agentsoc.evaluation.structural_report import (
    check_scenario,
    naive_findings_graph,
    naive_has_walk,
    naive_longest_hops,
)
from agentsoc.exceptions import DatasetIntegrityError
from agentsoc.graph.assess import run_structural_assessment
from agentsoc.graph.config import StructuralConfig
from agentsoc.graph.store import (
    ASSESSMENTS_FILE,
    STRUCTURAL_DIR,
    SUMMARY_FILE,
    load_assessments,
    load_structural_summary,
)
from agentsoc.schemas.graph import PathKind
from agentsoc.store.datasets import load_events
from agentsoc.store.detections import (
    DETECTIONS_FILE,
    INCIDENTS_FILE,
    REPORT_FILE,
    load_incidents,
)
from agentsoc.store.detections import SUMMARY_FILE as DETECTION_SUMMARY
from tests.support import signed_in_client

INPUT = PROJECT_ROOT / "data" / "samples" / "auth_structural_scenarios_synthetic.txt"
BY_KEY = {s.key: s for s in SCENARIOS}


def test_committed_file_matches_generator():
    assert INPUT.read_bytes() == generate_structural_scenario_text().encode("utf-8")


def test_generator_cli_writes_the_same_file(tmp_path):
    out = tmp_path / "x.txt"
    assert generate_scenarios_main(["--out", str(out), "--set", "structural"]) == 0
    assert out.read_bytes() == INPUT.read_bytes()


def prepare(tmp, source=INPUT):
    dataset, detection = tmp / "dataset", tmp / "detection"
    assert ingest_main([str(source), "--out", str(dataset), "--source", "synthetic",
                        "--label", "SYNTHETIC structural"]) == 0
    assert detect_main([str(dataset), "--out", str(detection)]) == 0
    return dataset, detection


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    dataset, detection = prepare(tmp_path_factory.mktemp("sse"))
    assert assess_structure_main([str(dataset), "--detection", str(detection)]) == 0
    incidents = {i.incident_id: i for i in load_incidents(detection)}
    assessments = {incidents[a.incident_id].principal_user: a for a in load_assessments(detection)}
    by_user = {i.principal_user: i for i in incidents.values()}
    events = {e.event_id: e for e in load_events(dataset)}
    return dataset, detection, assessments, by_user, events


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.key)
def test_scenario_matches_its_expectation(run, scenario):
    _, _, assessments, _, _ = run
    assert check_scenario(scenario, assessments) == []


class TestBeyondTheNaiveFindingsGraph:
    """Acceptance: where a graph of the findings' own events fails and the SSE succeeds."""

    def setup(self, run, key):
        _, _, assessments, by_user, events = run
        user = BY_KEY[key].expected.principal
        return assessments[user], naive_findings_graph(by_user[user], events)

    @pytest.mark.parametrize("key", ["T05", "T06", "T07"])
    def test_expansion_through_events_no_finding_cites(self, run, key):
        sse, naive = self.setup(run, key)
        extended = max((p for p in sse.paths if p.context_event_ids),
                       key=lambda p: len(p.event_ids))
        assert not naive_has_walk(naive, extended.hosts)
        assert len(extended.event_ids) > naive_longest_hops(naive)

    def test_upstream_expansion_across_accounts(self, run):
        sse, _ = self.setup(run, "T05")
        path = next(p for p in sse.paths if p.kind is PathKind.INFERRED)
        assert path.hosts[0] == "WS-T05-ALICE" and path.hosts[-1] == "T05-SRV"
        assert len(path.accounts) == 2

    @pytest.mark.parametrize("key,walk", [
        ("T10", ("WS-T10-USER", "T10-B", "T10-C")),
        ("T11", ("WS-T11-USER", "T11-A", "T11-B")),
    ])
    def test_rejects_a_path_the_naive_graph_reports(self, run, key, walk):
        sse, naive = self.setup(run, key)
        assert naive_has_walk(naive, walk)
        assert list(walk) not in [p.hosts for p in sse.paths]
        assert sse.disconnected

    def test_walk_through_a_cycle_is_longer_than_any_simple_path(self, run):
        sse, naive = self.setup(run, "T12")
        assert max(len(p.event_ids) for p in sse.paths) > naive_longest_hops(naive)

    def test_explains_a_break_the_naive_graph_cannot(self, run):
        sse, naive = self.setup(run, "T08")
        assert not naive.has_edge("T08-A", "T08-B")
        assert sse.disconnected[0].reason == "FAILED_LINK_ONLY"

    def test_marks_a_shared_server_link_as_weak(self, run):
        sse, naive = self.setup(run, "T14")
        assert naive.has_edge("T14-HUB", "T14-SRV")
        path = next(p for p in sse.paths if p.kind is PathKind.INFERRED)
        assert any(k.ambiguous for k in path.links)

    def test_does_not_accept_a_same_second_chain_as_established(self, run):
        sse, naive = self.setup(run, "T15")
        assert naive_has_walk(naive, ("WS-T15-USER", "T15-A", "T15-B"))
        assert sse.finding_validations[0].verdict == "CONDITIONALLY_FEASIBLE"

    def test_finds_hosts_every_route_must_cross(self, run):
        sse, _ = self.setup(run, "T16")
        assert any(c.via_hosts == ["T16-HUB", "T16-MID"] for c in sse.choke_points)


def test_every_edge_keeps_original_event_id_and_provenance(run):
    _, _, assessments, _, events = run
    for assessment in assessments.values():
        for edge in assessment.edges:
            event = events[edge.event_id]
            assert (edge.timestamp, edge.dataset, edge.raw_ref) == (
                event.timestamp, event.dataset, event.raw_ref)


def test_duplicates_keep_every_event_id(run):
    _, _, assessments, _, events = run
    edges = [e for e in assessments["t13.user@CORP"].edges if e.duplicate_event_ids]
    assert len(edges) == 2
    for edge in edges:
        assert all(d in events for d in edge.duplicate_event_ids)


def _hashes(detection):
    names = (DETECTIONS_FILE, INCIDENTS_FILE, DETECTION_SUMMARY, REPORT_FILE)
    return {n: hashlib.sha256((detection / n).read_bytes()).hexdigest() for n in names}


class TestPersistence:
    def test_detection_outputs_stay_byte_identical(self, tmp_path):
        dataset, detection = prepare(tmp_path)
        before = _hashes(detection)
        run_structural_assessment([dataset], detection)
        assert _hashes(detection) == before

    def test_output_is_byte_identical_across_runs(self, tmp_path):
        dataset, detection = prepare(tmp_path)
        run_structural_assessment([dataset], detection)
        path = detection / STRUCTURAL_DIR / ASSESSMENTS_FILE
        first = path.read_bytes()
        run_structural_assessment([dataset], detection, overwrite=True)
        assert path.read_bytes() == first

    def test_refuses_to_overwrite_unless_asked(self, tmp_path):
        dataset, detection = prepare(tmp_path)
        run_structural_assessment([dataset], detection)
        with pytest.raises(DatasetIntegrityError, match="not empty"):
            run_structural_assessment([dataset], detection)

    def test_records_its_own_config_hash(self, tmp_path):
        dataset, detection = prepare(tmp_path)
        config = StructuralConfig(max_paths=7)
        summary = run_structural_assessment([dataset], detection, config)
        assert summary.structural_config_sha256 == config.sha256()
        assert summary.detection_config_sha256 != summary.structural_config_sha256

    def test_tampered_assessments_are_rejected(self, tmp_path):
        dataset, detection = prepare(tmp_path)
        run_structural_assessment([dataset], detection)
        path = detection / STRUCTURAL_DIR / ASSESSMENTS_FILE
        path.write_text(path.read_text(encoding="utf-8").replace("FEASIBLE", "INFEASIBLE", 1),
                        encoding="utf-8")
        with pytest.raises(DatasetIntegrityError, match="hash does not match"):
            load_assessments(detection)

    def test_assessments_of_another_detection_run_are_rejected(self, tmp_path):
        dataset, detection = prepare(tmp_path)
        run_structural_assessment([dataset], detection)
        path = detection / DETECTION_SUMMARY
        data = json.loads(path.read_text(encoding="utf-8"))
        data["incidents_sha256"] = "b" * 64
        path.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(DatasetIntegrityError, match="different detection run"):
            load_assessments(detection)

    def test_tampered_dataset_stops_the_assessment(self, tmp_path):
        dataset, detection = prepare(tmp_path)
        path = dataset / "events.jsonl"
        path.write_text(path.read_text(encoding="utf-8").replace("T02-A", "T02-X", 1),
                        encoding="utf-8")
        with pytest.raises(DatasetIntegrityError):
            run_structural_assessment([dataset], detection)

    def test_summary_is_invalid_when_edited(self, tmp_path):
        dataset, detection = prepare(tmp_path)
        run_structural_assessment([dataset], detection)
        (detection / STRUCTURAL_DIR / SUMMARY_FILE).write_text("{}", encoding="utf-8")
        with pytest.raises(DatasetIntegrityError, match="invalid"):
            load_structural_summary(detection)


class TestRestApi:
    @pytest.fixture
    def client(self, tmp_path, monkeypatch):
        monkeypatch.setattr(app_data, "DEMO_INPUT", INPUT)
        monkeypatch.setattr(app_data, "DEMO_CONFIG", PROJECT_ROOT / "config" / "detection.json")
        service = Service(root=tmp_path, provider_factory=lambda: (None, "LLM disabled for test"))
        return signed_in_client(service)

    def incident_of(self, client, user):
        items = client.get("/api/incidents", params={"page_size": 200}).json()["items"]
        return next(i["incident_id"] for i in items if i["principal_user"] == user)

    def test_structure_endpoint_returns_the_assessment(self, client):
        incident = self.incident_of(client, "t05.bob@CORP")
        body = client.get(f"/api/incidents/{incident}/structure").json()
        assert body["is_proof_of_compromise"] is False
        assert any(p["kind"] == "INFERRED" and p["context_event_ids"] for p in body["paths"])
        assert all(e["raw_ref"]["line"] >= 1 for e in body["edges"])

    def test_unknown_incident_is_404(self, client):
        assert client.get("/api/incidents/INC-99999/structure").status_code == 404

    def test_investigation_uses_the_structural_evidence(self, client):
        incident = self.incident_of(client, "t03.user@CORP")
        body = client.post(f"/api/incidents/{incident}/investigate").json()
        assert body["structural_evidence"] == "used"
        assert "Structural validation" in " ".join(h["narrative"] for h in body["hypotheses"])

    def test_structure_is_404_when_not_built(self, tmp_path, client, monkeypatch):
        monkeypatch.setattr(app_data, "run_structural_assessment", lambda *a, **k: None)
        other = Service(root=tmp_path / "fresh", provider_factory=lambda: (None, "off"))
        fresh = signed_in_client(other)
        incident = self.incident_of(fresh, "t03.user@CORP")
        assert fresh.get(f"/api/incidents/{incident}/structure").status_code == 404


def test_large_batch_stays_bounded_and_verified(tmp_path):
    text, chains, _ = generate_large_batch_text(1000)
    source = tmp_path / "bulk.txt"
    source.write_text(text, encoding="utf-8", newline="\n")
    dataset, detection = prepare(tmp_path, source)
    summary = run_structural_assessment([dataset], detection)
    assessments = load_assessments(detection)
    assert summary.incidents_assessed == len(assessments) > 0
    assert max(a.stats.context_events for a in assessments) <= (
        StructuralConfig().max_context_events)
    verdicts = Counter(v.verdict.value for a in assessments for v in a.finding_validations)
    assert verdicts["FEASIBLE"] == chains
