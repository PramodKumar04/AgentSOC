"""Dashboard additions to the API: graph integrity, separate risk and severity, explicit
assessment states, provenance, audit filtering and labelled data sources.

Data is SYNTHETIC, built in a temporary root. LLM traffic is scripted; nothing leaves the
machine."""

import hashlib
import json
import re
import shutil
from collections import Counter
from itertools import pairwise
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentsoc.api.service import Service
from agentsoc.app_data import REGISTRY_FILE, discover_sources
from agentsoc.demo_sources import LANL_DATASET, LANL_RUNS, SYNTHETIC_KEY, prepare_demo_sources
from agentsoc.graph import view as graph_view
from agentsoc.risk.store import load_risk_summary
from agentsoc.schemas.graph import LinkBasis
from tests.integration.test_api import CountingProvider, ok
from tests.support import signed_in_client

FAKE_KEY = "gsk_" + "K" * 52


@pytest.fixture(scope="module")
def built_root(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("dashboard")
    discover_sources(root)
    report = prepare_demo_sources(root)
    assert {p.key: p.status for p in report}[SYNTHETIC_KEY] == "built"
    return root


def make_client(root: Path) -> tuple[TestClient, Service]:
    svc = Service(root=root, provider_factory=lambda: (None, "LLM disabled for test"))
    svc.sources()  # discovery rebuilds a damaged demo, so tests damage files after this
    return signed_in_client(svc), svc


@pytest.fixture
def env(built_root, tmp_path):
    root = tmp_path / "root"
    shutil.copytree(built_root, root)
    return make_client(root)


@pytest.fixture(scope="module")
def shared(built_root):
    """Read-only client for tests that do not change anything."""
    return make_client(built_root)


def incident_ids(client, source):
    return [i["incident_id"] for i in ok(client.get(
        f"/api/incidents?source={source}&page_size=200"))["items"]]


def rewrite_json(path: Path, **changes) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload.update(changes)
    path.write_text(json.dumps(payload), encoding="utf-8")


@pytest.fixture(scope="module")
def graphs(shared):
    client, _ = shared
    return [
        (ok(client.get(f"/api/incidents/{i}/graph?source={SYNTHETIC_KEY}")),
         ok(client.get(f"/api/incidents/{i}/structure?source={SYNTHETIC_KEY}")))
        for i in incident_ids(client, SYNTHETIC_KEY)
    ]


class TestGraphIntegrity:
    def test_scenario_set_exercises_inferred_and_ambiguous_paths(self, graphs):
        kinds = Counter(p["kind"] for g, _ in graphs for p in g["paths"])
        assert kinds["OBSERVED"] and kinds["INFERRED"]
        assert any(p["ambiguous"] for g, _ in graphs for p in g["paths"])

    def test_event_links_are_exactly_the_original_events(self, graphs):
        for graph, structure in graphs:
            drawn = [e for k in graph["links"] if k["kind"] != "ACCOUNT" for e in k["event_ids"]]
            assert sorted(drawn) == sorted(e["event_id"] for e in structure["edges"])

    def test_every_link_matches_the_endpoints_and_kind_of_its_events(self, graphs):
        for graph, structure in graphs:
            edges = {e["event_id"]: e for e in structure["edges"]}
            for link in graph["links"]:
                for event_id in link["event_ids"]:
                    edge = edges[event_id]
                    if link["kind"] == "ACCOUNT":
                        assert link["source"] == f"user:{edge['account']}"
                        assert link["target"] in (f"host:{edge['src_host']}",
                                                  f"host:{edge['dst_host']}")
                        assert edge["kind"] != "ATTEMPT"
                    else:
                        assert link["kind"] == edge["kind"]
                        assert link["source"] == f"host:{edge['src_host']}"
                        assert link["target"] == f"host:{edge['dst_host']}"

    def test_no_link_or_node_is_invented(self, graphs):
        for graph, structure in graphs:
            nodes = {n["node_id"] for n in graph["nodes"]}
            hosts = {h for e in structure["edges"] for h in (e["src_host"], e["dst_host"])}
            users = {e["account"] for e in structure["edges"]}
            assert nodes == {f"host:{h}" for h in hosts} | {f"user:{u}" for u in users}
            assert all(k["source"] in nodes and k["target"] in nodes for k in graph["links"])

    def test_paths_are_copied_not_recalculated(self, graphs):
        for graph, structure in graphs:
            copied = [(p["path_id"], p["kind"], p["verdict"], p["event_ids"], p["hosts"])
                      for p in graph["paths"]]
            original = [(p["path_id"], p["kind"], p["verdict"], p["event_ids"], p["hosts"])
                        for p in structure["paths"]]
            assert copied == original

    def test_path_links_resolve_hop_by_hop_and_are_never_attempts(self, graphs):
        for graph, _ in graphs:
            links = {k["link_id"]: k for k in graph["links"]}
            for path in graph["paths"]:
                assert len(path["link_ids"]) == len(path["event_ids"])
                for link_id, event_id, (a, b) in zip(
                    path["link_ids"], path["event_ids"], pairwise(path["hosts"]), strict=True,
                ):
                    link = links[link_id]
                    assert link["kind"] == "MOVEMENT" and event_id in link["event_ids"]
                    assert (link["source"], link["target"]) == (f"host:{a}", f"host:{b}")
                    assert path["path_id"] in link["path_ids"]

    def test_account_switches_are_annotations_with_stated_conditions(self, graphs):
        for graph, structure in graphs:
            originals = {p["path_id"]: p for p in structure["paths"]}
            for path in graph["paths"]:
                expected = [k for k in originals[path["path_id"]]["links"]
                            if k["basis"] == LinkBasis.ACCOUNT_SWITCH.value]
                assert len(path["switches"]) == len(expected)
                assert bool(path["switches"]) == (path["kind"] == "INFERRED")
                assert bool(path["conditions"]) == (path["kind"] == "INFERRED")
                assert path["verdict"] == (
                    "CONDITIONALLY_FEASIBLE" if path["kind"] == "INFERRED" else "FEASIBLE")
                assert path["is_proof_of_compromise"] is False

    def test_events_keep_their_source_line(self, graphs):
        for graph, structure in graphs:
            edges = {e["event_id"]: e for e in structure["edges"]}
            assert {e["event_id"] for e in graph["events"]} == set(edges)
            for event in graph["events"]:
                assert event["raw_line"] == edges[event["event_id"]]["raw_ref"]["line"]
                assert event["dataset"] == "synthetic"

    def test_uses_the_networkx_builder(self, shared, monkeypatch):
        client, _ = shared
        calls = []
        original = graph_view.build_authentication_graph
        monkeypatch.setattr(graph_view, "build_authentication_graph",
                            lambda edges: calls.append(1) or original(edges))
        ok(client.get("/api/incidents/INC-00002/graph"))
        assert calls == [1]

    def test_roles_come_from_configuration_and_assessment(self, shared):
        client, _ = shared
        roles = {}
        for inc in incident_ids(client, SYNTHETIC_KEY):
            graph = ok(client.get(f"/api/incidents/{inc}/graph?source={SYNTHETIC_KEY}"))
            for node in graph["nodes"]:
                roles.setdefault(node["label"], set()).update(node["roles"])
        assert "SENSITIVE" in roles["R07-DB"]
        assert "PRINCIPAL" in roles["r13.admin@CORP"] and "ADMIN" in roles["r13.admin@CORP"]
        assert not any("JUMP_HOST" in roles[h] for h in ("R07-DB", "R08-DB"))

    def test_unknown_incident(self, shared):
        client, _ = shared
        assert client.get("/api/incidents/INC-99999/graph").status_code == 404


class TestSeverityAndRiskStaySeparate:
    def test_summary_and_overview_use_the_verified_records(self, shared):
        client, _ = shared
        page = ok(client.get(f"/api/incidents?source={SYNTHETIC_KEY}&page_size=200"))["items"]
        bands = Counter()
        for row in page:
            risk = ok(client.get(f"/api/incidents/{row['incident_id']}/risk"
                                 f"?source={SYNTHETIC_KEY}"))
            assert row["risk_score"] == risk["record"]["risk"]["score"]
            assert row["risk_band"] == risk["record"]["risk"]["band"]
            assert row["severity"] == risk["detection_severity"]
            bands[row["risk_band"]] += 1
        overview = ok(client.get(f"/api/overview?source={SYNTHETIC_KEY}"))
        assert overview["risk_counts"] == {s: bands.get(s, 0)
                                           for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        assert overview["risk_assessed"] == len(page) and overview["risk_status"]["state"] == (
            "available")

    def test_contributions_are_reported_points(self, shared):
        client, _ = shared
        view = ok(client.get("/api/incidents/INC-00002/risk"))
        components = {c["name"]: c for c in view["record"]["risk"]["components"]}
        assert set(view["contributions"]) == set(components)
        assert sum(view["contributions"].values()) == pytest.approx(
            view["record"]["base_score"], abs=0.05)

    def test_severity_and_risk_differ_on_some_incident(self, shared):
        client, _ = shared
        page = ok(client.get(f"/api/incidents?source={SYNTHETIC_KEY}&page_size=200"))["items"]
        assert any(r["severity"] != r["risk_band"] for r in page)

    def test_default_sort_is_still_detection_severity(self, shared):
        client, _ = shared
        rows = ok(client.get(f"/api/incidents?source={SYNTHETIC_KEY}&page_size=200"))["items"]
        rank = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        order = [rank.index(r["severity"]) for r in rows]
        assert order == sorted(order)
        assert client.get("/api/incidents?sort=risk").status_code == 422

    def test_actions_are_read_only_proposals(self, shared):
        client, _ = shared
        for inc in incident_ids(client, SYNTHETIC_KEY):
            view = ok(client.get(f"/api/incidents/{inc}/risk?source={SYNTHETIC_KEY}"))
            for action in view["record"]["actions"]:
                assert action["status"] == "PROPOSED" and action["dry_run"] is True

    def test_no_route_can_change_or_execute_an_action(self, shared):
        client, _ = shared
        paths = client.app.openapi()["paths"]  # every route, including nested routers
        changing = sorted(
            path for path, ops in paths.items()
            if set(ops) & {"post", "put", "patch", "delete"}
            and not path.startswith(("/api/auth/", "/api/admin/users", "/api/admin/datasources")))
        # Investigating and recording an analyst's decision change state; neither acts.
        assert changing == ["/api/incidents/{incident_id}/investigate",
                            "/api/incidents/{incident_id}/review"]
        assert not [path for path in paths if "action" in path]
        for verb in ("approve", "execute"):
            assert client.post(f"/api/incidents/INC-00002/actions/A/{verb}").status_code == 404


class TestAssessmentStates:
    def states(self, client, svc, incident="INC-00002"):
        detail = ok(client.get(f"/api/incidents/{incident}"))
        return detail, detail["assessments"]

    def expect_no_scores(self, client, svc, detail):
        assert detail["risk_score"] is None and detail["risk_band"] is None
        assert client.get("/api/incidents/INC-00002/risk").status_code == 404
        overview = ok(client.get("/api/overview"))
        assert overview["risk_counts"] is None and overview["risk_assessed"] == 0

    def test_available(self, env):
        client, svc = env
        detail, states = self.states(client, svc)
        assert states["structural"]["state"] == states["risk"]["state"] == "available"
        assert detail["risk_score"] is not None and states["truncated"] is False

    def test_not_assessed(self, env):
        client, svc = env
        detection = svc.source(None).detection_dir
        shutil.rmtree(detection / "structural")
        shutil.rmtree(detection / "risk")
        detail, states = self.states(client, svc)
        assert states["structural"]["state"] == states["risk"]["state"] == "not_assessed"
        self.expect_no_scores(client, svc, detail)
        assert client.get("/api/incidents/INC-00002/graph").status_code == 404
        assert client.get("/api/incidents/INC-00002/structure").status_code == 404

    def test_stale_structural_assessment(self, env):
        client, svc = env
        path = svc.source(None).detection_dir / "structural" / "structural_summary.json"
        rewrite_json(path, detection_incidents_sha256="0" * 64)
        detail, states = self.states(client, svc)
        assert states["structural"]["state"] == "stale"
        assert states["risk"]["state"] in ("stale", "unavailable")
        self.expect_no_scores(client, svc, detail)
        assert client.get("/api/incidents/INC-00002/graph").status_code == 404

    def test_stale_risk_records(self, env):
        client, svc = env
        path = svc.source(None).detection_dir / "risk" / "risk_summary.json"
        rewrite_json(path, structural_assessments_sha256="0" * 64)
        detail, states = self.states(client, svc)
        assert states["structural"]["state"] == "available"
        assert states["risk"]["state"] == "stale"
        self.expect_no_scores(client, svc, detail)

    def test_tampered_structural_file_is_unavailable(self, env):
        client, svc = env
        path = svc.source(None).detection_dir / "structural" / "assessments.jsonl"
        path.write_text(path.read_text(encoding="utf-8").replace("alice", "mallory"),
                        encoding="utf-8")
        _, states = self.states(client, svc)
        assert states["structural"]["state"] == "unavailable"
        assert client.get("/api/incidents/INC-00002/graph").status_code == 404

    def test_record_that_fails_verification_is_unavailable(self, env):
        client, svc = env
        directory = svc.source(None).detection_dir / "risk"
        records = directory / "risk_records.jsonl"
        lines = [json.loads(k) for k in records.read_text(encoding="utf-8").splitlines()]
        for line in lines:
            line["incident_sha256"] = "a" * 64  # hash matches the file, not the incident
        text = "".join(json.dumps(k, separators=(",", ":")) + "\n" for k in lines)
        records.write_text(text, encoding="utf-8", newline="\n")
        rewrite_json(directory / "risk_summary.json",
                     records_sha256=hashlib.sha256(text.encode()).hexdigest())
        detail, states = self.states(client, svc)
        assert states["risk"]["state"] == "unavailable"
        self.expect_no_scores(client, svc, detail)

    def test_truncation_is_reported(self, env):
        client, svc = env
        data = svc.loaded(None)
        items = svc._structural_for(data)[0]
        reason = "Context stops at 6 hops; more linked events exist."
        stats = items["INC-00002"].stats.model_copy(update={
            "truncated": True, "truncation_reasons": [reason]})
        items["INC-00002"] = items["INC-00002"].model_copy(update={"stats": stats})
        _, states = self.states(client, svc)
        assert states["truncated"] is True and states["truncation_reasons"] == [reason]
        graph = ok(client.get("/api/incidents/INC-00002/graph"))
        assert graph["stats"]["truncated"] is True

    def test_detail_text_is_fixed_and_safe(self, env):
        client, svc = env
        path = svc.source(None).detection_dir / "risk" / "risk_summary.json"
        path.write_text(f"{{broken {FAKE_KEY}", encoding="utf-8")
        response = client.get("/api/incidents/INC-00002")
        assert FAKE_KEY not in response.text and "Traceback" not in response.text
        assert ok(response)["assessments"]["risk"]["state"] == "unavailable"

    def test_a_source_without_assessments_still_serves_detection(self, env):
        client, svc = env
        detection = svc.source(None).detection_dir
        shutil.rmtree(detection / "structural")
        shutil.rmtree(detection / "risk")
        before = ok(client.get("/api/overview"))
        assert before["incidents_total"] == 3
        assert before["severity_counts"] == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 1, "LOW": 1}
        (row, *_) = ok(client.get("/api/datasets"))
        assert row["structural"]["state"] == row["risk"]["state"] == "not_assessed"
        assert row["risk"]["output_sha256"] is None and row["status"] == "verified"


class TestProvenanceAndAudit:
    def test_datasets_report_each_analysis_stage(self, shared):
        client, svc = shared
        rows = {d["key"]: d for d in ok(client.get("/api/datasets"))}
        row = rows[SYNTHETIC_KEY]
        summary = load_risk_summary(svc.source(SYNTHETIC_KEY).detection_dir)
        assert row["risk"]["engine_version"] == summary.engine_version
        assert row["risk"]["config_sha256"] == summary.risk_config_sha256
        assert row["risk"]["output_sha256"] == summary.records_sha256
        assert row["risk"]["records"] == 31
        assert row["structural"]["engine_version"] and len(
            row["structural"]["output_sha256"]) == 64

    def test_activity_is_filtered_before_the_limit(self, env):
        client, svc = env
        provider = CountingProvider(svc.loaded(None).incidents)
        svc.provider_factory = lambda: (provider, None)
        ok(client.post("/api/incidents/INC-00002/investigate"))
        for _ in range(5):
            ok(client.post("/api/incidents/INC-00001/investigate?rerun=true"))
        log = ok(client.get("/api/activity?subject=INC-00002&source=demo&limit=1"))
        assert [e["subject_id"] for e in log["entries"]] == ["INC-00002"]
        assert log["total"] == 1 and log["chain_intact"] is True

    def test_same_incident_id_in_another_source_is_not_mixed_in(self, env):
        client, svc = env
        provider = CountingProvider(svc.loaded(None).incidents)
        svc.provider_factory = lambda: (provider, None)
        ok(client.post("/api/incidents/INC-00002/investigate"))
        log = ok(client.get(f"/api/activity?subject=INC-00002&source={SYNTHETIC_KEY}"))
        assert log["entries"] == [] and log["total"] == 0

    def test_filtered_view_still_checks_the_whole_chain(self, env):
        client, svc = env
        ok(client.get("/api/overview"))
        provider = CountingProvider(svc.loaded(None).incidents)
        svc.provider_factory = lambda: (provider, None)
        ok(client.post("/api/incidents/INC-00002/investigate"))
        lines = svc.activity_path.read_text(encoding="utf-8").splitlines()
        lines[0] = re.sub(r'"actor":"[^"]+"', '"actor":"attacker"', lines[0])
        svc.activity_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        log = ok(client.get("/api/activity?subject=INC-00002&source=demo"))
        assert log["chain_intact"] is False

    def test_unfiltered_activity_is_unchanged(self, env):
        client, _ = env
        ok(client.get("/api/overview"))
        log = ok(client.get("/api/activity"))
        assert log["total"] == len(log["entries"]) and log["chain_intact"] is True

    @pytest.mark.parametrize("query", ["subject=a%20b", "subject=%3Cscript%3E", "source=a%20b"])
    def test_bad_filters_are_rejected(self, shared, query):
        client, _ = shared
        assert client.get(f"/api/activity?{query}").status_code == 422


class TestLabelledSources:
    def test_empty_root_has_only_the_demo(self, tmp_path):
        assert [s.key for s in discover_sources(tmp_path)] == ["demo"]

    def test_prepared_source_is_labelled_synthetic_and_demo_stays_default(self, shared):
        client, _ = shared
        sources = ok(client.get("/api/sources"))
        assert sources[0]["key"] == "demo" and sources[0]["is_default"] is True
        extra = next(s for s in sources if s["key"] == SYNTHETIC_KEY)
        assert extra["provenance"] == "synthetic" and "SYNTHETIC" in extra["label"]
        assert not extra["is_default"]

    def test_lanl_labels_say_real(self):
        assert all("real, sampled" in label for _, _, label in LANL_RUNS)

    def test_missing_lanl_runs_are_skipped_not_faked(self, built_root):
        registered = json.loads((built_root / REGISTRY_FILE).read_text(encoding="utf-8"))
        assert [e["key"] for e in registered["sources"]] == [SYNTHETIC_KEY]

    def test_rerun_reuses_valid_output(self, built_root, tmp_path):
        root = tmp_path / "root"
        shutil.copytree(built_root, root)
        assert prepare_demo_sources(root)[0].status == "reused"

    def test_a_valid_dataset_outside_the_root_is_refused(self, built_root, tmp_path):
        root = tmp_path / "root"
        shutil.copytree(built_root, root)
        shutil.copytree(root / "demo_sources" / SYNTHETIC_KEY, tmp_path / "outside")
        path = root / REGISTRY_FILE
        registry = json.loads(path.read_text(encoding="utf-8"))
        registry["sources"][0].update(dataset_dir="../outside/dataset",
                                      detection_dir="../outside/detection")
        path.write_text(json.dumps(registry), encoding="utf-8")
        assert [s.key for s in discover_sources(root)] == ["demo"]

    @pytest.mark.parametrize("change", [
        {"provenance": "lanl"},  # synthetic data must never appear as real
        {"dataset_dir": "../../outside"},
        {"detection_dir": "does/not/exist"},
        {"provenance": "nonsense"},
    ])
    def test_a_wrong_registry_entry_is_refused(self, built_root, tmp_path, change):
        root = tmp_path / "root"
        shutil.copytree(built_root, root)
        path = root / REGISTRY_FILE
        registry = json.loads(path.read_text(encoding="utf-8"))
        registry["sources"][0].update(change)
        path.write_text(json.dumps(registry), encoding="utf-8")
        assert [s.key for s in discover_sources(root)] == ["demo"]

    def test_corrupt_registry_is_ignored(self, built_root, tmp_path):
        root = tmp_path / "root"
        shutil.copytree(built_root, root)
        (root / REGISTRY_FILE).write_text("{not json", encoding="utf-8")
        assert [s.key for s in discover_sources(root)] == ["demo"]

    def test_lanl_run_with_a_different_dataset_is_not_referenced(self, built_root, tmp_path):
        root = tmp_path / "root"
        shutil.copytree(built_root, root)
        # A LANL run directory whose assessment is really the synthetic one, beside a dataset
        # that exists but is not the one it was computed from.
        shutil.copytree(root / "demo" / "dataset", root / LANL_DATASET)
        run = root / "lanl_validation_target1" / LANL_RUNS[0][1]
        run.mkdir(parents=True)
        shutil.copytree(root / "demo_sources" / SYNTHETIC_KEY / "detection", run / "detection")
        report = {p.key: p for p in prepare_demo_sources(root)}
        assert report[LANL_RUNS[0][0]].status == "skipped"
        assert report[LANL_RUNS[0][0]].detail == "dataset does not match the assessment"
        registered = json.loads((root / REGISTRY_FILE).read_text(encoding="utf-8"))
        assert LANL_RUNS[0][0] not in [e["key"] for e in registered["sources"]]
