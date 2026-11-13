"""REST API over the existing modules (FastAPI TestClient; no network — LLM traffic is
scripted). Data is the SYNTHETIC demo scenario built in a temporary root."""

import json
import re
import threading
import time

import pytest

from agentsoc import app_data
from agentsoc.api.service import Service
from agentsoc.config import PROJECT_ROOT
from agentsoc.investigator.llm.base import LLMProvider, LLMUnavailableError
from tests.support import signed_in_client
from tests.unit.test_investigator import llm_json

FAKE_KEY = "gsk_" + "K" * 52


class CountingProvider(LLMProvider):
    """Returns a valid grounded answer for whichever incident is in the prompt."""

    name, model = "scripted", "scripted/model-1"

    def __init__(self, incidents, delay=0.0, fail: Exception | None = None):
        self.incidents = incidents
        self.delay = delay
        self.fail = fail
        self.calls = 0
        self.lock = threading.Lock()

    def complete_json(self, system, user, feedback=None):
        with self.lock:
            self.calls += 1
        time.sleep(self.delay)
        if self.fail:
            raise self.fail
        incident = next(i for i in self.incidents if f'"incident_id": "{i.incident_id}"' in user)
        return llm_json(incident)


@pytest.fixture
def env(tmp_path):
    svc = Service(root=tmp_path, provider_factory=lambda: (None, "LLM disabled for test"))
    incidents = svc.loaded(None).incidents
    provider = CountingProvider(incidents)
    svc.provider_factory = lambda: (provider, None)
    client = signed_in_client(svc)
    return client, svc, provider


def ok(response):
    assert response.status_code == 200, response.text
    return response.json()


class TestReadEndpoints:
    def test_health_and_sources(self, env):
        client, _, _ = env
        health = ok(client.get("/api/health"))
        assert health == {"status": "ok", "version": health["version"], "analysis": "available",
                          "sources": 1}
        (source,) = ok(client.get("/api/sources"))
        assert source["key"] == "demo" and source["provenance"] == "synthetic"

    def test_overview_numbers_come_from_detection(self, env):
        client, _, _ = env
        o = ok(client.get("/api/overview"))
        assert o["incidents_total"] == 3 and o["findings_total"] == 15
        assert o["severity_counts"] == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 1, "LOW": 1}
        assert o["dataset"]["provenance"] == "synthetic" and o["dataset"]["event_count"] == 176
        assert sum(r["findings"] for r in o["rule_activity"]) == 15
        assert o["investigations_completed"] == 0

    @pytest.mark.parametrize(
        ("query", "expected"),
        [
            ("", ["INC-00002", "INC-00001", "INC-00003"]),  # severity order
            ("q=alice", ["INC-00002"]),
            ("q=SRV-NEW", ["INC-00003"]),
            ("severity=MEDIUM&severity=LOW", ["INC-00001", "INC-00003"]),
            ("provenance=lanl", []),
            ("rule=LATERAL_CHAIN", ["INC-00002"]),
            ("sort=incident_id&order=desc", ["INC-00003", "INC-00002", "INC-00001"]),
            ("page=2&page_size=2", ["INC-00003"]),
        ],
    )
    def test_incident_filters(self, env, query, expected):
        client, _, _ = env
        page = ok(client.get(f"/api/incidents?{query}"))
        assert [i["incident_id"] for i in page["items"]] == expected

    @pytest.mark.parametrize("query", ["page_size=999", "page=0", "sort=password",
                                       "severity=URGENT", "source=a%20b"])
    def test_invalid_parameters_rejected(self, env, query):
        client, _, _ = env
        assert client.get(f"/api/incidents?{query}").status_code == 422

    def test_incident_detail(self, env):
        client, _, _ = env
        d = ok(client.get("/api/incidents/INC-00002"))
        assert d["principal_user"] == "alice.fin@CORP" and d["severity"] == "CRITICAL"
        assert len(d["timeline"]) == 9 and d["missing_evidence_ids"] == []
        labels = [e["time_label"] for e in d["timeline"]]
        assert labels == sorted(labels)
        assert {f["rule_id"] for f in d["findings"]} == set(d["rule_ids"])
        assert d["shared_evidence"]  # events cited by several rules are surfaced
        assert "not a confirmed compromise" in d["description"]
        assert all(e["provenance"] == "synthetic" and e["raw_line"] > 0 for e in d["timeline"])

    def test_evidence_endpoint_matches_incident(self, env):
        client, _, _ = env
        events = ok(client.get("/api/incidents/INC-00002/evidence"))
        detail = ok(client.get("/api/incidents/INC-00002"))
        assert [e["event_id"] for e in events] == [e["event_id"] for e in detail["timeline"]]

    @pytest.mark.parametrize("url", ["/api/incidents/INC-99999", "/api/incidents?source=nope",
                                     "/api/overview?source=nope", "/api/does-not-exist"])
    def test_not_found(self, env, url):
        client, _, _ = env
        r = client.get(url)
        assert r.status_code == 404 and "detail" in r.json()

    def test_events(self, env):
        client, _, _ = env
        evidence = ok(client.get("/api/events?user=alice&outcome=Fail"))
        assert evidence["total"] == 6
        assert all(e["outcome"] == "Fail" and e["cited_by"] for e in evidence["items"])
        everything = ok(client.get("/api/events?scope=all&page_size=10"))
        assert everything["total"] == 176 and len(everything["items"]) == 10
        assert ok(client.get("/api/events?q=does-not-exist"))["total"] == 0

    def test_datasets_report_provenance_and_verification(self, env):
        client, _, _ = env
        (d,) = ok(client.get("/api/datasets"))
        assert d["provenance"] == "synthetic" and d["status"] == "verified"
        assert d["event_count"] == 176 and d["lines_read"] == 176 and d["rejected_count"] == 0
        assert d["detection"]["incidents"] == 3 and len(d["events_sha256"]) == 64


class TestInvestigation:
    def test_investigate_then_cached(self, env):
        client, _, provider = env
        first = ok(client.post("/api/incidents/INC-00002/investigate"))
        assert first["status"] == "completed" and first["cached"] is False
        assert first["diagnostics"]["engine"] == "llm"
        assert first["conclusion"]["is_proof_of_compromise"] is False
        assert all(r["event_id"] for h in first["hypotheses"] for r in h["supporting"])
        second = ok(client.post("/api/incidents/INC-00002/investigate"))
        assert second["cached"] is True and provider.calls == 1
        assert ok(client.post("/api/incidents/INC-00002/investigate?rerun=true"))["cached"] is False
        assert provider.calls == 2

    def test_saved_investigation_is_per_incident(self, env):
        client, _, _ = env
        ok(client.post("/api/incidents/INC-00002/investigate"))
        saved = ok(client.get("/api/incidents/INC-00002/investigation"))
        assert saved["incident_id"] == "INC-00002"
        assert client.get("/api/incidents/INC-00001/investigation").status_code == 404

    def test_provider_failure_falls_back_without_leaking_details(self, env):
        client, _, provider = env
        provider.fail = LLMUnavailableError(f"Groq is unreachable; key {FAKE_KEY}")
        r = client.post("/api/incidents/INC-00002/investigate")
        body = ok(r)
        assert body["status"] == "completed_limited"
        assert body["diagnostics"]["engine"] == "deterministic"
        assert body["analyst_notes"] == []  # provider diagnostics stay server-side
        raw = r.text
        assert FAKE_KEY not in raw and "unreachable" not in raw and "Groq" not in raw
        assert len(body["hypotheses"]) >= 2

    def test_unexpected_provider_exception_still_completes(self, env):
        client, _, provider = env
        provider.fail = RuntimeError("boom")
        body = ok(client.post("/api/incidents/INC-00001/investigate"))
        assert body["status"] == "completed_limited" and "boom" not in json.dumps(body)

    def test_concurrent_clicks_run_one_investigation(self, env):
        _, svc, provider = env
        provider.delay = 0.3
        results = []
        threads = [threading.Thread(target=lambda: results.append(
            svc.investigate(None, "INC-00002", rerun=False))) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert provider.calls == 1
        assert sorted(r.cached for r in results) == [False, True, True, True]

    def test_history_and_open_by_id(self, env):
        client, _, _ = env
        inv = ok(client.post("/api/incidents/INC-00002/investigate"))
        (row,) = ok(client.get("/api/investigations"))
        assert row["investigation_id"] == inv["investigation_id"]
        assert row["incident_id"] == "INC-00002" and row["status"] == "completed"
        assert row["provenance"] == "synthetic"
        opened = ok(client.get(f"/api/investigations/{inv['investigation_id']}?source=demo"))
        assert opened["incident_id"] == "INC-00002"
        assert client.get("/api/investigations/INC-00001-0000000000000000").status_code == 404

    def test_activity_log_is_hash_chained(self, env):
        client, svc, _ = env
        ok(client.post("/api/incidents/INC-00002/investigate"))
        log = ok(client.get("/api/activity"))
        types = [e["event_type"] for e in log["entries"]]
        assert types[0] == "investigation.completed" and "dataset.verified" in types
        assert log["chain_intact"] is True
        lines = svc.activity_path.read_text().splitlines()
        lines[0] = re.sub(r'"actor":"[^"]+"', '"actor":"attacker"', lines[0])
        svc.activity_path.write_text("\n".join(lines) + "\n")
        assert ok(client.get("/api/activity"))["chain_intact"] is False

    def test_overview_counts_investigations(self, env):
        client, _, _ = env
        ok(client.post("/api/incidents/INC-00002/investigate"))
        assert ok(client.get("/api/overview"))["investigations_completed"] == 1
        page = ok(client.get("/api/incidents?q=alice"))
        assert page["items"][0]["investigation_status"] == "completed"


def test_empty_dataset(tmp_path, monkeypatch):
    sample = PROJECT_ROOT / "data" / "samples" / "lanl_format_synthetic_sample.txt"
    monkeypatch.setattr(app_data, "DEMO_INPUT", sample)
    svc = Service(root=tmp_path, provider_factory=lambda: (None, "disabled"))
    client = signed_in_client(svc)
    o = ok(client.get("/api/overview"))
    assert o["incidents_total"] == 0 and o["recent_incidents"] == []
    assert ok(client.get("/api/incidents"))["total"] == 0
    assert ok(client.get("/api/events"))["total"] == 0
    assert ok(client.get("/api/health"))["analysis"] == "limited"


def test_corrupted_dataset_returns_safe_error(env):
    client, svc, _ = env
    source = svc.source(None)
    path = source.detection_dir / "incidents.jsonl"
    path.write_text(path.read_text().replace("alice", "mallory"), encoding="utf-8")
    svc._loaded.clear()
    r = client.get("/api/overview")
    assert r.status_code == 500
    assert r.json() == {"detail": "Data could not be loaded or failed integrity verification."}
