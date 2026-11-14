"""Specialised agents, orchestrator, correlation and the reasoning-layer hand-off."""

import json
import socket
import time
from dataclasses import replace

import pytest

from agentsoc.agents import endpoint, identity, network, threat_intel
from agentsoc.agents.base import (
    AgentFinding,
    AgentReport,
    AgentStatus,
    InvestigationTask,
    Stance,
    Strength,
)
from agentsoc.agents.correlation import correlate
from agentsoc.agents.orchestrator import DEFAULT_AGENTS, orchestrate, prompt_payload
from agentsoc.api.service import Service
from agentsoc.investigator.llm.base import LLMProvider
from agentsoc.investigator.prompts import build_user_prompt
from tests.support import signed_in_client

INC = "INC-00002"


@pytest.fixture(scope="module")
def svc(tmp_path_factory):
    return Service(root=tmp_path_factory.mktemp("agents"), provider_factory=lambda: (None, "off"))


def task_for(svc, window=None) -> InvestigationTask:
    data, inc = svc.incident(None, INC)
    return svc.agent_task(data, inc, window)


def statements(report):
    return " ".join(f.statement for f in report.findings)


class TestAgents:
    def test_identity_compares_the_account_with_its_own_history(self, svc):
        report = identity.run(task_for(svc))
        assert report.status is AgentStatus.COMPLETED
        strong = [f for f in report.findings if f.strength is Strength.STRONG]
        assert strong and strong[0].stance is Stance.SUSPICIOUS and "failed" in strong[0].statement
        assert all(not f.expanded for f in report.findings)
        assert any("Identity-provider" in g for g in report.gaps)

    def test_identity_notes_configured_administrators_as_benign_context(self, svc):
        task = task_for(svc)
        admin = task.detection.model_copy(update={"admin_users": [task.incident.principal_user]})
        report = identity.run(replace(task, detection=admin, _cache={}))
        assert any(f.stance is Stance.BENIGN and "administrative" in f.statement
                   for f in report.findings)

    def test_network_checks_connection_history_and_structure(self, svc):
        report = network.run(task_for(svc))
        text = statements(report)
        assert "never occur earlier" in text and "observed movement path" in text
        assert any(f.event_ids for f in report.findings)

    def test_threat_intel_maps_attack_and_stays_offline(self, svc, tmp_path, monkeypatch):
        def no_network(*args, **kwargs):
            raise AssertionError("no network access is allowed")

        monkeypatch.setattr(socket.socket, "connect", no_network)
        report = threat_intel.run(task_for(svc), tmp_path / "missing.json")
        techniques = {t for f in report.findings for t in f.techniques}
        assert {"T1110", "T1021"} <= techniques
        assert all(f.stance is Stance.CONTEXT for f in report.findings)
        assert any("No local indicator watchlist" in g for g in report.gaps)
        assert any("No external threat-intelligence feed" in g for g in report.gaps)

    def test_watchlist_matches_are_reported_and_bad_files_ignored(self, svc, tmp_path):
        task = task_for(svc)
        path = tmp_path / "ti.json"
        path.write_text(json.dumps({"version": 1, "indicators": [
            {"type": "host", "value": "DB-FIN-01", "label": "Reported in a phishing case",
             "source": "internal IR ticket 42"},
            {"type": "account", "value": "nobody@CORP", "label": "x", "source": "y"}]}),
            encoding="utf-8")
        hits = [f for f in threat_intel.run(task, path).findings if f.stance is Stance.SUSPICIOUS]
        assert len(hits) == 1 and "DB-FIN-01" in hits[0].statement
        assert hits[0].strength is Strength.STRONG
        path.write_text('{"version": 1, "indicators": [{"type": "ip"}]}', encoding="utf-8")
        report = threat_intel.run(task, path)
        assert any("not valid and was ignored" in g for g in report.gaps)

    def test_endpoint_agent_says_it_has_no_data_and_what_to_ask_for(self, svc):
        report = endpoint.run(task_for(svc))
        assert report.status is AgentStatus.UNAVAILABLE and report.findings == []
        assert any("DB-FIN-01" in g and "process creation" in g for g in report.gaps)

    def test_expanded_run_adds_wider_window_findings_only(self, svc):
        standard = orchestrate(task_for(svc))
        expanded = orchestrate(task_for(svc, 24))
        assert not any(f.expanded for r in standard.reports for f in r.findings)
        extra = [f for r in expanded.reports for f in r.findings if f.expanded]
        assert extra and all(f.statement for f in extra)


def _agent(name, delay=0.0, fail=False, stance=Stance.SUSPICIOUS, hosts=("H1",)):
    def run(task):
        time.sleep(delay)
        if fail:
            raise RuntimeError("boom")
        return AgentReport(name, name.title(), "test", AgentStatus.COMPLETED, ["x"],
                           [AgentFinding(f"{name} finding", stance, Strength.WEAK, hosts=hosts)],
                           [])
    return (name, name.title(), "test", run)


class TestOrchestrator:
    def test_agents_run_in_parallel(self, svc):
        task = task_for(svc)
        started = time.perf_counter()
        result = orchestrate(task, [_agent(f"a{i}", delay=0.4) for i in range(4)])
        assert time.perf_counter() - started < 1.2
        assert [r.agent for r in result.reports] == ["a0", "a1", "a2", "a3"]

    def test_a_failing_or_slow_agent_does_not_stop_the_others(self, svc):
        result = orchestrate(task_for(svc), [_agent("good"), _agent("bad", fail=True),
                                             _agent("slow", delay=3)], timeout=1.0)
        by = {r.agent: r for r in result.reports}
        assert by["good"].status is AgentStatus.COMPLETED
        assert by["bad"].status is AgentStatus.FAILED and "internal error" in by["bad"].gaps[0]
        assert by["slow"].status is AgentStatus.FAILED and "within 1 s" in by["slow"].gaps[0]
        assert "Bad" in result.correlation.summary

    def test_default_pipeline_matches_the_design(self):
        assert [a[0] for a in DEFAULT_AGENTS] == ["identity", "network", "threat_intel",
                                                  "endpoint"]


class TestCorrelation:
    def report(self, name, *findings):
        return AgentReport(name, f"{name} agent", "", AgentStatus.COMPLETED, [], list(findings),
                           [])

    def test_two_agents_corroborate_an_entity(self):
        c = correlate([
            self.report("identity", AgentFinding("a", Stance.SUSPICIOUS, Strength.WEAK,
                                                 hosts=("H1",))),
            self.report("network", AgentFinding("b", Stance.SUSPICIOUS, Strength.WEAK,
                                                hosts=("H1", "H2")))])
        assert c.corroborated == ["Host H1 is flagged by the identity and network agents."]
        assert c.entities[0].name == "H1" and c.conflicts == []

    def test_one_agent_reporting_both_sides_is_not_a_conflict(self):
        c = correlate([self.report(
            "identity", AgentFinding("a", Stance.SUSPICIOUS, Strength.WEAK, accounts=("u",)),
            AgentFinding("b", Stance.BENIGN, Strength.WEAK, accounts=("u",)))])
        assert c.conflicts == []

    def test_disagreement_between_agents_is_a_conflict(self):
        c = correlate([
            self.report("identity", AgentFinding("a", Stance.BENIGN, Strength.WEAK,
                                                 accounts=("u",))),
            self.report("network", AgentFinding("b", Stance.SUSPICIOUS, Strength.WEAK,
                                                accounts=("u",)))])
        assert len(c.conflicts) == 1 and "network" in c.conflicts[0]


class CapturingProvider(LLMProvider):
    name, model = "capture", "test"

    def __init__(self):
        self.prompts = []

    def complete_json(self, system, user, feedback=None):
        self.prompts.append((system, user))
        return "{}"  # invalid: the investigation falls back, which is fine for this test


class TestReasoningLayer:
    def test_prompt_is_unchanged_without_agent_findings(self, svc):
        _, inc = svc.incident(None, INC)
        events = list(svc.evidence(None).values())
        assert "agent_findings" not in build_user_prompt(inc, events)
        with_agents = build_user_prompt(inc, events, None, {"agents": []})
        assert '"agent_findings"' in with_agents

    def test_investigation_passes_correlated_findings_to_the_model(self, tmp_path):
        provider = CapturingProvider()
        svc = Service(root=tmp_path, provider_factory=lambda: (provider, None))
        client = signed_in_client(svc)
        assert client.post(f"/api/incidents/{INC}/investigate").status_code == 200
        system, user = provider.prompts[0]
        assert "agent_findings" in system and '"agent_findings"' in user
        payload = json.loads(user.split("<incident_data>")[1].split("</incident_data>")[0])
        agents = {a["agent"]: a for a in payload["agent_findings"]["agents"]}
        assert set(agents) == {"identity", "network", "threat_intel", "endpoint"}
        assert agents["endpoint"]["status"] == "unavailable"

    def test_payload_is_bounded(self, svc):
        payload = prompt_payload(orchestrate(task_for(svc, 72)))
        assert all(len(a["findings"]) <= 12 for a in payload["agents"])
        assert all(len(f["statement"]) <= 300 for a in payload["agents"] for f in a["findings"])


class TestApi:
    def test_standard_and_expanded_runs(self, svc):
        client = signed_in_client(svc)
        standard = client.get(f"/api/incidents/{INC}/agents").json()
        assert standard["mode"] == "standard" and len(standard["agents"]) == 4
        assert standard["correlation"]["summary"]
        expanded = client.get(f"/api/incidents/{INC}/agents?window_hours=24").json()
        assert expanded["mode"] == "expanded" and expanded["window_hours"] == 24
        assert any(f["expanded"] for a in expanded["agents"] for f in a["findings"])
        technique = expanded["correlation"]["techniques"][0]
        assert technique["url"].startswith("https://attack.mitre.org/techniques/T")

    def test_unsupported_window_is_refused(self, svc):
        client = signed_in_client(svc)
        assert client.get(f"/api/incidents/{INC}/agents?window_hours=5").status_code == 400
        assert client.get(f"/api/incidents/{INC}/agents?window_hours=500").status_code == 422

    def test_more_evidence_reruns_the_agents_in_the_report(self, tmp_path):
        svc = Service(root=tmp_path, provider_factory=lambda: (None, "off"))
        client = signed_in_client(svc)
        assert client.get(f"/api/incidents/{INC}/report").json()["agents"]["mode"] == "standard"
        client.post(f"/api/incidents/{INC}/review",
                    json={"decision": "more_evidence", "window_hours": 6})
        report = client.get(f"/api/incidents/{INC}/report").json()
        assert report["agents"]["mode"] == "expanded" and report["agents"]["window_hours"] == 6
        markdown = client.get(f"/api/incidents/{INC}/report.md").text
        assert "## Specialised agents (expanded to ±6 h" in markdown
        assert "Endpoint investigation agent (unavailable)" in markdown


class TestResponsePlan:
    """How to stop the activity: evidence-based recommendations, never executed."""

    def plan(self, svc, window=None):
        return svc.incident_agents(None, INC, window).response_plan

    def test_corroborated_compromise_gets_containment_first(self, svc):
        plan = self.plan(svc)
        assert plan.posture == "contain_now"
        assert plan.steps[0].phase == "contain"
        revoke = next(s for s in plan.steps if s.action_type == "REVOKE_SESSION")
        assert revoke.target == "alice.fin@CORP" and revoke.disruptive
        assert revoke.risk_engine_proposed  # the risk engine proposed the same action
        assert {s.target for s in plan.steps if s.action_type == "ISOLATE_HOST"} >= {"DB-FIN-01"}
        assert {s.phase for s in plan.steps} == {"contain", "investigate", "recover", "prevent"}

    def test_every_step_names_its_evidence_and_nothing_is_executed(self, svc):
        plan = self.plan(svc)
        assert all(s.why and s.based_on for s in plan.steps)
        assert all(s.action_type for s in plan.steps if s.disruptive)
        assert any("does not carry out" in n for n in plan.notes)
        # Endpoint data is missing, so the plan asks for it rather than assuming.
        assert any(s.action.startswith("Collect:") for s in plan.steps)
        assert any("Endpoint investigation agent" in n for n in plan.notes)

    def test_more_evidence_is_suggested_only_before_it_is_requested(self, svc):
        ask = lambda p: any("more evidence" in s.action for s in p.steps)  # noqa: E731
        assert ask(self.plan(svc)) and not ask(self.plan(svc, 24))

    def test_containment_only_when_the_posture_calls_for_it(self, svc):
        data, _ = svc.incident(None, INC)
        for inc in data.incidents:
            plan = svc.incident_agents(None, inc.incident_id).response_plan
            contain = [s for s in plan.steps if s.phase == "contain"]
            if plan.posture != "contain_now":
                assert not any(s.disruptive for s in contain), inc.incident_id
            if plan.posture == "monitor":
                assert not contain and plan.steps[0].action_type == "MONITOR_ONLY"

    def test_no_suspicious_findings_means_monitor_only(self, svc):
        from agentsoc.agents.response import Posture, plan_response

        task = task_for(svc)
        reports = [AgentReport("identity", "Identity agent", "", AgentStatus.COMPLETED, [],
                               [AgentFinding("Normal.", Stance.BENIGN, Strength.MODERATE)], [])]
        plan = plan_response(task, reports, correlate(reports))
        assert plan.posture is Posture.MONITOR
        assert [s.action_type.value for s in plan.steps if s.action_type] == ["MONITOR_ONLY"]

    def test_a_dismissed_incident_gets_no_response(self, tmp_path):
        svc = Service(root=tmp_path, provider_factory=lambda: (None, "off"))
        client = signed_in_client(svc)
        client.post(f"/api/incidents/{INC}/review",
                    json={"decision": "dismissed", "reason": "expected_activity"})
        plan = client.get(f"/api/incidents/{INC}/agents").json()["response_plan"]
        assert plan["posture"] == "closed" and plan["steps"] == []

    def test_plan_survives_an_unavailable_risk_engine(self, tmp_path, monkeypatch):
        svc = Service(root=tmp_path, provider_factory=lambda: (None, "off"))

        def broken(*_):
            raise RuntimeError("risk engine down")
        monkeypatch.setattr(svc, "_risk_for", broken)
        plan = svc.incident_agents(None, INC).response_plan
        assert plan.posture == "contain_now"
        assert not any(s.risk_engine_proposed for s in plan.steps)

    def test_report_includes_the_plan(self, tmp_path):
        client = signed_in_client(Service(root=tmp_path, provider_factory=lambda: (None, "off")))
        report = client.get(f"/api/incidents/{INC}/report").json()
        assert report["agents"]["response_plan"]["posture"] == "contain_now"
        markdown = client.get(f"/api/incidents/{INC}/report.md").text
        assert "## How to stop this (recommended response)" in markdown
        assert "### Contain" in markdown and "needs approval" in markdown
