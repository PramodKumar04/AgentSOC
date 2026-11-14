"""Human in the loop: analyst decisions, wider context on request, and the full report."""

import hashlib
import json

import pytest

from agentsoc.api.service import Service
from agentsoc.auth.service import Role
from agentsoc.review.store import Decision
from tests.support import signed_in_client

INC = "INC-00002"


@pytest.fixture
def env(tmp_path):
    svc = Service(root=tmp_path / "root", provider_factory=lambda: (None, "off"))
    return svc, signed_in_client(svc, role=Role.ANALYST, username="kumar")


def review(client, decision, **body):
    return client.post(f"/api/incidents/{INC}/review", json={"decision": decision, **body})


def audit_lines(svc):
    return [json.loads(x) for x in svc.activity_path.read_text(encoding="utf-8").splitlines()]


class TestDecisions:
    def test_every_incident_starts_open(self, env):
        _, client = env
        assert client.get(f"/api/incidents/{INC}/review").json() == {
            "status": "open", "latest": None, "history": []}
        items = client.get("/api/incidents?page_size=200").json()["items"]
        assert {i["review_status"] for i in items} == {"open"}

    def test_accept_is_recorded_audited_and_listed(self, env):
        svc, client = env
        r = review(client, "accepted", note="Confirmed with the account owner's manager.")
        assert r.status_code == 200, r.text
        state = r.json()
        assert state["status"] == "accepted" and state["latest"]["analyst"] == "kumar"
        assert state["latest"]["current_version"] is True
        entry = audit_lines(svc)[-1]
        assert (entry["event_type"], entry["actor"], entry["subject_id"]) == (
            "incident.accepted", "kumar", INC)
        assert "manager" not in json.dumps(entry)  # the note stays in the review record
        accepted = client.get("/api/incidents?review=accepted").json()
        assert [i["incident_id"] for i in accepted["items"]] == [INC]
        overview = client.get("/api/overview").json()
        counts = overview["review_counts"]
        assert counts["accepted"] == 1
        assert counts["open"] == overview["incidents_total"] - 1

    @pytest.mark.parametrize(("body", "message"), [
        ({"decision": "dismissed"}, "why the incident is being dismissed"),
        ({"decision": "dismissed", "reason": "other"}, "Explain the reason"),
        ({"decision": "accepted", "reason": "false_positive"}, "only recorded when dismissing"),
        ({"decision": "accepted", "window_hours": 6}, "only used when requesting evidence"),
    ])
    def test_incomplete_decisions_are_refused(self, env, body, message):
        _, client = env
        r = client.post(f"/api/incidents/{INC}/review", json=body)
        assert r.status_code == 400 and message in r.json()["detail"]
        assert client.get(f"/api/incidents/{INC}/review").json()["history"] == []

    @pytest.mark.parametrize("body", [
        {"decision": "approve"}, {"decision": "dismissed", "reason": "boss said so"},
        {"decision": "more_evidence", "window_hours": 5}, {"decision": "accepted",
                                                            "note": "x" * 1001}])
    def test_invalid_values_are_refused(self, env, body):
        _, client = env
        assert client.post(f"/api/incidents/{INC}/review", json=body).status_code == 422

    def test_dismiss_then_reopen_keeps_history(self, env):
        _, client = env
        review(client, "dismissed", reason="expected_activity", note="Nightly backup job.")
        state = review(client, "reopened").json()
        assert state["status"] == "open"
        assert [h["decision"] for h in state["history"]] == ["reopened", "dismissed"]
        assert state["history"][1]["reason"] == "expected_activity"

    def test_changes_need_the_csrf_header(self, env):
        _, client = env
        r = client.post(f"/api/incidents/{INC}/review", json={"decision": "accepted"},
                        headers={"X-CSRF-Token": "forged"})
        assert r.status_code == 403

    def test_a_decision_on_another_version_does_not_carry_over(self, env):
        svc, client = env
        svc.reviews.add(source_key="demo", incident_id=INC,
                        incident_sha256=hashlib.sha256(b"older run").hexdigest(),
                        decision=Decision.DISMISSED, reason="false_positive", note=None,
                        window_hours=None, analyst="someone")
        state = client.get(f"/api/incidents/{INC}/review").json()
        assert state["status"] == "open"
        assert state["latest"]["current_version"] is False

    def test_decisions_change_no_detection_output_and_execute_nothing(self, env):
        svc, client = env
        detection = svc.source(None).detection_dir
        before = {p: p.read_bytes() for p in detection.rglob("*") if p.is_file()}
        review(client, "accepted")
        after = {p: p.read_bytes() for p in detection.rglob("*") if p.is_file()}
        assert before == after
        actions = client.get(f"/api/incidents/{INC}/risk").json()["record"]["actions"]
        assert all(a["status"] == "PROPOSED" and a["dry_run"] for a in actions)


class TestMoreEvidence:
    def test_request_records_the_window_and_context_is_factual(self, env):
        svc, client = env
        state = review(client, "more_evidence", note="Was this a known admin?").json()
        assert state["status"] == "more_evidence" and state["latest"]["window_hours"] == 24
        assert audit_lines(svc)[-1]["event_type"] == "incident.evidence_requested"
        ctx = client.get(f"/api/incidents/{INC}/context?window_hours=72").json()
        incident = client.get(f"/api/incidents/{INC}").json()
        own = {e["event_id"] for e in incident["timeline"]}
        assert ctx["account"] == incident["principal_user"]
        assert not own & {e["event_id"] for e in ctx["events"]}
        assert ctx["account_events"] >= len(own) - len(incident["missing_evidence_ids"])
        assert ctx["observations"] and ctx["limitations"]
        assert all(p["src_host"] != p["dst_host"] for p in ctx["pairs"])
        assert INC not in [x["incident_id"] for x in ctx["related"]]

    def test_wider_windows_never_show_less(self, env):
        _, client = env
        counts = [client.get(f"/api/incidents/{INC}/context?window_hours={w}").json()[
            "account_events"] for w in (1, 6, 24, 72)]
        assert counts == sorted(counts)

    def test_unsupported_window_is_refused(self, env):
        _, client = env
        r = client.get(f"/api/incidents/{INC}/context?window_hours=5")
        assert r.status_code == 400 and "window must be one of" in r.json()["detail"]
        assert client.get(f"/api/incidents/{INC}/context?window_hours=500").status_code == 422


class TestReport:
    def test_report_collects_everything_and_labels_synthetic_data(self, env):
        _, client = env
        review(client, "more_evidence", window_hours=6)
        report = client.get(f"/api/incidents/{INC}/report").json()
        assert report["incident"]["incident_id"] == INC
        assert report["generated_by"] == "kumar"
        assert report["review"]["status"] == "more_evidence"
        assert report["context"]["window_hours"] == 6
        assert report["notices"][0].startswith("SYNTHETIC DATA")
        assert any("dry-run" in n for n in report["notices"])
        assert len(report["dataset_sha256"]) == 64

    def test_markdown_export_escapes_untrusted_text_and_is_audited(self, env):
        svc, client = env
        review(client, "dismissed", reason="other",
               note="see [phish](http://evil.example) <script>alert(1)</script>\n# Heading")
        r = client.get(f"/api/incidents/{INC}/report.md")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/markdown")
        assert f"{INC}.md" in r.headers["content-disposition"]
        text = r.text
        assert "](http" not in text and "<script>" not in text
        assert "\n# Heading" not in text
        assert r"\[phish\]" in text
        assert audit_lines(svc)[-1]["event_type"] == "incident.report_exported"

    def test_report_needs_sign_in(self, env):
        from fastapi.testclient import TestClient

        from agentsoc.api.app import create_app

        svc, _ = env
        anonymous = TestClient(create_app(svc, serve_frontend=False))
        assert anonymous.get(f"/api/incidents/{INC}/report").status_code == 401
        assert anonymous.get(f"/api/incidents/{INC}/report.md").status_code == 401
