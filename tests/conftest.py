"""Shared factories for valid contract objects. Tests override single fields
to probe one validation rule at a time."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from agentsoc.schemas import (
    AuthEvent,
    Finding,
    Hypothesis,
    HypothesisKind,
    Incident,
    InvestigationResult,
    InvestigationSource,
    Severity,
)

T0 = datetime(2026, 1, 15, 9, 0, tzinfo=UTC)


def event_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "event_id": "EVT-0001",
        "timestamp": T0,
        "src_user": "alice.fin@CORP",
        "dst_user": "alice.fin@CORP",
        "src_host": "WS-FIN-01",
        "dst_host": "SRV-APP-02",
        "auth_type": "Kerberos",
        "logon_type": "Network",
        "orientation": "LogOn",
        "outcome": "Success",
        "dataset": "synthetic",
        "raw_ref": {"file": "synthetic/auth.csv", "line": 2},
    }
    data.update(overrides)
    return data


def finding_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "finding_id": "FND-0001",
        "rule_id": "FAIL_THEN_SUCCESS",
        "severity": Severity.HIGH,
        "user": "alice.fin@CORP",
        "event_ids": ["EVT-0001", "EVT-0002"],
        "first_seen": T0,
        "last_seen": T0 + timedelta(minutes=3),
        "description": "Five failures followed by success for alice.fin@CORP",
    }
    data.update(overrides)
    return data


def incident_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "incident_id": "INC-0001",
        "principal_user": "alice.fin@CORP",
        "first_seen": T0,
        "last_seen": T0 + timedelta(minutes=10),
        "findings": [Finding(**finding_data())],
        "event_ids": ["EVT-0001", "EVT-0002", "EVT-0003"],
        "rule_ids": ["FAIL_THEN_SUCCESS"],
        "involved_users": ["alice.fin@CORP"],
        "involved_hosts": ["WS-FIN-01", "SRV-APP-02"],
        "datasets": ["synthetic"],
        "severity": Severity.MEDIUM,
        "severity_rationale": "FAIL_THEN_SUCCESS=3 -> MEDIUM",
        "benign_explanations": ["User mistyped the password."],
        "flags": ["synthetic-data"],
    }
    data.update(overrides)
    return data


def hypothesis_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "hypothesis_id": "H1",
        "kind": HypothesisKind.MALICIOUS,
        "title": "Credential misuse leading to lateral movement",
        "narrative": "Failures then success from an unfamiliar workstation suggest stolen creds.",
        "attack_techniques": ["T1078", "T1021.002"],
        "proposed_path": ["alice.fin@CORP", "WS-FIN-07", "SRV-APP-02", "DB-FIN-01"],
        "supporting_event_ids": ["EVT-0001", "EVT-0002"],
        "contradicting_event_ids": [],
        "missing_information": ["MFA logs for the successful login"],
        "confidence": 0.74,
    }
    data.update(overrides)
    return data


def benign_hypothesis() -> Hypothesis:
    return Hypothesis(
        **hypothesis_data(
            hypothesis_id="H3",
            kind=HypothesisKind.BENIGN,
            title="User forgot password and logged in from a shared workstation",
            attack_techniques=[],
            proposed_path=[],
            confidence=0.21,
        )
    )


def conclusion_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "most_plausible_hypothesis_id": "H1",
        "summary": "Credential misuse is the most plausible explanation.",
        "confidence": 0.6,
        "uncertainty": "Authentication logs alone cannot confirm who used the account.",
        "alternative_hypothesis_ids": ["H3"],
        "next_steps": ["Ask the user whether they logged in from WS-FIN-07."],
        "evidence_gaps": ["MFA logs"],
    }
    data.update(overrides)
    return data


def investigation_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "incident_id": "INC-0001",
        "incident_sha256": "a" * 64,
        "hypotheses": [Hypothesis(**hypothesis_data()), benign_hypothesis()],
        "conclusion": conclusion_data(),
        "source": InvestigationSource.LLM,
        "provider": "groq",
        "model": "openai/gpt-oss-120b",
        "latency_ms": 480.0,
        "created_at": T0,
    }
    data.update(overrides)
    return data


@pytest.fixture
def auth_event() -> AuthEvent:
    return AuthEvent(**event_data())


@pytest.fixture
def incident() -> Incident:
    return Incident(**incident_data())


@pytest.fixture
def investigation() -> InvestigationResult:
    return InvestigationResult(**investigation_data())
