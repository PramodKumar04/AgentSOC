"""Deterministic fallback investigator: same output contract, no LLM.

Hypotheses are derived from which detection rules fired; confidence uses the fixed,
documented heuristics below (investigative estimates, not probabilities):

  H1 MALICIOUS credential misuse   = base[detection severity]
                                     (LOW .25, MEDIUM .40, HIGH .55, CRITICAL .70)
                                     + .10 if LATERAL_CHAIN or SENSITIVE_HOST_ACCESS fired
                                     - .25 if the principal is a configured admin account
  H2 BENIGN administrative/ops     = .60 if admin account, else .30;
                                     - .10 if failure rules fired (planned work rarely fails)
  H3 BENIGN misconfiguration/user  = .55 if only failure rules fired, else .20
     error

H2 is included when novelty rules fired or the account is an admin; H3 when failure
rules fired. At least one benign hypothesis is always present.
"""

from __future__ import annotations

from agentsoc.detection.catalog import RuleId
from agentsoc.schemas import AuthEvent, Hypothesis, HypothesisKind, Incident, Severity
from agentsoc.schemas.investigation import EvidenceNote, InvestigationConclusion

FAILURE_RULES = {RuleId.FAILURE_BURST, RuleId.FAIL_THEN_SUCCESS}
NOVELTY_RULES = {RuleId.NEW_SRC_HOST, RuleId.NEW_DST_HOST, RuleId.MULTI_HOST_SPREAD,
                 RuleId.LATERAL_CHAIN, RuleId.SENSITIVE_HOST_ACCESS}
ATTACK_BY_RULE: dict[RuleId, tuple[str, ...]] = {
    RuleId.FAILURE_BURST: ("T1110",),  # Brute Force
    RuleId.FAIL_THEN_SUCCESS: ("T1110", "T1078"),  # Brute Force -> Valid Accounts
    RuleId.NEW_SRC_HOST: ("T1078",),  # Valid Accounts
    RuleId.NEW_DST_HOST: ("T1078",),
    RuleId.MULTI_HOST_SPREAD: ("T1021",),  # Remote Services
    RuleId.LATERAL_CHAIN: ("T1021",),
    RuleId.SENSITIVE_HOST_ACCESS: ("T1078",),
}
BASE_CONFIDENCE = {Severity.LOW: 0.25, Severity.MEDIUM: 0.40, Severity.HIGH: 0.55,
                   Severity.CRITICAL: 0.70}
MAX_NOTES = 40


def _clamp(value: float) -> float:
    return round(min(0.95, max(0.05, value)), 2)


def _events_for(incident: Incident, rules: set[RuleId]) -> list[str]:
    ids = {e for f in incident.findings if RuleId(f.rule_id) in rules for e in f.event_ids}
    return [e for e in incident.event_ids if e in ids]  # keep incident (time) order


def _notes(ids: list[str], incident: Incident, events: dict[str, AuthEvent],
           stance: str) -> list[EvidenceNote]:
    rules_by_event: dict[str, set[str]] = {}
    for f in incident.findings:
        for e in f.event_ids:
            rules_by_event.setdefault(e, set()).add(f.rule_id)
    notes = []
    for eid in ids[:MAX_NOTES]:
        e = events.get(eid)
        what = (f"{e.outcome.value} {e.orientation.value} {e.src_host} -> {e.dst_host}"
                if e else "event not loaded")
        notes.append(EvidenceNote(
            event_id=eid,
            relevance=(f"{stance}: {what}; flagged by "
                       f"{', '.join(sorted(rules_by_event[eid]))}")[:300],
        ))
    return notes


def _next_steps(incident: Incident, rules: set[RuleId]) -> list[str]:
    hosts = ", ".join(incident.involved_hosts[:4])
    steps = [f"Confirm with {incident.principal_user} (out of band) whether this activity "
             "was theirs."]
    if rules & FAILURE_RULES:
        steps.append("Check identity-provider/helpdesk records for lockouts or password resets "
                      "in the incident window.")
    steps.append("Review MFA logs for the successful authentications in the incident window.")
    if rules & {RuleId.NEW_SRC_HOST, RuleId.NEW_DST_HOST, RuleId.MULTI_HOST_SPREAD}:
        steps.append(f"Verify the account is authorised to use {hosts} (asset owner, access "
                     "requests, change tickets).")
    if RuleId.LATERAL_CHAIN in rules:
        steps.append("Collect process and network telemetry from the intermediate hosts of the "
                     "authentication chain.")
    if RuleId.SENSITIVE_HOST_ACCESS in rules:
        steps.append("Review data-access logs on the sensitive host for the incident window.")
    return [s[:300] for s in steps[:10]]


def fallback_investigation(
    incident: Incident, events: dict[str, AuthEvent], *, is_admin: bool
) -> tuple[list[Hypothesis], InvestigationConclusion]:
    rules = {RuleId(r) for r in incident.rule_ids}
    failure_ids = _events_for(incident, rules & FAILURE_RULES)
    novelty_ids = _events_for(incident, rules & NOVELTY_RULES)
    all_ids = list(incident.event_ids)
    hypotheses: list[Hypothesis] = []

    techniques = sorted({t for r in rules for t in ATTACK_BY_RULE[r]})
    h1 = _clamp(BASE_CONFIDENCE[incident.severity]
                + (0.10 if rules & {RuleId.LATERAL_CHAIN, RuleId.SENSITIVE_HOST_ACCESS} else 0)
                - (0.25 if is_admin else 0))
    hypotheses.append(Hypothesis(
        hypothesis_id="H1",
        kind=HypothesisKind.MALICIOUS,
        title="Credential misuse by an unauthorised party",
        narrative=(
            f"The account {incident.principal_user} triggered {', '.join(sorted(rules))}. "
            "If the credentials were obtained by someone else, this activity would be expected: "
            + ("repeated failures before success suggest password guessing; " if failure_ids
               else "")
            + ("first-seen hosts and host-to-host movement suggest exploration or lateral "
               "movement. " if novelty_ids else "")
            + f"Deterministic estimate: severity {incident.severity.value} base"
            + (", +0.10 for chain/sensitive access" if rules & {RuleId.LATERAL_CHAIN,
               RuleId.SENSITIVE_HOST_ACCESS} else "")
            + (", -0.25 for configured admin account" if is_admin else "") + "."
        )[:2000],
        attack_techniques=techniques,
        supporting_event_ids=all_ids,
        evidence_notes=_notes(all_ids, incident, events, "supports"),
        missing_information=[
            "Confirmation from the account owner",
            "MFA status of the successful authentications",
            "Endpoint/process telemetry (not present in authentication logs)",
        ],
        confidence=h1,
    ))

    if novelty_ids or is_admin:
        contra = [e for e in failure_ids if e not in novelty_ids
                  and events.get(e) is not None and events[e].outcome.value == "Fail"]
        h2 = _clamp((0.60 if is_admin else 0.30) - (0.10 if failure_ids else 0))
        hypotheses.append(Hypothesis(
            hypothesis_id="H2",
            kind=HypothesisKind.BENIGN,
            title="Legitimate administrative or operational activity",
            narrative=(
                ("The principal is a configured administrative account; " if is_admin else "")
                + "access to new hosts can follow role changes, maintenance or new deployments. "
                + ("Repeated failures are less typical of planned work and are listed as "
                   "contradicting evidence." if contra else "")
            )[:2000],
            supporting_event_ids=novelty_ids or all_ids,
            contradicting_event_ids=contra,
            evidence_notes=_notes(novelty_ids or all_ids, incident, events, "consistent with")
            + _notes(contra, incident, events, "contradicts"),
            missing_information=["Change tickets or maintenance schedule",
                                 "Asset ownership and access-request records"],
            confidence=h2,
        ))

    if failure_ids:
        contra = [e for e in novelty_ids if e not in failure_ids]
        h3 = _clamp(0.55 if not novelty_ids else 0.20)
        hypotheses.append(Hypothesis(
            hypothesis_id="H3",
            kind=HypothesisKind.BENIGN,
            title="Authentication misconfiguration or user error",
            narrative=(
                "Failures followed by success are common when a user mistypes or recently changed "
                "a password, or when a service retries with stale credentials. "
                + ("Subsequent successful access to first-seen hosts is not explained by a "
                   "password problem and is listed as contradicting evidence." if contra else "")
            )[:2000],
            supporting_event_ids=failure_ids,
            contradicting_event_ids=contra,
            evidence_notes=_notes(failure_ids, incident, events, "consistent with")
            + _notes(contra, incident, events, "contradicts"),
            missing_information=["Failure reason codes (bad password, expired, locked)",
                                 "Recent password-change or reset records"],
            confidence=h3,
        ))

    if not any(h.kind is HypothesisKind.BENIGN for h in hypotheses):  # defensive; see docstring
        hypotheses.append(Hypothesis(
            hypothesis_id="H2", kind=HypothesisKind.BENIGN,
            title="Legitimate activity not captured by the detector's context",
            narrative="The detector lacks role and asset context that could explain the activity.",
            supporting_event_ids=all_ids, confidence=0.30,
        ))

    best = max(hypotheses, key=lambda h: (h.confidence, -hypotheses.index(h)))
    conclusion = InvestigationConclusion(
        most_plausible_hypothesis_id=best.hypothesis_id,
        summary=(f"Deterministic triage (no LLM): '{best.title}' scores highest "
                 f"({best.confidence:.2f}) among {len(hypotheses)} hypotheses for "
                 f"{incident.principal_user}.")[:2000],
        confidence=best.confidence,
        uncertainty=("Scores come from fixed rule-based heuristics, not from reasoning about the "
                     "specific events, and are not calibrated probabilities. Authentication logs "
                     "alone cannot show who operated the account or what was done on each host."),
        alternative_hypothesis_ids=[h.hypothesis_id for h in hypotheses if h is not best],
        next_steps=_next_steps(incident, rules),
        evidence_gaps=[g[:300] for g in incident.missing_information[:15]],
    )
    return hypotheses, conclusion
