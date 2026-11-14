"""Response planner: what the analyst should do to stop the activity, step by step.

Runs after the correlation agent. Every step is derived from evidence the agents reported
(who is involved, what succeeded, which hosts were reached, which ATT&CK techniques the
detections are consistent with) and names that evidence. Nothing is executed: AgentSOC's
response actions are dry-run, and each step that changes access needs a human to carry it out
in the organisation's own tools after approval. Where the evidence is weak the plan says
"verify first" instead of recommending containment.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum

from agentsoc.agents import endpoint
from agentsoc.agents.base import AgentReport, InvestigationTask, Stance, Strength
from agentsoc.agents.correlation import Correlation
from agentsoc.schemas import AuthOutcome
from agentsoc.schemas.response import ActionType


class Phase(StrEnum):
    CONTAIN = "contain"          # stop it spreading now
    INVESTIGATE = "investigate"  # confirm or rule out before or while containing
    RECOVER = "recover"          # restore normal access safely
    PREVENT = "prevent"          # stop it happening again


class Posture(StrEnum):
    CONTAIN_NOW = "contain_now"    # strong or corroborated evidence of a working compromise
    VERIFY_FIRST = "verify_first"  # suspicious, but not enough to justify disruption yet
    MONITOR = "monitor"            # nothing suspicious beyond the detection itself
    CLOSED = "closed"              # an analyst dismissed the incident


POSTURE_TEXT = {
    Posture.CONTAIN_NOW: "Contain now: more than one agent, or strong evidence, points to "
                         "access that worked. Act on the containment steps, then investigate.",
    Posture.VERIFY_FIRST: "Verify first: the activity is suspicious but not confirmed. Do the "
                          "investigation steps; contain if they confirm it.",
    Posture.MONITOR: "Monitor: the agents found nothing suspicious beyond the detection. "
                     "Keep watching the account; no containment is suggested.",
    Posture.CLOSED: "An analyst dismissed this incident, so no response is suggested. Reopen "
                    "it if new evidence appears.",
}


@dataclass(frozen=True)
class ResponseStep:
    phase: Phase
    action: str                       # what to do, in plain words
    target: str | None                # the account or host it applies to
    why: str                          # the evidence it rests on
    based_on: tuple[str, ...]         # agents or sources the evidence came from
    action_type: ActionType | None = None   # the matching dry-run action primitive
    risk_engine_proposed: bool = False      # RSEM proposed the same action for this target
    disruptive: bool = False                # interrupts users or services; needs approval


@dataclass(frozen=True)
class ResponsePlan:
    posture: Posture
    summary: str
    steps: list[ResponseStep] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _suspicious(reports: Iterable[AgentReport], agent: str | None = None):
    for r in reports:
        if agent is None or r.agent == agent:
            yield from (f for f in r.findings if f.stance is Stance.SUSPICIOUS)


def _titles(reports: list[AgentReport], agents: Iterable[str]) -> tuple[str, ...]:
    names = {r.agent: r.title for r in reports}
    return tuple(names[a] for a in sorted(set(agents)) if a in names)


def _join(titles: Iterable[str]) -> str:
    items = list(titles)
    return " and ".join([", ".join(items[:-1]), items[-1]] if len(items) > 2 else items)


def plan_response(task: InvestigationTask, reports: list[AgentReport],
                  correlation: Correlation, *,
                  proposed: Iterable[tuple[ActionType, str]] = (),
                  dismissed: bool = False) -> ResponsePlan:
    """Build the plan. `proposed`: (action, target) pairs the risk engine already proposed."""
    inc = task.incident
    account = inc.principal_user
    own = task.incident_events()
    proposed_set = set(proposed)
    notes = ["AgentSOC does not carry out any of these steps. Each one is a recommendation "
             "for a person to perform in the organisation's own tools, after approval where "
             "it is marked as disruptive."]

    if dismissed:
        return ResponsePlan(Posture.CLOSED, POSTURE_TEXT[Posture.CLOSED], [], notes)

    succeeded = [e for e in own if e.outcome is AuthOutcome.SUCCESS]
    failed = [e for e in own if e.outcome is AuthOutcome.FAILURE]
    reached = sorted({e.dst_host for e in succeeded if e.dst_host != e.src_host})
    techniques = set(correlation.techniques)
    entities = {(e.kind, e.name): e for e in correlation.entities}
    acct = entities.get(("account", account))
    acct_agents = acct.suspicious_agents if acct else []
    strong = any(f.strength is Strength.STRONG for f in _suspicious(reports))
    any_suspicious = any(True for _ in _suspicious(reports))
    corroborated_hosts = sorted(e.name for e in correlation.entities
                                if e.kind == "host" and len(e.suspicious_agents) >= 2)
    sensitive = sorted(set(reached) & set(task.detection.sensitive_host_access.hosts))
    watch_hits = [f for f in _suspicious(reports, "threat_intel")]

    worked = bool(succeeded)
    if worked and (len(acct_agents) >= 2 or corroborated_hosts or strong or watch_hits):
        posture = Posture.CONTAIN_NOW
    elif any_suspicious:
        posture = Posture.VERIFY_FIRST
    else:
        posture = Posture.MONITOR
    contain = posture is Posture.CONTAIN_NOW
    steps: list[ResponseStep] = []

    def step(phase, action, target, why, agents, action_type=None, disruptive=False):
        steps.append(ResponseStep(
            phase, action, target, why, _titles(reports, agents) or ("Response planner",),
            action_type, (action_type, target) in proposed_set if action_type else False,
            disruptive))

    # -- contain ---------------------------------------------------------------------------
    if posture is not Posture.MONITOR:
        why_acct = (f"Flagged as suspicious by the {_join(_titles(reports, acct_agents))}"
                    if acct_agents else "Named by the detection")
        if worked:
            why = (f"{why_acct}; {len(succeeded)} sign-in(s) during the incident succeeded"
                   + (f", reaching {', '.join(reached[:5])}" if reached else "") + ".")
            if contain:
                step(Phase.CONTAIN, f"End every active session of {account} and reset its "
                     "password.", account, why, acct_agents, ActionType.REVOKE_SESSION, True)
                if account in task.detection.admin_users:
                    step(Phase.CONTAIN, f"Temporarily remove {account}'s administrative "
                         "rights until the investigation finishes.", account,
                         f"{account} is an administrative account, so a stolen session "
                         "reaches more systems.", ["identity"],
                         ActionType.RESTRICT_PRIVILEGES, True)
            else:
                step(Phase.INVESTIGATE, f"Ask the owner of {account} whether they made these "
                     "sign-ins. If they did not, end its sessions and reset its password.",
                     account, why, acct_agents, ActionType.REVOKE_SESSION)
        elif failed:
            step(Phase.CONTAIN if contain else Phase.INVESTIGATE,
                 f"Require multi-factor authentication for {account} and check that account "
                 "lockout is working.", account,
                 f"{len(failed)} failed sign-in(s) and none succeeded: someone may be "
                 "guessing the password.", acct_agents or ["identity"], ActionType.ENABLE_MFA)

        for host in reached:
            ent = entities.get(("host", host))
            agents = ent.suspicious_agents if ent else []
            hot = host in corroborated_hosts or host in sensitive
            if contain and hot:
                why = (f"{account} reached {host} during the incident"
                       + (" and it is a configured sensitive host" if host in sensitive else "")
                       + (f"; flagged by the {_join(_titles(reports, agents))}"
                          if agents else "") + ".")
                step(Phase.CONTAIN, f"Isolate {host} from the network (keep it powered on "
                     "for forensics) until it has been checked.", host, why,
                     agents or ["network"], ActionType.ISOLATE_HOST, True)
            elif agents:
                step(Phase.INVESTIGATE, f"Restrict new connections to {host} and review who "
                     "signed in to it.", host,
                     f"Flagged by the {_join(_titles(reports, agents))}.", agents,
                     ActionType.QUARANTINE_ACCESS)

    # -- investigate -----------------------------------------------------------------------
    ep = next((r for r in reports if r.agent == endpoint.NAME), None)
    if posture is not Posture.MONITOR and ep is not None:
        for gap in ep.gaps[1:4]:
            step(Phase.INVESTIGATE, "Collect: " + gap, None,
                 "The endpoint agent has no telemetry; these records would confirm or rule "
                 "out the incident.", [endpoint.NAME])
    others = sorted({a for f in _suspicious(reports) if f.expanded for a in f.accounts}
                    - {account})
    if others:
        step(Phase.INVESTIGATE, f"Check whether {', '.join(others[:5])} "
             f"{'is' if len(others) == 1 else 'are'} also affected.", None,
             f"In the wider ±{task.window_hours} h window, these accounts appear in "
             "suspicious activity on the same hosts.", ["network"])
    for f in watch_hits:
        step(Phase.INVESTIGATE, "Escalate: an indicator from your watchlist is involved.",
             (f.accounts or f.hosts or (None,))[0], f.statement, ["threat_intel"])
    if not task.expanded and posture is not Posture.MONITOR:
        step(Phase.INVESTIGATE, "Ask the agents for more evidence (±24 h) to see whether the "
             "activity started earlier or is still going on.", None,
             "The standard run only compares the incident with earlier history.", [])
    if posture is Posture.MONITOR:
        step(Phase.INVESTIGATE, f"Keep watching {account}; reopen the incident if failures "
             "or new hosts appear.", account, "No agent reported a suspicious finding.", [],
             ActionType.MONITOR_ONLY)

    # -- recover ---------------------------------------------------------------------------
    if contain:
        step(Phase.RECOVER, f"Restore {account}'s access only after the password is changed "
             "and multi-factor authentication is on; reconnect isolated hosts only after they "
             "are checked clean.", account,
             "Restoring access before the cause is removed lets the activity resume.", [])

    # -- prevent ---------------------------------------------------------------------------
    if posture is not Posture.MONITOR:
        if "T1110" in techniques:
            step(Phase.PREVENT, "Enforce account lockout and multi-factor authentication for "
                 "remote sign-ins.", None,
                 "The detections are consistent with ATT&CK T1110 (Brute Force).",
                 ["threat_intel"], ActionType.ENABLE_MFA)
        if "T1021" in techniques or sensitive:
            target = sensitive[0] if len(sensitive) == 1 else None
            step(Phase.PREVENT, "Limit which hosts and accounts may connect to "
                 + (", ".join(sensitive) if sensitive else "servers")
                 + " (network segmentation, allow-lists for remote administration).", target,
                 "The activity moved between hosts"
                 + (" and reached sensitive hosts" if sensitive else "")
                 + "; ATT&CK T1021 (Remote Services)." if "T1021" in techniques
                 else "The activity reached sensitive hosts.", ["network", "threat_intel"])
        if "T1550" in techniques:
            step(Phase.PREVENT, f"Reset {account}'s credentials so captured hashes or tickets "
                 "stop working, and reduce NTLM use where possible.", account,
                 "The detections are consistent with ATT&CK T1550 (alternate authentication "
                 "material).", ["threat_intel"])

    count = {p: sum(s.phase is p for s in steps) for p in Phase}
    summary = (POSTURE_TEXT[posture] + f" {count[Phase.CONTAIN]} containment, "
               f"{count[Phase.INVESTIGATE]} investigation, {count[Phase.RECOVER]} recovery "
               f"and {count[Phase.PREVENT]} prevention step(s).")
    if correlation.unavailable_agents:
        notes.append("Not every agent had data ("
                     + ", ".join(correlation.unavailable_agents)
                     + "), so the plan may miss steps those sources would justify.")
    return ResponsePlan(posture, summary, steps, notes)
