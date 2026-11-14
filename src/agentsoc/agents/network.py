"""Network / host agent: how do the incident's hosts relate, and what else happened on them?
Uses host-to-host authentication history and the structural (SSE) assessment."""

from __future__ import annotations

from collections import Counter, defaultdict

from agentsoc.agents.base import (
    AgentFinding,
    AgentReport,
    InvestigationTask,
    Stance,
    Strength,
    status_for,
)
from agentsoc.schemas import AuthOutcome
from agentsoc.schemas.graph import Feasibility, PathKind

NAME = "network"
TITLE = "Network / host agent"
PURPOSE = "Examines host relationships and cross-host activity around the incident."


def run(task: InvestigationTask) -> AgentReport:
    inc = task.incident
    account = inc.principal_user
    own = task.incident_events()
    own_ids = set(inc.event_ids)
    hosts = set(inc.involved_hosts)
    findings: list[AgentFinding] = []
    examined = [f"{len(hosts)} host(s) in the incident",
                "Every earlier authentication between the same pair of hosts"]
    gaps = ["Network flow, firewall and proxy records are not available, so connections that "
            "did not authenticate are invisible.",
            "There is no asset inventory: host roles and criticality are unknown unless "
            "configured as sensitive hosts."]

    # Have these host-to-host connections ever happened before?
    pairs = sorted({(e.src_host, e.dst_host) for e in own if e.src_host != e.dst_host})
    seen_before: dict[tuple[str, str], int] = Counter()
    for e in task.events:
        if e.timestamp >= inc.first_seen:
            break
        if (e.src_host, e.dst_host) in pairs:
            seen_before[(e.src_host, e.dst_host)] += 1
    never = [p for p in pairs if not seen_before[p]]
    if never:
        findings.append(AgentFinding(
            f"{len(never)} of {len(pairs)} host-to-host connection(s) in the incident never "
            "occur earlier in this data source: "
            + ", ".join(f"{s} → {d}" for s, d in never[:5]) + ".",
            Stance.SUSPICIOUS, Strength.MODERATE,
            hosts=tuple(sorted({h for p in never for h in p})),
            event_ids=tuple(e.event_id for e in own if (e.src_host, e.dst_host) in never)))
    elif pairs:
        findings.append(AgentFinding(
            "Every host-to-host connection in the incident has happened before in this data "
            "source.", Stance.BENIGN, Strength.MODERATE, hosts=tuple(sorted(hosts))))

    # Fan-out from one account in a short time.
    destinations = sorted({e.dst_host for e in own if e.outcome is AuthOutcome.SUCCESS
                           and e.dst_host != e.src_host})
    if len(destinations) >= 3:
        findings.append(AgentFinding(
            f"{account} reached {len(destinations)} different hosts within the incident: "
            f"{', '.join(destinations[:6])}.", Stance.SUSPICIOUS, Strength.MODERATE,
            accounts=(account,), hosts=tuple(destinations)))

    sensitive = sorted(hosts & set(task.detection.sensitive_host_access.hosts))
    if sensitive:
        findings.append(AgentFinding(
            f"The incident reaches configured sensitive host(s): {', '.join(sensitive)}.",
            Stance.SUSPICIOUS, Strength.MODERATE, hosts=tuple(sensitive)))
    jump = sorted(h for h in hosts if task.detection.is_jump_host(h))
    if jump:
        findings.append(AgentFinding(
            f"{', '.join(jump)} is configured as a jump host, where many accounts are expected "
            "to pass through.", Stance.BENIGN, Strength.WEAK, hosts=tuple(jump)))

    # Structural assessment (SSE) of the same incident.
    s = task.structural
    if s is None:
        gaps.append("No verified structural assessment exists for this incident.")
    else:
        examined.append("The structural (graph) assessment of this incident")
        observed = [p for p in s.paths if p.kind is PathKind.OBSERVED
                    and p.verdict is Feasibility.FEASIBLE]
        inferred = [p for p in s.paths if p.kind is PathKind.INFERRED]
        if observed:
            longest = max(observed, key=lambda p: len(p.hosts))
            findings.append(AgentFinding(
                f"{len(observed)} observed movement path(s) are supported hop by hop by the "
                f"logs; the longest is {' → '.join(longest.hosts)}.", Stance.SUSPICIOUS,
                Strength.STRONG if len(longest.hosts) >= 3 else Strength.MODERATE,
                accounts=tuple(longest.accounts), hosts=tuple(longest.hosts),
                event_ids=tuple(longest.event_ids)))
        if inferred:
            findings.append(AgentFinding(
                f"{len(inferred)} path(s) only connect if the activity switched accounts; that "
                "switch is an assumption, not an observation.", Stance.CONTEXT, Strength.WEAK,
                hosts=tuple(sorted({h for p in inferred for h in p.hosts}))))
        for c in s.choke_points[:3]:
            findings.append(AgentFinding(
                f"Every observed route to {c.target_host} passes through "
                f"{', '.join(c.via_hosts)}.", Stance.CONTEXT, Strength.WEAK,
                hosts=(c.target_host, *c.via_hosts)))

    # Who else uses these hosts? Wider window only when the analyst asked for more.
    window = task.window_events() if task.expanded else own
    others: dict[str, Counter] = defaultdict(Counter)
    host_failures: dict[str, set[str]] = defaultdict(set)
    for e in task.window_events() if task.expanded else []:
        if e.event_id in own_ids:
            continue
        for h in {e.src_host, e.dst_host} & hosts:
            if e.src_user != account:
                others[h][e.src_user] += 1
                if e.outcome is AuthOutcome.FAILURE:
                    host_failures[h].add(e.src_user)
    if task.expanded:
        examined.append(f"{len(window)} event(s) on any host within ±{task.window_hours} h")
        for h in sorted(others):
            top = ", ".join(f"{u} ({n})" for u, n in others[h].most_common(4))
            findings.append(AgentFinding(
                f"Other accounts also used {h} within ±{task.window_hours} h: {top}.",
                Stance.CONTEXT, Strength.WEAK, hosts=(h,),
                accounts=tuple(u for u, _ in others[h].most_common(4)), expanded=True))
        for h, users in sorted(host_failures.items()):
            if len(users) >= 3:
                findings.append(AgentFinding(
                    f"{len(users)} different accounts failed to authenticate on {h} in this "
                    "window, a pattern also seen in password spraying.", Stance.SUSPICIOUS,
                    Strength.MODERATE, hosts=(h,), accounts=tuple(sorted(users)[:6]),
                    expanded=True))
        pivots = sorted({e.src_user for e in task.window_events()
                         if e.timestamp > inc.last_seen and e.src_host in destinations
                         and e.src_user != account and e.dst_host not in hosts})
        if pivots:
            findings.append(AgentFinding(
                f"After the incident, other account(s) moved on from hosts it reached: "
                f"{', '.join(pivots[:5])}. This may be unrelated, or a change of account.",
                Stance.SUSPICIOUS, Strength.WEAK, accounts=tuple(pivots[:5]),
                hosts=tuple(destinations), expanded=True))
        if not others:
            findings.append(AgentFinding(
                f"No other account used the incident's hosts within ±{task.window_hours} h.",
                Stance.CONTEXT, Strength.WEAK, hosts=tuple(sorted(hosts)), expanded=True))

    return AgentReport(NAME, TITLE, PURPOSE, status_for(findings), examined, findings, gaps)
