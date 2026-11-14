"""Identity agent: how does this account normally authenticate, and how does the incident
compare? Uses the account's own history in the same data source as its baseline."""

from __future__ import annotations

from collections import Counter

from agentsoc.agents.base import (
    AgentFinding,
    AgentReport,
    InvestigationTask,
    Stance,
    Strength,
    status_for,
    touches,
)
from agentsoc.schemas import AuthOutcome

NAME = "identity"
TITLE = "Identity agent"
PURPOSE = "Analyses the account's authentication behaviour against its own history."


def _rate(part: int, whole: int) -> float:
    return part / whole if whole else 0.0


def run(task: InvestigationTask) -> AgentReport:
    inc = task.incident
    account = inc.principal_user
    own = task.incident_events()
    history = [e for e in task.events if touches(e, account) and e.timestamp < inc.first_seen]
    findings: list[AgentFinding] = []
    gaps = ["Identity-provider records (MFA prompts, password resets, lockouts, risky sign-in "
            "flags) are not available to AgentSOC.",
            "HR or directory data (role, department, leave) is not available."]
    examined = [f"{len(own)} incident event(s) for {account}",
                f"{len(history)} earlier event(s) for {account} in this data source"]

    if account in task.detection.admin_users:
        findings.append(AgentFinding(
            f"{account} is configured as an administrative account; broad or unusual host "
            "access can be part of its normal work.", Stance.BENIGN, Strength.MODERATE,
            accounts=(account,)))
    if task.detection.is_excluded(account):
        findings.append(AgentFinding(
            f"{account} matches a machine or service account pattern; automated activity is "
            "likely.", Stance.BENIGN, Strength.WEAK, accounts=(account,)))

    if not history:
        findings.append(AgentFinding(
            f"{account} has no activity in this data source before the incident, so its "
            "behaviour cannot be compared with a baseline.", Stance.CONTEXT, Strength.WEAK,
            accounts=(account,)))
    else:
        failures_before = sum(e.outcome is AuthOutcome.FAILURE for e in history)
        failures_now = sum(e.outcome is AuthOutcome.FAILURE for e in own)
        before, now = _rate(failures_before, len(history)), _rate(failures_now, len(own))
        if failures_now and now >= max(0.3, 3 * before):
            findings.append(AgentFinding(
                f"{failures_now} of {len(own)} incident events failed ({now:.0%}), against "
                f"{failures_before} of {len(history)} before the incident ({before:.0%}).",
                Stance.SUSPICIOUS, Strength.STRONG if now >= 0.5 and before < 0.1
                else Strength.MODERATE, accounts=(account,),
                event_ids=tuple(e.event_id for e in own if e.outcome is AuthOutcome.FAILURE)))
        elif failures_now:
            findings.append(AgentFinding(
                f"The failure rate during the incident ({now:.0%}) is close to this account's "
                f"usual rate ({before:.0%}).", Stance.BENIGN, Strength.WEAK,
                accounts=(account,)))

        known_dst = {e.dst_host for e in history if e.outcome is AuthOutcome.SUCCESS}
        known_src = {e.src_host for e in history if e.outcome is AuthOutcome.SUCCESS}
        new_dst = sorted({e.dst_host for e in own if e.outcome is AuthOutcome.SUCCESS}
                         - known_dst)
        new_src = sorted({e.src_host for e in own if e.outcome is AuthOutcome.SUCCESS}
                         - known_src)
        if new_dst:
            findings.append(AgentFinding(
                f"{account} signed in successfully to {len(new_dst)} host(s) it had never "
                f"reached before: {', '.join(new_dst[:6])}.", Stance.SUSPICIOUS,
                Strength.MODERATE, accounts=(account,), hosts=tuple(new_dst),
                event_ids=tuple(e.event_id for e in own if e.dst_host in new_dst)))
        elif own:
            findings.append(AgentFinding(
                f"Every host {account} reached during the incident had been reached by this "
                "account before.", Stance.BENIGN, Strength.MODERATE, accounts=(account,)))
        if new_src:
            findings.append(AgentFinding(
                f"{account} authenticated from {len(new_src)} source host(s) not used before: "
                f"{', '.join(new_src[:6])}.", Stance.SUSPICIOUS, Strength.WEAK,
                accounts=(account,), hosts=tuple(new_src)))

        hours = Counter(e.timestamp.hour for e in history if e.outcome is AuthOutcome.SUCCESS)
        if sum(hours.values()) >= 10:
            usual = {h for h, n in hours.items() if n >= max(2, 0.05 * sum(hours.values()))}
            odd = sorted({e.timestamp.hour for e in own} - usual)
            if odd:
                clock = ("hours are offsets in anonymised data, not local time"
                         if task.relative_time else "hours are UTC")
                findings.append(AgentFinding(
                    f"Incident activity falls in hour(s) {', '.join(f'{h:02d}' for h in odd)}, "
                    f"which this account rarely uses ({clock}).", Stance.SUSPICIOUS,
                    Strength.WEAK, accounts=(account,)))

    if task.expanded:
        start, end = task.window
        mine = [e for e in task.window_events() if touches(e, account)
                and e.event_id not in set(inc.event_ids)]
        after = [e for e in mine if e.timestamp > inc.last_seen]
        after_fail = [e for e in after if e.outcome is AuthOutcome.FAILURE]
        findings.append(AgentFinding(
            f"Within ±{task.window_hours} h, {account} has {len(mine)} further event(s): "
            f"{len(mine) - len(after)} before and {len(after)} after the incident.",
            Stance.CONTEXT, Strength.WEAK, accounts=(account,),
            event_ids=tuple(e.event_id for e in mine[:50]), expanded=True))
        if after_fail:
            findings.append(AgentFinding(
                f"{len(after_fail)} failed authentication(s) for {account} continue after the "
                "incident ended.", Stance.SUSPICIOUS, Strength.MODERATE, accounts=(account,),
                event_ids=tuple(e.event_id for e in after_fail[:50]), expanded=True))
        elif after:
            findings.append(AgentFinding(
                f"After the incident, {account} authenticates successfully with no further "
                "failures, which is consistent with normal use.", Stance.BENIGN, Strength.WEAK,
                accounts=(account,), expanded=True))
        examined.append(f"Events for {account} between {task.label(start)} and "
                        f"{task.label(end)}")

    return AgentReport(NAME, TITLE, PURPOSE, status_for(findings), examined, findings, gaps)
