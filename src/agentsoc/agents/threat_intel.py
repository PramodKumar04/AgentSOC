"""Threat-intelligence agent: MITRE ATT&CK context for the detections, and matches against a
local watchlist of indicators the organisation maintains.

Offline by design: no external feed or reputation service is queried, so incident data never
leaves AgentSOC. A mapped technique says what the activity is consistent with, not that the
technique was used.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError

from agentsoc.agents.base import (
    AgentFinding,
    AgentReport,
    InvestigationTask,
    Stance,
    Strength,
    status_for,
)
from agentsoc.config import PROJECT_ROOT
from agentsoc.detection.catalog import CATALOG, RuleId
from agentsoc.schemas.common import Contract, Identifier

NAME = "threat_intel"
TITLE = "Threat intelligence agent"
PURPOSE = "Adds MITRE ATT&CK context and checks a local indicator watchlist."
WATCHLIST = PROJECT_ROOT / "config" / "threat_intel.json"

# ATT&CK (Enterprise) techniques an authentication detection can be consistent with.
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1110": ("Brute Force", "Credential Access"),
    "T1078": ("Valid Accounts", "Initial Access, Persistence, Privilege Escalation, "
                                "Defense Evasion"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1550": ("Use Alternate Authentication Material", "Lateral Movement, Defense Evasion"),
}
BY_RULE: dict[RuleId, tuple[str, ...]] = {
    RuleId.FAILURE_BURST: ("T1110",),
    RuleId.FAIL_THEN_SUCCESS: ("T1110", "T1078"),
    RuleId.NEW_SRC_HOST: ("T1078",),
    RuleId.NEW_DST_HOST: ("T1078",),
    RuleId.MULTI_HOST_SPREAD: ("T1021",),
    RuleId.LATERAL_CHAIN: ("T1021",),
    RuleId.SENSITIVE_HOST_ACCESS: ("T1078",),
    RuleId.CROSS_ACCOUNT_PIVOT: ("T1078", "T1550"),
}


class Indicator(Contract):
    type: Literal["account", "host"]
    value: Identifier
    label: str = Field(min_length=1, max_length=200)
    source: str = Field(min_length=1, max_length=200)


class Watchlist(Contract):
    version: Literal[1] = 1
    indicators: list[Indicator] = Field(default_factory=list, max_length=10_000)


def load_watchlist(path: Path = WATCHLIST) -> tuple[Watchlist | None, str | None]:
    """(watchlist, problem). A missing file is not a problem: there is simply no watchlist."""
    try:
        return Watchlist.model_validate(json.loads(path.read_text(encoding="utf-8"))), None
    except FileNotFoundError:
        return None, None
    except (OSError, ValueError, ValidationError):
        return None, f"The watchlist {path.name} is not valid and was ignored."


def run(task: InvestigationTask, watchlist_path: Path = WATCHLIST) -> AgentReport:
    inc = task.incident
    findings: list[AgentFinding] = []
    examined = [f"{len(inc.rule_ids)} triggered detection rule(s)"]
    gaps = ["No external threat-intelligence feed or reputation service is queried, so "
            "incident data stays inside AgentSOC.",
            "IP addresses, domains and file hashes are not part of authentication logs."]

    techniques: dict[str, list[str]] = {}
    for rule in inc.rule_ids:
        for t in BY_RULE.get(RuleId(rule), ()):
            techniques.setdefault(t, []).append(CATALOG[RuleId(rule)].title)
    for t, rules in sorted(techniques.items()):
        name, tactic = TECHNIQUES[t]
        findings.append(AgentFinding(
            f"Consistent with ATT&CK {t} {name} ({tactic}), from: {', '.join(sorted(set(rules)))}. "
            "This is a mapping of the pattern, not evidence the technique was used.",
            Stance.CONTEXT, Strength.WEAK, techniques=(t,)))

    watchlist, problem = load_watchlist(watchlist_path)
    if problem:
        gaps.append(problem)
    elif watchlist is None or not watchlist.indicators:
        gaps.append("No local indicator watchlist is configured (config/threat_intel.json).")
    else:
        examined.append(f"{len(watchlist.indicators)} indicator(s) on the local watchlist")
        accounts = {inc.principal_user, *inc.involved_users}
        hosts = set(inc.involved_hosts)
        if task.expanded:
            for e in task.window_events():
                accounts.update(u for u in (e.src_user, e.dst_user) if u)
                hosts.update((e.src_host, e.dst_host))
        for ind in watchlist.indicators:
            hit = ind.value in (accounts if ind.type == "account" else hosts)
            if hit:
                in_incident = ind.value in ({inc.principal_user, *inc.involved_users}
                                            if ind.type == "account" else set(inc.involved_hosts))
                findings.append(AgentFinding(
                    f"{ind.type.capitalize()} {ind.value} is on the watchlist: {ind.label} "
                    f"(source: {ind.source})"
                    + ("" if in_incident else f", seen within ±{task.window_hours} h") + ".",
                    Stance.SUSPICIOUS, Strength.STRONG if in_incident else Strength.MODERATE,
                    accounts=(ind.value,) if ind.type == "account" else (),
                    hosts=(ind.value,) if ind.type == "host" else (),
                    expanded=not in_incident))
        if not any(f.stance is Stance.SUSPICIOUS for f in findings):
            findings.append(AgentFinding(
                "No account or host in the incident is on the local watchlist.",
                Stance.CONTEXT, Strength.WEAK))

    return AgentReport(NAME, TITLE, PURPOSE, status_for(findings), examined, findings, gaps)
