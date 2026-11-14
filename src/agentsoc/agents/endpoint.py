"""Endpoint investigation agent.

AgentSOC has no endpoint telemetry (process creation, command lines, EDR alerts, services,
scheduled tasks). Rather than guess, this agent reports itself unavailable and lists the
exact endpoint records that would confirm or rule out the incident, host by host, so the
analyst knows what to request. A future endpoint data source plugs in here.
"""

from __future__ import annotations

from agentsoc.agents.base import AgentReport, AgentStatus, InvestigationTask
from agentsoc.schemas import AuthOutcome

NAME = "endpoint"
TITLE = "Endpoint investigation agent"
PURPOSE = "Investigates endpoint telemetry for supporting evidence."


def run(task: InvestigationTask) -> AgentReport:
    inc = task.incident
    own = task.incident_events()
    reached: dict[str, str] = {}
    for e in own:
        if e.outcome is AuthOutcome.SUCCESS and e.dst_host != e.src_host:
            reached.setdefault(e.dst_host, task.label(e.timestamp))
    origins = sorted({e.src_host for e in own})
    gaps = ["No endpoint telemetry source is connected to AgentSOC; nothing on the hosts "
            "themselves could be checked."]
    for host, when in sorted(reached.items(), key=lambda kv: kv[1]):
        gaps.append(f"On {host}, around {when}: process creation and command lines for "
                    f"{inc.principal_user}'s logon session, new services or scheduled tasks, "
                    "and any EDR alert.")
    if origins:
        gaps.append(f"On {', '.join(origins[:5])}: what started the authentication attempts "
                    "(the process and its parent), and signs of credential-dumping tools.")
    return AgentReport(NAME, TITLE, PURPOSE, AgentStatus.UNAVAILABLE,
                       ["Endpoint data sources connected to AgentSOC: none"], [], gaps)
