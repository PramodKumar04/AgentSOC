"""Agent orchestrator: creates one investigation task per specialised agent, runs them in
parallel, isolates failures, and hands the results to the correlation agent.

Standard run: the incident against the account's and hosts' history. Expanded run (the analyst
asked for more evidence): the same agents also search ±N hours around the incident.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from datetime import UTC, datetime

from agentsoc.agents import endpoint, identity, network, threat_intel
from agentsoc.agents.base import AgentReport, AgentStatus, InvestigationTask
from agentsoc.agents.correlation import Correlation, correlate
from agentsoc.logging_setup import get_logger

logger = get_logger(__name__)

AgentModule = tuple[str, str, str, Callable[[InvestigationTask], AgentReport]]
DEFAULT_AGENTS: list[AgentModule] = [
    (m.NAME, m.TITLE, m.PURPOSE, m.run) for m in (identity, network, threat_intel, endpoint)]
AGENT_TIMEOUT_SECONDS = 30.0


@dataclass(frozen=True)
class AgentAnalysis:
    incident_id: str
    window_hours: int | None
    reports: list[AgentReport]
    correlation: Correlation
    generated_at: datetime
    duration_ms: float


def _run_one(name: str, run: Callable[[InvestigationTask], AgentReport],
             task: InvestigationTask) -> AgentReport:
    started = time.perf_counter()
    report = run(task)
    return AgentReport(report.agent, report.title, report.purpose, report.status,
                       report.examined, report.findings, report.gaps,
                       round((time.perf_counter() - started) * 1000, 1))


def _failed(name: str, title: str, purpose: str, why: str) -> AgentReport:
    return AgentReport(name, title, purpose, AgentStatus.FAILED, [], [],
                       [f"This agent did not complete ({why}); its aspect is unexamined."])


def orchestrate(task: InvestigationTask, agents: list[AgentModule] | None = None,
                timeout: float = AGENT_TIMEOUT_SECONDS) -> AgentAnalysis:
    agents = agents or DEFAULT_AGENTS
    started = time.perf_counter()
    reports: list[AgentReport] = []
    pool = ThreadPoolExecutor(max_workers=len(agents), thread_name_prefix="agentsoc-agent")
    try:
        futures = [(spec, pool.submit(_run_one, spec[0], spec[3], task)) for spec in agents]
        deadline = time.monotonic() + timeout
        for (name, title, purpose, _), future in futures:
            try:
                reports.append(future.result(timeout=max(0.0, deadline - time.monotonic())))
            except FutureTimeout:
                logger.warning("agent timed out", extra={"context": {"agent": name}})
                reports.append(_failed(name, title, purpose, f"no result within {timeout:.0f} s"))
            except Exception:
                logger.exception("agent failed", extra={"context": {"agent": name}})
                reports.append(_failed(name, title, purpose, "internal error"))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return AgentAnalysis(task.incident.incident_id, task.window_hours, reports,
                         correlate(reports), datetime.now(UTC),
                         round((time.perf_counter() - started) * 1000, 1))


MAX_PROMPT_FINDINGS = 12


def prompt_payload(analysis: AgentAnalysis) -> dict:
    """Compact, bounded view for the language-model reasoning layer (untrusted data block)."""
    return {
        "agents": [{
            "agent": r.agent, "status": r.status.value,
            "findings": [{"stance": f.stance.value, "strength": f.strength.value,
                          "statement": f.statement[:300]}
                         for f in r.findings[:MAX_PROMPT_FINDINGS]],
            "not_available": r.gaps[:3],
        } for r in analysis.reports],
        "corroborated": analysis.correlation.corroborated[:8],
        "conflicts": analysis.correlation.conflicts[:8],
    }
