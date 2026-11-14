"""Incident correlation agent: combines the specialised agents' findings by entity.

An account or host flagged as suspicious by two or more independent agents is corroborated;
one flagged suspicious by one agent and benign by another is a conflict the analyst should
resolve. The agent counts and groups; it does not score or conclude.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from agentsoc.agents.base import AgentReport, AgentStatus, Stance

NAME = "correlation"
TITLE = "Incident correlation agent"


@dataclass(frozen=True)
class EntityView:
    kind: str                       # "account" or "host"
    name: str
    suspicious_agents: list[str]
    benign_agents: list[str]
    findings: int


@dataclass(frozen=True)
class Correlation:
    entities: list[EntityView]
    corroborated: list[str]
    conflicts: list[str]
    techniques: list[str]
    open_questions: list[str]
    unavailable_agents: list[str]
    counts: dict[str, int]
    summary: str


def correlate(reports: list[AgentReport]) -> Correlation:
    titles = {r.agent: r.title for r in reports}
    suspicious: dict[tuple[str, str], set[str]] = defaultdict(set)
    benign: dict[tuple[str, str], set[str]] = defaultdict(set)
    count: dict[tuple[str, str], int] = defaultdict(int)
    techniques: set[str] = set()
    stance_counts = {s.value: 0 for s in Stance}
    for r in reports:
        for f in r.findings:
            stance_counts[f.stance.value] += 1
            techniques.update(f.techniques)
            for kind, names in (("account", f.accounts), ("host", f.hosts)):
                for name in names:
                    key = (kind, name)
                    count[key] += 1
                    if f.stance is Stance.SUSPICIOUS:
                        suspicious[key].add(r.agent)
                    elif f.stance is Stance.BENIGN:
                        benign[key].add(r.agent)

    entities = [EntityView(kind, name, sorted(suspicious[(kind, name)]),
                           sorted(benign[(kind, name)]), n)
                for (kind, name), n in count.items()]
    entities.sort(key=lambda e: (-len(e.suspicious_agents), -e.findings, e.kind, e.name))

    def names(agents: list[str]) -> str:
        return " and ".join(titles[a].removesuffix(" agent") for a in agents)

    corroborated = [f"{e.kind.capitalize()} {e.name} is flagged by the "
                    f"{names(e.suspicious_agents)} agents."
                    for e in entities if len(e.suspicious_agents) >= 2]
    # A conflict needs two different agents disagreeing, not one agent reporting both sides.
    conflicts = [f"{e.kind.capitalize()} {e.name} is flagged as suspicious by the "
                 f"{names(e.suspicious_agents)} agent(s), while the "
                 f"{names(e.benign_agents)} agent(s) found an innocent explanation."
                 for e in entities
                 if any(s != b for s in e.suspicious_agents for b in e.benign_agents)]
    unavailable = [r.title for r in reports if r.status in (AgentStatus.UNAVAILABLE,
                                                             AgentStatus.FAILED)]
    questions: list[str] = []
    for r in reports:
        for g in r.gaps:
            if g not in questions:
                questions.append(g)

    completed = sum(r.status in (AgentStatus.COMPLETED, AgentStatus.NO_FINDINGS)
                    for r in reports)
    summary = (f"{completed} of {len(reports)} specialised agents ran on this incident's data. "
               f"They reported {stance_counts['suspicious']} suspicious, "
               f"{stance_counts['benign']} benign-leaning and {stance_counts['context']} "
               "contextual finding(s). ")
    summary += (f"{len(corroborated)} entit{'y is' if len(corroborated) == 1 else 'ies are'} "
                "flagged by more than one agent." if corroborated
                else "No entity is flagged by more than one agent.")
    if unavailable:
        summary += f" Not available: {', '.join(unavailable)}."
    return Correlation(entities[:20], corroborated, conflicts, sorted(techniques),
                       questions[:12], unavailable, stance_counts, summary)
