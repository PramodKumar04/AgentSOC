"""Wider context for an incident, when an analyst asks for more evidence.

Deterministic and read-only: everything comes from the same hash-verified dataset as the
incident. It reports facts (counts, first sightings, related incidents) and draws no
conclusion. It cannot see anything the dataset does not contain.
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from agentsoc.schemas import AuthEvent, AuthOutcome, Incident

MAX_EVENTS = 100
TOP = 10


@dataclass(frozen=True)
class HostActivity:
    host: str
    events: int
    failures: int
    other_accounts: list[tuple[str, int]]


@dataclass(frozen=True)
class PairHistory:
    src_host: str
    dst_host: str
    before: int           # in the whole dataset, before the incident started
    first_seen: datetime | None
    after: int            # after the incident ended


@dataclass(frozen=True)
class RelatedIncident:
    incident_id: str
    principal_user: str
    severity: str
    first_seen: datetime
    last_seen: datetime
    relation: str


@dataclass(frozen=True)
class IncidentContext:
    window_hours: int
    window_start: datetime
    window_end: datetime
    account: str
    account_events: int
    account_failures: int
    account_before: int
    account_after: int
    account_src_hosts: list[str]
    account_dst_hosts: list[str]
    account_first_seen: datetime | None
    events: list[AuthEvent]          # the account's events in the window, not in the incident
    events_truncated: bool
    hosts: list[HostActivity]
    pairs: list[PairHistory]
    related: list[RelatedIncident]
    observations: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def _touches(event: AuthEvent, account: str) -> bool:
    return event.src_user == account or event.dst_user == account


def build_context(incident: Incident, events: Sequence[AuthEvent],
                  incidents: Sequence[Incident], window_hours: int,
                  label: Callable[[datetime], str]) -> IncidentContext:
    """`events` must be the whole dataset sorted by time."""
    start = incident.first_seen - timedelta(hours=window_hours)
    end = incident.last_seen + timedelta(hours=window_hours)
    times = [e.timestamp for e in events]
    window = events[bisect_left(times, start):bisect_right(times, end)]
    own = set(incident.event_ids)
    account = incident.principal_user
    hosts = set(incident.involved_hosts)

    mine = [e for e in window if _touches(e, account)]
    extra = [e for e in mine if e.event_id not in own]
    failures = sum(e.outcome is AuthOutcome.FAILURE for e in mine)
    before = sum(e.timestamp < incident.first_seen for e in mine)
    after = sum(e.timestamp > incident.last_seen for e in mine)
    first_ever = next((e.timestamp for e in events if _touches(e, account)), None)

    host_rows = []
    for host in sorted(hosts):
        touching = [e for e in window if host in (e.src_host, e.dst_host)]
        others = Counter(e.src_user for e in touching if e.src_user != account)
        host_rows.append(HostActivity(
            host, len(touching), sum(e.outcome is AuthOutcome.FAILURE for e in touching),
            sorted(others.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP]))

    by_id = {e.event_id: e for e in window}
    pairs = sorted({(by_id[i].src_host, by_id[i].dst_host) for i in incident.event_ids
                    if i in by_id and by_id[i].src_host != by_id[i].dst_host})
    pair_rows = []
    for src, dst in pairs:
        hits = [e for e in events if e.src_host == src and e.dst_host == dst]
        pair_rows.append(PairHistory(
            src, dst, sum(e.timestamp < incident.first_seen for e in hits),
            hits[0].timestamp if hits else None,
            sum(e.timestamp > incident.last_seen for e in hits)))

    related = []
    for other in incidents:
        if other.incident_id == incident.incident_id:
            continue
        shared = sorted(hosts & set(other.involved_hosts))
        if other.principal_user == account:
            relation = "same account"
        elif shared:
            relation = "shares host(s): " + ", ".join(shared[:5])
        else:
            continue
        related.append(RelatedIncident(other.incident_id, other.principal_user,
                                       other.severity.value, other.first_seen,
                                       other.last_seen, relation))
    related.sort(key=lambda r: (r.relation != "same account", r.first_seen))

    observations = [
        f"{account} has {len(mine)} authentication event(s) between {label(start)} and "
        f"{label(end)}: {before} before the incident, {after} after it, {failures} failed.",
        f"{len(extra)} of these are not part of the incident's evidence.",
    ]
    if first_ever is not None:
        observations.append(f"The earliest event for {account} in this data source is at "
                            f"{label(first_ever)}.")
    for p in pair_rows:
        if p.before == 0:
            observations.append(f"{p.src_host} → {p.dst_host} does not occur in this data source "
                                "before the incident.")
        else:
            observations.append(f"{p.src_host} → {p.dst_host} occurs {p.before} time(s) before "
                                f"the incident, first at {label(p.first_seen)}.")
    same = sum(r.relation == "same account" for r in related)
    if related:
        observations.append(f"{len(related)} other incident(s) in this data source are related: "
                            f"{same} for the same account, {len(related) - same} sharing hosts.")
    else:
        observations.append("No other incident in this data source involves this account or "
                            "these hosts.")

    return IncidentContext(
        window_hours, start, end, account, len(mine), failures, before, after,
        sorted({e.src_host for e in mine}), sorted({e.dst_host for e in mine}), first_ever,
        extra[:MAX_EVENTS], len(extra) > MAX_EVENTS, host_rows, pair_rows, related[:25],
        observations,
        ["Only authentication events in this data source are searched. Endpoint, network, "
         "identity-provider and HR records are not available to AgentSOC.",
         "Absence of an event means it is not in this data source, not that it did not happen.",
         "These are facts for the analyst to weigh; AgentSOC draws no conclusion from them."])
