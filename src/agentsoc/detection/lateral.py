"""Lateral-movement analysis on top of the rule set (Target 1).

`enrich_chains` adds observed path facts and jump-host context to LATERAL_CHAIN
findings without changing which chains are reported. `cross_account_pivots` is the
CROSS_ACCOUNT_PIVOT rule. As in `rules.py`, evidence is a subset of the input and only
successful access events are movement: a failed logon never places an account on a host.

Jump hosts are context supplied by the operator. Findings on them are never dropped,
and a host that is not configured is treated as unknown, neither benign nor malicious.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime
from itertools import groupby, pairwise

from agentsoc.detection.baseline import Novelty, is_access
from agentsoc.detection.catalog import RuleId
from agentsoc.detection.config import DetectionConfig
from agentsoc.detection.correlate import SEVERITY_ORDER
from agentsoc.detection.rules import Detection
from agentsoc.schemas import AuthEvent, Severity
from agentsoc.schemas.incidents import MetricValue


def _sensitive_on(path: Sequence[str], config: DetectionConfig) -> int:
    sensitive = set(config.sensitive_host_access.hosts)
    return sum(host in sensitive for host in path)


def _apply_jump_context(
    detection: Detection,
    acted_from: Sequence[str],
    transit: Sequence[str],
    path: Sequence[str],
    config: DetectionConfig,
) -> Detection:
    """Add `benign_context` when a host the account acted from is a configured jump host.

    Severity drops one band only if every transit host is a jump host and no sensitive
    host is on the path; the `severity_adjustment` metric records it.
    """
    jump_hosts = sorted({h for h in acted_from if config.is_jump_host(h)})
    if not jump_hosts:
        return detection
    metrics: dict[str, MetricValue] = {
        **detection.metrics,
        "benign_context": (
            f"Acted from configured jump host(s) {', '.join(jump_hosts)}; this can be routine "
            "administrative access. Context only: it does not clear the activity."
        ),
    }
    severity = detection.severity
    if (
        severity is not Severity.LOW
        and config.severity_policy.jump_host_point_reduction > 0
        and all(config.is_jump_host(h) for h in transit)
        and _sensitive_on(path, config) == 0
    ):
        lowered = SEVERITY_ORDER[SEVERITY_ORDER.index(severity) - 1]
        metrics["severity_adjustment"] = (
            f"Finding lowered from {severity.value} to {lowered.value}: every transit host is "
            "a configured jump host and no sensitive host is on the path."
        )
        severity = lowered
    return replace(detection, metrics=metrics, severity=severity)


def enrich_chains(chains: Sequence[Detection], config: DetectionConfig) -> list[Detection]:
    """Add path metrics and jump-host context; the set of chains and their evidence are kept."""
    enriched = []
    for chain in chains:
        events = chain.events
        path = [events[0].src_host, *(e.dst_host for e in events)]
        gaps = [(b.timestamp - a.timestamp).total_seconds()
                for a, b in pairwise(events)]
        with_metrics = replace(chain, metrics={
            **chain.metrics,
            "distinct_hosts": len(set(path)),
            "longest_hop_gap_seconds": int(max(gaps)),
            "sensitive_hosts_on_path": _sensitive_on(path, config),
            "ends_on_sensitive_host": _sensitive_on(path[-1:], config) == 1,
        })
        enriched.append(_apply_jump_context(with_metrics, path[:-1], path[1:-1], path, config))
    return enriched


def account_name(user: str) -> str:
    """The account name without its domain: LANL records one user under several domains,
    and those must not look like two accounts."""
    return user.partition("@")[0].casefold()


def _account(event: AuthEvent) -> str:
    return account_name(event.src_user)


def _pivot(
    departure: AuthEvent,
    arrivals_on_host: dict[str, AuthEvent],
    last_on_host: datetime | None,
    config: DetectionConfig,
) -> Detection | None:
    cfg = config.cross_account_pivot
    hub, me = departure.src_host, _account(departure)
    if last_on_host and (departure.timestamp - last_on_host).total_seconds() <= cfg.window_seconds:
        return None  # the account's own logon already explains why it is on this host
    others: list[AuthEvent] = []
    for name, arrival in reversed(arrivals_on_host.items()):  # most recent first
        if (departure.timestamp - arrival.timestamp).total_seconds() > cfg.window_seconds:
            break
        if name != me:
            others.append(arrival)
    if not others:
        return None
    nearest = others[0]
    gap = int((departure.timestamp - nearest.timestamp).total_seconds())
    path = [nearest.src_host, hub, departure.dst_host]
    detection = Detection(
        rule_id=RuleId.CROSS_ACCOUNT_PIVOT,
        user=departure.src_user,
        severity=cfg.severity,
        events=(*reversed(others[: cfg.max_evidence_arrivals]), departure),
        metrics={
            "pivot_host": hub,
            "path": " > ".join(path),
            "arriving_account": nearest.src_user,
            "arrival_event_id": nearest.event_id,
            "departure_event_id": departure.event_id,
            "arrival_time": nearest.timestamp.isoformat(),
            "departure_time": departure.timestamp.isoformat(),
            "seconds_after_arrival": gap,
            "other_accounts_on_host": len(others),
            "threshold_window_seconds": cfg.window_seconds,
        },
        description=(
            f"{departure.src_user} authenticated from {hub} to {departure.dst_host}, its first "
            f"use of {hub} as a source since the baseline, {gap} s after {nearest.src_user} "
            f"arrived on {hub} from {nearest.src_host} ({len(others)} other account(s) arrived "
            f"within {cfg.window_seconds} s). The accounts share a host in time; this does not "
            "show that credentials were transferred or compromised."
        ),
    )
    return _apply_jump_context(detection, [hub], [hub], path, config)


def cross_account_pivots(
    evaluated: Sequence[AuthEvent], novelty: Novelty, config: DetectionConfig
) -> list[Detection]:
    """One account arrives on a host; within the window a different account leaves that host
    for another, using it as a source for the first time and without having logged on to it.

    Reported at most once per (account, host) because only first-seen sources qualify.
    Evaluates post-baseline events, like the other novelty rules; the departing account
    needs a baseline, the arriving account does not.
    """
    first_seen_sources = {e.event_id for e in novelty.new_src}
    arrivals: dict[str, dict[str, AuthEvent]] = {}  # host -> account -> latest arrival
    last_logon: dict[tuple[str, str], datetime] = {}
    found: list[Detection] = []
    accesses = (e for e in evaluated if is_access(e, config))
    # Order within one second is unknown, so a departure only sees earlier seconds.
    for _, second in groupby(accesses, key=lambda e: e.timestamp):
        batch = list(second)
        for event in batch:
            if event.event_id in first_seen_sources and event.src_host != event.dst_host:
                detection = _pivot(
                    event, arrivals.get(event.src_host, {}),
                    last_logon.get((event.src_host, _account(event))), config,
                )
                if detection:
                    found.append(detection)
        for event in batch:
            last_logon[(event.dst_host, _account(event))] = event.timestamp
            if event.src_host != event.dst_host:
                on_host = arrivals.setdefault(event.dst_host, {})
                on_host.pop(_account(event), None)  # re-insert so the newest stays last
                on_host[_account(event)] = event
    return found
