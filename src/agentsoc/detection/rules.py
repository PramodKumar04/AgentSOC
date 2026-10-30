"""Detection rules. Each rule is a pure function over time-sorted events of ONE
provenance partition and returns `Detection`s whose evidence is a subset of
its input — rules never create events.

`metrics` hold raw observed facts; `description` is the rule's interpretation.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime

from agentsoc.detection.baseline import Novelty, UserProfile, is_access, is_failure
from agentsoc.detection.catalog import RuleId
from agentsoc.detection.config import DetectionConfig
from agentsoc.schemas import AuthEvent, AuthOrientation, AuthOutcome, Severity
from agentsoc.schemas.incidents import MetricValue


@dataclass(frozen=True)
class Detection:
    rule_id: RuleId
    user: str
    severity: Severity
    events: tuple[AuthEvent, ...]  # evidence, time-ordered
    description: str
    metrics: dict[str, MetricValue] = field(default_factory=dict)


def group_by_user(events: Sequence[AuthEvent]) -> dict[str, list[AuthEvent]]:
    """Group by source user, preserving time order; keys sorted for determinism."""
    groups: dict[str, list[AuthEvent]] = {}
    for event in events:
        groups.setdefault(event.src_user, []).append(event)
    return dict(sorted(groups.items()))


def merged_windows(
    times: Sequence[datetime], min_count: int, window_s: int
) -> list[tuple[int, int]]:
    """Index ranges [start, end] where >= min_count items fall within window_s;
    overlapping qualifying windows are merged into one range."""
    ranges: list[tuple[int, int]] = []
    left = 0
    for right in range(len(times)):
        while (times[right] - times[left]).total_seconds() > window_s:
            left += 1
        if right - left + 1 >= min_count:
            if ranges and left <= ranges[-1][1]:
                ranges[-1] = (ranges[-1][0], right)
            else:
                ranges.append((left, right))
    return ranges


def _span(events: Sequence[AuthEvent]) -> int:
    return int((events[-1].timestamp - events[0].timestamp).total_seconds())


def failure_bursts(events: Sequence[AuthEvent], config: DetectionConfig) -> list[Detection]:
    cfg = config.failure_burst
    found: list[Detection] = []
    for user, user_events in group_by_user(events).items():
        failures = [e for e in user_events if is_failure(e, config)]
        for start, end in merged_windows(
            [e.timestamp for e in failures], cfg.min_failures, cfg.window_seconds
        ):
            burst = failures[start : end + 1]
            sources = sorted({e.src_host for e in burst})
            found.append(Detection(
                rule_id=RuleId.FAILURE_BURST,
                user=user,
                severity=cfg.severity,
                events=tuple(burst),
                metrics={
                    "failure_count": len(burst),
                    "span_seconds": _span(burst),
                    "threshold_failures": cfg.min_failures,
                    "threshold_window_seconds": cfg.window_seconds,
                    "distinct_source_hosts": len(sources),
                },
                description=(
                    f"{len(burst)} failed authentications for {user} within {_span(burst)} s "
                    f"(threshold: {cfg.min_failures} within {cfg.window_seconds} s) "
                    f"from source host(s) {', '.join(sources)}."
                ),
            ))
    return found


def fail_then_success(events: Sequence[AuthEvent], config: DetectionConfig) -> list[Detection]:
    """A success preceded by >= min_failures CONSECUTIVE failures (no success between
    them) that all lie within window_seconds before the success."""
    cfg = config.fail_then_success
    found: list[Detection] = []
    for user, user_events in group_by_user(events).items():
        pending: list[AuthEvent] = []
        for event in user_events:
            if is_failure(event, config):
                pending.append(event)
                continue
            is_success = event.outcome is AuthOutcome.SUCCESS
            if not is_success or event.orientation is AuthOrientation.LOGOFF:
                continue
            recent = [
                f for f in pending
                if (event.timestamp - f.timestamp).total_seconds() <= cfg.window_seconds
            ]
            if len(recent) >= cfg.min_failures:
                gap = int((event.timestamp - recent[-1].timestamp).total_seconds())
                same_source = event.src_host in {f.src_host for f in recent}
                found.append(Detection(
                    rule_id=RuleId.FAIL_THEN_SUCCESS,
                    user=user,
                    severity=cfg.severity,
                    events=(*recent, event),
                    metrics={
                        "failures_before_success": len(recent),
                        "seconds_from_last_failure": gap,
                        "success_src_host": event.src_host,
                        "success_dst_host": event.dst_host,
                        "success_from_a_failing_source": same_source,
                        "threshold_failures": cfg.min_failures,
                        "threshold_window_seconds": cfg.window_seconds,
                    },
                    description=(
                        f"{user} authenticated successfully ({event.src_host} -> {event.dst_host}) "
                        f"{gap} s after {len(recent)} consecutive failures "
                        f"(threshold: {cfg.min_failures} within {cfg.window_seconds} s)."
                    ),
                ))
            pending = []  # any success ends the consecutive-failure run
    return found


def new_src_hosts(
    novelty: Novelty, profiles: dict[str, UserProfile], config: DetectionConfig
) -> list[Detection]:
    return [
        Detection(
            rule_id=RuleId.NEW_SRC_HOST,
            user=e.src_user,
            severity=config.new_src_host.severity,
            events=(e,),
            metrics={
                "src_host": e.src_host,
                "baseline_src_hosts": len(profiles[e.src_user].src_hosts),
            },
            description=(
                f"{e.src_user} authenticated successfully from {e.src_host}, a source host not "
                f"seen in the baseline ({len(profiles[e.src_user].src_hosts)} known "
                f"source host(s))."
            ),
        )
        for e in novelty.new_src
    ]


def new_dst_hosts(
    novelty: Novelty, profiles: dict[str, UserProfile], config: DetectionConfig
) -> list[Detection]:
    return [
        Detection(
            rule_id=RuleId.NEW_DST_HOST,
            user=e.src_user,
            severity=config.new_dst_host.severity,
            events=(e,),
            metrics={
                "dst_host": e.dst_host,
                "baseline_dst_hosts": len(profiles[e.src_user].dst_hosts),
            },
            description=(
                f"{e.src_user} authenticated successfully to {e.dst_host}, a destination host not "
                f"seen in the baseline ({len(profiles[e.src_user].dst_hosts)} known "
                f"destination host(s))."
            ),
        )
        for e in novelty.new_dst
    ]


def multi_host_spread(novelty: Novelty, config: DetectionConfig) -> list[Detection]:
    cfg = config.multi_host_spread
    found: list[Detection] = []
    for user, firsts in group_by_user(novelty.new_dst).items():
        for start, end in merged_windows(
            [e.timestamp for e in firsts], cfg.min_new_hosts, cfg.window_seconds
        ):
            spread = firsts[start : end + 1]
            hosts = [e.dst_host for e in spread]
            found.append(Detection(
                rule_id=RuleId.MULTI_HOST_SPREAD,
                user=user,
                severity=cfg.severity,
                events=tuple(spread),
                metrics={
                    "new_destination_hosts": len(hosts),
                    "span_seconds": _span(spread),
                    "threshold_hosts": cfg.min_new_hosts,
                    "threshold_window_seconds": cfg.window_seconds,
                },
                description=(
                    f"{user} reached {len(hosts)} first-seen destination hosts "
                    f"({', '.join(hosts)}) within {_span(spread)} s "
                    f"(threshold: {cfg.min_new_hosts} within {cfg.window_seconds} s)."
                ),
            ))
    return found


def lateral_chains(
    evaluated: Sequence[AuthEvent],
    novelty: Novelty,
    profiles: dict[str, UserProfile],
    config: DetectionConfig,
) -> list[Detection]:
    """Follow one account along remote hops where each hop starts on the host the
    previous hop arrived at, within max_hop_gap_seconds. Only maximal chains with
    >= min_hops hops and at least one first-seen hop are reported. Revisiting a
    host already on the chain ends it (no loops)."""
    cfg = config.lateral_chain
    found: list[Detection] = []
    hops_by_user = group_by_user(
        [e for e in evaluated
         if is_access(e, config) and e.src_host != e.dst_host and e.src_user in profiles]
    )
    for user, hops in hops_by_user.items():
        arrivals: dict[str, list[AuthEvent]] = {}
        chains: list[list[AuthEvent]] = []
        extended: set[int] = set()
        for hop in hops:
            prev = arrivals.get(hop.src_host)
            visited = {h for x in prev for h in (x.src_host, x.dst_host)} if prev else set()
            if (
                prev
                and (hop.timestamp - prev[-1].timestamp).total_seconds() <= cfg.max_hop_gap_seconds
                and hop.dst_host not in visited
            ):
                chain = [*prev, hop]
                extended.add(id(prev))
            else:
                chain = [hop]
            chains.append(chain)
            arrivals[hop.dst_host] = chain
        for chain in chains:
            novel = sum(e.event_id in novelty.novel_event_ids for e in chain)
            if id(chain) in extended or len(chain) < cfg.min_hops or novel == 0:
                continue
            path = [chain[0].src_host, *(e.dst_host for e in chain)]
            found.append(Detection(
                rule_id=RuleId.LATERAL_CHAIN,
                user=user,
                severity=cfg.severity,
                events=tuple(chain),
                metrics={
                    "hops": len(chain),
                    "path": " > ".join(path),
                    "span_seconds": _span(chain),
                    "first_seen_hops": novel,
                    "threshold_max_hop_gap_seconds": cfg.max_hop_gap_seconds,
                },
                description=(
                    f"{user} authenticated along {' -> '.join(path)} ({len(chain)} hops in "
                    f"{_span(chain)} s); each hop started on the previous hop's destination. "
                    f"{novel} hop(s) were first-seen relative to the baseline."
                ),
            ))
    return found


def sensitive_access(novelty: Novelty, config: DetectionConfig) -> list[Detection]:
    cfg = config.sensitive_host_access
    sensitive = set(cfg.hosts)
    return [
        Detection(
            rule_id=RuleId.SENSITIVE_HOST_ACCESS,
            user=e.src_user,
            severity=cfg.severity,
            events=(e,),
            metrics={"dst_host": e.dst_host, "src_host": e.src_host},
            description=(
                f"{e.src_user} authenticated to configured sensitive host {e.dst_host} "
                f"for the first time since the baseline (from {e.src_host})."
            ),
        )
        for e in novelty.new_dst
        if e.dst_host in sensitive
    ]
