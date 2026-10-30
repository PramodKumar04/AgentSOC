"""Behavioural baseline: which source and destination hosts each user normally
authenticates with, learned from the first `baseline_seconds` of a dataset.

Only SUCCESSFUL access events build the profile — a failed attempt must not
make a host "familiar".
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from agentsoc.detection.config import DetectionConfig
from agentsoc.schemas import AuthEvent, AuthOutcome


@dataclass
class UserProfile:
    src_hosts: set[str] = field(default_factory=set)
    dst_hosts: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class BaselineSplit:
    baseline_end: datetime | None  # None for an empty partition
    baseline_events: list[AuthEvent]
    evaluated_events: list[AuthEvent]


def is_access(event: AuthEvent, config: DetectionConfig) -> bool:
    return event.outcome is AuthOutcome.SUCCESS and event.orientation in config.access_orientations


def is_failure(event: AuthEvent, config: DetectionConfig) -> bool:
    return (
        event.outcome is AuthOutcome.FAILURE and event.orientation in config.failure_orientations
    )


def split_baseline(events: Sequence[AuthEvent], config: DetectionConfig) -> BaselineSplit:
    """`events` must be time-sorted. Baseline = [first event, first + baseline_seconds)."""
    if not events:
        return BaselineSplit(None, [], [])
    end = events[0].timestamp + timedelta(seconds=config.baseline_seconds)
    baseline = [e for e in events if e.timestamp < end]
    return BaselineSplit(end, baseline, list(events[len(baseline):]))


def build_profiles(
    baseline_events: Sequence[AuthEvent], config: DetectionConfig
) -> dict[str, UserProfile]:
    profiles: dict[str, UserProfile] = {}
    for event in baseline_events:
        if is_access(event, config):
            profile = profiles.setdefault(event.src_user, UserProfile())
            profile.src_hosts.add(event.src_host)
            profile.dst_hosts.add(event.dst_host)
    return profiles


@dataclass
class Novelty:
    """First-seen (since baseline) access events, in time order."""

    new_src: list[AuthEvent] = field(default_factory=list)
    new_dst: list[AuthEvent] = field(default_factory=list)
    novel_event_ids: set[str] = field(default_factory=set)
    users_without_baseline: set[str] = field(default_factory=set)


def annotate_novelty(
    evaluated: Sequence[AuthEvent], profiles: dict[str, UserProfile], config: DetectionConfig
) -> Novelty:
    """Mark the first post-baseline access per (user, source host) and (user, destination
    host) not in the user's profile. Later accesses to the same host are not re-flagged."""
    result = Novelty()
    seen_src = {u: set(p.src_hosts) for u, p in profiles.items()}
    seen_dst = {u: set(p.dst_hosts) for u, p in profiles.items()}
    for event in evaluated:
        if not is_access(event, config):
            continue
        user = event.src_user
        if user not in profiles:
            result.users_without_baseline.add(user)
            continue
        if event.src_host not in seen_src[user]:
            seen_src[user].add(event.src_host)
            result.new_src.append(event)
            result.novel_event_ids.add(event.event_id)
        if event.dst_host not in seen_dst[user]:
            seen_dst[user].add(event.dst_host)
            result.new_dst.append(event)
            result.novel_event_ids.add(event.event_id)
    return result
