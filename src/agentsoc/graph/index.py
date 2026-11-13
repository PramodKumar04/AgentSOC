"""Shared event index: one streaming pass over the hash-verified events file.

Only events that could matter are kept: movement and failed attempts by non-excluded
accounts inside the padded time span of some incident, plus every event an incident
cites. All incidents share this one index, so no event is copied per incident.
"""

from __future__ import annotations

import hashlib
import json
from bisect import bisect_left, bisect_right
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from agentsoc.detection.config import DetectionConfig
from agentsoc.detection.lateral import account_name
from agentsoc.exceptions import DatasetIntegrityError
from agentsoc.graph.config import StructuralConfig
from agentsoc.schemas import AuthEvent, DatasetSource, Incident
from agentsoc.schemas.graph import EdgeKind
from agentsoc.store.datasets import EVENTS_FILE, load_manifest


@dataclass(slots=True)
class IndexedEvent:
    event_id: str
    timestamp: datetime
    t: float
    account: str
    account_key: str
    src_host: str
    dst_host: str
    kind: EdgeKind
    auth_type: str | None
    logon_type: str | None
    dataset: str
    raw_file: str
    raw_line: int
    duplicate_event_ids: list[str] = field(default_factory=list)

    @property
    def order(self) -> tuple[float, str]:
        return (self.t, self.event_id)


def _raw_lines(dataset_dir: Path) -> Iterator[bytes]:
    """Yield event lines, then raise if the file does not match its manifest."""
    manifest = load_manifest(dataset_dir)
    digest = hashlib.sha256()
    with (dataset_dir / EVENTS_FILE).open("rb") as handle:
        for raw in handle:
            digest.update(raw)
            yield raw
    if digest.hexdigest() != manifest.events_sha256:
        raise DatasetIntegrityError("events file hash does not match its manifest")


def read_evidence(
    dataset_dirs: Sequence[str | Path], event_ids: set[str]
) -> dict[str, AuthEvent]:
    """Original events by ID from the verified files, independently of the index."""
    found: dict[str, AuthEvent] = {}
    for directory in dataset_dirs:
        for raw in _raw_lines(Path(directory)):
            if json.loads(raw)["event_id"] in event_ids:
                event = AuthEvent.model_validate_json(raw)
                found[event.event_id] = event
    return found


def _classify(raw: Mapping, config: DetectionConfig) -> EdgeKind | None:
    orientation, outcome = raw["orientation"], raw["outcome"]
    if outcome == "Success" and orientation in config.access_orientations:
        return EdgeKind.LOCAL if raw["src_host"] == raw["dst_host"] else EdgeKind.MOVEMENT
    if outcome == "Fail" and orientation in config.failure_orientations:
        return EdgeKind.ATTEMPT
    return None


class EventIndex:
    """Time-sorted per-host views over one provenance partition."""

    def __init__(self, events: Iterable[IndexedEvent]) -> None:
        self.by_id: dict[str, IndexedEvent] = {}
        departures: dict[str, list[IndexedEvent]] = {}
        arrivals: dict[str, list[IndexedEvent]] = {}
        attempts: dict[str, list[IndexedEvent]] = {}
        for event in events:
            self.by_id[event.event_id] = event
            for alias in event.duplicate_event_ids:
                self.by_id[alias] = event
            if event.kind is EdgeKind.MOVEMENT:
                departures.setdefault(event.src_host, []).append(event)
                arrivals.setdefault(event.dst_host, []).append(event)
            elif event.kind is EdgeKind.ATTEMPT:
                attempts.setdefault(event.src_host, []).append(event)
        self._departures = self._sorted(departures)
        self._arrivals = self._sorted(arrivals)
        self._attempts = self._sorted(attempts)
        self._own_departures = self._by_account(departures)
        self._own_arrivals = self._by_account(arrivals)

    @staticmethod
    def _sorted(table: dict[str, list[IndexedEvent]]) -> dict:
        out = {}
        for host, items in table.items():
            items.sort(key=lambda e: e.order)
            out[host] = (items, [e.t for e in items])
        return out

    @staticmethod
    def _by_account(table: dict[str, list[IndexedEvent]]) -> dict:
        grouped: dict[tuple[str, str], list[IndexedEvent]] = {}
        for host, items in table.items():
            for event in items:  # already time-sorted
                grouped.setdefault((host, event.account_key), []).append(event)
        return {key: (items, [e.t for e in items]) for key, items in grouped.items()}

    def __len__(self) -> int:
        return len({id(e) for e in self.by_id.values()})

    def get(self, event_id: str) -> IndexedEvent | None:
        return self.by_id.get(event_id)

    @staticmethod
    def _nearest(
        forward: bool, entry: tuple | None, t: float, gap: float
    ) -> Iterator[IndexedEvent]:
        """Events nearest in time first, without copying the window: a busy host costs only
        as many steps as the caller takes."""
        if entry is None:
            return
        items, times = entry
        if forward:  # t < event time <= t + gap
            for k in range(bisect_right(times, t), bisect_right(times, t + gap)):
                yield items[k]
        else:  # t - gap <= event time < t
            for k in range(bisect_left(times, t) - 1, bisect_left(times, t - gap) - 1, -1):
                yield items[k]

    def linked(
        self, event: IndexedEvent, *, forward: bool, gap: float, skip: set[str], limit: int
    ) -> tuple[list[IndexedEvent], bool]:
        """Up to `limit` unseen time-valid neighbours, the account's own first, then the
        nearest in time. Also says whether more were left out."""
        host = event.dst_host if forward else event.src_host
        table, own_table = ((self._departures, self._own_departures) if forward
                            else (self._arrivals, self._own_arrivals))
        chosen: list[IndexedEvent] = []
        for item in self._nearest(forward, own_table.get((host, event.account_key)), event.t, gap):
            if item.event_id not in skip:
                if len(chosen) == limit:
                    return chosen, True
                chosen.append(item)
        for item in self._nearest(forward, table.get(host), event.t, gap):
            if item.account_key != event.account_key and item.event_id not in skip:
                if len(chosen) == limit:
                    return chosen, True
                chosen.append(item)
        return chosen, False

    def attempts_from(self, host: str, low: float, high: float) -> list[IndexedEvent]:
        """Failed attempts from `host` with low <= t <= high."""
        if host not in self._attempts:
            return []
        items, times = self._attempts[host]
        return items[bisect_left(times, low):bisect_right(times, high)]

    def other_accounts_arriving(
        self, host: str, t: float, gap: float, account_key: str, limit: int
    ) -> int:
        """Distinct other accounts arriving at `host` before `t`, counted up to `limit`."""
        seen: set[str] = set()
        for event in self._nearest(False, self._arrivals.get(host), t, gap):
            if event.account_key != account_key:
                seen.add(event.account_key)
                if len(seen) >= limit:
                    break
        return len(seen)


def _merged_spans(
    incidents: Sequence[Incident], pad: float
) -> dict[str, list[tuple[float, float]]]:
    """Per provenance, the padded incident time spans with overlaps merged."""
    raw: dict[str, list[tuple[float, float]]] = {}
    for incident in incidents:
        span = (incident.first_seen.timestamp() - pad, incident.last_seen.timestamp() + pad)
        for dataset in incident.datasets:
            raw.setdefault(dataset.value, []).append(span)
    merged: dict[str, list[tuple[float, float]]] = {}
    for dataset, spans in raw.items():
        out: list[tuple[float, float]] = []
        for low, high in sorted(spans):
            if out and low <= out[-1][1]:
                out[-1] = (out[-1][0], max(out[-1][1], high))
            else:
                out.append((low, high))
        merged[dataset] = out
    return merged


def build_event_index(
    dataset_dirs: Sequence[str | Path],
    incidents: Sequence[Incident],
    detection_config: DetectionConfig,
    config: StructuralConfig,
) -> dict[DatasetSource, EventIndex]:
    """One pass, O(N) time; memory is proportional to the events kept."""
    cited = {e for i in incidents for e in i.event_ids}
    pad = float(config.max_link_gap_seconds * max(config.max_expansion_hops, 1))
    spans = _merged_spans(incidents, pad)
    excluded: dict[str, bool] = {}
    kept: dict[tuple, IndexedEvent] = {}
    for directory in dataset_dirs:
        for line in _raw_lines(Path(directory)):
            raw = json.loads(line)
            kind = _classify(raw, detection_config)
            is_cited = raw["event_id"] in cited
            if kind is None:
                continue
            user = raw["src_user"]
            if user not in excluded:
                excluded[user] = detection_config.is_excluded(user)
            if excluded[user] and not is_cited:
                continue
            timestamp = datetime.fromisoformat(raw["timestamp"])
            t = timestamp.timestamp()
            windows = spans.get(raw["dataset"], ())
            if not is_cited and not any(low <= t <= high for low, high in windows):
                continue
            if kind is EdgeKind.LOCAL and not is_cited:
                continue  # a local logon cannot be movement context
            key = (raw["timestamp"], user, raw["dst_user"], raw["src_host"], raw["dst_host"],
                   raw["auth_type"], raw["logon_type"], raw["orientation"], raw["outcome"],
                   raw["dataset"])
            if key in kept:
                kept[key].duplicate_event_ids.append(raw["event_id"])
                continue
            kept[key] = IndexedEvent(
                event_id=raw["event_id"], timestamp=timestamp, t=t, account=user,
                account_key=account_name(user), src_host=raw["src_host"],
                dst_host=raw["dst_host"], kind=kind, auth_type=raw["auth_type"],
                logon_type=raw["logon_type"], dataset=raw["dataset"],
                raw_file=raw["raw_ref"]["file"], raw_line=raw["raw_ref"]["line"],
            )
    partitions: dict[str, list[IndexedEvent]] = {}
    for event in kept.values():
        partitions.setdefault(event.dataset, []).append(event)
    indexes = {DatasetSource(name): EventIndex(items) for name, items in partitions.items()}
    for incident in incidents:
        for dataset in incident.datasets:
            indexes.setdefault(dataset, EventIndex(()))
    return indexes
