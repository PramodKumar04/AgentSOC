"""SQLite event index: faithful, verified, isolated, and queryable."""

import hashlib
import random
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentsoc.config import PROJECT_ROOT
from agentsoc.perception.lanl import ingest_lanl_file
from agentsoc.perception.quality import build_quality_report
from agentsoc.schemas import AuthEvent, DatasetSource
from agentsoc.store import eventdb
from agentsoc.store.datasets import EVENTS_FILE, load_events, load_manifest, write_processed_dataset

SAMPLES = PROJECT_ROOT / "data" / "samples"
LANL_WINDOW = (PROJECT_ROOT / "data" / "processed" / "lanl_validation" / "datasets"
               / "lines_1_100000")


def make_dataset(directory: Path, sample: str = "auth_structural_scenarios_synthetic.txt") -> Path:
    result = ingest_lanl_file(SAMPLES / sample, dataset=DatasetSource.SYNTHETIC)
    write_processed_dataset(result, build_quality_report(result), directory, dataset_label="t")
    return directory


def digest_tree(directory: Path) -> dict[str, str]:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir()}


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    root = tmp_path_factory.mktemp("eventdb")
    dataset = make_dataset(root / "dataset")
    index = root / "index.sqlite"
    eventdb.build_index(dataset, index, source_key="scenarios")
    return dataset, index, load_events(dataset)


class TestBuild:
    def test_export_is_byte_identical_and_dataset_untouched(self, tmp_path):
        dataset = make_dataset(tmp_path / "dataset")
        before = digest_tree(dataset)
        index = tmp_path / "i.sqlite"
        info = eventdb.build_index(dataset, index, source_key="s")
        out = tmp_path / "export.jsonl"
        assert eventdb.export_jsonl(index, out) == load_manifest(dataset).events_sha256
        assert out.read_bytes() == (dataset / EVENTS_FILE).read_bytes()
        assert digest_tree(dataset) == before
        assert info.event_count == load_manifest(dataset).event_count
        assert info.provenance == "synthetic"

    @pytest.mark.skipif(not LANL_WINDOW.is_dir(), reason="real LANL window not available")
    def test_real_lanl_window_round_trips_byte_identically(self, tmp_path):
        before = digest_tree(LANL_WINDOW)
        index = tmp_path / "lanl.sqlite"
        eventdb.build_index(LANL_WINDOW, index, source_key="lanl")
        assert eventdb.export_jsonl(index, tmp_path / "e.jsonl") == (
            load_manifest(LANL_WINDOW).events_sha256)
        assert digest_tree(LANL_WINDOW) == before

    def test_tampered_dataset_builds_nothing(self, tmp_path):
        dataset = make_dataset(tmp_path / "dataset")
        events = dataset / EVENTS_FILE
        events.write_bytes(events.read_bytes().replace(b"Success", b"Fail", 1))
        index = tmp_path / "i.sqlite"
        with pytest.raises(eventdb.EventStoreError, match="does not match"):
            eventdb.build_index(dataset, index, source_key="s")
        assert list(tmp_path.glob("i.sqlite*")) == []

    def test_failed_rebuild_keeps_the_previous_index(self, tmp_path):
        dataset = make_dataset(tmp_path / "dataset")
        index = tmp_path / "i.sqlite"
        eventdb.build_index(dataset, index, source_key="s")
        before = index.read_bytes()
        events = dataset / EVENTS_FILE
        events.write_bytes(events.read_bytes() + b"not json\n")
        with pytest.raises(eventdb.EventStoreError):
            eventdb.build_index(dataset, index, source_key="s")
        assert index.read_bytes() == before

    def test_changed_dataset_is_reported_stale(self, tmp_path):
        dataset = make_dataset(tmp_path / "dataset")
        index = tmp_path / "i.sqlite"
        eventdb.build_index(dataset, index, source_key="s")
        eventdb.check_current(index, dataset)
        manifest = dataset / "manifest.json"
        manifest.write_text(manifest.read_text().replace(
            load_manifest(dataset).events_sha256, "0" * 64), encoding="utf-8")
        with pytest.raises(eventdb.EventIndexStaleError):
            eventdb.check_current(index, dataset)

    def test_non_utc_timestamps_are_refused(self):
        with pytest.raises(eventdb.EventStoreError, match="UTC"):
            eventdb.to_micros(datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=2))))

    def test_timestamps_round_trip_exactly(self):
        moment = datetime(2026, 11, 13, 9, 30, 15, 123456, tzinfo=UTC)
        assert eventdb.from_micros(eventdb.to_micros(moment)) == moment


def matches(event: AuthEvent, q: eventdb.EventQuery) -> bool:
    def has(value, needle):
        return needle is None or (value is not None and needle.lower() in value.lower())
    return all([
        has(event.event_id, q.event_id),
        q.user is None or has(event.src_user, q.user) or has(event.dst_user, q.user),
        q.host is None or has(event.src_host, q.host) or has(event.dst_host, q.host),
        has(event.src_host, q.src_host), has(event.dst_host, q.dst_host),
        q.outcome is None or event.outcome.value == q.outcome,
        q.auth_type is None or event.auth_type == q.auth_type,
        q.start is None or event.timestamp >= q.start,
        q.end is None or event.timestamp < q.end,
    ])


def all_pages(index, query, size=7):
    found, page = [], 1
    while True:
        items, total = eventdb.search(index, query, page=page, page_size=size)
        found += items
        if len(found) >= total or not items:
            return found, total
        page += 1


class TestQueries:
    def test_results_equal_a_plain_filter(self, built):
        _, index, events = built
        rng = random.Random(7)  # noqa: S311 — reproducible test data, not security
        users = sorted({e.src_user for e in events})
        hosts = sorted({h for e in events for h in (e.src_host, e.dst_host)})
        times = sorted(e.timestamp for e in events)
        for _ in range(150):
            start = rng.choice([None, rng.choice(times)])
            query = eventdb.EventQuery(
                user=rng.choice([None, rng.choice(users)[:4].upper()]),
                host=rng.choice([None, rng.choice(hosts)[2:6]]),
                src_host=rng.choice([None, None, rng.choice(hosts)]),
                outcome=rng.choice([None, "Success", "Fail"]),
                auth_type=rng.choice([None, "Kerberos", "NTLM"]),
                start=start, end=start + timedelta(hours=rng.randint(1, 48)) if start else None)
            expected = [e for e in events if matches(e, query)]
            found, total = all_pages(index, query)
            assert found == expected and total == len(expected), query

    def test_wildcards_are_matched_literally(self, built):
        _, index, events = built
        for needle in ("%", "_", "\\"):
            _, total = eventdb.search(index, eventdb.EventQuery(user=needle))
            assert total == sum(1 for e in events if matches(e, eventdb.EventQuery(user=needle)))

    def test_histogram_counts_every_event_once(self, built):
        _, index, events = built
        rows = eventdb.outcome_histogram(index, 3600)
        assert sum(s for _, s, _ in rows) == sum(e.outcome.value == "Success" for e in events)
        assert sum(f for _, _, f in rows) == sum(e.outcome.value == "Fail" for e in events)
        assert all(b.minute == 0 and b.second == 0 for b, _, _ in rows)

    def test_distinct_values_only_for_allowed_columns(self, built):
        _, index, _ = built
        assert "Success" in eventdb.distinct_values(index, "outcome")
        with pytest.raises(eventdb.EventStoreError):
            eventdb.distinct_values(index, "src_user; DROP TABLE events")

    @pytest.mark.parametrize(("page", "size"), [(0, 10), (1, 0), (1, 1001)])
    def test_bad_pages_are_refused(self, built, page, size):
        _, index, _ = built
        with pytest.raises(eventdb.EventStoreError):
            eventdb.search(index, eventdb.EventQuery(), page=page, page_size=size)

    def test_index_is_opened_read_only(self, built):
        _, index, _ = built
        with eventdb._reader(index) as conn, pytest.raises(Exception, match="readonly"):
            conn.execute("DELETE FROM events")
