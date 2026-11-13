"""Relative (anonymised offset) and absolute (real clock) time display."""

import json
import shutil
from datetime import UTC, datetime, timedelta, timezone

import pytest

from agentsoc.api.service import Service
from agentsoc.app_data import (
    REGISTRY_FILE,
    discover_sources,
    format_hour,
    format_time,
    relative_time,
)
from agentsoc.demo_sources import SYNTHETIC_KEY, prepare_demo_sources
from tests.support import signed_in_client

MOMENT = datetime(1970, 1, 4, 10, 55, 7, tzinfo=UTC)


def test_relative_is_unchanged():
    assert format_time(MOMENT) == relative_time(MOMENT) == "Day 3 10:55:07"
    assert format_hour(MOMENT) == "Day 3 10:00"


def test_absolute_states_the_zone_and_converts_to_utc():
    local = datetime(2026, 11, 13, 14, 30, 5, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    assert format_time(local, "absolute") == "2026-11-13 09:00:05 UTC"
    assert format_hour(local, "absolute") == "2026-11-13 09:00 UTC"


@pytest.fixture(scope="module")
def root(tmp_path_factory):
    base = tmp_path_factory.mktemp("time")
    discover_sources(base)
    prepare_demo_sources(base)
    return base


def with_display(root, tmp_path, value):
    copy = tmp_path / "root"
    shutil.copytree(root, copy)
    path = copy / REGISTRY_FILE
    registry = json.loads(path.read_text(encoding="utf-8"))
    registry["sources"][0]["time_display"] = value
    path.write_text(json.dumps(registry), encoding="utf-8")
    return copy


def test_existing_sources_keep_relative_labels(root):
    client = signed_in_client(Service(root=root, provider_factory=lambda: (None, "off")))
    detail = client.get("/api/incidents/INC-00002").json()
    assert detail["first_seen_label"].startswith("Day ")
    assert all(e["time_label"].startswith("Day ") for e in detail["timeline"])


def test_absolute_source_labels_every_time_in_utc(root, tmp_path):
    copy = with_display(root, tmp_path, "absolute")
    client = signed_in_client(Service(root=copy, provider_factory=lambda: (None, "off")))
    detail = client.get(f"/api/incidents/INC-00001?source={SYNTHETIC_KEY}").json()
    labels = [detail["first_seen_label"], detail["last_seen_label"],
              *(e["time_label"] for e in detail["timeline"]),
              *(f["first_seen_label"] for f in detail["findings"])]
    assert labels and all(label.endswith(" UTC") for label in labels)
    assert "UTC" in detail["description"]
    overview = client.get(f"/api/overview?source={SYNTHETIC_KEY}").json()
    assert all(a["label"].endswith(":00 UTC") for a in overview["activity"])
    # The default demo source is unaffected.
    assert client.get("/api/incidents/INC-00002").json()["first_seen_label"].startswith("Day ")


def test_unknown_display_mode_is_refused(root, tmp_path):
    copy = with_display(root, tmp_path, "local-ish")
    assert SYNTHETIC_KEY not in [s.key for s in discover_sources(copy)]
