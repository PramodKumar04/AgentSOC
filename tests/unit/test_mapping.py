"""Column mapping and header CSV import (Phase C, validated on CSV before any database)."""

import csv
import json
from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal

import pytest
from pydantic import ValidationError

from agentsoc.app_data import DEMO_CONFIG, DEMO_INPUT
from agentsoc.detection.config import load_detection_config
from agentsoc.detection.engine import run_detection
from agentsoc.exceptions import IngestionError
from agentsoc.ingest.csv_import import MAPPING_FILE, ingest_csv, write_mapped_dataset
from agentsoc.ingest.mapping import MappingSpec, map_record
from agentsoc.perception.lanl import ingest_lanl_file
from agentsoc.perception.records import RejectedRecord, RejectReason
from agentsoc.schemas import AuthEvent, DatasetSource
from agentsoc.schemas.events import RawRef
from agentsoc.store.datasets import load_events, load_manifest

REF = RawRef(file="t.csv", line=2)


def spec(**overrides):
    base = {
        "record_id": "id",
        "timestamp": {"column": "ts"},
        "fields": {
            "src_user": {"column": "user"}, "src_host": {"column": "client"},
            "dst_host": {"column": "server"},
            "orientation": {"column": "kind", "values": {"login": "LogOn", "logout": "LogOff"}},
            "outcome": {"column": "result", "values": {"ok": "Success", "denied": "Fail"}},
        },
    }
    base.update(overrides)
    return MappingSpec.model_validate(base)


ROW = {"id": "4711", "ts": "2026-11-13T09:00:05Z", "user": "alice@CORP", "client": "WS-1",
       "server": "SRV-DB", "kind": "login", "result": "denied"}


def mapped(row=None, s=None):
    return map_record({**ROW, **(row or {})}, s or spec(), ref=REF, prefix="hr-db",
                      dataset=DatasetSource.ORGANIZATION)


def rejected(row, s=None):
    result = mapped(row, s)
    assert isinstance(result, RejectedRecord), result
    return result


class TestSpecValidation:
    def test_required_fields_must_be_mapped(self):
        fields = dict(spec().fields)
        del fields["orientation"]
        with pytest.raises(ValidationError, match="orientation"):
            spec(fields=fields)

    def test_a_constant_must_be_confirmed(self):
        fields = {**spec().fields, "orientation": {"constant": "LogOn"}}
        with pytest.raises(ValidationError, match="constants must be confirmed: orientation"):
            spec(fields=fields)
        confirmed = spec(fields=fields, confirmed_constants=["orientation"])
        assert confirmed.disclosures() == [
            "orientation is not read from the source: every event is set to 'LogOn' "
            "(confirmed by an administrator)."]

    def test_confirmation_of_a_mapped_column_is_refused(self):
        with pytest.raises(ValidationError, match="not constants: outcome"):
            spec(confirmed_constants=["outcome"])

    @pytest.mark.parametrize("field", [
        {"column": "kind", "values": {"login": "SignIn"}},
        {"constant": "Unknown"},
    ])
    def test_targets_must_be_agentsoc_values(self, field):
        fields = {**spec().fields, "orientation": field}
        with pytest.raises(ValidationError, match="is not one of"):
            spec(fields=fields, confirmed_constants=["orientation"] if "constant" in field else [])

    @pytest.mark.parametrize(("field", "message"), [
        ({"column": "user", "constant": "x"}, "either a column or a constant"),
        ({}, "either a column or a constant"),
        ({"column": "user", "values": {"a": "b"}}, "cannot have a value map"),
        ({"constant": "bad\"name"}, "unsupported characters"),
    ])
    def test_field_shape(self, field, message):
        fields = {**spec().fields, "src_user": field}
        confirm = ["src_user"] if "constant" in field and "column" not in field else []
        with pytest.raises(ValidationError, match=message):
            spec(fields=fields, confirmed_constants=confirm)

    def test_unknown_field_and_zone_are_refused(self):
        with pytest.raises(ValidationError):
            spec(fields={**spec().fields, "password": {"column": "pw"}})
        with pytest.raises(ValidationError, match="unknown time zone"):
            spec(timestamp={"column": "ts", "naive_timezone": "Mars/Olympus"})

    def test_hostile_column_names_are_refused(self):
        with pytest.raises(ValidationError):
            spec(record_id='id"; DROP TABLE x; --')

    def test_hash_is_stable_and_sensitive(self):
        assert spec().sha256() == spec().sha256()
        assert spec().sha256() != spec(timestamp={"column": "ts", "format": "epoch_seconds"}
                                       ).sha256()


class TestMapRecord:
    def test_maps_values_and_keeps_the_record_identity(self):
        event = mapped()
        assert isinstance(event, AuthEvent)
        assert event.event_id == "hr-db.4711"
        assert event.timestamp == datetime(2026, 11, 13, 9, 0, 5, tzinfo=UTC)
        assert (event.orientation.value, event.outcome.value) == ("LogOn", "Fail")
        assert event.raw_ref == REF and event.dataset is DatasetSource.ORGANIZATION
        assert event.dst_user is None

    @pytest.mark.parametrize(("row", "reason", "field"), [
        ({"kind": "unlock"}, RejectReason.INVALID_ORIENTATION, "orientation"),
        ({"kind": "LogOn "}, None, None),  # surrounding space only: accepted
        ({"result": "Success?"}, RejectReason.INVALID_OUTCOME, "outcome"),
        ({"user": ""}, RejectReason.MISSING_REQUIRED_FIELD, "src_user"),
        ({"user": None}, RejectReason.MISSING_REQUIRED_FIELD, "src_user"),
        ({"server": "srv{inject}"}, RejectReason.INVALID_FIELD, "dst_host"),
        ({"client": "x" * 129}, RejectReason.INVALID_FIELD, "src_host"),
        ({"id": "a/b"}, RejectReason.INVALID_FIELD, "record_id"),
        ({"id": ""}, RejectReason.MISSING_REQUIRED_FIELD, "record_id"),
        ({"ts": "yesterday"}, RejectReason.INVALID_TIMESTAMP, "timestamp"),
        ({"ts": "2026-11-13T09:00:05"}, RejectReason.INVALID_TIMESTAMP, "timestamp"),
        ({"ts": date(2026, 11, 13)}, RejectReason.INVALID_TIMESTAMP, "timestamp"),
        ({"ts": "1900-01-01T00:00:00Z"}, RejectReason.INVALID_TIMESTAMP, "timestamp"),
        ({"user": b"alice"}, RejectReason.UNSUPPORTED_VALUE, "src_user"),
        ({"user": "al�ice"}, RejectReason.ENCODING_ERROR, "src_user"),
    ])
    def test_bad_values_are_rejected_with_a_reason(self, row, reason, field):
        result = mapped(row)
        if reason is None:
            assert isinstance(result, AuthEvent)
            return
        assert isinstance(result, RejectedRecord)
        assert (result.reason, result.field, result.line) == (reason, field, REF.line)

    def test_orientation_is_never_invented(self):
        fields = {**spec().fields, "orientation": {"column": "kind"}}
        assert rejected({"kind": "login"}, spec(fields=fields)).reason is (
            RejectReason.INVALID_ORIENTATION)
        assert rejected({"kind": None}, spec(fields=fields)).reason is (
            RejectReason.MISSING_REQUIRED_FIELD)

    def test_confirmed_constant_applies_to_every_record(self):
        fields = {**spec().fields, "orientation": {"constant": "LogOn"}}
        s = spec(fields=fields, confirmed_constants=["orientation"])
        assert mapped({"kind": "anything"}, s).orientation.value == "LogOn"

    def test_naive_times_need_a_named_zone(self):
        s = spec(timestamp={"column": "ts", "naive_timezone": "Europe/London"})
        summer = mapped({"ts": "2026-07-01T10:00:00"}, s).timestamp
        winter = mapped({"ts": "2026-12-01T10:00:00"}, s).timestamp
        assert summer == datetime(2026, 7, 1, 9, tzinfo=UTC)
        assert winter == datetime(2026, 12, 1, 10, tzinfo=UTC)
        assert "Europe/London" in s.disclosures()[0]

    @pytest.mark.parametrize(("fmt", "value", "expected"), [
        ("epoch_seconds", "1789290005", datetime(2026, 9, 13, 9, 0, 5, tzinfo=UTC)),
        ("epoch_seconds", "1789290005.5", datetime(2026, 9, 13, 9, 0, 5, 500000, tzinfo=UTC)),
        ("epoch_millis", "1789290005000", datetime(2026, 9, 13, 9, 0, 5, tzinfo=UTC)),
        ("epoch_seconds", 1789290005, datetime(2026, 9, 13, 9, 0, 5, tzinfo=UTC)),
        ("iso8601", "2026-11-13 14:30:05+05:30", datetime(2026, 11, 13, 9, 0, 5, tzinfo=UTC)),
    ])
    def test_time_formats(self, fmt, value, expected):
        s = spec(timestamp={"column": "ts", "format": fmt})
        assert mapped({"ts": value}, s).timestamp == expected

    @pytest.mark.parametrize("value", ["-5", "1e9", "١٢٣", "12345678901234567"])
    def test_epoch_values_must_be_plain_digits(self, value):
        s = spec(timestamp={"column": "ts", "format": "epoch_seconds"})
        assert rejected({"ts": value}, s).reason is RejectReason.INVALID_TIMESTAMP

    def test_database_types(self):
        moment = datetime(2026, 11, 13, 14, 30, 5, tzinfo=timezone(timedelta(hours=5, minutes=30)))
        event = mapped({"ts": moment, "id": 4711, "user": "alice@CORP"})
        assert event.timestamp == datetime(2026, 11, 13, 9, 0, 5, tzinfo=UTC)
        assert event.event_id == "hr-db.4711"
        assert mapped({"id": Decimal("12")}).event_id == "hr-db.12"
        s = spec(fields={**spec().fields, "outcome": {"column": "result",
                                                      "values": {"true": "Success",
                                                                 "false": "Fail"}}})
        assert mapped({"result": True}, s).outcome.value == "Success"

    def test_rejection_excerpt_is_bounded_and_limited_to_mapped_columns(self):
        result = rejected({"kind": "zzz", "secret_column": "do-not-copy", "user": "u" * 500})
        assert len(result.raw_excerpt) <= 200 and "do-not-copy" not in result.raw_excerpt


def write_csv(path, rows, header=("id", "ts", "user", "client", "server", "kind", "result")):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)
    return path


class TestCsvImport:
    def test_rows_are_sorted_and_problems_reported(self, tmp_path):
        path = write_csv(tmp_path / "auth.csv", [
            ["2", "2026-11-13T09:00:10Z", "bob@CORP", "WS-2", "SRV", "login", "ok"],
            ["1", "2026-11-13T09:00:05Z", "alice@CORP", "WS-1", "SRV", "login", "ok"],
            ["1", "2026-11-13T09:00:06Z", "alice@CORP", "WS-1", "SRV", "login", "ok"],
            ["3", "2026-11-13T09:00:07Z", "carol@CORP", "WS-3"],
            ["4", "2026-11-13T09:00:08Z", "dave@CORP", "WS-4", "SRV", "unlock", "ok"],
            [],
        ])
        result = ingest_csv(path, spec(), prefix="hr-db")
        assert [e.event_id for e in result.events] == ["hr-db.1", "hr-db.2"]
        assert [(r.line, r.reason) for r in result.rejected] == [
            (4, RejectReason.DUPLICATE_RECORD_ID), (5, RejectReason.WRONG_FIELD_COUNT),
            (6, RejectReason.INVALID_ORIENTATION)]
        assert result.out_of_order == 1 and result.blank_lines == 1
        assert result.parser_version.startswith("mapping/1:")

    def test_missing_columns_and_bad_prefix_stop_the_import(self, tmp_path):
        path = write_csv(tmp_path / "a.csv", [], header=("id", "ts", "user"))
        with pytest.raises(IngestionError, match="client, kind, result, server"):
            ingest_csv(path, spec(), prefix="hr-db")
        with pytest.raises(IngestionError, match="prefix"):
            ingest_csv(path, spec(), prefix="HR DB")

    def test_dataset_round_trip_with_mapping_record(self, tmp_path):
        path = write_csv(tmp_path / "auth.csv", [
            ["1", "2026-11-13T09:00:05Z", "alice@CORP", "WS-1", "SRV", "login", "ok"]])
        s = spec(fields={**spec().fields, "dst_user": {"constant": "svc@CORP"}},
                 confirmed_constants=["dst_user"])
        result = ingest_csv(path, s, prefix="hr-db")
        manifest, _ = write_mapped_dataset(result, s, tmp_path / "ds", dataset_label="test")
        assert load_events(tmp_path / "ds") == result.events
        assert load_manifest(tmp_path / "ds").parser_version == manifest.parser_version
        record = json.loads((tmp_path / "ds" / MAPPING_FILE).read_text(encoding="utf-8"))
        assert record["mapping_sha256"] == s.sha256()
        assert "dst_user is not read from the source" in record["disclosures"][0]


def test_csv_import_detects_exactly_what_the_lanl_parser_detects(tmp_path):
    """The synthetic demo, exported as a headered CSV, must produce identical detections."""
    lanl = ingest_lanl_file(DEMO_INPUT, dataset=DatasetSource.SYNTHETIC)
    rows = []
    for line_no, line in enumerate(DEMO_INPUT.read_text(encoding="utf-8").splitlines(), 1):
        t, su, du, sh, dh, at, lt, o, out = line.split(",")
        rows.append([line_no, t, su, "" if du == "?" else du, sh, dh,
                     "" if at == "?" else at, "" if lt == "?" else lt, o, out])
    header = ("line", "offset", "src_user", "dst_user", "src_host", "dst_host", "auth_type",
              "logon_type", "orientation", "outcome")
    path = write_csv(tmp_path / "demo.csv", rows, header=header)
    s = MappingSpec.model_validate({
        "record_id": "line", "timestamp": {"column": "offset", "format": "epoch_seconds"},
        "fields": {f: {"column": f} for f in header[2:]}})
    mapped_result = ingest_csv(path, s, prefix="demo", dataset=DatasetSource.SYNTHETIC)
    assert not mapped_result.rejected and not lanl.rejected
    assert len(mapped_result.events) == len(lanl.events)
    rename = {}
    for a, b in zip(lanl.events, mapped_result.events, strict=True):
        assert a.model_dump(exclude={"event_id", "raw_ref"}) == b.model_dump(
            exclude={"event_id", "raw_ref"})
        assert b.event_id == f"demo.{a.raw_ref.line}"
        rename[b.event_id] = a.event_id

    config = load_detection_config(DEMO_CONFIG)
    expected, actual = run_detection(lanl.events, config), run_detection(mapped_result.events,
                                                                         config)
    assert len(actual.incidents) == len(expected.incidents) > 0

    def shape(incidents):
        return [(i.incident_id, i.principal_user, i.severity, sorted(i.event_ids))
                for i in incidents]

    renamed = [(i, u, sev, sorted(rename[e] for e in ids))
               for i, u, sev, ids in shape(actual.incidents)]
    assert renamed == shape(expected.incidents)
