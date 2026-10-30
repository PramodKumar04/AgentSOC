"""Data-quality report and processed-dataset persistence."""

import json

import pytest

from agentsoc.exceptions import DatasetIntegrityError, IngestionError
from agentsoc.perception.lanl import ingest_lanl_file
from agentsoc.perception.quality import build_quality_report, render_markdown
from agentsoc.store.datasets import (
    EVENTS_FILE,
    MANIFEST_FILE,
    REJECTED_FILE,
    REPORT_JSON,
    REPORT_MD,
    load_events,
    load_manifest,
    write_processed_dataset,
)

LINES = [
    "1,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Fail",
    "2,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success",
    "3,U2@DOM1,,C3,C1,?,?,LogOff,Success",
    "x,U2@DOM1,U2@DOM1,C3,C1,?,?,LogOff,Success",
    "",
]


@pytest.fixture
def result(tmp_path):
    path = tmp_path / "auth.txt"
    path.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    return ingest_lanl_file(path)


class TestQualityReport:
    def test_metrics(self, result):
        r = build_quality_report(result)
        assert (r.lines_read, r.blank_lines, r.accepted, r.rejected) == (5, 1, 3, 1)
        assert r.rejection_rate == pytest.approx(1 / 4)
        assert r.rejected_by_reason == {"INVALID_TIMESTAMP": 1}
        assert r.rejected_by_field == {"time": 1}
        assert r.missing_optional == {"dst_user": 1, "auth_type": 1, "logon_type": 1}
        assert r.outcome_counts == {"Success": 2, "Fail": 1}
        assert r.failure_rate == pytest.approx(1 / 3)
        assert r.unique_users == 2 and r.unique_hosts == 3
        assert r.auth_type_top == {"Kerberos": 2, "(missing)": 1}
        assert r.time_start < r.time_end

    def test_empty_input_has_no_division_errors(self, tmp_path):
        path = tmp_path / "empty.txt"
        path.write_bytes(b"")
        r = build_quality_report(ingest_lanl_file(path))
        assert r.rejection_rate == 0 and r.failure_rate == 0 and r.time_start is None
        assert "n/a" in render_markdown(r, dataset_label="empty")

    def test_markdown_states_provenance_and_numbers(self, result):
        md = render_markdown(build_quality_report(result), dataset_label="SYNTHETIC test file")
        assert "SYNTHETIC test file" in md
        assert "| Accepted events | 3 |" in md
        assert "`INVALID_TIMESTAMP`" in md


class TestDatasetStore:
    def write(self, result, out, **kwargs):
        report = build_quality_report(result)
        return write_processed_dataset(result, report, out, dataset_label="test", **kwargs)

    def test_writes_all_files_and_round_trips(self, result, tmp_path):
        out = tmp_path / "ds"
        manifest = self.write(result, out)
        for name in (EVENTS_FILE, REJECTED_FILE, REPORT_JSON, REPORT_MD, MANIFEST_FILE):
            assert (out / name).is_file()
        assert manifest.event_count == 3 and manifest.rejected_count == 1
        assert load_events(out) == result.events
        assert load_manifest(out) == manifest
        rejected = [json.loads(x) for x in (out / REJECTED_FILE).read_text().splitlines()]
        assert rejected[0]["reason"] == "INVALID_TIMESTAMP"

    def test_output_is_byte_reproducible(self, result, tmp_path):
        self.write(result, tmp_path / "a")
        self.write(result, tmp_path / "b")
        for name in (EVENTS_FILE, REJECTED_FILE, REPORT_JSON, REPORT_MD):
            assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()
        assert b"\r\n" not in (tmp_path / "a" / EVENTS_FILE).read_bytes()

    def test_refuses_to_overwrite_without_flag(self, result, tmp_path):
        self.write(result, tmp_path / "ds")
        with pytest.raises(IngestionError, match="not empty"):
            self.write(result, tmp_path / "ds")
        self.write(result, tmp_path / "ds", overwrite=True)

    def test_detects_tampered_events(self, result, tmp_path):
        out = tmp_path / "ds"
        self.write(result, out)
        path = out / EVENTS_FILE
        path.write_text(path.read_text().replace("U1@DOM1", "U9@DOM1"), encoding="utf-8")
        with pytest.raises(DatasetIntegrityError, match="hash"):
            load_events(out)

    def test_invalid_record_reports_line_number(self, result, tmp_path):
        out = tmp_path / "ds"
        self.write(result, out)
        path = out / EVENTS_FILE
        lines = path.read_text().splitlines()
        lines[1] = '{"event_id": "bad"}'
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with pytest.raises(DatasetIntegrityError, match=f"{EVENTS_FILE}:2"):
            load_events(out, verify=False)

    def test_missing_or_invalid_manifest(self, result, tmp_path):
        with pytest.raises(DatasetIntegrityError, match="not found"):
            load_events(tmp_path)
        out = tmp_path / "ds"
        self.write(result, out)
        (out / MANIFEST_FILE).write_text("{}", encoding="utf-8")
        with pytest.raises(DatasetIntegrityError, match="invalid"):
            load_events(out)
