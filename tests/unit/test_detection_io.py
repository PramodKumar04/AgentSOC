"""Verified input loading and reproducible detection outputs."""

import json

import pytest

from agentsoc.detection.engine import run_detection
from agentsoc.detection.inputs import load_verified_inputs
from agentsoc.exceptions import DatasetIntegrityError, DetectionError
from agentsoc.perception.lanl import ingest_lanl_file
from agentsoc.perception.quality import build_quality_report
from agentsoc.schemas import DatasetSource
from agentsoc.store.datasets import EVENTS_FILE, MANIFEST_FILE, write_processed_dataset
from agentsoc.store.detections import (
    DETECTIONS_FILE,
    INCIDENTS_FILE,
    REPORT_FILE,
    SUMMARY_FILE,
    load_findings,
    load_incidents,
    write_detection_outputs,
)
from tests.detection_support import config

LINES = [f"{t},U1@D,U1@D,C1,C1,Kerberos,Network,LogOn,Fail" for t in range(0, 50, 10)]
LINES.append("60,U1@D,U1@D,C1,C1,Kerberos,Network,LogOn,Success")
CFG = config(baseline_seconds=0)


def make_dataset(tmp_path, name="ds", source="auth.txt", dataset=DatasetSource.SYNTHETIC):
    raw = tmp_path / source
    raw.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    result = ingest_lanl_file(raw, dataset=dataset)
    out = tmp_path / name
    write_processed_dataset(result, build_quality_report(result), out, dataset_label="test")
    return out


class TestVerifiedInputs:
    def test_loads_verified_dataset(self, tmp_path):
        (inp,) = load_verified_inputs([make_dataset(tmp_path)])
        assert inp.manifest.dataset is DatasetSource.SYNTHETIC
        assert len(inp.events) == 6

    def test_tampered_dataset_rejected(self, tmp_path):
        ds = make_dataset(tmp_path)
        path = ds / EVENTS_FILE
        path.write_text(path.read_text().replace("Fail", "Success", 1), encoding="utf-8")
        with pytest.raises(DatasetIntegrityError, match="hash"):
            load_verified_inputs([ds])

    def test_provenance_mismatch_rejected(self, tmp_path):
        ds = make_dataset(tmp_path)
        manifest = json.loads((ds / MANIFEST_FILE).read_text())
        manifest["dataset"] = "lanl"
        (ds / MANIFEST_FILE).write_text(json.dumps(manifest), encoding="utf-8")
        with pytest.raises(DatasetIntegrityError, match="provenance"):
            load_verified_inputs([ds])

    def test_overlapping_event_ids_across_inputs_rejected(self, tmp_path):
        a = make_dataset(tmp_path, "a")
        b = make_dataset(tmp_path, "b")  # same source file name -> same event IDs
        with pytest.raises(DatasetIntegrityError, match="already loaded"):
            load_verified_inputs([a, b])

    def test_no_inputs(self):
        with pytest.raises(DatasetIntegrityError):
            load_verified_inputs([])

    def test_unprocessed_directory_rejected(self, tmp_path):
        with pytest.raises(DatasetIntegrityError, match="manifest"):
            load_verified_inputs([tmp_path])


class TestOutputs:
    def run(self, tmp_path, out_name="out"):
        inputs = load_verified_inputs([make_dataset(tmp_path, f"ds-{out_name}")])
        result = run_detection([e for i in inputs for e in i.events], CFG)
        summary = write_detection_outputs(result, inputs, CFG, tmp_path / out_name)
        return inputs, result, summary

    def test_writes_four_files_with_provenance(self, tmp_path):
        inputs, _, summary = self.run(tmp_path)
        out = tmp_path / "out"
        for name in (DETECTIONS_FILE, INCIDENTS_FILE, SUMMARY_FILE, REPORT_FILE):
            assert (out / name).is_file()
        (ref,) = summary.inputs
        assert ref.events_sha256 == inputs[0].manifest.events_sha256
        assert ref.dataset is DatasetSource.SYNTHETIC
        assert summary.config_sha256 == CFG.sha256()
        assert summary.incidents_total == 1
        assert summary.findings_by_rule["FAILURE_BURST"] == 1

    def test_round_trip(self, tmp_path):
        _, result, _ = self.run(tmp_path)
        assert load_incidents(tmp_path / "out") == result.incidents
        assert load_findings(tmp_path / "out") == result.findings

    def test_outputs_byte_reproducible(self, tmp_path):
        ds = make_dataset(tmp_path)
        for out in ("a", "b"):
            inputs = load_verified_inputs([ds])
            result = run_detection([e for i in inputs for e in i.events], CFG)
            write_detection_outputs(result, inputs, CFG, tmp_path / out)
        for name in (DETECTIONS_FILE, INCIDENTS_FILE, REPORT_FILE):
            assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()

    def test_tampered_incidents_detected_on_load(self, tmp_path):
        self.run(tmp_path)
        path = tmp_path / "out" / INCIDENTS_FILE
        path.write_text(path.read_text().replace("MEDIUM", "LOW"), encoding="utf-8")
        with pytest.raises(DatasetIntegrityError, match="hash"):
            load_incidents(tmp_path / "out")

    def test_refuses_overwrite(self, tmp_path):
        inputs, result, _ = self.run(tmp_path)
        with pytest.raises(DetectionError, match="not empty"):
            write_detection_outputs(result, inputs, CFG, tmp_path / "out")

    def test_refuses_evidence_not_in_recorded_inputs(self, tmp_path):
        _, result, _ = self.run(tmp_path)
        other = load_verified_inputs([make_dataset(tmp_path, "other", source="other.txt")])
        with pytest.raises(DetectionError, match="unknown events"):
            write_detection_outputs(result, other, CFG, tmp_path / "out2")

    def test_report_marks_heuristic_nature(self, tmp_path):
        self.run(tmp_path)
        report = (tmp_path / "out" / REPORT_FILE).read_text(encoding="utf-8")
        assert "not**" in report and "confirmation of compromise" in report
        assert "Possible benign explanations" in report

    def test_empty_detection_still_writes_outputs(self, tmp_path):
        ds = make_dataset(tmp_path)
        inputs = load_verified_inputs([ds])
        result = run_detection([], CFG)
        summary = write_detection_outputs(result, inputs, CFG, tmp_path / "empty")
        assert summary.incidents_total == 0
        assert (tmp_path / "empty" / INCIDENTS_FILE).read_text() == ""
        assert "No incidents" in (tmp_path / "empty" / REPORT_FILE).read_text()
