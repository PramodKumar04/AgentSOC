"""LANL validation tooling, exercised on small SYNTHETIC LANL-format fixtures."""

import argparse
import gzip
import json

import pytest

from agentsoc.detection.config import DetectionConfig
from agentsoc.detection.engine import run_detection
from agentsoc.evaluation import lanl_validation as lv
from agentsoc.evaluation.measure import peak_memory_bytes
from agentsoc.evaluation.validate import RunSpec
from agentsoc.perception.lanl import ingest_lanl_file
from agentsoc.perception.quality import build_quality_report
from agentsoc.schemas import DatasetSource
from agentsoc.store.datasets import load_manifest, write_processed_dataset

LINES = [
    "1,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Fail",
    "2,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Fail",
    "3,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Fail",
    "4,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Fail",
    "5,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Fail",
    "6,U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,Success",
    "7,U1@?,U1@?,C1,TGT,Kerberos,?,TGT,Fail",
    "8,C9$@DOM1,C9$@DOM1,C9,C9,?,Network,LogOff,Success",
    "9,U2@DOM1,U2@DOM1,C3,U22,?,?,TGS,Success",
]
CFG = DetectionConfig(baseline_seconds=0)


@pytest.fixture
def dataset(tmp_path):
    raw = tmp_path / "auth.txt"
    raw.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    result = ingest_lanl_file(raw, dataset=DatasetSource.SYNTHETIC)
    out = tmp_path / "ds"
    write_processed_dataset(result, build_quality_report(result), out, dataset_label="test")
    return out, result.events


def detect(events):
    return run_detection(events, CFG)


def scan(ds, result=None, redteam=()):
    cited = {e for f in result.findings for e in f.event_ids} if result else set()
    return lv.scan_events(ds, load_manifest(ds).base_time, cited_ids=cited,
                          redteam_keys={r.key for r in redteam}, config=CFG)


def test_peak_memory_probe_returns_a_real_number():
    before = peak_memory_bytes()
    block = bytearray(64 * 2**20)
    after = peak_memory_bytes()
    assert before is not None and after is not None
    assert after >= before and after > 64 * 2**20
    del block


class TestRunSpec:
    def test_parse(self):
        assert RunSpec.parse("a:10:100") == RunSpec("a", 10, 100, "default")
        assert RunSpec.parse("b:0:5:half_window").baseline == "half_window"
        assert RunSpec.parse("a:10:100").dataset_name == "lines_11_110"

    @pytest.mark.parametrize("text", ["a:1", "a:1:2:weird", "a:x:2"])
    def test_rejects_bad_specs(self, text):
        with pytest.raises((ValueError, argparse.ArgumentTypeError)):
            RunSpec.parse(text)


class TestRedTeamLoading:
    def test_plain_and_gzip(self, tmp_path):
        text = "150885,U620@DOM1,C17693,C1003\nbad line\n151036,U748@DOM1,C17693,C305\n"
        plain = tmp_path / "rt.txt"
        plain.write_text(text)
        gz = tmp_path / "rt.txt.gz"
        with gzip.open(gz, "wt") as handle:
            handle.write(text)
        assert lv.load_redteam(plain) == lv.load_redteam(gz)
        assert [r.t for r in lv.load_redteam(plain)] == [150885, 151036]


class TestScan:
    def test_streaming_facts(self, dataset):
        ds, _ = dataset
        s = scan(ds)
        assert s.events == len(LINES)
        assert (s.min_offset, s.max_offset) == (1, 9)
        assert s.non_computer_dst == {"TGT": 1, "U22": 1}
        assert s.user_domains["U1"] == {"DOM1", "?"}
        assert s.excluded_by_pattern[r".+\$@.+"] == 1
        assert s.events_sha256 == load_manifest(ds).events_sha256

    def test_ingestion_section_reports_integrity(self, dataset):
        ds, _ = dataset
        manifest = load_manifest(ds)
        quality = json.loads((ds / "quality_report.json").read_text())
        section = lv.ingestion_section(manifest, quality, scan(ds))
        assert section["events_sha256_recomputed_matches"]
        assert section["all_events_have_manifest_provenance"]
        assert section["users_with_multiple_domains"] == 1
        assert section["time_coverage_s"] == 8


class TestIntegrity:
    def _prepare(self, dataset):
        ds, events = dataset
        result = detect(events)
        return ds, result, scan(ds, result)

    def test_passes_on_engine_output(self, dataset):
        ds, result, s = self._prepare(dataset)
        report = lv.integrity_section(result.incidents, result.findings, s,
                                      load_manifest(ds), CFG)
        assert report["passed"], report["failures"]
        assert report["cited_event_ids"] == report["cited_event_ids_found_in_verified_input"]

    def test_detects_missing_evidence(self, dataset):
        ds, result, s = self._prepare(dataset)
        s.cited.pop(next(iter(s.cited)))
        report = lv.integrity_section(result.incidents, result.findings, s,
                                      load_manifest(ds), CFG)
        assert not report["passed"]
        assert "not in verified input" in report["failures"][0]

    def test_detects_unreproducible_severity(self, dataset):
        ds, result, s = self._prepare(dataset)
        tampered = [i.model_copy(update={"severity": "CRITICAL"}) for i in result.incidents]
        report = lv.integrity_section(tampered, result.findings, s, load_manifest(ds), CFG)
        assert any("severity not reproducible" in f for f in report["failures"])

    def test_detects_provenance_mismatch_with_manifest(self, dataset):
        ds, result, s = self._prepare(dataset)
        # model_copy skips validation, so pass the enum, as validated data would hold.
        tampered = [i.model_copy(update={"datasets": [DatasetSource.LANL]})
                    for i in result.incidents]
        report = lv.integrity_section(tampered, result.findings, s, load_manifest(ds), CFG)
        assert any("provenance" in f for f in report["failures"])


def test_severity_inflation_counts_shared_evidence(dataset):
    _, events = dataset
    result = detect(events)
    section = lv.severity_inflation_section(result.incidents)
    # FAILURE_BURST and FAIL_THEN_SUCCESS cite the same five failures.
    assert section["incidents_with_cross_rule_shared_evidence"] == 1
    assert section["details"][0]["events_shared_by_multiple_rules"] == 5


def test_identity_split_detected(dataset):
    ds, events = dataset
    # events[:5] are U1@DOM1 failures; the same failures under domain "?" form a 2nd principal.
    extra = [e.model_copy(update={"event_id": f"x{k}", "src_user": "U1@?"})
             for k, e in enumerate(events[:5])]
    result = detect(list(events) + extra)
    section = lv.identity_section(result.incidents, scan(ds))
    assert section["incident_principals_split_across_domains"] == {"U1": ["U1@?", "U1@DOM1"]}


class TestRedTeamComparison:
    def test_exact_matching_and_citation(self, dataset):
        ds, events = dataset
        result = detect(events)
        labels = [
            lv.RedTeamEvent(5, "U1@DOM1", "C1", "C2"),  # matches a cited failure event
            lv.RedTeamEvent(9, "U2@DOM1", "C3", "U22"),  # matches, not cited
            lv.RedTeamEvent(4, "U1@DOM1", "C1", "C99"),  # in range, no matching event
            lv.RedTeamEvent(500, "U1@DOM1", "C1", "C2"),  # outside the sample
        ]
        s = scan(ds, result, labels)
        out = lv.redteam_comparison(labels, s, result.findings, result.incidents, 0)
        assert out["labels_in_sample_time_range"] == 3
        assert out["labels_matched_to_events"] == 2
        assert out["labels_unmatched_in_range"] == 1
        assert out["matched_cited_by_any_finding"] == 1
        assert not {"precision", "recall", "f1", "accuracy"} & set(out)

    def test_baseline_membership(self, dataset):
        ds, events = dataset
        result = detect(events)
        labels = [lv.RedTeamEvent(5, "U1@DOM1", "C1", "C2")]
        out = lv.redteam_comparison(labels, scan(ds, result, labels), result.findings,
                                    result.incidents, baseline_end_offset=100)
        assert out["matched_after_baseline"] == 0


class TestRuleSection:
    def baseline(self, evaluated):
        return {"partitions": {"lanl": {"evaluated_events": evaluated,
                                        "baseline_coverage_fraction": 0.0056}}}

    def test_zero_findings_explained_without_claiming_success(self):
        rules = lv.rule_section([], [], self.baseline(0), DetectionConfig())
        assert "Not evaluable" in rules["NEW_DST_HOST"]["zero_findings_explanation"]
        assert "0.56%" in rules["LATERAL_CHAIN"]["zero_findings_explanation"]
        assert "not evidence" in rules["FAILURE_BURST"]["zero_findings_explanation"]

    def test_sensitive_rule_inert_without_hosts(self):
        rules = lv.rule_section([], [], self.baseline(10), DetectionConfig())
        assert "Inert" in rules["SENSITIVE_HOST_ACCESS"]["zero_findings_explanation"]

    def test_counts_and_examples(self, dataset):
        _, events = dataset
        result = detect(events)
        rules = lv.rule_section(result.findings, result.incidents, self.baseline(9), CFG)
        burst = rules["FAILURE_BURST"]
        assert (burst["findings"], burst["distinct_users"], burst["incidents_containing_rule"]) \
            == (1, 1, 1)
        assert burst["examples"][0]["evidence_count"] == 5
        assert burst["benign_explanations"]


def test_lines_per_day(tmp_path):
    archive = tmp_path / "auth.txt.gz"
    rows = ["1,a", "86399,b", "86400,c", "172800,d", "999999,e"]
    with gzip.open(archive, "wt") as handle:
        handle.write("\n".join(rows) + "\n")
    assert lv.lines_per_day(archive, 2) == {"day_0": 2, "day_1": 1}


class TestUncitedReasons:
    def run(self, dataset, label, **kwargs):
        ds, events = dataset
        result = detect(events)
        out = lv.redteam_comparison([label], scan(ds, result, [label]), result.findings,
                                    result.incidents, **kwargs)
        return out["events"][0]["not_cited_reason"]

    def test_inside_baseline(self, dataset):
        label = lv.RedTeamEvent(9, "U2@DOM1", "C3", "U22")
        assert "inside the baseline" in self.run(dataset, label, baseline_end_offset=100)

    def test_user_without_baseline(self, dataset):
        label = lv.RedTeamEvent(9, "U2@DOM1", "C3", "U22")
        reason = self.run(dataset, label, baseline_end_offset=0,
                          users_without_baseline={"U2@DOM1"})
        assert "no baseline activity" in reason

    def test_fallback_reason(self, dataset):
        label = lv.RedTeamEvent(9, "U2@DOM1", "C3", "U22")
        assert "no rule condition met" in self.run(dataset, label, baseline_end_offset=0)

    def test_methodology_text_is_clean(self, dataset):
        ds, events = dataset
        result = detect(events)
        out = lv.redteam_comparison([], scan(ds, result), result.findings, result.incidents, 0)
        assert "  " not in out["methodology"]
