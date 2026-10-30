"""Engine-level behaviour: pre-processing, provenance, correlation, severity, evidence."""

import pytest

from agentsoc.detection.catalog import (
    ADMIN_EXPLANATION,
    CATALOG,
    GENERIC_LIMITATION,
    GENERIC_MISSING,
    RuleId,
)
from agentsoc.detection.config import SeverityPolicy
from agentsoc.detection.correlate import incident_severity
from agentsoc.detection.engine import run_detection, verify_evidence
from agentsoc.exceptions import DetectionError
from agentsoc.schemas import Severity
from tests.detection_support import Stream, config, rules_of

NO_BASELINE = {"baseline_seconds": 0}


class TestPreprocessing:
    def test_exact_duplicates_collapsed_by_default(self):
        s = Stream()
        for _ in range(5):
            s.add(0, outcome="Fail")  # identical content, distinct IDs
        result = run_detection(s.events, config(**NO_BASELINE))
        assert result.findings == []
        assert result.partitions["synthetic"].collapsed_duplicates == 4

    def test_duplicates_counted_when_collapse_disabled(self):
        s = Stream()
        for _ in range(5):
            s.add(0, outcome="Fail")
        cfg = config(**NO_BASELINE, collapse_exact_duplicates=False)
        assert rules_of(run_detection(s.events, cfg)) == ["FAILURE_BURST"]

    def test_machine_and_system_accounts_excluded_and_counted(self):
        s = Stream()
        for user in ("C1$@DOM1", "ANONYMOUS LOGON@C1", "SYSTEM@C1"):
            s.fails([0, 1, 2, 3, 4], user=user)
        result = run_detection(s.events, config(**NO_BASELINE))
        assert result.findings == []
        assert result.partitions["synthetic"].excluded_events == 15

    def test_empty_input(self):
        result = run_detection([], config())
        assert (result.findings, result.incidents, result.partitions) == ([], [], {})

    def test_duplicate_event_ids_rejected(self):
        a, b = Stream(prefix="X"), Stream(prefix="X")
        a.add(0)
        b.add(1)
        with pytest.raises(DetectionError, match="duplicate event_ids"):
            run_detection(a.events + b.events, config())


class TestProvenance:
    def test_partitions_are_never_correlated_together(self):
        syn, lanl = Stream("synthetic", "S"), Stream("lanl", "L")
        syn.fails([0, 10, 20])
        lanl.fails([30, 40])  # same user: 5 failures only if (wrongly) combined
        result = run_detection(syn.events + lanl.events, config(**NO_BASELINE))
        assert result.findings == []
        assert set(result.partitions) == {"synthetic", "lanl"}

    def test_each_incident_has_single_provenance_and_flags(self):
        syn, lanl = Stream("synthetic", "S"), Stream("lanl", "L")
        syn.fails([0, 10, 20, 30, 40])
        lanl.fails([0, 10, 20, 30, 40])
        incidents = run_detection(syn.events + lanl.events, config(**NO_BASELINE)).incidents
        assert sorted(i.datasets[0].value for i in incidents) == ["lanl", "synthetic"]
        assert all(len(i.datasets) == 1 for i in incidents)
        lanl_incident = next(i for i in incidents if i.datasets[0] == "lanl")
        assert {"lanl-data", "relative-timestamps"} <= set(lanl_incident.flags)
        assert any("relative offsets" in x for x in lanl_incident.limitations)


class TestCorrelation:
    def test_related_findings_merge_into_one_incident(self):
        s = Stream()
        s.fails([0, 10, 20, 30, 40])
        s.add(50)
        (incident,) = run_detection(s.events, config(**NO_BASELINE)).incidents
        assert incident.rule_ids == ["FAILURE_BURST", "FAIL_THEN_SUCCESS"]
        assert incident.first_seen == s.events[0].timestamp
        assert incident.last_seen == s.events[-1].timestamp
        assert incident.event_ids == [e.event_id for e in s.events]

    def test_findings_beyond_gap_form_separate_incidents(self):
        s = Stream()
        s.fails([0, 10, 20, 30, 40])
        s.fails([10_000, 10_010, 10_020, 10_030, 10_040])
        incidents = run_detection(s.events, config(**NO_BASELINE)).incidents
        assert [i.incident_id for i in incidents] == ["INC-00001", "INC-00002"]

    def test_different_users_never_merge(self):
        s = Stream()
        s.fails([0, 10, 20, 30, 40], user="u1@D")
        s.fails([0, 10, 20, 30, 40], user="u2@D")
        incidents = run_detection(s.events, config(**NO_BASELINE)).incidents
        assert sorted(i.principal_user for i in incidents) == ["u1@D", "u2@D"]

    def test_incident_states_uncertainty(self):
        s = Stream()
        s.fails([0, 10, 20, 30, 40])
        (incident,) = run_detection(s.events, config(**NO_BASELINE)).incidents
        assert set(CATALOG[RuleId.FAILURE_BURST].benign_explanations) <= set(
            incident.benign_explanations
        )
        assert GENERIC_LIMITATION in incident.limitations
        assert GENERIC_MISSING in incident.missing_information
        assert any("synthetic" in x for x in incident.limitations)
        assert incident.status == "OPEN"

    def test_admin_principal_gets_benign_explanation_and_flag(self):
        s = Stream()
        s.fails([0, 10, 20, 30, 40], user="admin@D")
        (incident,) = run_detection(
            s.events, config(**NO_BASELINE, admin_users=["admin@D"])
        ).incidents
        assert incident.benign_explanations[0] == ADMIN_EXPLANATION
        assert "known-admin-account" in incident.flags


class TestSeverity:
    policy = SeverityPolicy()

    @pytest.mark.parametrize(
        ("rules", "expected"),
        [
            ([RuleId.NEW_DST_HOST], Severity.LOW),  # 1
            ([RuleId.FAIL_THEN_SUCCESS], Severity.MEDIUM),  # 3
            ([RuleId.FAILURE_BURST, RuleId.FAIL_THEN_SUCCESS], Severity.HIGH),  # 5
            (
                [RuleId.FAIL_THEN_SUCCESS, RuleId.LATERAL_CHAIN, RuleId.FAILURE_BURST],
                Severity.CRITICAL,
            ),  # 8
        ],
    )
    def test_bands(self, rules, expected):
        assert incident_severity(rules, is_admin=False, policy=self.policy)[0] is expected

    def test_repeated_rule_counts_once(self):
        once = incident_severity([RuleId.NEW_DST_HOST], is_admin=False, policy=self.policy)
        many = incident_severity([RuleId.NEW_DST_HOST] * 9, is_admin=False, policy=self.policy)
        assert once == many

    def test_admin_lowered_one_band_but_not_below_low(self):
        high = [RuleId.FAILURE_BURST, RuleId.FAIL_THEN_SUCCESS]
        band, rationale = incident_severity(high, is_admin=True, policy=self.policy)
        assert band is Severity.MEDIUM and "Lowered one band" in rationale
        low = incident_severity([RuleId.NEW_DST_HOST], is_admin=True, policy=self.policy)
        assert low[0] is Severity.LOW

    def test_rationale_shows_calculation(self):
        _, rationale = incident_severity(
            [RuleId.FAILURE_BURST, RuleId.FAIL_THEN_SUCCESS], is_admin=False, policy=self.policy
        )
        assert "FAILURE_BURST=2 + FAIL_THEN_SUCCESS=3 = 5" in rationale


class TestEvidenceVerification:
    def detect(self):
        s = Stream()
        s.fails([0, 10, 20, 30, 40])
        return s, run_detection(s.events, config(**NO_BASELINE))

    def test_valid_evidence_passes(self):
        s, result = self.detect()
        verify_evidence(result.findings, result.incidents, {e.event_id for e in s.events})

    def test_unknown_event_reference_rejected(self):
        s, result = self.detect()
        known = {e.event_id for e in s.events} - {s.events[0].event_id}
        with pytest.raises(DetectionError, match="cites unknown events"):
            verify_evidence(result.findings, result.incidents, known)

    def test_orphan_finding_rejected(self):
        s, result = self.detect()
        with pytest.raises(DetectionError, match="inconsistent"):
            verify_evidence(result.findings, [], {e.event_id for e in s.events})

    def test_output_is_deterministic(self):
        _, a = self.detect()
        _, b = self.detect()
        assert a.incidents == b.incidents and a.findings == b.findings
