"""Lateral-movement rule behaviour on small SYNTHETIC fixtures (Target 1). These verify
rule logic only; they say nothing about real-world detection accuracy."""

import json

import pytest

from agentsoc.config import PROJECT_ROOT
from agentsoc.detection.catalog import CATALOG, RuleId
from agentsoc.detection.config import (
    CrossAccountPivotConfig,
    DetectionConfig,
    LateralChainConfig,
    NoveltyConfig,
    SensitiveAccessConfig,
    SeverityPolicy,
    load_detection_config,
)
from agentsoc.detection.correlate import incident_severity
from agentsoc.detection.engine import ENGINE_VERSION, run_detection
from agentsoc.exceptions import ConfigurationError
from agentsoc.investigator.fallback import ATTACK_BY_RULE, fallback_investigation
from tests.detection_support import Stream, config

A, B = "alice@D", "bob@D"
WINDOW = CrossAccountPivotConfig().window_seconds
GAP = LateralChainConfig().max_hop_gap_seconds


def of_rule(events, rule, **cfg):
    return [f for f in run_detection(events, config(**cfg)).findings if f.rule_id == rule]


def chains(s, **cfg):
    return of_rule(s.events, "LATERAL_CHAIN", **cfg)


def pivots(s, **cfg):
    return of_rule(s.events, "CROSS_ACCOUNT_PIVOT", **cfg)


def two_hop(s, via="APP1", end="DB1", user=A, ws="WS1"):
    s.baseline(user=user, src=ws, dsts=("SRV1",))
    return s.add(2000, user, ws, via), s.add(2600, user, via, end)


def pivot_setup(s, *, arrive=2000, depart=2300, hub="HUB"):
    """A arrives on the hub; B leaves it to SRV2, for the first time from that source."""
    s.baseline(user=A, src="WS1", dsts=("SRV1",))
    s.baseline(user=B, src="WS2", dsts=("SRV1",))
    return s.add(arrive, A, "WS1", hub), s.add(depart, B, hub, "SRV2")


class TestChainBackwardCompatibility:
    """The pre-existing LATERAL_CHAIN contract must not move."""

    def test_existing_metrics_and_evidence_unchanged(self):
        s = Stream()
        h1, h2 = two_hop(s)
        (f,) = chains(s)
        assert f.event_ids == [h1.event_id, h2.event_id]
        assert f.severity == "HIGH"
        assert f.metrics["hops"] == 2
        assert f.metrics["path"] == "WS1 > APP1 > DB1"
        assert f.metrics["span_seconds"] == 600
        assert f.metrics["first_seen_hops"] == 2
        assert f.metrics["threshold_max_hop_gap_seconds"] == GAP

    def test_description_unchanged_without_jump_hosts(self):
        s = Stream()
        two_hop(s)
        (f,) = chains(s)
        assert f.description == (
            "alice@D authenticated along WS1 -> APP1 -> DB1 (2 hops in 600 s); each hop started "
            "on the previous hop's destination. 2 hop(s) were first-seen relative to the baseline."
        )

    def test_existing_rule_ids_preserved(self):
        for rule in ("FAILURE_BURST", "FAIL_THEN_SUCCESS", "NEW_SRC_HOST", "NEW_DST_HOST",
                     "MULTI_HOST_SPREAD", "LATERAL_CHAIN", "SENSITIVE_HOST_ACCESS"):
            assert RuleId(rule) in CATALOG


class TestChainEdges:
    def test_failed_hop_never_extends_a_chain(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "APP1")
        s.add(2100, A, "APP1", "DB1", outcome="Fail")
        s.add(2200, A, "DB1", "X1")
        assert chains(s) == []

    def test_only_failed_hops_produce_no_chain(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "APP1", outcome="Fail")
        s.add(2100, A, "APP1", "DB1", outcome="Fail")
        assert chains(s) == []

    def test_hop_gap_exactly_at_limit_keeps_chain(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "APP1")
        s.add(2000 + GAP, A, "APP1", "DB1")
        assert len(chains(s)) == 1

    def test_hop_gap_one_second_over_limit_breaks_chain(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "APP1")
        s.add(2000 + GAP + 1, A, "APP1", "DB1")
        assert chains(s) == []

    def test_repeated_host_ends_chain_and_is_reported_once(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "APP1")
        s.add(2100, A, "APP1", "DB1")
        s.add(2200, A, "DB1", "APP1")
        (f,) = chains(s)
        assert f.metrics["path"] == "WS1 > APP1 > DB1"
        assert f.metrics["distinct_hosts"] == 3

    def test_missing_baseline_is_not_evaluated(self):
        s = Stream()
        s.baseline(user=B, src="WS2", dsts=("SRV1",))  # anchors the window; A has no baseline
        s.add(2000, A, "WS1", "APP1")
        s.add(2100, A, "APP1", "DB1")
        result = run_detection(s.events, config())
        assert result.findings == []
        assert A in next(iter(result.partitions.values())).users_without_baseline

    def test_exact_duplicates_do_not_inflate_a_chain(self):
        s = Stream()
        h1, h2 = two_hop(s)
        for event in (h1, h2):
            s.add(int((event.timestamp - s.events[0].timestamp).total_seconds()),
                  A, event.src_host, event.dst_host)
        (f,) = chains(s)
        assert f.metrics["hops"] == 2
        assert len(f.event_ids) == 2


class TestChainPathMetrics:
    def test_records_observed_path_facts(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "APP1")
        s.add(2100, A, "APP1", "APP2")
        s.add(2600, A, "APP2", "DB1")
        (f,) = chains(s)
        assert f.metrics["distinct_hosts"] == 4
        assert f.metrics["longest_hop_gap_seconds"] == 500
        assert f.metrics["sensitive_hosts_on_path"] == 0
        assert f.metrics["ends_on_sensitive_host"] is False

    def test_sensitive_terminus(self):
        s = Stream()
        two_hop(s)
        (f,) = chains(s, sensitive_host_access=SensitiveAccessConfig(hosts=["DB1"]))
        assert f.metrics["sensitive_hosts_on_path"] == 1
        assert f.metrics["ends_on_sensitive_host"] is True

    def test_sensitive_transit_is_counted_but_is_not_the_terminus(self):
        s = Stream()
        two_hop(s)
        (f,) = chains(s, sensitive_host_access=SensitiveAccessConfig(hosts=["APP1"]))
        assert f.metrics["sensitive_hosts_on_path"] == 1
        assert f.metrics["ends_on_sensitive_host"] is False


class TestJumpHostContext:
    def test_default_is_empty_and_adds_nothing(self):
        assert DetectionConfig().jump_hosts == []
        s = Stream()
        two_hop(s)
        (f,) = chains(s)
        assert "benign_context" not in f.metrics
        assert "severity_adjustment" not in f.metrics

    def test_unconfigured_host_is_never_labelled(self):
        s = Stream()
        two_hop(s, via="JUMP1")  # looks like a jump host, but nothing is configured
        (f,) = chains(s)
        assert "benign_context" not in f.metrics
        assert f.severity == "HIGH"

    def test_transit_through_only_jump_hosts_is_kept_and_lowered_one_band(self):
        s = Stream()
        two_hop(s, via="JUMP1")
        (f,) = chains(s, jump_hosts=["JUMP.*"])
        assert "JUMP1" in f.metrics["benign_context"]
        assert f.severity == "MEDIUM"
        assert "HIGH" in f.metrics["severity_adjustment"]
        assert "MEDIUM" in f.metrics["severity_adjustment"]

    def test_mixed_transit_adds_context_without_reduction(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "JUMP1")
        s.add(2100, A, "JUMP1", "APP1")
        s.add(2200, A, "APP1", "DB1")
        (f,) = chains(s, jump_hosts=["JUMP.*"])
        assert "benign_context" in f.metrics
        assert "severity_adjustment" not in f.metrics
        assert f.severity == "HIGH"

    def test_jump_origin_adds_context_without_reduction(self):
        s = Stream()
        s.baseline(user=A, src="JUMP1", dsts=("SRV1",))
        s.add(2000, A, "JUMP1", "APP1")
        s.add(2100, A, "APP1", "DB1")
        (f,) = chains(s, jump_hosts=["JUMP.*"])
        assert "benign_context" in f.metrics
        assert f.severity == "HIGH"

    def test_jump_destination_alone_is_not_context(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "APP1")
        s.add(2100, A, "APP1", "JUMP1")
        (f,) = chains(s, jump_hosts=["JUMP.*"])
        assert "benign_context" not in f.metrics

    def test_sensitive_path_is_never_reduced(self):
        s = Stream()
        two_hop(s, via="JUMP1")
        (f,) = chains(s, jump_hosts=["JUMP.*"],
                      sensitive_host_access=SensitiveAccessConfig(hosts=["DB1"]))
        assert "benign_context" in f.metrics
        assert "severity_adjustment" not in f.metrics
        assert f.severity == "HIGH"

    def test_patterns_match_the_whole_host_name(self):
        s = Stream()
        two_hop(s, via="NOTJUMP1")
        (f,) = chains(s, jump_hosts=["JUMP.*"])
        assert "benign_context" not in f.metrics

    def test_invalid_pattern_rejected(self, tmp_path):
        path = tmp_path / "c.json"
        path.write_text(json.dumps({"jump_hosts": ["(unclosed"]}), encoding="utf-8")
        with pytest.raises(ConfigurationError):
            load_detection_config(path)

    def test_zero_reduction_keeps_severity_but_still_adds_context(self):
        s = Stream()
        two_hop(s, via="JUMP1")
        (f,) = chains(s, jump_hosts=["JUMP.*"],
                      severity_policy=SeverityPolicy(jump_host_point_reduction=0))
        assert "benign_context" in f.metrics
        assert "severity_adjustment" not in f.metrics
        assert f.severity == "HIGH"

    def test_incident_points_are_reduced_and_explained(self):
        s = Stream()
        two_hop(s, via="JUMP1")
        (i,) = run_detection(s.events, config(jump_hosts=["JUMP.*"])).incidents
        # NEW_DST 1 + NEW_SRC 1 + LATERAL_CHAIN (3 - 1) = 4 -> MEDIUM; unreduced 5 -> HIGH.
        assert i.severity == "MEDIUM"
        assert "LATERAL_CHAIN=2" in i.severity_rationale
        assert "jump host" in i.severity_rationale

    def test_one_unreduced_chain_keeps_full_points(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "JUMP1")
        s.add(2100, A, "JUMP1", "APP1")
        s.add(2200, A, "WS1", "APP2")  # a separate chain with no jump host
        s.add(2300, A, "APP2", "APP3")
        (i,) = run_detection(s.events, config(jump_hosts=["JUMP.*"])).incidents
        assert "LATERAL_CHAIN=3" in i.severity_rationale

    def test_reduction_never_erases_a_rule(self):
        policy = SeverityPolicy(jump_host_point_reduction=5)
        _, rationale = incident_severity(
            [RuleId.LATERAL_CHAIN], is_admin=False, policy=policy,
            reduced_rules={RuleId.LATERAL_CHAIN},
        )
        assert "LATERAL_CHAIN=1" in rationale


class TestCrossAccountPivot:
    def test_fires_with_original_events_and_timestamps(self):
        s = Stream()
        arrival, departure = pivot_setup(s)
        (f,) = pivots(s)
        assert f.user == B
        assert f.event_ids == [arrival.event_id, departure.event_id]
        assert (f.first_seen, f.last_seen) == (arrival.timestamp, departure.timestamp)
        assert f.metrics["pivot_host"] == "HUB"
        assert f.metrics["arriving_account"] == A
        assert f.metrics["arrival_event_id"] == arrival.event_id
        assert f.metrics["departure_event_id"] == departure.event_id
        assert f.metrics["arrival_time"] == arrival.timestamp.isoformat()
        assert f.metrics["departure_time"] == departure.timestamp.isoformat()
        assert f.metrics["seconds_after_arrival"] == 300
        assert f.metrics["path"] == "WS1 > HUB > SRV2"

    def test_default_severity_and_weight_are_below_lateral_chain(self):
        assert CrossAccountPivotConfig().severity == "LOW"
        points = SeverityPolicy().points
        assert points[RuleId.CROSS_ACCOUNT_PIVOT] < points[RuleId.LATERAL_CHAIN]

    def test_language_does_not_claim_compromise(self):
        s = Stream()
        pivot_setup(s)
        (f,) = pivots(s)
        info = CATALOG[RuleId.CROSS_ACCOUNT_PIVOT]
        assert "does not show" in f.description
        assert "stolen" not in f.description.lower()
        assert any("compromise" in text or "transferred" in text for text in info.limitations)
        assert info.benign_explanations

    def test_window_boundary_inclusive(self):
        s = Stream()
        pivot_setup(s, arrive=2000, depart=2000 + WINDOW)
        assert len(pivots(s)) == 1

    def test_one_second_past_window_is_silent(self):
        s = Stream()
        pivot_setup(s, arrive=2000, depart=2000 + WINDOW + 1)
        assert pivots(s) == []

    def test_same_second_order_is_unknown_so_silent(self):
        s = Stream()
        pivot_setup(s, arrive=2000, depart=2000)
        assert pivots(s) == []

    def test_departure_before_arrival_is_silent(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.baseline(user=B, src="WS2", dsts=("SRV1",))
        s.add(2000, B, "HUB", "SRV2")
        s.add(2300, A, "WS1", "HUB")
        assert pivots(s) == []

    @pytest.mark.parametrize("field", ["arrival", "departure"])
    def test_failed_authentication_never_forms_an_edge(self, field):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.baseline(user=B, src="WS2", dsts=("SRV1",))
        s.add(2000, A, "WS1", "HUB", outcome="Fail" if field == "arrival" else "Success")
        s.add(2300, B, "HUB", "SRV2", outcome="Fail" if field == "departure" else "Success")
        assert pivots(s) == []

    def test_logoff_is_not_an_arrival(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.baseline(user=B, src="WS2", dsts=("SRV1",))
        s.add(2000, A, "WS1", "HUB", orientation="LogOff")
        s.add(2300, B, "HUB", "SRV2")
        assert pivots(s) == []

    def test_other_accounts_local_logon_is_not_an_arrival(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.baseline(user=B, src="WS2", dsts=("SRV1",))
        s.add(2000, A, "HUB", "HUB")
        s.add(2300, B, "HUB", "SRV2")
        assert pivots(s) == []

    def test_same_account_is_not_a_pivot(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "HUB")
        s.add(2300, A, "HUB", "SRV2")
        assert pivots(s) == []

    def test_same_name_in_another_domain_is_not_a_pivot(self):
        s = Stream()
        s.baseline(user="alice@D", src="WS1", dsts=("SRV1",))
        s.baseline(user="alice@OTHER", src="WS2", dsts=("SRV1",))
        s.add(2000, "alice@D", "WS1", "HUB")
        s.add(2300, "alice@OTHER", "HUB", "SRV2")
        assert pivots(s) == []

    def test_familiar_source_is_silent(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.baseline(user=B, src="HUB", dsts=("SRV1",))
        s.add(2000, A, "WS1", "HUB")
        s.add(2300, B, "HUB", "SRV2")
        assert pivots(s) == []

    def test_departing_account_that_arrived_itself_is_silent(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.baseline(user=B, src="WS2", dsts=("SRV1",))
        s.add(2000, A, "WS1", "HUB")
        s.add(2100, B, "WS2", "HUB")
        s.add(2300, B, "HUB", "SRV2")
        assert pivots(s) == []

    def test_departing_account_local_logon_explains_presence(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.baseline(user=B, src="WS2", dsts=("SRV1",))
        s.add(2000, A, "WS1", "HUB")
        s.add(2100, B, "HUB", "HUB")
        s.add(2300, B, "HUB", "SRV2")
        assert pivots(s) == []

    def test_departing_account_without_baseline_is_not_evaluated(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "HUB")
        s.add(2300, B, "HUB", "SRV2")
        assert pivots(s) == []

    def test_arriving_account_needs_no_baseline(self):
        s = Stream()
        s.baseline(user=B, src="WS2", dsts=("SRV1",))
        s.add(2000, A, "WS1", "HUB")
        s.add(2300, B, "HUB", "SRV2")
        assert len(pivots(s)) == 1

    def test_arrival_in_the_baseline_window_is_not_used(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.baseline(user=B, src="WS2", dsts=("SRV1",))
        s.add(990, A, "WS1", "HUB")  # inside the 1000 s baseline
        s.add(1100, B, "HUB", "SRV2")
        assert pivots(s) == []

    def test_repeat_departures_report_once(self):
        s = Stream()
        pivot_setup(s)
        s.add(2400, B, "HUB", "SRV3")
        assert len(pivots(s)) == 1

    def test_duplicate_arrival_counts_once(self):
        s = Stream()
        arrival, _ = pivot_setup(s)
        s.add(2000, A, "WS1", arrival.dst_host)
        (f,) = pivots(s)
        assert f.metrics["other_accounts_on_host"] == 1
        assert len(f.event_ids) == 2

    def test_same_account_arriving_repeatedly_cites_its_latest_arrival(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.baseline(user=B, src="WS2", dsts=("SRV1",))
        s.add(2000, A, "WS1", "HUB")
        latest = s.add(2200, A, "WS1", "HUB")
        departure = s.add(2300, B, "HUB", "SRV2")
        (f,) = pivots(s)
        assert f.event_ids == [latest.event_id, departure.event_id]
        assert f.metrics["other_accounts_on_host"] == 1

    def test_evidence_is_capped_but_the_count_is_not(self):
        s = Stream()
        s.baseline(user=B, src="WS2", dsts=("SRV1",))
        names = [f"u{k}@D" for k in range(6)]
        arrivals = [s.add(2000 + k, name, "WS1", "HUB") for k, name in enumerate(names)]
        departure = s.add(2300, B, "HUB", "SRV2")
        (f,) = pivots(s, cross_account_pivot=CrossAccountPivotConfig(max_evidence_arrivals=2))
        assert f.metrics["other_accounts_on_host"] == 6
        assert f.metrics["arriving_account"] == "u5@D"
        assert f.event_ids == [arrivals[4].event_id, arrivals[5].event_id, departure.event_id]

    def test_disabled(self):
        s = Stream()
        pivot_setup(s)
        assert pivots(s, cross_account_pivot=CrossAccountPivotConfig(enabled=False)) == []

    def test_provenance_is_never_crossed(self):
        syn, lanl = Stream("synthetic", "S"), Stream("lanl", "L")
        syn.baseline(user=A, src="WS1", dsts=("SRV1",))
        syn.add(2000, A, "WS1", "HUB")
        lanl.baseline(user=B, src="WS2", dsts=("SRV1",))
        lanl.add(2300, B, "HUB", "SRV2")
        assert of_rule(syn.events + lanl.events, "CROSS_ACCOUNT_PIVOT") == []

    def test_jump_host_pivot_is_kept_with_context(self):
        s = Stream()
        pivot_setup(s, hub="JUMP1")
        (f,) = pivots(s, jump_hosts=["JUMP.*"])
        assert "JUMP1" in f.metrics["benign_context"]

    def test_unconfigured_hub_has_no_context(self):
        s = Stream()
        pivot_setup(s)
        (f,) = pivots(s)
        assert "benign_context" not in f.metrics

    def test_pivot_severity_lowered_only_when_above_low(self):
        s = Stream()
        pivot_setup(s, hub="JUMP1")
        cfg = CrossAccountPivotConfig(severity="MEDIUM")
        (f,) = pivots(s, jump_hosts=["JUMP.*"], cross_account_pivot=cfg)
        assert f.severity == "LOW"
        assert "severity_adjustment" in f.metrics
        s2 = Stream()
        pivot_setup(s2, hub="JUMP1")
        (low,) = pivots(s2, jump_hosts=["JUMP.*"])
        assert low.severity == "LOW"
        assert "severity_adjustment" not in low.metrics


class TestCorrelationAndScoring:
    def test_accounts_stay_in_separate_incidents(self):
        s = Stream()
        pivot_setup(s)
        incidents = {i.principal_user: i for i in run_detection(s.events, config()).incidents}
        assert set(incidents) == {A, B}
        assert A in incidents[B].involved_users

    def test_shared_departure_is_not_counted_twice(self):
        s = Stream()
        pivot_setup(s)
        incidents = {i.principal_user: i for i in run_detection(s.events, config()).incidents}
        bob = incidents[B]
        assert {"NEW_SRC_HOST", "NEW_DST_HOST", "CROSS_ACCOUNT_PIVOT"} == set(bob.rule_ids)
        assert "= 2." in bob.severity_rationale  # NEW_DST 1 + PIVOT 1; NEW_SRC not added again
        assert "NEW_SRC_HOST" in bob.severity_rationale
        assert "not scored" in bob.severity_rationale

    def test_new_source_with_independent_evidence_counts_the_pair_once(self):
        s = Stream()
        pivot_setup(s)
        s.add(2400, B, "OTHER", "SRV1")  # a second first-seen source, not part of the pivot
        incidents = {i.principal_user: i for i in run_detection(s.events, config()).incidents}
        rationale = incidents[B].severity_rationale
        assert "NEW_SRC_HOST=1" in rationale
        assert "CROSS_ACCOUNT_PIVOT not scored" in rationale

    def test_pivot_is_scored_when_new_source_rule_is_disabled(self):
        s = Stream()
        pivot_setup(s)
        cfg = {"new_src_host": NoveltyConfig(enabled=False)}
        incidents = {i.principal_user: i for i in run_detection(s.events, config(**cfg)).incidents}
        assert "CROSS_ACCOUNT_PIVOT=1" in incidents[B].severity_rationale
        assert "not scored" not in incidents[B].severity_rationale

    def test_pivot_cannot_raise_a_band_at_default_weights(self):
        s = Stream()
        pivot_setup(s)
        s.add(2400, B, "OTHER", "SRV1")
        with_rule = {i.principal_user: i.severity
                     for i in run_detection(s.events, config()).incidents}
        off = CrossAccountPivotConfig(enabled=False)
        without = {i.principal_user: i.severity
                   for i in run_detection(s.events, config(cross_account_pivot=off)).incidents}
        assert with_rule == without

    def test_rationale_format_unchanged_when_nothing_is_adjusted(self):
        _, rationale = incident_severity(
            [RuleId.LATERAL_CHAIN, RuleId.NEW_DST_HOST], is_admin=False, policy=SeverityPolicy()
        )
        assert rationale == (
            "Points over distinct rules: LATERAL_CHAIN=3 + NEW_DST_HOST=1 = 4. "
            "Bands: MEDIUM>=3, HIGH>=5, CRITICAL>=8 -> MEDIUM."
        )

    def test_finding_evidence_stays_consistent_with_incident(self):
        s = Stream()
        pivot_setup(s)
        result = run_detection(s.events, config())
        for incident in result.incidents:
            for finding in incident.findings:
                assert set(finding.event_ids) <= set(incident.event_ids)


class TestCompatibility:
    def test_engine_version_records_the_new_rule_set(self):
        assert ENGINE_VERSION == "auth-detect/1.1"

    def test_config_written_before_the_rule_existed_still_loads(self):
        cfg = load_detection_config(
            PROJECT_ROOT / "data" / "samples" / "scenarios_detection_config.json"
        )
        assert cfg.severity_policy.points[RuleId.CROSS_ACCOUNT_PIVOT] == 1
        assert cfg.jump_hosts == []

    def test_partial_points_are_still_rejected(self, tmp_path):
        path = tmp_path / "c.json"
        path.write_text(json.dumps({"severity_policy": {"points": {"LATERAL_CHAIN": 3}}}),
                        encoding="utf-8")
        with pytest.raises(ConfigurationError, match="points missing"):
            load_detection_config(path)

    def test_every_rule_has_an_attack_mapping(self):
        assert set(ATTACK_BY_RULE) == set(RuleId)

    def test_fallback_investigator_handles_a_pivot_incident(self):
        s = Stream()
        pivot_setup(s)
        incident = next(i for i in run_detection(s.events, config()).incidents
                        if i.principal_user == B)
        events = {e.event_id: e for e in s.events}
        hypotheses, conclusion = fallback_investigation(incident, events, is_admin=False)
        assert any(h.kind == "BENIGN" for h in hypotheses)
        assert any("legitimately" in step for step in conclusion.next_steps)
        joined = " ".join(t for h in hypotheses for t in h.attack_techniques)
        assert "T1003" not in joined  # credential dumping is not observable here
