"""Per-rule behaviour on small SYNTHETIC fixtures. These verify rule logic only;
they say nothing about real-world detection accuracy."""

from datetime import timedelta

import pytest

from agentsoc.detection.config import (
    FailThenSuccessConfig,
    LateralChainConfig,
    SensitiveAccessConfig,
)
from agentsoc.detection.engine import run_detection
from agentsoc.detection.rules import merged_windows
from tests.detection_support import BASE, Stream, config, rules_of

# Failure-only fixtures don't need novelty rules; a disabled baseline keeps them isolated.
NO_BASELINE = {"baseline_seconds": 0}


class TestMergedWindows:
    def times(self, *seconds):
        return [BASE + timedelta(seconds=s) for s in seconds]

    def test_merges_overlapping_windows(self):
        assert merged_windows(self.times(0, 10, 20, 30, 40), 3, 25) == [(0, 4)]

    def test_separate_windows(self):
        assert merged_windows(self.times(0, 1, 2, 100, 101, 102), 3, 10) == [(0, 2), (3, 5)]

    def test_below_threshold(self):
        assert merged_windows(self.times(0, 100, 200), 2, 50) == []

    def test_empty(self):
        assert merged_windows([], 2, 10) == []


class TestFailureBurst:
    def test_fires_at_threshold(self):
        s = Stream()
        s.fails([0, 60, 120, 180, 240])
        result = run_detection(s.events, config(**NO_BASELINE))
        (finding,) = [f for f in result.findings if f.rule_id == "FAILURE_BURST"]
        assert finding.metrics["failure_count"] == 5
        assert finding.event_ids == [e.event_id for e in s.events]

    def test_below_threshold_is_silent(self):
        s = Stream()
        s.fails([0, 60, 120, 180])
        assert "FAILURE_BURST" not in rules_of(run_detection(s.events, config(**NO_BASELINE)))

    def test_failures_spread_beyond_window_are_silent(self):
        s = Stream()
        s.fails([0, 200, 400, 600, 800])  # 5 failures over 800 s; window is 600 s
        assert "FAILURE_BURST" not in rules_of(run_detection(s.events, config(**NO_BASELINE)))

    def test_overlapping_bursts_merge_and_distant_bursts_split(self):
        s = Stream()
        s.fails([0, 30, 60, 90, 120, 150, 180])  # one burst of 7
        s.fails([10_000, 10_010, 10_020, 10_030, 10_040])  # a second, much later
        result = run_detection(s.events, config(**NO_BASELINE))
        bursts = [f for f in result.findings if f.rule_id == "FAILURE_BURST"]
        counts = [f.metrics["failure_count"] for f in bursts]
        assert counts == [7, 5]

    def test_logoff_and_success_are_not_failures(self):
        s = Stream()
        for t in range(5):
            s.add(t, orientation="LogOff", outcome="Fail")
        assert rules_of(run_detection(s.events, config(**NO_BASELINE))) == []

    def test_missing_optional_fields_do_not_block_detection(self):
        s = Stream()
        for t in range(5):
            s.add(t, outcome="Fail", dst_user=None, auth_type=None, logon_type=None)
        assert "FAILURE_BURST" in rules_of(run_detection(s.events, config(**NO_BASELINE)))


class TestFailThenSuccess:
    def test_fires(self):
        s = Stream()
        fails = s.fails([0, 10, 20], src="WS9")
        ok = s.add(30, src="WS9")
        (finding,) = run_detection(s.events, config(**NO_BASELINE)).findings
        assert finding.rule_id == "FAIL_THEN_SUCCESS"
        assert finding.event_ids == [e.event_id for e in [*fails, ok]]
        assert finding.metrics["seconds_from_last_failure"] == 10
        assert finding.metrics["success_from_a_failing_source"] is True

    def test_success_outside_window_is_silent(self):
        s = Stream()
        s.fails([0, 10, 20])
        s.add(700)  # oldest qualifying failure must be within 600 s
        assert rules_of(run_detection(s.events, config(**NO_BASELINE))) == []

    def test_intervening_success_resets_the_run(self):
        s = Stream()
        s.fails([0, 10])
        s.add(15)
        s.fails([20])
        s.add(30)
        assert rules_of(run_detection(s.events, config(**NO_BASELINE))) == []

    def test_logoff_is_not_a_success(self):
        s = Stream()
        s.fails([0, 10, 20])
        s.add(30, orientation="LogOff")
        assert rules_of(run_detection(s.events, config(**NO_BASELINE))) == []

    def test_threshold_configurable(self):
        s = Stream()
        s.fails([0])
        s.add(5)
        cfg = config(**NO_BASELINE, fail_then_success=FailThenSuccessConfig(min_failures=1))
        assert rules_of(run_detection(s.events, cfg)) == ["FAIL_THEN_SUCCESS"]


class TestNovelty:
    def test_new_destination_flagged_once(self):
        s = Stream()
        s.baseline(dsts=("SRV1",))
        first = s.add(2000, dst="SRV9")
        s.add(2100, dst="SRV9")
        result = run_detection(s.events, config())
        (finding,) = [f for f in result.findings if f.rule_id == "NEW_DST_HOST"]
        assert finding.event_ids == [first.event_id]

    def test_new_source_flagged(self):
        s = Stream()
        s.baseline(src="WS1", dsts=("SRV1",))
        s.add(2000, src="WS9", dst="SRV1")
        assert rules_of(run_detection(s.events, config())) == ["NEW_SRC_HOST"]

    def test_benign_repeated_familiar_access_is_silent(self):
        s = Stream()
        s.baseline(dsts=("SRV1", "SRV2"))
        for k in range(50):
            s.add(2000 + 30 * k, dst="SRV1" if k % 2 else "SRV2")
        assert run_detection(s.events, config()).findings == []

    def test_activity_inside_baseline_is_never_novel(self):
        s = Stream()
        s.baseline(dsts=("SRV1",))
        s.add(500, dst="SRV7")  # still inside the baseline window
        s.add(2000, dst="SRV7")
        assert run_detection(s.events, config()).findings == []

    def test_user_without_baseline_is_not_evaluated_but_reported(self):
        s = Stream()
        s.baseline(user="u1@D")
        s.add(2000, user="u2@D", src="WS5", dst="SRV5")
        result = run_detection(s.events, config())
        assert result.findings == []
        assert result.partitions["synthetic"].users_without_baseline == ["u2@D"]

    def test_failed_attempts_do_not_build_a_baseline(self):
        s = Stream()
        s.fails([0], dst="SRV1")
        s.add(2000, dst="SRV1")
        result = run_detection(s.events, config())
        assert result.partitions["synthetic"].users_with_baseline == 0


class TestMultiHostSpread:
    def test_fires_on_three_new_hosts_in_window(self):
        s = Stream()
        s.baseline()
        for k, dst in enumerate(("A1", "A2", "A3")):
            s.add(2000 + 600 * k, dst=dst)
        result = run_detection(s.events, config())
        (finding,) = [f for f in result.findings if f.rule_id == "MULTI_HOST_SPREAD"]
        assert finding.metrics["new_destination_hosts"] == 3

    def test_new_hosts_spread_beyond_window_are_silent(self):
        s = Stream()
        s.baseline()
        for k, dst in enumerate(("A1", "A2", "A3")):
            s.add(2000 + 2000 * k, dst=dst)  # 3 hosts over 4000 s; window 3600 s
        assert "MULTI_HOST_SPREAD" not in rules_of(run_detection(s.events, config()))

    def test_revisiting_one_new_host_does_not_count_twice(self):
        s = Stream()
        s.baseline()
        for t in (2000, 2100, 2200):
            s.add(t, dst="A1")
        assert "MULTI_HOST_SPREAD" not in rules_of(run_detection(s.events, config()))


class TestLateralChain:
    def chain_findings(self, s, **cfg):
        return [f for f in run_detection(s.events, config(**cfg)).findings
                if f.rule_id == "LATERAL_CHAIN"]

    def test_two_hop_chain(self):
        s = Stream()
        s.baseline(src="WS1", dsts=("SRV1",))
        h1 = s.add(2000, src="WS1", dst="APP1")
        h2 = s.add(2600, src="APP1", dst="DB1")
        (finding,) = self.chain_findings(s)
        assert finding.event_ids == [h1.event_id, h2.event_id]
        assert finding.metrics["path"] == "WS1 > APP1 > DB1"

    def test_reports_only_the_maximal_chain(self):
        s = Stream()
        s.baseline(src="WS1", dsts=("SRV1",))
        s.add(2000, src="WS1", dst="A")
        s.add(2100, src="A", dst="B")
        s.add(2200, src="B", dst="C")
        (finding,) = self.chain_findings(s)
        assert finding.metrics["hops"] == 3

    def test_star_pattern_from_one_host_is_not_a_chain(self):
        s = Stream()
        s.baseline(src="WS1", dsts=("SRV1",))
        for k, dst in enumerate(("A", "B", "C")):
            s.add(2000 + 60 * k, src="WS1", dst=dst)
        assert self.chain_findings(s) == []

    def test_hop_gap_beyond_limit_breaks_chain(self):
        s = Stream()
        s.baseline(src="WS1", dsts=("SRV1",))
        s.add(2000, src="WS1", dst="APP1")
        s.add(2000 + 1801, src="APP1", dst="DB1")
        assert self.chain_findings(s) == []

    def test_fully_familiar_chain_is_silent(self):
        s = Stream()
        s.add(0, src="WS1", dst="APP1")
        s.add(1, src="APP1", dst="DB1")
        s.add(2000, src="WS1", dst="APP1")
        s.add(2100, src="APP1", dst="DB1")
        assert self.chain_findings(s) == []

    def test_loops_do_not_extend(self):
        s = Stream()
        s.baseline(src="WS1", dsts=("SRV1",))
        s.add(2000, src="WS1", dst="A")
        s.add(2100, src="A", dst="WS1")  # back to start: chain A->WS1 ends here
        s.add(2200, src="WS1", dst="A")
        assert all(f.metrics["hops"] <= 2 for f in self.chain_findings(s))

    def test_min_hops_configurable(self):
        s = Stream()
        s.baseline(src="WS1", dsts=("SRV1",))
        s.add(2000, src="WS1", dst="A")
        s.add(2100, src="A", dst="B")
        assert self.chain_findings(s, lateral_chain=LateralChainConfig(min_hops=3)) == []


class TestSensitiveAccess:
    def test_first_seen_sensitive_host(self):
        s = Stream()
        s.baseline()
        s.add(2000, dst="DB1")
        cfg = config(sensitive_host_access=SensitiveAccessConfig(hosts=["DB1"]))
        assert "SENSITIVE_HOST_ACCESS" in rules_of(run_detection(s.events, cfg))

    def test_familiar_sensitive_host_is_silent(self):
        s = Stream()
        s.baseline(dsts=("DB1",))
        s.add(2000, dst="DB1")
        cfg = config(sensitive_host_access=SensitiveAccessConfig(hosts=["DB1"]))
        assert run_detection(s.events, cfg).findings == []

    def test_inert_without_configured_hosts(self):
        s = Stream()
        s.baseline()
        s.add(2000, dst="DB1")
        assert "SENSITIVE_HOST_ACCESS" not in rules_of(run_detection(s.events, config()))


@pytest.mark.parametrize(
    "rule_cfg",
    ["failure_burst", "fail_then_success", "new_src_host", "new_dst_host",
     "multi_host_spread", "lateral_chain", "sensitive_host_access"],
)
def test_every_rule_can_be_disabled(rule_cfg):
    s = Stream()
    s.baseline(src="WS1", dsts=("SRV1",))
    s.fails([1500, 1510, 1520, 1530, 1540], src="WS9", dst="WS9")
    s.add(1550, src="WS9", dst="WS9")
    s.add(2000, src="WS9", dst="APP1")
    s.add(2100, src="APP1", dst="DB1")
    cfg = config(sensitive_host_access=SensitiveAccessConfig(hosts=["DB1"]))
    disabled = cfg.model_copy(update={
        rule_cfg: getattr(cfg, rule_cfg).model_copy(update={"enabled": False})
    })
    assert rule_cfg.upper() in rules_of(run_detection(s.events, cfg))
    assert rule_cfg.upper() not in rules_of(run_detection(s.events, disabled))
