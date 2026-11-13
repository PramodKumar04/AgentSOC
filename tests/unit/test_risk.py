"""RSEM behaviour on small SYNTHETIC fixtures (Target 3). These verify arithmetic and
safeguards only; they are not calibration and say nothing about real-world accuracy."""

import ast
import itertools
import random
from pathlib import Path

import pytest
from pydantic import ValidationError

import agentsoc.risk
from agentsoc.config import PROJECT_ROOT
from agentsoc.detection.config import SensitiveAccessConfig
from agentsoc.exceptions import ConfigurationError
from agentsoc.graph.proposed import assessment_sha256
from agentsoc.investigator.agent import InvestigatorAgent
from agentsoc.risk.actions import DESTRUCTIVE
from agentsoc.risk.assess import assess_incident_risk
from agentsoc.risk.confidence import assess_confidence, baseline_coverage
from agentsoc.risk.config import RiskBands, RiskConfig, RiskWeights, load_risk_config
from agentsoc.risk.ledger import depth_value
from agentsoc.risk.score import score_incident
from agentsoc.risk.verify import RiskVerificationError, verify_record
from agentsoc.schemas import Feasibility, Severity
from agentsoc.schemas.graph import PathKind
from agentsoc.schemas.response import ActionStatus, ActionType
from agentsoc.schemas.rsem import EvidenceAttribution, IncidentRiskRecord
from tests.detection_support import Stream
from tests.structural_support import Assessed
from tests.unit.test_investigator import ScriptedProvider, llm_json

A, B = "alice@D", "bob@D"
DB = {"sensitive_host_access": SensitiveAccessConfig(hosts=["DB1"])}


def walk(s, hosts, user=A, start=2000, step=300):
    return [s.add(start + k * step, user, a, b)
            for k, (a, b) in enumerate(itertools.pairwise(hosts))]


def chain(s, hops=("APP1", "DB1"), user=A, ws="WS1"):
    s.baseline(user=user, src=ws, dsts=("SRV1",))
    return walk(s, [ws, *hops], user)


def pivot(s, hub="HUB", end="SRV2"):
    s.baseline(user=A, src="WS1", dsts=("SRV1",))
    s.baseline(user=B, src="WS2", dsts=("SRV1",))
    return s.add(2000, A, "WS1", hub), s.add(2300, B, hub, end)


def record_of(checked, user, config=None, no_baseline=()):
    return assess_incident_risk(checked.incidents[user], checked[user], checked.detection,
                                no_baseline, config or RiskConfig())


def component(record, name):
    return next(c for c in record.risk.components if c.name == name)


def score(checked, user, config=None):
    return record_of(checked, user, config).risk.score


class TestConfig:
    def test_committed_file_gives_the_approved_defaults(self):
        config = load_risk_config(PROJECT_ROOT / "config" / "risk.json")
        assert config == RiskConfig()
        assert config.weights.model_dump() == {
            "credential_pressure": 0.15, "access_novelty": 0.10, "movement_depth": 0.35,
            "sequence_breadth": 0.10, "sensitive_exposure": 0.30,
        }

    @pytest.mark.parametrize("score,band", [
        (0, "LOW"), (19.9, "LOW"), (20, "MEDIUM"), (44.9, "MEDIUM"), (45, "HIGH"), (69.9, "HIGH"),
        (70, "CRITICAL"), (100, "CRITICAL"),
    ])
    def test_band_boundaries(self, score, band):
        assert RiskConfig().bands.band(score) == band

    def test_weights_must_sum_to_one(self):
        with pytest.raises(ValidationError):
            RiskWeights(movement_depth=0.9)

    def test_bands_must_be_ordered(self):
        with pytest.raises(ValidationError):
            RiskBands(medium_at=50, high_at=45)

    def test_ambiguous_cannot_outweigh_inferred(self):
        with pytest.raises(ValidationError):
            RiskConfig(ambiguous_hop_discount=0.9)

    def test_sensitive_values_must_fall_with_certainty(self):
        with pytest.raises(ValidationError):
            RiskConfig(sensitive_inferred_value=0.1)

    def test_unknown_key_rejected(self, tmp_path):
        path = tmp_path / "c.json"
        path.write_text('{"weight": 1}', encoding="utf-8")
        with pytest.raises(ConfigurationError):
            load_risk_config(path)

    def test_hash_is_sensitive(self):
        assert RiskConfig().sha256() != RiskConfig(max_actions=1).sha256()


class TestDepth:
    @pytest.mark.parametrize("hops,value", [
        (1, 0), (1.5, .3), (2, .6), (3, .85), (4, 1.0), (9, 1.0),
    ])
    def test_curve(self, hops, value):
        assert depth_value(hops, RiskConfig()) == pytest.approx(value)


class TestAttribution:
    def test_every_credited_event_appears_once(self):
        s = Stream()
        for k in range(3):
            s.add(2000 + k * 20, A, "WS1", "WS1", outcome="Fail")
        chain(s)
        record = record_of(Assessed(s.events), A)
        ids = [a.event_id for a in record.attributions]
        assert len(ids) == len(set(ids))

    def test_schema_rejects_double_credit(self):
        s = Stream()
        chain(s)
        record = record_of(Assessed(s.events), A)
        item = EvidenceAttribution(event_id=record.attributions[0].event_id,
                                   component="access_novelty")
        data = record.model_dump()
        data["attributions"].append(item.model_dump())
        with pytest.raises(ValidationError, match="only one component"):
            IncidentRiskRecord(**data)

    def test_overlapping_rules_on_one_event_count_once(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "NEW", "NEW2")  # NEW_SRC and NEW_DST on one event
        record = record_of(Assessed(s.events), A)
        assert component(record, "access_novelty").value == pytest.approx(1 / 5)

    def test_route_events_are_not_also_novelty(self):
        s = Stream()
        chain(s, hops=("APP1", "APP2"))
        record = record_of(Assessed(s.events), A)
        assert component(record, "access_novelty").value == 0
        assert {a.component for a in record.attributions} == {"movement_depth"}

    def test_failure_rules_share_one_value(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        for k in range(5):
            s.add(2000 + k, A, "WS1", "WS1", outcome="Fail")
        s.add(2010, A, "WS1", "WS1")
        record = record_of(Assessed(s.events), A)
        assert component(record, "credential_pressure").value == pytest.approx(0.8)

    def test_duplicate_events_do_not_change_the_score(self):
        one, two = Stream(), Stream()
        chain(one), chain(two)
        for e in list(two.events)[-2:]:
            two.add(int((e.timestamp - two.events[0].timestamp).total_seconds()), A,
                    e.src_host, e.dst_host)
        assert score(Assessed(one.events), A) == score(Assessed(two.events), A)

    def test_shared_server_arrivals_add_no_breadth(self):
        s = Stream()
        s.baseline(user=B, src="WS2", dsts=("SRV1",))
        for k in range(5):
            s.add(2000 + k, f"u{k}@D", f"W{k}", "HUB")
        s.add(2300, B, "HUB", "SRV2")
        assert component(record_of(Assessed(s.events), B), "sequence_breadth").value == 0

    def test_failed_events_are_never_movement_credit(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "X")
        s.add(2100, A, "X", "Y", outcome="Fail")
        s.add(2200, A, "Y", "Z")
        checked = Assessed(s.events)
        record = record_of(checked, A)
        edges = {e.event_id: e for e in checked[A].edges}
        for item in record.attributions:
            if item.component == "movement_depth":
                assert edges[item.event_id].kind == "MOVEMENT"


class TestStructuralDistinction:
    def test_observed_scores_at_least_inferred(self):
        observed, inferred = Stream(), Stream()
        observed.baseline(user=B, src="WS1", dsts=("SRV1",))
        walk(observed, ["WS1", "HUB", "SRV2"], user=B)
        pivot(inferred)
        assert score(Assessed(observed.events), B) >= score(Assessed(inferred.events), B)

    def test_inferred_scores_at_least_ambiguous(self):
        clean, busy = Stream(), Stream()
        pivot(clean)
        busy.baseline(user=B, src="WS2", dsts=("SRV1",))
        for k in range(5):
            busy.add(2000 + k, f"u{k}@D", f"W{k}", "HUB")
        busy.add(2300, B, "HUB", "SRV2")
        assert score(Assessed(clean.events), B) >= score(Assessed(busy.events), B)

    def test_observed_sensitive_outranks_ambiguous_sensitive(self):
        observed, busy = Stream(), Stream()
        observed.baseline(user=A, src="WS1", dsts=("SRV1",))
        walk(observed, ["WS1", "HUB", "DB1"])
        busy.baseline(user=A, src="WS1", dsts=("SRV1",))
        busy.add(2000, A, "WS1", "HUB")
        for k in range(5):
            busy.add(2010 + k, f"u{k}@D", f"W{k}", "HUB")
        busy.add(2300, B, "HUB", "DB1")
        high = record_of(Assessed(observed.events, detection=DB), A)
        low = record_of(Assessed(busy.events, detection=DB), A)
        assert component(high, "sensitive_exposure").value == 1.0
        assert component(low, "sensitive_exposure").value == pytest.approx(0.2)
        assert high.risk.score > low.risk.score

    def test_inferred_route_is_labelled(self):
        s = Stream()
        pivot(s)
        record = record_of(Assessed(s.events), B)
        assert record.route.kind is PathKind.INFERRED


class TestCaps:
    def test_structure_alone_cannot_reach_high(self):
        s = Stream()
        chain(s, hops=("H1", "H2", "H3", "H4"))
        for k in range(4):
            s.add(2500 + k, A, "H2", f"B{k}")
        checked = Assessed(s.events)
        chain_only = checked.incidents[A].model_copy(update={"findings": [
            f for f in checked.incidents[A].findings if f.rule_id == "LATERAL_CHAIN"]})
        result = score_incident(chain_only, checked[A], checked.detection, RiskConfig())
        assert result.base_score == pytest.approx(45)
        assert result.assessment.score == pytest.approx(44.9)
        assert result.assessment.band is Severity.MEDIUM
        assert result.adjustments[-1].name == "uncorroborated_structure"

    def test_no_observed_route_cannot_reach_critical(self):
        s = Stream()
        accounts = ["a1@D", "a2@D", "a3@D", "a4@D"]
        for k, user in enumerate(accounts):
            s.baseline(user=user, src=f"W{k}", dsts=("SRV1",))
        for k, user in enumerate(accounts):
            s.add(2000 + 100 * k, user, f"H{k}", f"H{k + 1}")
        checked = Assessed(s.events)
        config = RiskConfig(
            weights=RiskWeights(credential_pressure=0, access_novelty=0, movement_depth=1,
                                sequence_breadth=0, sensitive_exposure=0),
            inferred_hop_discount=1.0)
        target = accounts[-1]
        assert not [p for p in checked[target].paths
                    if p.kind is PathKind.OBSERVED and len(p.event_ids) >= 2]
        result = score_incident(checked.incidents[target], checked[target], checked.detection,
                                config)
        assert result.assessment.score == pytest.approx(69.9)
        assert result.assessment.band is Severity.HIGH


class TestEvidenceQuality:
    def checked(self):
        s = Stream()
        chain(s)
        return Assessed(s.events)

    def factor(self, checked, assessment):
        result = score_incident(checked.incidents[A], assessment, checked.detection, RiskConfig())
        return next((a.value for a in result.adjustments if a.name == "evidence_quality"), 1.0)

    def test_complete_evidence_is_not_reduced(self):
        checked = self.checked()
        assert self.factor(checked, checked[A]) == 1.0

    def test_missing_evidence_reduces_the_score(self):
        checked = self.checked()
        changed = checked[A].model_copy(update={"missing_event_ids": ["E999"]})
        assert self.factor(checked, changed) == pytest.approx(0.8)

    def test_truncated_context_reduces_the_score(self):
        checked = self.checked()
        stats = checked[A].stats.model_copy(update={"truncated": True,
                                                    "truncation_reasons": ["cut"]})
        changed = checked[A].model_copy(update={"stats": stats})
        assert self.factor(checked, changed) == pytest.approx(0.9)

    def test_infeasible_finding_reduces_the_score(self):
        checked = self.checked()
        items = [v.model_copy(update={"verdict": Feasibility.INFEASIBLE})
                 for v in checked[A].finding_validations]
        changed = checked[A].model_copy(update={"finding_validations": items})
        assert self.factor(checked, changed) == pytest.approx(0.9)

    def test_floor_stops_penalties_stacking_without_limit(self):
        checked = self.checked()
        stats = checked[A].stats.model_copy(update={"truncated": True,
                                                    "truncation_reasons": ["cut"]})
        items = [v.model_copy(update={"verdict": Feasibility.INFEASIBLE})
                 for v in checked[A].finding_validations]
        changed = checked[A].model_copy(update={
            "stats": stats, "finding_validations": items, "missing_event_ids": ["E999"]})
        config = RiskConfig(missing_evidence_penalty=0.9)
        result = score_incident(checked.incidents[A], changed, checked.detection, config)
        assert result.adjustments[0].value == pytest.approx(config.quality_floor)

    def test_failed_event_cannot_earn_novelty_even_if_a_finding_cites_it(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        for k in range(6):
            s.add(2000 + k, A, "WS1", "WS1", outcome="Fail")
        checked = Assessed(s.events)
        incident = checked.incidents[A]
        finding = incident.findings[0].model_copy(update={"rule_id": "NEW_DST_HOST"})
        forged = incident.model_copy(update={"findings": [finding]})
        result = score_incident(forged, checked[A], checked.detection, RiskConfig())
        assert result.selection.novelty_ids == ()


class TestMonotonicity:
    """Removing supporting evidence must never increase risk."""

    def streams(self):
        for seed in range(30):
            rng = random.Random(seed)  # noqa: S311
            hosts = [f"H{k}" for k in range(rng.randint(3, 10))]
            users = [f"u{k}@D" for k in range(rng.randint(1, 4))]
            s = Stream()
            for user in users:
                s.baseline(user=user, src=hosts[0], dsts=(hosts[1],))
            for _ in range(rng.randint(5, 60)):
                s.add(rng.randint(1001, 3500), rng.choice(users), rng.choice(hosts),
                      rng.choice(hosts), outcome=rng.choice(["Success"] * 5 + ["Fail"]))
            s.events.sort(key=lambda e: e.timestamp)
            yield s

    def value(self, checked, incident, assessment):
        return score_incident(incident, assessment, checked.detection, RiskConfig()).base_score

    def test_dropping_any_path(self):
        for s in self.streams():
            checked = Assessed(s.events, detection=DB)
            for user, assessment in checked.by_user.items():
                incident = checked.incidents[user]
                before = self.value(checked, incident, assessment)
                for path in assessment.paths:
                    reduced = assessment.model_copy(update={
                        "paths": [p for p in assessment.paths if p is not path]})
                    assert self.value(checked, incident, reduced) <= before + 1e-9

    def test_shortening_any_path(self):
        for s in self.streams():
            checked = Assessed(s.events)
            for user, assessment in checked.by_user.items():
                incident = checked.incidents[user]
                before = self.value(checked, incident, assessment)
                for path in assessment.paths:
                    if len(path.event_ids) < 2:
                        continue
                    shorter = path.model_copy(update={
                        "event_ids": path.event_ids[:-1], "hosts": path.hosts[:-1],
                        "links": path.links[:-1]})
                    reduced = assessment.model_copy(update={"paths": [
                        shorter if p is path else p for p in assessment.paths]})
                    assert self.value(checked, incident, reduced) <= before + 1e-9

    def test_dropping_any_finding(self):
        for s in self.streams():
            checked = Assessed(s.events)
            for user, assessment in checked.by_user.items():
                incident = checked.incidents[user]
                before = self.value(checked, incident, assessment)
                for finding in incident.findings:
                    reduced = incident.model_copy(update={"findings": [
                        f for f in incident.findings if f is not finding]})
                    assert self.value(checked, reduced, assessment) <= before + 1e-9

    @staticmethod
    def new_upstream_evidence(before, after, incident_before, incident_after):
        """What the earlier stages newly produced after an event was removed."""
        def stretch(part, whole):
            size = len(part)
            return any(list(whole[k:k + size]) == list(part)
                       for k in range(len(whole) - size + 1))

        known = {}
        for finding in incident_before.findings:
            known.setdefault(finding.rule_id, []).append(set(finding.event_ids))
        changes = [
            any(not any(set(f.event_ids) <= seen for seen in known.get(f.rule_id, []))
                for f in incident_after.findings),
            any(not any(stretch(p.event_ids, q.event_ids) for q in before.paths)
                for p in after.paths),
            before.stats.truncated and not after.stats.truncated,
        ]
        return any(changes)

    def test_any_increase_after_removal_traces_to_new_upstream_evidence(self):
        """Removing an event can change what detection and the SSE produce (a later logon
        becomes first-seen, context stops being truncated). RSEM itself never adds risk."""
        for s in self.streams():
            checked = Assessed(s.events)
            for user in checked.by_user:
                record = record_of(checked, user)
                if not record.route:
                    continue
                for removed in record.route.event_ids:
                    again = Assessed([e for e in s.events if e.event_id != removed])
                    if user in again.by_user and (
                        record_of(again, user).risk.score > record.risk.score
                    ):
                        assert self.new_upstream_evidence(
                            checked[user], again[user], checked.incidents[user],
                            again.incidents[user])

    @pytest.mark.parametrize("hops", [("A", "B"), ("A", "B", "C"), ("A", "B", "C", "D", "E", "F")])
    def test_removing_each_hop_of_an_attack_shape_never_raises_it(self, hops):
        def build(skip=None):
            s = Stream()
            s.baseline(user=A, src="WS1", dsts=("SRV1",))
            for k in range(3):
                s.add(1900 + k * 10, A, "WS1", "WS1", outcome="Fail")
            s.add(1950, A, "WS1", "WS1")
            events = walk(s, ["WS1", *hops])
            drop = None if skip is None else events[skip].event_id
            return Assessed([e for e in s.events if e.event_id != drop])

        full = record_of(build(), A).risk.score
        for index in range(len(hops)):
            assert record_of(build(index), A).risk.score <= full

    def test_removing_a_saturated_route_hop_cannot_raise_the_score(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        hops = walk(s, ["WS1", "H1", "H2", "H3", "H4", "H5", "H6"])
        full = score(Assessed(s.events), A)
        shorter = Stream()
        shorter.baseline(user=A, src="WS1", dsts=("SRV1",))
        walk(shorter, ["WS1", "H1", "H2", "H3", "H4", "H5"])
        assert len(hops) == 6
        assert score(Assessed(shorter.events), A) <= full


class TestBaselineAndConfidence:
    def test_missing_baseline_lowers_confidence_and_leaves_risk_alone(self):
        s = Stream()
        chain(s)
        checked = Assessed(s.events)
        known, unknown = record_of(checked, A), record_of(checked, A, no_baseline={A})
        assert unknown.risk.score == known.risk.score
        assert unknown.confidence.score < known.confidence.score

    def test_short_baseline_lowers_coverage(self):
        s = Stream()
        chain(s)
        checked = Assessed(s.events)
        assert baseline_coverage(checked.incidents[A], checked.detection, (), RiskConfig()) < 1

    def test_confidence_is_separate_from_risk(self):
        s = Stream()
        chain(s, hops=("APP1", "DB1"))
        checked = Assessed(s.events)
        record = record_of(checked, A)
        changed = RiskConfig(weights=RiskWeights(credential_pressure=1, access_novelty=0,
                                                 movement_depth=0, sequence_breadth=0,
                                                 sensitive_exposure=0))
        other = record_of(checked, A, changed)
        assert other.risk.score != record.risk.score
        assert other.confidence.score == record.confidence.score

    def investigate(self, checked, reply=None):
        incident = checked.incidents[A]
        events = [checked.events[e] for e in incident.event_ids]
        provider = ScriptedProvider(reply) if reply else None
        return InvestigatorAgent(provider, disabled_reason="off").investigate(
            incident, events, structural=checked.evidence(A))

    def four_hops(self):
        s = Stream()
        chain(s, hops=("APP1", "DB1", "X1", "Y1"))
        return Assessed(s.events)

    def test_llm_numbers_cannot_change_either_score(self):
        checked = self.four_hops()
        incident = checked.incidents[A]
        low = self.investigate(checked, llm_json(incident, **{"hypotheses.0.confidence": 0.01}))
        high = self.investigate(checked, llm_json(incident, **{"hypotheses.0.confidence": 0.99}))
        config = RiskConfig()
        results = [assess_confidence(incident, checked[A], checked.detection, (), config, inv)
                   for inv in (low, high)]
        assert results[0].score == results[1].score

    def test_investigation_fact_raises_confidence_only(self):
        checked = self.four_hops()
        incident = checked.incidents[A]
        config = RiskConfig()
        before = assess_confidence(incident, checked[A], checked.detection, (), config)
        after = assess_confidence(incident, checked[A], checked.detection, (), config,
                                  self.investigate(checked, llm_json(incident)))
        assert after.score > before.score
        assert after.includes_investigation

    def test_fallback_rates_below_llm(self):
        checked = self.four_hops()
        incident = checked.incidents[A]
        config = RiskConfig()
        llm = assess_confidence(incident, checked[A], checked.detection, (), config,
                                self.investigate(checked, llm_json(incident)))
        fallback = assess_confidence(incident, checked[A], checked.detection, (), config,
                                     self.investigate(checked))
        assert llm.score > fallback.score

    def test_unsupported_llm_path_lowers_confidence(self):
        checked = self.four_hops()
        incident = checked.incidents[A]
        config = RiskConfig()
        supported = self.investigate(checked, llm_json(
            incident, **{"hypotheses.0.proposed_path": ["WS1", "APP1", "DB1"]}))
        unsupported = self.investigate(checked, llm_json(
            incident, **{"hypotheses.0.proposed_path": ["WS1", "PAYROLL-DB"]}))
        high = assess_confidence(incident, checked[A], checked.detection, (), config, supported)
        low = assess_confidence(incident, checked[A], checked.detection, (), config, unsupported)
        assert low.score < high.score

    def test_rsem_imports_nothing_from_the_investigator(self):
        package = Path(agentsoc.risk.__file__).parent
        for path in package.glob("*.py"):
            if path.name == "confidence.py":
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.ImportFrom):
                    assert "investigator" not in (node.module or ""), path.name


class TestActions:
    def high_risk(self):
        s = Stream()
        chain(s)
        return Assessed(s.events, detection=DB)

    def test_all_actions_are_proposals_and_dry_run(self):
        record = record_of(self.high_risk(), A)
        assert all(a.status is ActionStatus.PROPOSED and a.dry_run is True for a in record.actions)

    def test_all_but_monitoring_need_approval(self):
        for action in record_of(self.high_risk(), A).actions:
            assert action.requires_approval == (action.action_type is not ActionType.MONITOR_ONLY)

    def test_ranked_by_priority(self):
        actions = record_of(self.high_risk(), A).actions
        priorities = [a.score.composite for a in actions]
        assert priorities == sorted(priorities, reverse=True)

    def test_priority_never_changes_the_risk(self):
        checked = self.high_risk()
        config = RiskConfig(alpha=0.1, beta=0.9, max_actions=1)
        assert (record_of(checked, A, config).risk.score == record_of(checked, A).risk.score)

    def test_destructive_allowed_only_with_full_support(self):
        record = record_of(self.high_risk(), A)
        assert record.risk.band is Severity.HIGH
        assert any(a.action_type in DESTRUCTIVE for a in record.actions)

    def test_withheld_below_high(self):
        s = Stream()
        chain(s)
        record = record_of(Assessed(s.events), A)
        assert not [a for a in record.actions if a.action_type in DESTRUCTIVE]
        assert any("below High" in r for w in record.withheld_actions for r in w.reasons)

    def test_withheld_when_confidence_is_low(self):
        checked = self.high_risk()
        config = RiskConfig(destructive_min_confidence=99)
        record = record_of(checked, A, config)
        assert not [a for a in record.actions if a.action_type in DESTRUCTIVE]
        assert any("confidence" in r for w in record.withheld_actions for r in w.reasons)

    def test_withheld_without_an_observed_route(self):
        s = Stream()
        pivot(s, end="DB1")
        checked = Assessed(s.events, detection=DB)
        config = RiskConfig(bands=RiskBands(medium_at=1, high_at=2, critical_at=99))
        record = record_of(checked, B, config)
        assert record.risk.band is Severity.HIGH
        assert not [a for a in record.actions if a.action_type in DESTRUCTIVE]
        assert any("observed" in r for w in record.withheld_actions for r in w.reasons)

    def test_targets_come_only_from_the_evidence(self):
        checked = self.high_risk()
        allowed = {A} | {h for e in checked[A].edges for h in (e.src_host, e.dst_host)}
        assert {a.target for a in record_of(checked, A).actions} <= allowed

    def test_monitor_is_always_offered(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "NEW")
        actions = record_of(Assessed(s.events), A).actions
        assert ActionType.MONITOR_ONLY in {a.action_type for a in actions}

    def test_sensitive_target_costs_more(self):
        checked = self.high_risk()
        config = RiskConfig(sensitive_host_impact=0.0)
        record = record_of(checked, A)
        cheaper = record_of(checked, A, config)
        assert record.risk.score == cheaper.risk.score


class TestSchema:
    def record(self):
        s = Stream()
        chain(s)
        return record_of(Assessed(s.events), A)

    def test_cannot_claim_proof(self):
        data = self.record().model_dump()
        data["is_proof_of_compromise"] = True
        with pytest.raises(ValidationError):
            IncidentRiskRecord(**data)

    def test_score_must_match_breakdown(self):
        data = self.record().model_dump()
        data["risk"]["score"] = 99.0
        with pytest.raises(ValidationError, match="breakdown"):
            IncidentRiskRecord(**data)

    def test_actions_cannot_be_approved(self):
        data = self.record().model_dump()
        data["actions"][0]["status"] = "APPROVED"
        with pytest.raises(ValidationError, match="only propose"):
            IncidentRiskRecord(**data)


class TestVerifier:
    def setup_method(self):
        s = Stream()
        chain(s)
        self.checked = Assessed(s.events, detection=DB)
        self.record = record_of(self.checked, A)
        self.config = RiskConfig()

    def verify(self, record=None, config=None, assessment=None, incident=None):
        verify_record(record or self.record, incident or self.checked.incidents[A],
                      assessment or self.checked[A], self.checked.detection,
                      config or self.config)

    def replace_components(self, name, **changes):
        components = [c.model_copy(update=changes) if c.name == name else c
                      for c in self.record.risk.components]
        risk = self.record.risk.model_copy(update={"components": components})
        return self.record.model_copy(update={"risk": risk})

    def test_accepts_a_genuine_record(self):
        self.verify()

    def test_rejects_an_edited_incident(self):
        changed = self.checked.incidents[A].model_copy(update={"severity_rationale": "edited"})
        with pytest.raises(RiskVerificationError, match="incident hash"):
            self.verify(incident=changed)

    def test_rejects_an_edited_assessment(self):
        changed = self.checked[A].model_copy(update={"paths": []})
        assert assessment_sha256(changed) != self.record.structural_sha256
        with pytest.raises(RiskVerificationError, match="structural"):
            self.verify(assessment=changed)

    def test_rejects_an_inflated_component(self):
        with pytest.raises(RiskVerificationError):
            self.verify(self.replace_components("movement_depth", value=1.0))

    def test_rejects_a_wrong_weight(self):
        with pytest.raises(RiskVerificationError):
            self.verify(self.replace_components("movement_depth", weight=0.9))

    def test_rejects_a_changed_final_score(self):
        risk = self.record.risk.model_copy(update={"score": 99.0})
        with pytest.raises(RiskVerificationError, match="final score"):
            self.verify(self.record.model_copy(update={"risk": risk}))

    def test_rejects_a_wrong_band(self):
        risk = self.record.risk.model_copy(update={"band": Severity.CRITICAL})
        with pytest.raises(RiskVerificationError, match="band"):
            self.verify(self.record.model_copy(update={"risk": risk}))

    def test_rejects_double_credit(self):
        extra = EvidenceAttribution(event_id=self.record.attributions[0].event_id,
                                    component="access_novelty")
        tampered = self.record.model_copy(update={
            "attributions": [*self.record.attributions, extra]})
        with pytest.raises(RiskVerificationError, match="twice"):
            self.verify(tampered)

    def test_rejects_credit_for_an_invented_event(self):
        extra = EvidenceAttribution(event_id="FORGED", component="access_novelty")
        tampered = self.record.model_copy(update={
            "attributions": [*self.record.attributions, extra]})
        with pytest.raises(RiskVerificationError, match="not on the graph"):
            self.verify(tampered)

    def test_rejects_an_action_target_outside_the_evidence(self):
        first = self.record.actions[0].model_copy(update={"target": "PAYROLL-DB"})
        tampered = self.record.model_copy(update={"actions": [first, *self.record.actions[1:]]})
        with pytest.raises(RiskVerificationError, match="outside the evidence"):
            self.verify(tampered)

    def test_rejects_a_destructive_action_past_the_gate(self):
        config = RiskConfig(destructive_min_confidence=99)
        with pytest.raises(RiskVerificationError, match="gate"):
            self.verify(config=config)

    def test_rejects_an_approved_action(self):
        first = self.record.actions[0].model_copy(update={"status": ActionStatus.APPROVED})
        tampered = self.record.model_copy(update={"actions": [first, *self.record.actions[1:]]})
        with pytest.raises(RiskVerificationError, match="proposed dry-run"):
            self.verify(tampered)

    def test_rejects_a_misreported_detection_severity(self):
        comparison = self.record.severity_comparison.model_copy(
            update={"detection_severity": Severity.LOW})
        tampered = self.record.model_copy(update={"severity_comparison": comparison})
        with pytest.raises(RiskVerificationError, match="severity"):
            self.verify(tampered)

    def test_rejects_a_changed_confidence(self):
        confidence = self.record.confidence.model_copy(update={"score": 99.0})
        tampered = self.record.model_copy(update={"confidence": confidence})
        with pytest.raises(RiskVerificationError, match="confidence"):
            self.verify(tampered)
