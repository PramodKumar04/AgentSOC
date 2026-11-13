"""SSE behaviour on small SYNTHETIC fixtures (Target 2). These verify logic only; they say
nothing about real-world detection accuracy."""

import itertools
import json
import random
from datetime import timedelta

import networkx as nx
import pytest
from pydantic import ValidationError

from agentsoc.detection.lateral import account_name
from agentsoc.exceptions import ConfigurationError
from agentsoc.graph.build import (
    build_authentication_graph,
    build_event_graph,
    expand_context,
    movement_view,
    to_edge,
)
from agentsoc.graph.config import StructuralConfig, load_structural_config
from agentsoc.graph.proposed import (
    StructuralEvidence,
    assessment_sha256,
    validate_proposed_path,
)
from agentsoc.graph.validate import assess_incident
from agentsoc.graph.verify import (
    StructuralVerificationError,
    verify_assessment,
    verify_chain,
)
from agentsoc.investigator.agent import InvestigatorAgent
from agentsoc.investigator.grounding import InvestigationValidationError, parse_and_ground
from agentsoc.investigator.prompts import SYSTEM_PROMPT, build_user_prompt
from agentsoc.schemas import Feasibility
from agentsoc.schemas.graph import (
    AssessmentStats,
    EdgeKind,
    FindingValidation,
    HopLink,
    LinkBasis,
    PathKind,
    StructuralAssessment,
    StructuralPath,
)
from tests.detection_support import Stream
from tests.structural_support import Assessed, index_of, indexed
from tests.unit.test_investigator import ScriptedProvider, llm_json

A, B = "alice@D", "bob@D"
GAP = StructuralConfig().max_link_gap_seconds


def chain(s, user=A, ws="WS1", hops=("APP1", "DB1"), start=2000, step=300):
    s.baseline(user=user, src=ws, dsts=("SRV1",))
    previous, out = ws, []
    for k, host in enumerate(hops):
        out.append(s.add(start + k * step, user, previous, host))
        previous = host
    return out


def pivot(s, hub="HUB", arrive=2000, depart=2300):
    s.baseline(user=A, src="WS1", dsts=("SRV1",))
    s.baseline(user=B, src="WS2", dsts=("SRV1",))
    return s.add(arrive, A, "WS1", hub), s.add(depart, B, hub, "SRV2")


def path_between(assessment, *hosts):
    return next(p for p in assessment.paths if p.hosts == list(hosts))


class TestSchemas:
    def stats(self, **changes):
        data = dict(anchors=1, context_events=0, movement_edges=1, attempt_edges=0, local_edges=0,
                    event_graph_nodes=1, event_graph_arcs=0, account_switch_arcs=0,
                    depth_reached=0, truncated=False)
        return AssessmentStats(**{**data, **changes})

    def path(self, **changes):
        data = dict(path_id="P1", kind=PathKind.OBSERVED, verdict=Feasibility.FEASIBLE,
                    event_ids=["E1"], hosts=["A", "B"], accounts=["a"], reasons=["r"])
        return StructuralPath(**{**data, **changes})

    def test_observed_path_cannot_be_conditional(self):
        with pytest.raises(ValidationError):
            self.path(verdict=Feasibility.CONDITIONALLY_FEASIBLE, conditions=["c"])

    def test_path_cannot_claim_proof_of_compromise(self):
        with pytest.raises(ValidationError):
            self.path(is_proof_of_compromise=True)

    def test_inferred_path_needs_a_switch_and_conditions(self):
        with pytest.raises(ValidationError):
            self.path(kind=PathKind.INFERRED, verdict=Feasibility.CONDITIONALLY_FEASIBLE,
                      conditions=["c"])

    def test_switch_without_inferred_kind_is_rejected(self):
        link = HopLink(from_event_id="E1", to_event_id="E2", host="B", gap_seconds=5,
                       basis=LinkBasis.ACCOUNT_SWITCH, other_accounts_arriving=0)
        with pytest.raises(ValidationError):
            self.path(event_ids=["E1", "E2"], hosts=["A", "B", "C"], links=[link])

    def test_hosts_must_match_hops(self):
        with pytest.raises(ValidationError):
            self.path(hosts=["A", "B", "C"])

    def test_same_account_link_cannot_be_ambiguous(self):
        with pytest.raises(ValidationError):
            HopLink(from_event_id="E1", to_event_id="E2", host="B", gap_seconds=5,
                    basis=LinkBasis.SAME_ACCOUNT, other_accounts_arriving=0, ambiguous=True)

    def test_feasible_finding_cannot_have_missing_evidence(self):
        with pytest.raises(ValidationError):
            FindingValidation(finding_id="F", rule_id="R", verdict=Feasibility.FEASIBLE,
                              missing_event_ids=["E1"], reasons=["r"])

    def test_truncated_flag_needs_reasons(self):
        with pytest.raises(ValidationError):
            self.stats(truncated=True)

    def test_assessment_rejects_a_path_off_the_graph(self):
        with pytest.raises(ValidationError):
            StructuralAssessment(incident_id="I", incident_sha256="a" * 64, datasets=["synthetic"],
                                 paths=[self.path()], stats=self.stats(), limitations=["l"])


class TestAuthenticationGraph:
    def test_users_and_hosts_with_event_provenance_on_edges(self):
        s = Stream()
        event = s.add(10, A, "WS1", "SRV1")
        graph = build_authentication_graph([to_edge(indexed(event))])
        assert {("host", "WS1"), ("host", "SRV1"), ("user", A)} <= set(graph.nodes)
        edge = graph[("host", "WS1")][("host", "SRV1")][event.event_id]["edge"]
        assert (edge.event_id, edge.timestamp, edge.dataset) == (
            event.event_id, event.timestamp, event.dataset)
        assert edge.raw_ref == event.raw_ref

    def test_failed_authentication_is_not_a_movement_edge(self):
        s = Stream()
        ok, failed = s.add(10, A, "WS1", "SRV1"), s.add(20, A, "WS1", "SRV2", outcome="Fail")
        graph = build_authentication_graph([to_edge(indexed(ok)), to_edge(indexed(failed))])
        view = movement_view(graph)
        assert view.has_edge(("host", "WS1"), ("host", "SRV1"))
        assert not view.has_edge(("host", "WS1"), ("host", "SRV2"))

    def test_failed_authentication_relates_no_account_to_a_host(self):
        s = Stream()
        failed = s.add(20, A, "WS1", "SRV2", outcome="Fail")
        graph = build_authentication_graph([to_edge(indexed(failed))])
        assert not list(graph.successors(("user", A)))

    def test_movement_view_is_not_a_copy(self):
        s = Stream()
        event = s.add(10, A, "WS1", "SRV1")
        graph = build_authentication_graph([to_edge(indexed(event))])
        assert nx.is_frozen(movement_view(graph))


class TestEventGraph:
    def build(self, s, anchors=(), **cfg):
        events = [indexed(e) for e in s.events if indexed(e).kind is EdgeKind.MOVEMENT]
        config = StructuralConfig(**cfg)
        return build_event_graph(events, set(anchors), index_of(s.events), config)

    def test_links_only_with_shared_host_and_later_time(self):
        s = Stream()
        a, b = s.add(10, A, "X", "Y"), s.add(20, A, "Y", "Z")
        c = s.add(30, A, "Q", "R")
        graph = self.build(s).graph
        assert graph.has_edge(a.event_id, b.event_id)
        assert graph.degree(c.event_id) == 0

    def test_same_second_never_links(self):
        s = Stream()
        s.add(10, A, "X", "Y")
        s.add(10, A, "Y", "Z")
        assert self.build(s).graph.number_of_edges() == 0

    def test_gap_boundary(self):
        at, over = Stream(), Stream()
        at.add(0, A, "X", "Y"), at.add(GAP, A, "Y", "Z")
        over.add(0, A, "X", "Y"), over.add(GAP + 1, A, "Y", "Z")
        assert self.build(at).graph.number_of_edges() == 1
        assert self.build(over).graph.number_of_edges() == 0

    def test_host_cycle_stays_acyclic_in_time(self):
        s = Stream()
        for k, (src, dst) in enumerate([("X", "Y"), ("Y", "X"), ("X", "Y"), ("Y", "X")]):
            s.add(10 * k, A, src, dst)
        graph = self.build(s).graph
        assert nx.is_directed_acyclic_graph(graph)
        assert nx.dag_longest_path_length(graph) == 3

    def test_marks_account_switches(self):
        s = Stream()
        a, b = s.add(10, A, "X", "Y"), s.add(20, B, "Y", "Z")
        assert self.build(s).graph[a.event_id][b.event_id]["basis"] is LinkBasis.ACCOUNT_SWITCH

    def test_same_account_in_another_domain_is_not_a_switch(self):
        s = Stream()
        a, b = s.add(10, "alice@D1", "X", "Y"), s.add(20, "alice@D2", "Y", "Z")
        assert self.build(s).graph[a.event_id][b.event_id]["basis"] is LinkBasis.SAME_ACCOUNT

    def test_link_limit_never_drops_the_same_account(self):
        s = Stream()
        own = s.add(10, B, "W", "HUB")
        for k in range(10):
            s.add(100 + k, f"u{k}@D", "W", "HUB")
        departure = s.add(200, B, "HUB", "Z")
        built = self.build(s, max_links_per_event=2)
        assert built.graph.has_edge(own.event_id, departure.event_id)
        assert built.arcs_dropped > 0

    def test_every_same_account_link_survives_the_limit(self):
        s = Stream()
        own = [s.add(10 + k, B, f"W{k}", "HUB") for k in range(4)]
        departure = s.add(200, B, "HUB", "Z")
        built = self.build(s, max_links_per_event=2)
        assert all(built.graph.has_edge(e.event_id, departure.event_id) for e in own)

    def test_link_limit_never_drops_two_anchors(self):
        s = Stream()
        first = s.add(10, A, "W", "HUB")
        for k in range(10):
            s.add(100 + k, f"u{k}@D", "W", "HUB")
        departure = s.add(200, B, "HUB", "Z")
        built = self.build(s, anchors={first.event_id, departure.event_id}, max_links_per_event=2)
        assert built.graph.has_edge(first.event_id, departure.event_id)


class TestExpansion:
    def expand(self, s, seeds, **cfg):
        return expand_context(index_of(s.events), [indexed(e) for e in seeds],
                              StructuralConfig(**cfg))

    def test_follows_both_directions(self):
        s = Stream()
        up, seed, down = s.add(10, A, "U", "X"), s.add(20, A, "X", "Y"), s.add(30, A, "Y", "Z")
        assert set(self.expand(s, [seed]).events) == {up.event_id, seed.event_id, down.event_id}

    def test_does_not_zigzag(self):
        s = Stream()
        seed = s.add(100, A, "X", "Y")
        next_hop = s.add(200, A, "Y", "Z")
        s.add(150, B, "Q", "Y")  # only reachable by stepping backward from next_hop
        found = self.expand(s, [seed]).events
        assert next_hop.event_id in found
        assert len(found) == 2

    def test_failed_events_never_expand(self):
        s = Stream()
        seed = s.add(20, A, "X", "Y")
        s.add(30, A, "Y", "Z", outcome="Fail")
        assert set(self.expand(s, [seed]).events) == {seed.event_id}

    def test_depth_limit_is_disclosed(self):
        s = Stream()
        seed = s.add(10, A, "H0", "H1")
        for k in range(1, 6):
            s.add(10 + k * 10, A, f"H{k}", f"H{k + 1}")
        result = self.expand(s, [seed], max_expansion_hops=2)
        assert len(result.events) == 3
        assert any("hops" in r for r in result.truncation_reasons)

    def test_branch_limit_is_disclosed_and_prefers_own_account(self):
        s = Stream()
        seed = s.add(10, A, "X", "HUB")
        for k in range(10):
            s.add(20 + k, f"u{k}@D", "HUB", f"T{k}")
        own = s.add(200, A, "HUB", "MINE")
        result = self.expand(s, [seed], max_links_per_event=2)
        assert own.event_id in result.events
        assert any("followed" in r for r in result.truncation_reasons)

    def test_event_cap_is_disclosed_and_keeps_seeds(self):
        s = Stream()
        seed = s.add(10, A, "X", "HUB")
        for k in range(10):
            s.add(20 + k, f"u{k}@D", "HUB", f"T{k}")
        result = self.expand(s, [seed], max_links_per_event=50, max_context_events=4)
        assert seed.event_id in result.events
        assert len(result.events) == 4
        assert any("limit" in r for r in result.truncation_reasons)

    def test_no_truncation_when_nothing_was_cut(self):
        s = Stream()
        seed = s.add(10, A, "X", "Y")
        assert self.expand(s, [seed]).truncation_reasons == []


class TestPaths:
    def test_observed_path_for_a_chain(self):
        s = Stream()
        h = chain(s)
        out = Assessed(s.events)[A]
        path = path_between(out, "WS1", "APP1", "DB1")
        assert (path.kind, path.verdict) == (PathKind.OBSERVED, Feasibility.FEASIBLE)
        assert path.event_ids == [e.event_id for e in h]
        assert path.is_proof_of_compromise is False

    def test_upstream_context_event_is_marked_as_not_rule_cited(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("UP",))
        up = s.add(990, A, "WS1", "UP")  # inside the 1000 s baseline
        s.add(1100, A, "UP", "NEW")
        out = Assessed(s.events)[A]
        path = path_between(out, "WS1", "UP", "NEW")
        assert path.context_event_ids == [up.event_id]

    def test_cross_account_path_is_inferred_with_a_stated_condition(self):
        s = Stream()
        pivot(s)
        out = Assessed(s.events)[B]
        path = path_between(out, "WS1", "HUB", "SRV2")
        assert path.kind is PathKind.INFERRED
        assert path.verdict is Feasibility.CONDITIONALLY_FEASIBLE
        assert "same party" in path.conditions[0]

    def test_busy_host_makes_the_link_ambiguous(self):
        s = Stream()
        s.baseline(user=B, src="WS2", dsts=("SRV1",))
        for k in range(5):
            s.add(2000 + k, f"u{k}@D", f"W{k}", "HUB")
        s.add(2300, B, "HUB", "SRV2")
        path = next(p for p in Assessed(s.events)[B].paths if p.kind is PathKind.INFERRED)
        assert path.links[0].ambiguous
        assert "weak evidence" in path.conditions[0]

    def test_ambiguity_threshold_boundary(self):
        def link_for(arrivals):
            s = Stream()
            s.baseline(user=B, src="WS2", dsts=("SRV1",))
            for k in range(arrivals):
                s.add(2000 + k, f"u{k}@D", f"W{k}", "HUB")
            s.add(2300, B, "HUB", "SRV2")
            return next(p for p in Assessed(s.events)[B].paths
                        if p.kind is PathKind.INFERRED).links[0]
        threshold = StructuralConfig().ambiguous_link_accounts
        assert not link_for(threshold).ambiguous
        assert link_for(threshold + 1).ambiguous

    def test_observed_paths_rank_before_inferred(self):
        s = Stream()
        pivot(s)
        out = Assessed(s.events)[B]
        kinds = [p.kind for p in out.paths]
        assert kinds == sorted(kinds, key=lambda k: k is PathKind.INFERRED)

    def test_failed_event_is_never_on_a_path(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "APP1")
        failed = s.add(2100, A, "APP1", "DB1", outcome="Fail")
        s.add(2200, A, "DB1", "X1")
        out = Assessed(s.events)[A]
        assert all(failed.event_id not in p.event_ids for p in out.paths)

    def test_max_paths_is_disclosed(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        for k in range(5):
            s.add(2000 + k * 100, A, f"S{k}", f"D{k}")
        out = Assessed(s.events, max_paths=2)[A]
        assert len(out.paths) == 2
        assert out.stats.truncated

    def test_cycle_reports_revisited_host_and_group(self):
        s = Stream()
        chain(s, hops=("A1", "B1", "A1", "C1"))
        out = Assessed(s.events)[A]
        path = path_between(out, "WS1", "A1", "B1", "A1", "C1")
        assert path.revisited_hosts == ["A1"]
        assert ["A1", "B1"] in out.cyclic_host_groups

    def test_incident_with_no_movement_has_no_paths(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        for k in range(6):
            s.add(2000 + k, A, "WS1", "SRV1", outcome="Fail")
        out = Assessed(s.events)[A]
        assert out.paths == []
        assert out.non_movement_anchors[EdgeKind.ATTEMPT] == 6

    def test_output_is_deterministic(self):
        def run():
            s = Stream()
            pivot(s)
            return Assessed(s.events)[B].model_dump_json()
        assert run() == run()


class TestFindingValidation:
    def test_chain_confirmed(self):
        s = Stream()
        chain(s)
        (item,) = Assessed(s.events)[A].finding_validations
        assert item.verdict is Feasibility.FEASIBLE
        assert item.checked_path == ["WS1", "APP1", "DB1"]

    def test_same_second_chain_is_conditional(self):
        s = Stream()
        chain(s, step=0)
        (item,) = Assessed(s.events)[A].finding_validations
        assert item.verdict is Feasibility.CONDITIONALLY_FEASIBLE
        assert "share one second" in item.conditions[0]

    def test_chain_with_missing_event_is_infeasible_and_not_repaired(self):
        s = Stream()
        hops = chain(s)
        checked = Assessed(s.events)
        incident = checked.incidents[A]
        reduced = index_of([e for e in s.events if e.event_id != hops[0].event_id])
        out = assess_incident(incident, reduced, checked.config)
        (item,) = out.finding_validations
        assert item.verdict is Feasibility.INFEASIBLE
        assert item.missing_event_ids == [hops[0].event_id]
        assert out.missing_event_ids == [hops[0].event_id]
        assert all(hops[0].event_id not in p.event_ids for p in out.paths)

    def test_pivot_is_conditional_and_never_feasible(self):
        s = Stream()
        pivot(s)
        out = Assessed(s.events)[B]
        (item,) = out.finding_validations
        assert item.verdict is Feasibility.CONDITIONALLY_FEASIBLE

    def test_shared_server_pivot_is_flagged_weak(self):
        s = Stream()
        s.baseline(user=B, src="WS2", dsts=("SRV1",))
        for k in range(5):
            s.add(2000 + k, f"u{k}@D", f"W{k}", "HUB")
        s.add(2300, B, "HUB", "SRV2")
        out = Assessed(s.events)[B]
        assert all("weak evidence" in c for v in out.finding_validations for c in v.conditions)

    def test_chain_is_marked_as_extended_by_a_longer_path(self):
        s = Stream()
        chain(s, hops=("A1", "B1", "A1", "C1"))
        out = Assessed(s.events)[A]
        assert all(v.extended_by for v in out.finding_validations)

    def test_other_rules_are_not_validated_as_paths(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "NEW")
        assert Assessed(s.events)[A].finding_validations == []


class TestDisconnected:
    def reason(self, assessment):
        return [d.reason for d in assessment.disconnected]

    def test_no_shared_host(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "X")
        s.add(2100, A, "P", "Q")
        out = Assessed(s.events)[A]
        assert self.reason(out) == ["NO_SHARED_HOST"]
        assert out.account_bridges[0].account == A

    def test_time_order(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "X", "Y")
        s.add(2100, A, "WS1", "X")
        assert self.reason(Assessed(s.events)[A]) == ["TIME_ORDER"]

    def test_gap_exceeded(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "X")
        s.add(2000 + GAP + 1, A, "X", "Y")
        assert self.reason(Assessed(s.events)[A]) == ["GAP_EXCEEDED"]

    def test_failed_link_only_records_the_attempt_as_an_edge(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "X")
        failed = s.add(2050, A, "X", "Y", outcome="Fail")
        s.add(2100, A, "Y", "Z")
        out = Assessed(s.events)[A]
        assert self.reason(out) == ["FAILED_LINK_ONLY"]
        assert failed.event_id in out.disconnected[0].detail
        edge = next(e for e in out.edges if e.event_id == failed.event_id)
        assert edge.kind is EdgeKind.ATTEMPT

    def test_connected_events_are_not_reported(self):
        s = Stream()
        chain(s)
        out = Assessed(s.events)[A]
        assert out.disconnected == []
        assert len(out.sequences) == 1

    def test_sequence_flags_account_switch(self):
        s = Stream()
        pivot(s)
        (sequence,) = Assessed(s.events)[B].sequences
        assert sequence.requires_account_switch


class TestChokePoints:
    def test_hosts_all_routes_must_cross(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "HUB")
        s.add(2010, A, "WS2", "HUB")
        s.add(2100, A, "HUB", "MID")
        s.add(2200, A, "MID", "END")
        (point, *_) = Assessed(s.events)[A].choke_points
        assert point.via_hosts == ["HUB", "MID"]
        assert point.entry_hosts == ["WS1", "WS2"]

    def test_parallel_routes_share_no_choke(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "M1")
        s.add(2010, A, "WS1", "M2")
        s.add(2100, A, "M1", "END")
        s.add(2110, A, "M2", "END")
        targets = Assessed(s.events)[A].choke_points
        assert not [p for p in targets if p.target_host == "END"]


class TestVerifier:
    def setup_method(self):
        s = Stream()
        chain(s)
        self.checked = Assessed(s.events)
        self.out = self.checked[A]

    def verify(self, assessment, events=None):
        verify_assessment(assessment, events if events is not None else self.checked.events,
                          self.checked.detection, self.checked.config)

    def test_accepts_a_genuine_assessment(self):
        self.verify(self.out)

    def test_rejects_an_edge_with_no_original_event(self):
        events = {k: v for k, v in self.checked.events.items()
                  if k != self.out.edges[0].event_id}
        with pytest.raises(StructuralVerificationError, match="no original event"):
            self.verify(self.out, events)

    def test_rejects_an_edge_that_differs_from_its_event(self):
        edge = self.out.edges[0].model_copy(update={"dst_host": "FORGED"})
        forged = self.out.model_copy(update={"edges": [edge, *self.out.edges[1:]]})
        with pytest.raises(StructuralVerificationError, match="differs"):
            self.verify(forged)

    def test_rejects_a_failed_event_labelled_as_movement(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        failed = s.add(2000, A, "WS1", "X", outcome="Fail")
        edge = to_edge(indexed(failed)).model_copy(update={"kind": EdgeKind.MOVEMENT})
        forged = self.out.model_copy(update={"edges": [edge], "paths": [],
                                             "finding_validations": []})
        with pytest.raises(StructuralVerificationError, match="wrong kind"):
            verify_assessment(forged, {failed.event_id: failed}, self.checked.detection,
                              self.checked.config)

    def test_rejects_a_chain_with_a_host_gap(self):
        first, second = list(self.checked.events)[-2:]
        with pytest.raises(StructuralVerificationError):
            verify_chain([second, first], self.checked.events, self.checked.detection,
                         self.checked.config)

    def test_rejects_a_misreported_host_walk(self):
        path = self.out.paths[0]
        forged_path = path.model_copy(update={"hosts": ["WS1", "APP1", "FORGED"]})
        forged = self.out.model_copy(update={"paths": [forged_path]})
        with pytest.raises(StructuralVerificationError, match="misreports its hosts"):
            self.verify(forged)

    def test_rejects_a_hidden_account_switch(self):
        s = Stream()
        arrival, departure = pivot(s)
        checked = Assessed(s.events)
        out = checked[B]
        forged_path = StructuralPath(
            path_id="P9", kind=PathKind.OBSERVED, verdict=Feasibility.FEASIBLE,
            event_ids=[arrival.event_id, departure.event_id], hosts=["WS1", "HUB", "SRV2"],
            accounts=[A], reasons=["forged"],
            links=[HopLink(from_event_id=arrival.event_id, to_event_id=departure.event_id,
                           host="HUB", gap_seconds=300, basis=LinkBasis.SAME_ACCOUNT,
                           other_accounts_arriving=0)],
        )
        forged = out.model_copy(update={"paths": [forged_path]})
        with pytest.raises(StructuralVerificationError, match="account continuity"):
            verify_assessment(forged, checked.events, checked.detection, checked.config)


class TestProposedPath:
    def check(self, checked, user, proposed):
        return validate_proposed_path("H1", proposed, checked.evidence(user))

    def test_supported_path_is_feasible_with_original_events(self):
        s = Stream()
        hops = chain(s)
        result = self.check(Assessed(s.events), A, ["WS1", "APP1", "DB1"])
        assert result.verdict is Feasibility.FEASIBLE
        assert result.evidence_event_ids == [e.event_id for e in hops]

    def test_unobserved_hop_is_infeasible_and_says_not_observed(self):
        s = Stream()
        chain(s)
        result = self.check(Assessed(s.events), A, ["WS1", "APP1", "SECRET-DB"])
        assert result.verdict is Feasibility.INFEASIBLE
        assert result.missing_edges[0].target == "SECRET-DB"
        assert "observed" in result.reasons[0]
        assert not any("impossible" in r for r in result.reasons)

    def test_failed_only_hop_is_infeasible(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "WS1", "X")
        s.add(2050, A, "X", "Y", outcome="Fail")
        s.add(2100, A, "Y", "Z")
        result = self.check(Assessed(s.events), A, ["WS1", "X", "Y"])
        assert result.verdict is Feasibility.INFEASIBLE
        assert "failed attempts" in result.reasons[0]

    def test_wrong_time_order_is_infeasible(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, A, "X", "Y")
        s.add(2100, A, "WS1", "X")
        result = self.check(Assessed(s.events), A, ["WS1", "X", "Y"])
        assert result.verdict is Feasibility.INFEASIBLE
        assert "time-ordered" in result.reasons[0]

    def test_cross_account_path_is_conditional(self):
        s = Stream()
        pivot(s)
        result = self.check(Assessed(s.events), B, ["WS1", "HUB", "SRV2"])
        assert result.verdict is Feasibility.CONDITIONALLY_FEASIBLE
        assert "same party" in result.conditions[0]

    def test_prefers_a_same_account_route(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        s.add(2000, B, "WS1", "HUB")
        s.add(2010, A, "WS1", "HUB")
        s.add(2100, A, "HUB", "NEW")
        result = self.check(Assessed(s.events), A, ["WS1", "HUB", "NEW"])
        assert result.verdict is Feasibility.FEASIBLE

    def test_no_structural_evidence_means_not_validated(self):
        result = validate_proposed_path("H1", ["A", "B"], None)
        assert result.verdict is Feasibility.INFEASIBLE

    def test_single_host_is_not_a_path(self):
        s = Stream()
        chain(s)
        assert self.check(Assessed(s.events), A, ["WS1"]).verdict is Feasibility.INFEASIBLE

    def test_independent_verifier_can_overrule_the_graph(self):
        s = Stream()
        chain(s)
        checked = Assessed(s.events)
        tampered = {k: v for k, v in checked.events.items()
                    if k != checked[A].paths[0].event_ids[0]}
        evidence = StructuralEvidence(checked[A], tampered, checked.detection, checked.config)
        result = validate_proposed_path("H1", ["WS1", "APP1", "DB1"], evidence)
        assert result.verdict is Feasibility.INFEASIBLE
        assert "independent verification" in result.reasons[0]

    def test_truncation_is_stated_when_a_hop_is_unsupported(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("SRV1",))
        for k in range(5):
            s.add(2000 + k * 100, A, f"S{k}", f"D{k}")
        result = self.check(Assessed(s.events, max_paths=2), A, ["S0", "NOPE"])
        assert any("truncated" in r for r in result.reasons)


class TestInvestigatorIntegration:
    def checked(self):
        s = Stream()
        chain(s, hops=("APP1", "DB1", "X1", "Y1"))
        return Assessed(s.events)

    def run(self, checked, user, reply):
        incident = checked.incidents[user]
        events = [checked.events[e] for e in incident.event_ids]
        agent = InvestigatorAgent(ScriptedProvider(reply))
        return agent.investigate(incident, events, structural=checked.evidence(user))

    def path_reply(self, incident, path):
        data = json.loads(llm_json(incident))
        data["hypotheses"][0]["proposed_path"] = path
        return json.dumps(data)

    def test_prompt_marks_structural_evidence_as_untrusted_data(self):
        checked = self.checked()
        incident = checked.incidents[A]
        prompt = build_user_prompt(incident, [], checked[A])
        block = prompt.split("<incident_data>")[1]
        assert "structural_validation" in block
        assert "machine-derived from the same untrusted logs" in SYSTEM_PROMPT
        assert "not evidence of compromise" in SYSTEM_PROMPT

    def test_prompt_has_no_structural_block_without_an_assessment(self):
        checked = self.checked()
        assert "structural_validation" not in build_user_prompt(checked.incidents[A], [])

    def test_supported_proposal_is_validated(self):
        checked = self.checked()
        reply = self.path_reply(checked.incidents[A], ["WS1", "APP1", "DB1"])
        result = self.run(checked, A, reply)
        assert result.path_validations[0].verdict is Feasibility.FEASIBLE

    def test_invalid_proposal_is_never_validated(self):
        checked = self.checked()
        reply = self.path_reply(checked.incidents[A], ["WS1", "PAYROLL-DB"])
        result = self.run(checked, A, reply)
        assert result.source == "llm"
        assert result.path_validations[0].verdict is Feasibility.INFEASIBLE
        assert result.path_validations[0].evidence_event_ids == []

    def test_every_proposal_needs_a_validation(self):
        checked = self.checked()
        result = self.run(checked, A, self.path_reply(checked.incidents[A], ["WS1", "APP1"]))
        with pytest.raises(ValidationError, match="deterministic validation"):
            type(result)(**{**result.model_dump(), "path_validations": []})

    def test_structural_hash_recorded(self):
        checked = self.checked()
        result = self.run(checked, A, llm_json(checked.incidents[A]))
        assert result.structural_sha256 == assessment_sha256(checked[A])

    def test_assessment_for_another_incident_version_is_not_used(self):
        checked = self.checked()
        incident = checked.incidents[A].model_copy(update={"severity_rationale": "changed"})
        agent = InvestigatorAgent(ScriptedProvider(llm_json(incident)))
        result = agent.investigate(
            incident, [checked.events[e] for e in incident.event_ids],
            structural=checked.evidence(A))
        assert result.structural_sha256 is None
        assert any("different version" in w for w in result.warnings)

    def test_may_cite_events_on_structural_paths_only(self):
        s = Stream()
        s.baseline(user=A, src="WS1", dsts=("UP",))
        up = s.add(990, A, "WS1", "UP")
        s.add(1100, A, "UP", "NEW")
        checked = Assessed(s.events)
        incident = checked.incidents[A]
        data = json.loads(llm_json(incident))
        data["hypotheses"][1]["contradicting_event_ids"] = []
        data["hypotheses"][0]["supporting_event_ids"].append(up.event_id)
        text = json.dumps(data)
        with pytest.raises(InvestigationValidationError, match="not in incident"):
            parse_and_ground(text, incident)
        parse_and_ground(text, incident, {up.event_id})

    def test_fallback_mentions_structure_but_keeps_its_confidence(self):
        checked = self.checked()
        incident = checked.incidents[A]
        events = [checked.events[e] for e in incident.event_ids]
        agent = InvestigatorAgent(None, disabled_reason="off")
        without = agent.investigate(incident, events)
        with_graph = agent.investigate(incident, events, structural=checked.evidence(A))
        assert "Structural validation" in with_graph.hypotheses[0].narrative
        assert ([h.confidence for h in with_graph.hypotheses]
                == [h.confidence for h in without.hypotheses])
        assert with_graph.conclusion.is_proof_of_compromise is False


class TestConfig:
    def test_committed_file_matches_defaults(self):
        from agentsoc.config import PROJECT_ROOT
        assert load_structural_config(PROJECT_ROOT / "config" / "structural.json") == (
            StructuralConfig())

    def test_unknown_key_rejected(self, tmp_path):
        path = tmp_path / "c.json"
        path.write_text('{"max_hops": 2}', encoding="utf-8")
        with pytest.raises(ConfigurationError):
            load_structural_config(path)

    def test_hash_is_its_own_and_sensitive(self):
        assert StructuralConfig().sha256() != StructuralConfig(max_paths=1).sha256()


class TestInvariantsOnRandomGraphs:
    """Seeded random event streams: properties that must hold whatever the input."""

    @pytest.mark.parametrize("seed", range(25))
    def test_properties(self, seed):
        rng = random.Random(seed)  # noqa: S311
        hosts = [f"H{k}" for k in range(rng.randint(3, 12))]
        users = [f"u{k}@D" for k in range(rng.randint(2, 6))]
        s = Stream()
        for user in users:
            s.baseline(user=user, src=hosts[0], dsts=(hosts[1],))
        for _ in range(rng.randint(5, 120)):
            s.add(rng.randint(1001, 3500), rng.choice(users), rng.choice(hosts), rng.choice(hosts),
                  outcome=rng.choice(["Success", "Success", "Success", "Fail"]))
        s.events.sort(key=lambda e: e.timestamp)
        checked = Assessed(s.events)
        events = checked.events
        for user, assessment in checked.by_user.items():
            verify_assessment(assessment, events, checked.detection, checked.config)
            for edge in assessment.edges:
                assert edge.event_id in events
            for path in assessment.paths:
                hops = [events[e] for e in path.event_ids]
                assert all(h.outcome.value == "Success" for h in hops)
                assert all(h.src_host != h.dst_host for h in hops)
                for a, b in itertools.pairwise(hops):
                    assert a.dst_host == b.src_host
                    assert a.timestamp < b.timestamp
                    assert b.timestamp - a.timestamp <= timedelta(seconds=GAP)
                same = len({account_name(h.src_user) for h in hops}) == 1
                assert same == (path.kind is PathKind.OBSERVED) or len(hops) == 1
                assert path.is_proof_of_compromise is False
            assert user == checked.incidents[user].principal_user

