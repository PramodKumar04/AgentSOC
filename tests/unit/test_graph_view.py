"""The display graph is a faithful, bundled picture of one structural assessment."""

from datetime import UTC, datetime, timedelta

from agentsoc.detection.config import DetectionConfig
from agentsoc.graph.view import build_incident_graph
from agentsoc.schemas import RawRef
from agentsoc.schemas.events import DatasetSource
from agentsoc.schemas.graph import (
    AssessmentStats,
    ChokePoint,
    EdgeKind,
    Feasibility,
    GraphEdge,
    HopLink,
    LinkBasis,
    PathKind,
    StructuralAssessment,
    StructuralPath,
)

T0 = datetime(2026, 1, 1, tzinfo=UTC)
A, B = "a@CORP", "b@CORP"


def edge(n, account, src, dst, kind=EdgeKind.MOVEMENT, rules=()):
    return GraphEdge(
        event_id=f"E{n}", timestamp=T0 + timedelta(seconds=n * 60), account=account,
        src_host=src, dst_host=dst, kind=kind, dataset=DatasetSource.SYNTHETIC,
        raw_ref=RawRef(file="f", line=n), rule_ids=list(rules),
    )


def assessment(edges, paths=(), choke_points=()):
    return StructuralAssessment(
        incident_id="INC-1", incident_sha256="a" * 64, datasets=[DatasetSource.SYNTHETIC],
        edges=list(edges), paths=list(paths), choke_points=list(choke_points),
        stats=AssessmentStats(
            anchors=0, context_events=0, movement_edges=0, attempt_edges=0, local_edges=0,
            event_graph_nodes=0, event_graph_arcs=0, account_switch_arcs=0, depth_reached=0,
            truncated=False),
        limitations=["Observed logs only."],
    )


def view(a, config=None, principal=A):
    return build_incident_graph(a, detection_config=config or DetectionConfig(),
                                principal_user=principal, time_label=lambda t: t.isoformat())


def links(graph):
    return {k.link_id: k for k in graph.links}


def test_parallel_events_share_one_link_and_keep_every_id():
    graph = view(assessment([edge(2, A, "H1", "H2"), edge(1, A, "H1", "H2")]))
    link = links(graph)["MOVEMENT|host:H1|host:H2"]
    assert link.event_ids == ["E1", "E2"]  # chronological
    assert link.first_seen_label != link.last_seen_label


def test_different_kinds_between_the_same_hosts_stay_separate():
    graph = view(assessment([edge(1, A, "H1", "H2"), edge(2, A, "H1", "H2", EdgeKind.ATTEMPT)]))
    found = links(graph)
    assert found["MOVEMENT|host:H1|host:H2"].event_ids == ["E1"]
    assert found["ATTEMPT|host:H1|host:H2"].event_ids == ["E2"]


def test_failed_attempt_never_links_an_account_to_a_host():
    graph = view(assessment([edge(1, B, "H1", "H2", EdgeKind.ATTEMPT)], ), principal=A)
    assert not [k for k in graph.links if k.kind == "ACCOUNT"]
    user = next(n for n in graph.nodes if n.kind == "user")
    assert user.label == B and user.event_count == 1


def test_account_link_records_both_relations():
    graph = view(assessment([edge(1, A, "H1", "H2"), edge(2, A, "H2", "H3")]))
    found = links(graph)
    assert found["ACCOUNT|user:a@CORP|host:H2"].relations == ["ACTED_FROM", "REACHED"]
    assert found["ACCOUNT|user:a@CORP|host:H1"].relations == ["ACTED_FROM"]
    assert found["ACCOUNT|user:a@CORP|host:H2"].event_ids == ["E1", "E2"]


def test_local_logon_is_a_self_link_on_its_host():
    graph = view(assessment([edge(1, A, "H1", "H1", EdgeKind.LOCAL)]))
    link = links(graph)["LOCAL|host:H1|host:H1"]
    assert link.source == link.target == "host:H1"


def inferred_path(ambiguous):
    hop = HopLink(from_event_id="E1", to_event_id="E2", host="H2", gap_seconds=60,
                  basis=LinkBasis.ACCOUNT_SWITCH, other_accounts_arriving=4 if ambiguous else 0,
                  ambiguous=ambiguous)
    return StructuralPath(
        path_id="P1", kind=PathKind.INFERRED, verdict=Feasibility.CONDITIONALLY_FEASIBLE,
        event_ids=["E1", "E2"], hosts=["H1", "H2", "H3"], accounts=[A, B], links=[hop],
        conditions=["Assumes one party operates both accounts."], reasons=["Observed hops."],
    )


def test_inferred_path_adds_no_edge_and_marks_the_host():
    edges = [edge(1, A, "H1", "H2"), edge(2, B, "H2", "H3")]
    plain = view(assessment(edges))
    graph = view(assessment(edges, [inferred_path(False)]))
    assert [k.link_id for k in graph.links] == [k.link_id for k in plain.links]
    assert graph.paths[0].link_ids == ["MOVEMENT|host:H1|host:H2", "MOVEMENT|host:H2|host:H3"]
    switch = graph.paths[0].switches[0]
    assert switch.host == "H2" and switch.ambiguous is False
    host = next(n for n in graph.nodes if n.label == "H2")
    assert host.roles == ["ACCOUNT_SWITCH"]


def test_ambiguous_switch_is_flagged():
    edges = [edge(1, A, "H1", "H2"), edge(2, B, "H2", "H3")]
    graph = view(assessment(edges, [inferred_path(True)]))
    assert graph.paths[0].ambiguous is True
    host = next(n for n in graph.nodes if n.label == "H2")
    assert "AMBIGUOUS_SWITCH" in host.roles


def test_host_roles_follow_configuration():
    config = DetectionConfig(jump_hosts=["JUMP-.*"], sensitive_host_access={"hosts": ["DB"]},
                             admin_users=[B])
    point = ChokePoint(target_event_id="E2", target_host="DB", entry_hosts=["WS"],
                       via_hosts=["JUMP-1"])
    graph = view(assessment([edge(1, B, "WS", "JUMP-1"), edge(2, B, "JUMP-1", "DB")],
                            choke_points=[point]), config, principal=B)
    roles = {n.label: n.roles for n in graph.nodes}
    assert roles["JUMP-1"] == ["CHOKE_POINT", "JUMP_HOST"]
    assert roles["DB"] == ["SENSITIVE"] and roles["WS"] == []
    assert roles[B] == ["ADMIN", "PRINCIPAL"]


def test_output_is_deterministic():
    edges = [edge(1, A, "H1", "H2"), edge(2, A, "H2", "H3"), edge(3, B, "H3", "H1")]
    forward, backward = view(assessment(edges)), view(assessment(list(reversed(edges))))
    assert forward.nodes == backward.nodes and forward.links == backward.links
