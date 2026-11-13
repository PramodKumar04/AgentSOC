"""SYNTHETIC structural scenarios in LANL `auth.txt` format (Target 2).

Fully deterministic. Every scenario has its own accounts and hosts and states its
expected structural outcome here, written by hand. Several are built so the detection
rules see less than the graph does: an event no rule cites, an order the rules do not
check, or a link only a failed attempt would have made.

Names imitate an enterprise; none refer to real people or systems. Matching these
expectations shows the SSE behaves as designed; it says nothing about real-world accuracy.
"""

from __future__ import annotations

import itertools
from collections.abc import Mapping
from dataclasses import dataclass, field

from agentsoc.data_gen.lateral_scenarios import Account, Row, _at, _familiar, _render, _s
from agentsoc.data_gen.scenarios import _line, _t

OBSERVED, INFERRED = "OBSERVED", "INFERRED"
FEASIBLE, CONDITIONAL, INFEASIBLE = "FEASIBLE", "CONDITIONALLY_FEASIBLE", "INFEASIBLE"
CHAIN, PIVOT = "LATERAL_CHAIN", "CROSS_ACCOUNT_PIVOT"
BASELINE_END = _t(2, 9)  # the earliest event is day 0 09:00, and the baseline is 2 days


@dataclass(frozen=True)
class ExpectedPath:
    kind: str
    verdict: str
    hosts: tuple[str, ...]
    context_events: int = 0
    ambiguous: bool = False


@dataclass(frozen=True)
class StructuralExpected:
    """`principal` is the incident checked; None means no incident at all is expected."""

    principal: str | None = None
    paths: tuple[ExpectedPath, ...] = ()  # must all be present
    forbidden_walks: tuple[tuple[str, ...], ...] = ()  # must not appear on any path
    finding_verdicts: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    extended_rules: tuple[str, ...] = ()
    disconnected: Mapping[str, int] = field(default_factory=dict)
    choke_via: tuple[str, ...] = ()
    cyclic_hosts: tuple[str, ...] = ()
    account_bridge: bool = False
    failed_anchors: int = 0
    duplicate_edges: int = 0


@dataclass(frozen=True)
class StructuralScenario:
    key: str
    title: str
    case: str  # the numbered test case from the Target 2 brief, or "beyond rules"
    accounts: tuple[Account, ...]
    rows: tuple[Row, ...]
    expected: StructuralExpected
    beyond_naive: str | None = None  # what a findings-to-edges graph cannot show


def _account(number: str, name: str = "user") -> Account:
    return Account(_s(f"{number}.{name}"), f"WS-{number.upper()}-{name.upper()}",
                   (f"SRV-{number.upper()}-{name.upper()}",))


def _normal() -> StructuralScenario:
    a = _account("t01")
    rows = [_line(_at(4, k), a.user, a.workstation, a.servers[0]) for k in range(5)]
    return StructuralScenario("T01", "Normal repeated access: no incident to assess", "1", (a,),
                              tuple(rows), StructuralExpected())


def _single_hop() -> StructuralScenario:
    a = _account("t02")
    rows = [_line(_at(5), a.user, a.workstation, "T02-A")]
    return StructuralScenario(
        "T02", "Single-hop movement", "2", (a,), tuple(rows),
        StructuralExpected(a.user, paths=(
            ExpectedPath(OBSERVED, FEASIBLE, (a.workstation, "T02-A")),)),
    )


def _multi_hop() -> StructuralScenario:
    a = _account("t03")
    walk = [a.workstation, "T03-A", "T03-B", "T03-C"]
    rows = [_line(_at(6, 5 * k), a.user, s, d)
            for k, (s, d) in enumerate(itertools.pairwise(walk))]
    return StructuralScenario(
        "T03", "Multi-hop movement confirmed edge by edge", "3", (a,), tuple(rows),
        StructuralExpected(
            a.user, paths=(ExpectedPath(OBSERVED, FEASIBLE, tuple(walk)),),
            finding_verdicts={CHAIN: (FEASIBLE,)},
        ),
    )


def _pivot() -> StructuralScenario:
    alice, bob = _account("t04", "alice"), _account("t04", "bob")
    rows = [
        _line(_at(7, 0), alice.user, alice.workstation, "T04-HUB"),
        _line(_at(7, 10), bob.user, "T04-HUB", "T04-SRV"),
    ]
    return StructuralScenario(
        "T04", "Cross-account pivot: conditional, never an observed path", "4", (alice, bob),
        tuple(rows),
        StructuralExpected(
            bob.user,
            paths=(ExpectedPath(INFERRED, CONDITIONAL,
                                (alice.workstation, "T04-HUB", "T04-SRV")),),
            finding_verdicts={PIVOT: (CONDITIONAL,)},
        ),
    )


def _pivot_upstream() -> StructuralScenario:
    alice = Account(_s("t05.alice"), "WS-T05-ALICE", ("T05-X",))
    bob = _account("t05", "bob")
    rows = [
        _line(_at(8, 0), alice.user, alice.workstation, "T05-X"),
        _line(_at(8, 5), alice.user, "T05-X", "T05-HUB"),
        _line(_at(8, 10), bob.user, "T05-HUB", "T05-SRV"),
    ]
    return StructuralScenario(
        "T05", "Cross-account path extended upstream through an event no rule cites here",
        "beyond rules", (alice, bob), tuple(rows),
        StructuralExpected(
            bob.user,
            paths=(ExpectedPath(INFERRED, CONDITIONAL,
                                (alice.workstation, "T05-X", "T05-HUB", "T05-SRV"),
                                context_events=1),),
            finding_verdicts={PIVOT: (CONDITIONAL,)}, extended_rules=(PIVOT,),
        ),
        beyond_naive="Sees only the pivot's two events, so it misses the upstream hop.",
    )


def _upstream_baseline() -> StructuralScenario:
    a = Account(_s("t06.user"), "WS-T06", ("SRV-T06",))
    rows = [
        _line(BASELINE_END - 60, a.user, a.workstation, "T06-A"),  # inside the baseline
        _line(BASELINE_END + 60, a.user, "T06-A", "T06-B"),
    ]
    return StructuralScenario(
        "T06", "Upstream hop inside the baseline window, invisible to the chain rule",
        "beyond rules", (a,), tuple(rows),
        StructuralExpected(
            a.user, paths=(ExpectedPath(OBSERVED, FEASIBLE, (a.workstation, "T06-A", "T06-B"),
                                        context_events=1),),
        ),
        beyond_naive="Sees one cited hop; the graph recovers the observed upstream hop.",
    )


def _downstream_no_baseline() -> StructuralScenario:
    user = _s("t07.new")
    ws = "WS-T07"
    rows = [_line(_at(9, 0, 20 * k), user, ws, ws, logon="Interactive", outcome="Fail")
            for k in range(3)]
    rows += [
        _line(_at(9, 2), user, ws, "T07-A"),
        _line(_at(9, 7), user, "T07-A", "T07-B"),  # no baseline: no novelty rule cites this
    ]
    return StructuralScenario(
        "T07", "Downstream hop no rule can cite (no baseline for the account)", "beyond rules",
        (), tuple(rows),
        StructuralExpected(
            user, paths=(ExpectedPath(OBSERVED, FEASIBLE, (ws, "T07-A", "T07-B"),
                                      context_events=1),),
            failed_anchors=3,
        ),
        beyond_naive="Sees the failures and one hop; the graph follows the account onward.",
    )


def _failed_link() -> StructuralScenario:
    a = _account("t08")
    rows = [
        _line(_at(10, 0), a.user, a.workstation, "T08-A"),
        _line(_at(10, 5), a.user, "T08-A", "T08-B", outcome="Fail"),
        _line(_at(10, 10), a.user, "T08-B", "T08-C"),
    ]
    return StructuralScenario(
        "T08", "Failed authentication is the only link: no movement path", "7", (a,), tuple(rows),
        StructuralExpected(
            a.user,
            forbidden_walks=(("T08-A", "T08-B"),),
            disconnected={"FAILED_LINK_ONLY": 1},
        ),
        beyond_naive="Cannot say why the events do not connect.",
    )


def _no_shared_host() -> StructuralScenario:
    a = _account("t09")
    rows = [
        _line(_at(11, 0), a.user, a.workstation, "T09-A"),
        _line(_at(11, 5), a.user, "T09-B", "T09-C"),
    ]
    return StructuralScenario(
        "T09", "Disconnected hosts: same account, no shared host", "5", (a,), tuple(rows),
        StructuralExpected(a.user, disconnected={"NO_SHARED_HOST": 1}, account_bridge=True),
    )


def _time_order() -> StructuralScenario:
    a = _account("t10")
    rows = [
        _line(_at(12, 0), a.user, "T10-B", "T10-C"),
        _line(_at(12, 5), a.user, a.workstation, "T10-B"),
    ]
    return StructuralScenario(
        "T10", "Hosts connect but time does not: a host-only graph would be wrong",
        "beyond rules", (a,), tuple(rows),
        StructuralExpected(
            a.user,
            forbidden_walks=((a.workstation, "T10-B", "T10-C"),),
            disconnected={"TIME_ORDER": 1},
        ),
        beyond_naive="Reports a path that the event times rule out.",
    )


def _gap() -> StructuralScenario:
    a = _account("t11")
    rows = [
        _line(_at(13, 0), a.user, a.workstation, "T11-A"),
        _line(_at(13, 0) + 1801, a.user, "T11-A", "T11-B"),
    ]
    return StructuralScenario(
        "T11", "Connected hosts one second past the link limit", "5", (a,), tuple(rows),
        StructuralExpected(
            a.user,
            forbidden_walks=((a.workstation, "T11-A", "T11-B"),),
            disconnected={"GAP_EXCEEDED": 1},
        ),
        beyond_naive="Reports a path the link limit rules out.",
    )


def _cycle() -> StructuralScenario:
    a = _account("t12")
    walk = [a.workstation, "T12-A", "T12-B", "T12-A", "T12-C"]
    rows = [_line(_at(14, 5 * k), a.user, s, d)
            for k, (s, d) in enumerate(itertools.pairwise(walk))]
    return StructuralScenario(
        "T12", "Cyclic path: one walk through a revisited host", "6", (a,), tuple(rows),
        StructuralExpected(
            a.user, paths=(ExpectedPath(OBSERVED, FEASIBLE, tuple(walk)),),
            finding_verdicts={CHAIN: (FEASIBLE, FEASIBLE)}, extended_rules=(CHAIN,),
            cyclic_hosts=("T12-A", "T12-B"),
        ),
        beyond_naive="Simple-path search drops the revisit and under-counts the walk.",
    )


def _duplicates() -> StructuralScenario:
    a = _account("t13")
    hops = [
        _line(_at(15, 0), a.user, a.workstation, "T13-A"),
        _line(_at(15, 5), a.user, "T13-A", "T13-B"),
    ]
    return StructuralScenario(
        "T13", "Duplicate events collapse to one edge that keeps both IDs", "8", (a,),
        tuple(hops + hops),
        StructuralExpected(
            a.user, paths=(ExpectedPath(OBSERVED, FEASIBLE, (a.workstation, "T13-A", "T13-B")),),
            finding_verdicts={CHAIN: (FEASIBLE,)}, duplicate_edges=2,
        ),
    )


def _shared_server() -> StructuralScenario:
    bob = _account("t14", "bob")
    others = [_account("t14", f"u{k}") for k in range(5)]
    rows = [_line(_at(16, k), o.user, o.workstation, "T14-HUB") for k, o in enumerate(others)]
    rows.append(_line(_at(16, 10), bob.user, "T14-HUB", "T14-SRV"))
    return StructuralScenario(
        "T14", "Busy shared server: the cross-account link is flagged weak", "beyond rules",
        (bob, *others), tuple(rows),
        StructuralExpected(
            bob.user,
            paths=(ExpectedPath(INFERRED, CONDITIONAL,
                                (others[-1].workstation, "T14-HUB", "T14-SRV"),
                                ambiguous=True),),
            finding_verdicts={PIVOT: (CONDITIONAL,)},
        ),
        beyond_naive="Treats a link through a busy server like any other edge.",
    )


def _same_second() -> StructuralScenario:
    a = _account("t15")
    rows = [
        _line(_at(17), a.user, a.workstation, "T15-A"),
        _line(_at(17), a.user, "T15-A", "T15-B"),
    ]
    return StructuralScenario(
        "T15", "Chain hops in one second: the order cannot be established", "beyond rules", (a,),
        tuple(rows),
        StructuralExpected(
            a.user, forbidden_walks=((a.workstation, "T15-A", "T15-B"),),
            finding_verdicts={CHAIN: (CONDITIONAL,)}, disconnected={"TIME_ORDER": 1},
        ),
        beyond_naive="Accepts the chain as fully established.",
    )


def _choke() -> StructuralScenario:
    a = _account("t16")
    rows = [
        _line(_at(18, 0), a.user, a.workstation, "T16-HUB"),
        _line(_at(18, 1), a.user, "T16-WS2", "T16-HUB"),
        _line(_at(18, 5), a.user, "T16-HUB", "T16-MID"),
        _line(_at(18, 10), a.user, "T16-MID", "T16-END"),
    ]
    return StructuralScenario(
        "T16", "Two entry routes that must pass through the same hosts", "beyond rules", (a,),
        tuple(rows),
        StructuralExpected(
            a.user,
            paths=(ExpectedPath(OBSERVED, FEASIBLE,
                                (a.workstation, "T16-HUB", "T16-MID", "T16-END")),
                   ExpectedPath(OBSERVED, FEASIBLE,
                                ("T16-WS2", "T16-HUB", "T16-MID", "T16-END")),),
            finding_verdicts={CHAIN: (FEASIBLE,)},  # the rule reports one of the two routes
            choke_via=("T16-HUB", "T16-MID"),
        ),
        beyond_naive="Has no notion of hosts that every route must cross.",
    )


def _failure_only() -> StructuralScenario:
    a = _account("t17")
    rows = [_line(_at(19, 0, 10 * k), a.user, a.workstation, "T17-SRV", outcome="Fail")
            for k in range(6)]
    return StructuralScenario(
        "T17", "Failures only: an incident with no movement at all", "7", (a,), tuple(rows),
        StructuralExpected(a.user, failed_anchors=6),
    )


SCENARIOS: tuple[StructuralScenario, ...] = (
    _normal(), _single_hop(), _multi_hop(), _pivot(), _pivot_upstream(), _upstream_baseline(),
    _downstream_no_baseline(), _failed_link(), _no_shared_host(), _time_order(), _gap(), _cycle(),
    _duplicates(), _shared_server(), _same_second(), _choke(), _failure_only(),
)


def generate_structural_scenario_text() -> str:
    rows: list[Row] = []
    for scenario in SCENARIOS:
        for account in scenario.accounts:
            rows += _familiar(account)
        rows += scenario.rows
    return _render(rows)
