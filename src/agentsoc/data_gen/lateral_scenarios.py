"""SYNTHETIC lateral-movement scenarios in LANL `auth.txt` format (Target 1).

Fully deterministic. Every scenario has its own accounts and hosts, so scenarios
cannot influence each other, and states its expected outcome here, written by
hand before the detection code ran. The demo file in `scenarios.py` is separate
and unchanged.

Names imitate an enterprise; none refer to real people or systems. Matching these
expectations shows the rules behave as designed; it says nothing about real-world
detection accuracy.
"""

from __future__ import annotations

import itertools
from collections.abc import Mapping
from dataclasses import dataclass, field

from agentsoc.data_gen.scenarios import _line, _t

BASELINE_DAYS = (0, 1)
SCENARIO_DAY = 3
LOW, MEDIUM, HIGH, CRITICAL = "LOW", "MEDIUM", "HIGH", "CRITICAL"

Row = tuple[int, str]


@dataclass(frozen=True)
class Account:
    user: str
    workstation: str
    servers: tuple[str, ...] = ()


@dataclass(frozen=True)
class Expected:
    """Accounts not listed in `findings` must produce no findings at all."""

    findings: Mapping[str, Mapping[str, int]] = field(default_factory=dict)
    severity: Mapping[str, str] = field(default_factory=dict)
    chain_paths: tuple[str, ...] = ()
    pivots: tuple[tuple[str, str, str], ...] = ()  # (departing, arriving, host)
    benign_context: tuple[str, ...] = ()  # accounts with a benign_context finding
    severity_adjusted: tuple[str, ...] = ()  # accounts with a severity_adjustment finding
    without_baseline: tuple[str, ...] = ()
    collapsed_duplicates: int = 0


@dataclass(frozen=True)
class Scenario:
    key: str
    title: str
    accounts: tuple[Account, ...]
    rows: tuple[Row, ...]
    expected: Expected
    case: str  # the numbered test case from the Target 1 brief, or "extra"


def _familiar(account: Account) -> list[Row]:
    """Routine baseline activity: a local logon, then the account's usual servers."""
    out = []
    for day in BASELINE_DAYS:
        out.append(_line(_t(day, 9), account.user, account.workstation, account.workstation,
                         logon="Interactive"))
        for k, server in enumerate(account.servers):
            out.append(_line(_t(day, 10, k), account.user, account.workstation, server))
    return out


def _at(hour: int, minute: int = 0, second: int = 0) -> int:
    return _t(SCENARIO_DAY, hour, minute, second)


def _s(user: str, domain: str = "CORP") -> str:
    return f"{user}@{domain}"


def _rule(*pairs: tuple[str, int]) -> dict[str, int]:
    return dict(pairs)


def _normal() -> Scenario:
    a = Account(_s("s01.user"), "WS-S01", ("SRV-S01-A",))
    rows = [_line(_at(4, k), a.user, a.workstation, "SRV-S01-A") for k in range(10)]
    return Scenario("S01", "Normal repeated access to a familiar server", (a,), tuple(rows),
                    Expected(), case="1")


def _spread() -> Scenario:
    a = Account(_s("s02.user"), "WS-S02", ("SRV-S02-A",))
    rows = [_line(_at(5, 5 * k), a.user, a.workstation, f"S02-NEW-{k}") for k in range(3)]
    return Scenario(
        "S02", "One workstation reaching three new servers (a star, not a chain)", (a,),
        tuple(rows),
        Expected(findings={a.user: _rule(("NEW_DST_HOST", 3), ("MULTI_HOST_SPREAD", 1))},
                 severity={a.user: MEDIUM}),
        case="2",
    )


def _multi_hop() -> Scenario:
    a = Account(_s("s03.user"), "WS-S03", ("SRV-S03-A",))
    path = [a.workstation, "S03-A", "S03-B", "S03-C"]
    rows = [_line(_at(6, 5 * k), a.user, src, dst)
            for k, (src, dst) in enumerate(itertools.pairwise(path))]
    return Scenario(
        "S03", "Three-hop movement through previously unseen hosts", (a,), tuple(rows),
        Expected(
            findings={a.user: _rule(("NEW_DST_HOST", 3), ("NEW_SRC_HOST", 2),
                                    ("MULTI_HOST_SPREAD", 1), ("LATERAL_CHAIN", 1))},
            severity={a.user: HIGH},
            chain_paths=("WS-S03 > S03-A > S03-B > S03-C",),
        ),
        case="3",
    )


def _fail_then_success() -> Scenario:
    a = Account(_s("s04.user"), "WS-S04", ("SRV-S04-A",))
    ws = a.workstation
    rows = [_line(_at(7, 0, 20 * k), a.user, ws, ws, logon="Interactive", outcome="Fail")
            for k in range(3)]
    rows += [
        _line(_at(7, 2), a.user, ws, ws, logon="Interactive"),
        _line(_at(7, 5), a.user, ws, "S04-A"),
        # A FAILED second hop must not extend movement.
        _line(_at(7, 10), a.user, "S04-A", "S04-B", outcome="Fail"),
    ]
    return Scenario(
        "S04", "Failures, a success, then a failed onward hop (no movement edge)", (a,),
        tuple(rows),
        Expected(findings={a.user: _rule(("FAIL_THEN_SUCCESS", 1), ("NEW_DST_HOST", 1))},
                 severity={a.user: MEDIUM}),
        case="4",
    )


def _disconnected() -> Scenario:
    a = Account(_s("s05.gap"), "WS-S05A", ("SRV-S05-A",))
    b = Account(_s("s05.late"), "WS-S05B", ("SRV-S05-B",))
    rows = [
        # Consecutive logons that do not share a host: no continuous path.
        _line(_at(8, 0), a.user, a.workstation, "S05-A"),
        _line(_at(8, 5), a.user, "S05-B", "S05-C"),
        # Connected hosts, but 1,801 s apart (limit is 1,800 s).
        _line(_at(9, 0), b.user, b.workstation, "S05-D"),
        _line(_at(9, 0) + 1801, b.user, "S05-D", "S05-E"),
    ]
    expected_rules = _rule(("NEW_DST_HOST", 2), ("NEW_SRC_HOST", 1))
    return Scenario(
        "S05", "Disconnected host sequences (no shared host; hop gap over the limit)", (a, b),
        tuple(rows),
        Expected(findings={a.user: expected_rules, b.user: expected_rules},
                 severity={a.user: LOW, b.user: LOW}),
        case="5",
    )


def _cycle() -> Scenario:
    a = Account(_s("s06.user"), "WS-S06", ("SRV-S06-A",))
    rows = [
        _line(_at(10, 0), a.user, a.workstation, "S06-A"),
        _line(_at(10, 5), a.user, "S06-A", "S06-B"),
        _line(_at(10, 10), a.user, "S06-B", "S06-A"),  # revisits a host: the chain stops
    ]
    return Scenario(
        "S06", "Cyclic authentication (a revisited host ends the chain)", (a,), tuple(rows),
        Expected(
            findings={a.user: _rule(("NEW_DST_HOST", 2), ("NEW_SRC_HOST", 2),
                                    ("LATERAL_CHAIN", 1))},
            severity={a.user: HIGH},
            chain_paths=("WS-S06 > S06-A > S06-B",),
        ),
        case="6",
    )


def _privileged_sensitive() -> Scenario:
    a = Account(_s("s07.admin"), "WS-S07", ("SRV-S07-A",))
    rows = [_line(_at(11), a.user, a.workstation, "S07-DB")]
    return Scenario(
        "S07", "Configured admin account reaches a configured sensitive host", (a,), tuple(rows),
        Expected(findings={a.user: _rule(("NEW_DST_HOST", 1), ("SENSITIVE_HOST_ACCESS", 1))},
                 severity={a.user: LOW}),  # MEDIUM by points, lowered for a configured admin
        case="7",
    )


def _jump_host() -> Scenario:
    admin = Account(_s("s08.admin"), "WS-S08A", ("SRV-S08-A",))
    ops = Account(_s("s08.ops"), "WS-S08B", ("SRV-S08-B",))
    rows = [
        _line(_at(12, 0), admin.user, admin.workstation, "S08-JUMP-1"),
        _line(_at(12, 5), admin.user, "S08-JUMP-1", "S08-SRV"),
        # Same shape, but ending on a sensitive host: context is added, never a reduction.
        _line(_at(13, 0), ops.user, ops.workstation, "S08-JUMP-2"),
        _line(_at(13, 5), ops.user, "S08-JUMP-2", "S08-DB"),
    ]
    return Scenario(
        "S08", "Legitimate administrative movement through configured jump hosts", (admin, ops),
        tuple(rows),
        Expected(
            findings={
                admin.user: _rule(("NEW_DST_HOST", 2), ("NEW_SRC_HOST", 1), ("LATERAL_CHAIN", 1)),
                ops.user: _rule(("NEW_DST_HOST", 2), ("NEW_SRC_HOST", 1), ("LATERAL_CHAIN", 1),
                                ("SENSITIVE_HOST_ACCESS", 1)),
            },
            severity={admin.user: LOW, ops.user: CRITICAL},
            chain_paths=("WS-S08A > S08-JUMP-1 > S08-SRV", "WS-S08B > S08-JUMP-2 > S08-DB"),
            benign_context=(admin.user, ops.user),
            severity_adjusted=(admin.user,),
        ),
        case="8",
    )


def _duplicates() -> Scenario:
    a = Account(_s("s09.user"), "WS-S09", ("SRV-S09-A",))
    hops = [
        _line(_at(14, 0), a.user, a.workstation, "S09-A"),
        _line(_at(14, 5), a.user, "S09-A", "S09-B"),
    ]
    return Scenario(
        "S09", "Every hop recorded twice (exact duplicates collapse)", (a,),
        tuple(hops + hops),
        Expected(
            findings={a.user: _rule(("NEW_DST_HOST", 2), ("NEW_SRC_HOST", 1),
                                    ("LATERAL_CHAIN", 1))},
            severity={a.user: HIGH},
            chain_paths=("WS-S09 > S09-A > S09-B",),
            collapsed_duplicates=2,
        ),
        case="9",
    )


def _pivot() -> Scenario:
    arriving = Account(_s("s10.alice"), "WS-S10A", ("SRV-S10-A",))
    departing = Account(_s("s10.bob"), "WS-S10B", ("SRV-S10-B",))
    rows = [
        _line(_at(15, 0), arriving.user, arriving.workstation, "S10-HUB"),
        _line(_at(15, 10), departing.user, "S10-HUB", "S10-SRV"),
    ]
    return Scenario(
        "S10", "Cross-account pivot: one account arrives, another departs the same host",
        (arriving, departing), tuple(rows),
        Expected(
            findings={
                arriving.user: _rule(("NEW_DST_HOST", 1)),
                departing.user: _rule(("NEW_SRC_HOST", 1), ("NEW_DST_HOST", 1),
                                      ("CROSS_ACCOUNT_PIVOT", 1)),
            },
            severity={arriving.user: LOW, departing.user: LOW},
            pivots=((departing.user, arriving.user, "S10-HUB"),),
        ),
        case="extra",
    )


def _no_pivot_explained() -> Scenario:
    other = Account(_s("s11.other"), "WS-S11A", ("SRV-S11-A",))
    service = Account(_s("s11.svc"), "S11-HUB", ("S11-SRV",))  # routinely acts from the hub
    walker = Account(_s("s11.walk"), "WS-S11C", ("SRV-S11-C",))
    rows = [
        _line(_at(16, 0), other.user, other.workstation, "S11-HUB"),
        _line(_at(16, 5), service.user, "S11-HUB", "S11-SRV"),  # familiar source: not first-seen
        _line(_at(16, 6), walker.user, walker.workstation, "S11-HUB"),
        _line(_at(16, 7), walker.user, "S11-HUB", "S11-SRV2"),  # arrived there itself
    ]
    return Scenario(
        "S11", "Departures already explained: a familiar source, or the account's own arrival",
        (other, service, walker), tuple(rows),
        Expected(
            findings={
                other.user: _rule(("NEW_DST_HOST", 1)),
                walker.user: _rule(("NEW_DST_HOST", 2), ("NEW_SRC_HOST", 1),
                                   ("LATERAL_CHAIN", 1)),
            },
            severity={other.user: LOW, walker.user: HIGH},
            chain_paths=("WS-S11C > S11-HUB > S11-SRV2",),
        ),
        case="extra",
    )


def _same_person_two_domains() -> Scenario:
    corp = Account(_s("s12.user"), "WS-S12A", ("SRV-S12-A",))
    branch = Account(_s("s12.user", "BRANCH"), "WS-S12B", ("SRV-S12-B",))
    rows = [
        _line(_at(17, 0), corp.user, corp.workstation, "S12-HUB"),
        _line(_at(17, 5), branch.user, "S12-HUB", "S12-SRV"),
    ]
    return Scenario(
        "S12", "Same account name under two domains is not a cross-account pivot",
        (corp, branch), tuple(rows),
        Expected(
            findings={
                corp.user: _rule(("NEW_DST_HOST", 1)),
                branch.user: _rule(("NEW_SRC_HOST", 1), ("NEW_DST_HOST", 1)),
            },
            severity={corp.user: LOW, branch.user: LOW},
        ),
        case="extra",
    )


def _missing_baseline() -> Scenario:
    user = _s("s13.new")
    rows = [
        _line(_at(18, 0), user, "WS-S13", "S13-A"),
        _line(_at(18, 5), user, "S13-A", "S13-B"),
    ]
    # Deliberately no Account: this user has no activity in the baseline window.
    return Scenario(
        "S13", "An account with no baseline is not evaluated by novelty rules", (), tuple(rows),
        Expected(without_baseline=(user,)), case="extra",
    )


def _failed_arrival() -> Scenario:
    arriving = Account(_s("s14.alice"), "WS-S14A", ("SRV-S14-A",))
    departing = Account(_s("s14.bob"), "WS-S14B", ("SRV-S14-B",))
    rows = [
        _line(_at(19, 0), arriving.user, arriving.workstation, "S14-HUB", outcome="Fail"),
        _line(_at(19, 5), departing.user, "S14-HUB", "S14-SRV"),
    ]
    return Scenario(
        "S14", "A FAILED arrival does not place another account on the host",
        (arriving, departing), tuple(rows),
        Expected(findings={departing.user: _rule(("NEW_SRC_HOST", 1), ("NEW_DST_HOST", 1))},
                 severity={departing.user: LOW}),
        case="extra",
    )


def _pivot_on_jump_host() -> Scenario:
    arriving = Account(_s("s15.alice"), "WS-S15A", ("SRV-S15-A",))
    departing = Account(_s("s15.bob"), "WS-S15B", ("SRV-S15-B",))
    rows = [
        _line(_at(20, 0), arriving.user, arriving.workstation, "S15-JUMP-1"),
        _line(_at(20, 5), departing.user, "S15-JUMP-1", "S15-SRV"),
    ]
    return Scenario(
        "S15", "Cross-account pivot on a configured jump host is kept, with context",
        (arriving, departing), tuple(rows),
        Expected(
            findings={
                arriving.user: _rule(("NEW_DST_HOST", 1)),
                departing.user: _rule(("NEW_SRC_HOST", 1), ("NEW_DST_HOST", 1),
                                      ("CROSS_ACCOUNT_PIVOT", 1)),
            },
            severity={arriving.user: LOW, departing.user: LOW},
            pivots=((departing.user, arriving.user, "S15-JUMP-1"),),
            benign_context=(departing.user,),
        ),
        case="8",
    )


SCENARIOS: tuple[Scenario, ...] = (
    _normal(), _spread(), _multi_hop(), _fail_then_success(), _disconnected(), _cycle(),
    _privileged_sensitive(), _jump_host(), _duplicates(), _pivot(), _no_pivot_explained(),
    _same_person_two_domains(), _missing_baseline(), _failed_arrival(), _pivot_on_jump_host(),
)


def _render(rows: list[Row]) -> str:
    rows.sort(key=lambda row: row[0])  # stable: equal times keep insertion order
    return "".join(line + "\n" for _, line in rows)


def generate_lateral_scenario_text() -> str:
    """Return the LANL-format file content (sorted by time, stable, '\\n' endings)."""
    rows: list[Row] = []
    for scenario in SCENARIOS:
        for account in scenario.accounts:
            rows += _familiar(account)
        rows += scenario.rows
    return _render(rows)


def generate_large_batch_text(accounts: int, *, repeats: int = 20) -> tuple[str, int, int]:
    """Case 10: a large SYNTHETIC batch for scale tests.

    Returns (text, expected LATERAL_CHAIN findings, expected CROSS_ACCOUNT_PIVOT findings).
    All accounts share one server, the worst case for cross-account lookups. Every 50th
    account walks through it; the next one departs from it without having arrived.
    """
    rows: list[Row] = []
    hub = "BULK-HUB"
    chains = pivots = 0
    for n in range(accounts):
        user, ws = _s(f"bulk.{n:06d}"), f"BULK-WS-{n:06d}"
        second = n % 60
        for day in BASELINE_DAYS:
            rows.append(_line(_t(day, 9, n // 60 % 60, second), user, ws, ws, logon="Interactive"))
            rows.append(_line(_t(day, 10, n // 60 % 60, second), user, ws, hub))
        if n % 50 == 1:
            rows.append(_line(_at(9, 26, second), user, hub, f"BULK-APP-{n:06d}"))
            pivots += 1
            continue
        rows += [_line(_at(9, k % 20, second), user, ws, hub) for k in range(repeats)]
        if n % 50 == 0:
            rows.append(_line(_at(9, 25, second), user, ws, hub))
            rows.append(_line(_at(9, 26, second), user, hub, f"BULK-APP-{n:06d}"))
            chains += 1
    return _render(rows), chains, pivots
