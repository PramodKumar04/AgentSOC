"""SYNTHETIC risk scenarios in LANL `auth.txt` format (Target 3).

Fully deterministic. Every scenario has its own accounts and hosts. Each expected score
is worked out by hand from the published weights and shown in `working`.

Matching these numbers shows the arithmetic and safeguards behave as designed. They are
not calibration, and they say nothing about real-world accuracy.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass

from agentsoc.data_gen.lateral_scenarios import Account, Row, _at, _familiar, _render, _s
from agentsoc.data_gen.scenarios import _line

LOW, MEDIUM, HIGH, CRITICAL = "LOW", "MEDIUM", "HIGH", "CRITICAL"
ADMIN_USERS = ("r13.admin@CORP", "r14.admin@CORP")
SENSITIVE_HOSTS = ("R07-DB", "R08-DB", "R11-DB", "R12-DB", "R14-DB", "R16-DB")
JUMP_HOST_PATTERNS = ("R15-JUMP-.*", "R16-JUMP-.*")


@dataclass(frozen=True)
class RiskExpected:
    principal: str
    score: float  # worked out by hand; before the final rounding to one decimal
    band: str
    severity: str  # detection severity, which must stay visible and unchanged
    destructive_allowed: bool = False


@dataclass(frozen=True)
class RiskScenario:
    key: str
    title: str
    working: str  # the hand calculation
    accounts: tuple[Account, ...]
    rows: tuple[Row, ...]
    expected: RiskExpected


def _acct(number: str, name: str = "user") -> Account:
    return Account(_s(f"{number}.{name}"), f"WS-{number.upper()}-{name.upper()}",
                   (f"SRV-{number.upper()}-{name.upper()}",))


def _walk(user: str, hosts: list[str], hour: int) -> list[Row]:
    return [_line(_at(hour, 5 * k), user, s, d)
            for k, (s, d) in enumerate(itertools.pairwise(hosts))]


def _failures(user: str, ws: str, hour: int, count: int) -> list[Row]:
    return [_line(_at(hour, 0, 15 * k), user, ws, ws, logon="Interactive", outcome="Fail")
            for k in range(count)]


def _credential_only() -> RiskScenario:
    a = _acct("r01")
    rows = [*_failures(a.user, a.workstation, 4, 3),
            _line(_at(4, 2), a.user, a.workstation, a.workstation, logon="Interactive")]
    return RiskScenario(
        "R01", "Credential-only: failures then success, no movement",
        "credential .8 x 15 = 12.0", (a,), tuple(rows),
        RiskExpected(a.user, 12.0, LOW, MEDIUM),
    )


def _burst() -> RiskScenario:
    a = _acct("r02")
    return RiskScenario(
        "R02", "Failure burst only", "credential .5 x 15 = 7.5", (a,),
        tuple(_failures(a.user, a.workstation, 5, 6)),
        RiskExpected(a.user, 7.5, LOW, LOW),
    )


def _star() -> RiskScenario:
    a = _acct("r03")
    rows = [_line(_at(6, 5 * k), a.user, a.workstation, f"R03-N{k}") for k in range(3)]
    return RiskScenario(
        "R03", "Three new servers, no chain: overlapping rules count once",
        "novelty 3/5 x 10 = 6.0", (a,), tuple(rows),
        RiskExpected(a.user, 6.0, LOW, MEDIUM),
    )


def _hops(key: str, count: int, hour: int, score: float, band: str, severity: str,
          working: str) -> RiskScenario:
    a = _acct(key.lower())
    hosts = [a.workstation, *(f"{key}-H{k}" for k in range(count))]
    return RiskScenario(key, f"Observed movement, {count} hops", working, (a,),
                        tuple(_walk(a.user, hosts, hour)),
                        RiskExpected(a.user, score, band, severity))


def _to_sensitive() -> RiskScenario:
    a = _acct("r07")
    return RiskScenario(
        "R07", "Two observed hops ending on a sensitive host",
        "depth .6 x 35 = 21.0; sensitive 1 x 30 = 30.0; total 51.0", (a,),
        tuple(_walk(a.user, [a.workstation, "R07-A", "R07-DB"], 10)),
        RiskExpected(a.user, 51.0, HIGH, CRITICAL, destructive_allowed=True),
    )


def _full_attack() -> RiskScenario:
    a = _acct("r08")
    rows = [*_failures(a.user, a.workstation, 11, 3),
            _line(_at(11, 2), a.user, a.workstation, a.workstation, logon="Interactive"),
            *_walk(a.user, [a.workstation, "R08-A", "R08-B", "R08-DB"], 12)]
    return RiskScenario(
        "R08", "Failures, success, then three hops to a sensitive host",
        "credential 12.0; depth .85 x 35 = 29.75; sensitive 30.0; total 71.75", (a,),
        tuple(rows), RiskExpected(a.user, 71.75, CRITICAL, CRITICAL, destructive_allowed=True),
    )


def _inferred() -> RiskScenario:
    alice, bob = _acct("r09", "alice"), _acct("r09", "bob")
    rows = [_line(_at(13, 0), alice.user, alice.workstation, "R09-HUB"),
            _line(_at(13, 10), bob.user, "R09-HUB", "R09-SRV")]
    return RiskScenario(
        "R09", "Cross-account route: counts less than the same route observed",
        "effective hops 1 + 1 x .5 = 1.5; depth .6 x .5 = .3; .3 x 35 = 10.5", (alice, bob),
        tuple(rows), RiskExpected(bob.user, 10.5, LOW, LOW),
    )


def _ambiguous() -> RiskScenario:
    bob = _acct("r10", "bob")
    others = [_acct("r10", f"u{k}") for k in range(5)]
    rows = [_line(_at(14, k), o.user, o.workstation, "R10-HUB") for k, o in enumerate(others)]
    rows.append(_line(_at(14, 10), bob.user, "R10-HUB", "R10-SRV"))
    return RiskScenario(
        "R10", "Cross-account route through a busy shared server",
        "effective hops 1 + 1 x .2 = 1.2; depth .12; .12 x 35 = 4.2", (bob, *others), tuple(rows),
        RiskExpected(bob.user, 4.2, LOW, LOW),
    )


def _sensitive_inferred() -> RiskScenario:
    alice, bob = _acct("r11", "alice"), _acct("r11", "bob")
    rows = [_line(_at(15, 0), alice.user, alice.workstation, "R11-HUB"),
            _line(_at(15, 10), bob.user, "R11-HUB", "R11-DB")]
    return RiskScenario(
        "R11", "Sensitive host reached only through an inferred link",
        "depth .3 x 35 = 10.5; sensitive .5 x 30 = 15.0; total 25.5", (alice, bob), tuple(rows),
        RiskExpected(alice.user, 25.5, MEDIUM, LOW),
    )


def _sensitive_ambiguous() -> RiskScenario:
    alice, bob = _acct("r12", "alice"), _acct("r12", "bob")
    others = [_acct("r12", f"u{k}") for k in range(4)]
    rows = [_line(_at(16, 0), alice.user, alice.workstation, "R12-HUB")]
    rows += [_line(_at(16, 1 + k), o.user, o.workstation, "R12-HUB") for k, o in enumerate(others)]
    rows.append(_line(_at(16, 10), bob.user, "R12-HUB", "R12-DB"))
    return RiskScenario(
        "R12", "Sensitive host reached only through an ambiguous link",
        "depth .12 x 35 = 4.2; sensitive .2 x 30 = 6.0; total 10.2", (alice, bob, *others),
        tuple(rows), RiskExpected(alice.user, 10.2, LOW, LOW),
    )


def _admin() -> RiskScenario:
    a = _acct("r13", "admin")
    return RiskScenario(
        "R13", "Configured admin, two hops, nothing sensitive",
        "depth 21.0 x admin .85 = 17.85", (a,),
        tuple(_walk(a.user, [a.workstation, "R13-A", "R13-B"], 17)),
        RiskExpected(a.user, 17.85, LOW, MEDIUM),
    )


def _admin_sensitive() -> RiskScenario:
    a = _acct("r14", "admin")
    return RiskScenario(
        "R14", "Configured admin reaches a sensitive host: no reduction",
        "21.0 + 30.0 = 51.0", (a,),
        tuple(_walk(a.user, [a.workstation, "R14-A", "R14-DB"], 18)),
        RiskExpected(a.user, 51.0, HIGH, HIGH, destructive_allowed=True),
    )


def _jump() -> RiskScenario:
    a = _acct("r15")
    return RiskScenario(
        "R15", "Route only through a configured jump host",
        "depth .6 x jump .85 = .51; .51 x 35 = 17.85", (a,),
        tuple(_walk(a.user, [a.workstation, "R15-JUMP-1", "R15-SRV"], 19)),
        RiskExpected(a.user, 17.85, LOW, MEDIUM),
    )


def _jump_sensitive() -> RiskScenario:
    a = _acct("r16")
    return RiskScenario(
        "R16", "Jump host, but the route ends on a sensitive host: no reduction",
        "21.0 + 30.0 = 51.0", (a,),
        tuple(_walk(a.user, [a.workstation, "R16-JUMP-1", "R16-DB"], 20)),
        RiskExpected(a.user, 51.0, HIGH, CRITICAL, destructive_allowed=True),
    )


def _breadth() -> RiskScenario:
    a = _acct("r17")
    rows = [_line(_at(21, 0), a.user, a.workstation, "R17-A"),
            _line(_at(21, 5), a.user, "R17-A", "R17-B"),
            _line(_at(21, 6), a.user, "R17-A", "R17-C")]
    return RiskScenario(
        "R17", "Route plus a connected branch: branch counted once, as breadth",
        "depth 21.0; breadth 1/4 x 10 = 2.5; total 23.5", (a,), tuple(rows),
        RiskExpected(a.user, 23.5, MEDIUM, HIGH),
    )


def _no_baseline() -> RiskScenario:
    user, ws = _s("r18.new"), "WS-R18"
    rows = [*_failures(user, ws, 22, 3), _line(_at(22, 2), user, ws, "R18-A"),
            _line(_at(22, 7), user, "R18-A", "R18-B")]
    return RiskScenario(
        "R18", "No baseline: confidence falls, risk does not rise",
        "credential 12.0; depth 21.0; total 33.0", (), tuple(rows),
        RiskExpected(user, 33.0, MEDIUM, MEDIUM),
    )


def _duplicates() -> RiskScenario:
    a = _acct("r19")
    hops = _walk(a.user, [a.workstation, "R19-A", "R19-B"], 23)
    return RiskScenario(
        "R19", "Every event recorded twice: the score does not move",
        "same as two hops: 21.0", (a,), tuple(hops + hops),
        RiskExpected(a.user, 21.0, MEDIUM, HIGH),
    )


SCENARIOS: tuple[RiskScenario, ...] = (
    _credential_only(), _burst(), _star(),
    _hops("R04", 2, 7, 21.0, MEDIUM, HIGH, "depth .6 x 35 = 21.0"),
    _hops("R05", 3, 8, 29.75, MEDIUM, HIGH, "depth .85 x 35 = 29.75"),
    _hops("R06", 5, 9, 37.5, MEDIUM, HIGH,
          "four hops saturate depth at 35.0; the fifth counts once as breadth, 1/4 x 10 = 2.5"),
    _to_sensitive(), _full_attack(), _inferred(), _ambiguous(), _sensitive_inferred(),
    _sensitive_ambiguous(), _admin(), _admin_sensitive(), _jump(), _jump_sensitive(), _breadth(),
    _no_baseline(), _duplicates(),
)


def generate_risk_scenario_text() -> str:
    rows: list[Row] = []
    for scenario in SCENARIOS:
        for account in scenario.accounts:
            rows += _familiar(account)
        rows += scenario.rows
    return _render(rows)
