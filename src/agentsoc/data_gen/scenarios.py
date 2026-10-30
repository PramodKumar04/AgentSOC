"""SYNTHETIC authentication scenarios in LANL `auth.txt` format.

Fully deterministic (no randomness). Four days of routine activity for five
accounts; scenarios on day 3:

  A  alice.fin  6 failures on an unfamiliar workstation, success, then
                WS-FIN-07 -> SRV-APP-02 -> DB-FIN-01 (attack-like chain)
  B  carol.fin  3 failures then success on her own workstation (forgot password)
  C  dave.it    configured admin, first access to 3 new servers (maintenance)
  D  bob.hr     40 repeated accesses to a familiar server; 2 failures then success
                (below threshold) — should produce nothing
  E  erin.ops   an exact duplicate record — collapsed before detection

Names imitate an enterprise; none refer to real people or systems.
"""

from __future__ import annotations

DAY = 86_400
DOMAIN = "CORP"

# (user, workstation, usual servers)
USERS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("alice.fin@CORP", "WS-FIN-01", ("SRV-FILE-01", "SRV-MAIL-01")),
    ("bob.hr@CORP", "WS-HR-01", ("SRV-FILE-01", "SRV-MAIL-01")),
    ("carol.fin@CORP", "WS-FIN-02", ("SRV-FILE-01", "SRV-MAIL-01", "SRV-APP-02")),
    ("dave.it@CORP", "WS-IT-01",
     ("SRV-FILE-01", "SRV-MAIL-01", "SRV-APP-01", "SRV-APP-02", "DB-FIN-01")),
    ("erin.ops@CORP", "WS-OPS-01", ("SRV-MAIL-01", "SRV-APP-01")),
)
ADMIN_USERS = ("dave.it@CORP",)
SENSITIVE_HOSTS = ("DB-FIN-01",)
ROUTINE_DAYS = 4
SCENARIO_DAY = 3


def _t(day: int, hour: int, minute: int = 0, second: int = 0) -> int:
    return day * DAY + hour * 3600 + minute * 60 + second


def _line(
    t: int, user: str, src: str, dst: str, *,
    auth: str = "Kerberos", logon: str = "Network", orientation: str = "LogOn",
    outcome: str = "Success",
) -> tuple[int, str]:
    return t, f"{t},{user},{user},{src},{dst},{auth},{logon},{orientation},{outcome}"


def _routine(day: int) -> list[tuple[int, str]]:
    out = []
    for i, (user, ws, servers) in enumerate(USERS):
        machine = f"{ws}$@{DOMAIN}"  # machine-account noise; excluded by default config
        out.append(_line(_t(day, 8, 55, i), machine, ws, ws, logon="?", orientation="TGT"))
        out.append(_line(_t(day, 9, i), user, ws, ws, logon="Interactive"))
        for j, server in enumerate(servers):
            out.append(_line(_t(day, 10 + j, i), user, ws, server))
        out.append(_line(_t(day, 17, 0, i), user, ws, ws, auth="?", logon="?",
                         orientation="LogOff"))
    return out


def _scenarios(day: int) -> list[tuple[int, str]]:
    out = []
    # A: attack-like sequence for alice.fin
    for k in range(6):
        out.append(_line(_t(day, 10, 30, k * 20), "alice.fin@CORP", "WS-FIN-07", "WS-FIN-07",
                         logon="Interactive", outcome="Fail"))
    out.append(_line(_t(day, 10, 32, 30), "alice.fin@CORP", "WS-FIN-07", "WS-FIN-07",
                     logon="Interactive"))
    out.append(_line(_t(day, 10, 40), "alice.fin@CORP", "WS-FIN-07", "SRV-APP-02"))
    out.append(_line(_t(day, 10, 55), "alice.fin@CORP", "SRV-APP-02", "DB-FIN-01"))
    # B: carol.fin forgot her password
    for k in range(3):
        out.append(_line(_t(day, 8, 50, k * 30), "carol.fin@CORP", "WS-FIN-02", "WS-FIN-02",
                         logon="Interactive", outcome="Fail"))
    out.append(_line(_t(day, 8, 51, 30), "carol.fin@CORP", "WS-FIN-02", "WS-FIN-02",
                     logon="Interactive"))
    # C: admin maintenance on newly deployed servers
    for k in range(3):
        out.append(_line(_t(day, 14, 5 * k), "dave.it@CORP", "WS-IT-01", f"SRV-NEW-0{k + 1}"))
    # D: benign repetition and sub-threshold failures
    for k in range(40):
        out.append(_line(_t(day, 15, 0, 30 * k), "bob.hr@CORP", "WS-HR-01", "SRV-FILE-01"))
    out.append(_line(_t(day, 16, 0, 0), "bob.hr@CORP", "WS-HR-01", "WS-HR-01",
                     logon="Interactive", outcome="Fail"))
    out.append(_line(_t(day, 16, 0, 20), "bob.hr@CORP", "WS-HR-01", "WS-HR-01",
                     logon="Interactive", outcome="Fail"))
    out.append(_line(_t(day, 16, 0, 40), "bob.hr@CORP", "WS-HR-01", "WS-HR-01",
                     logon="Interactive"))
    # E: exact duplicate of a routine record
    out.append(_line(_t(day, 10, 4), "erin.ops@CORP", "WS-OPS-01", "SRV-MAIL-01"))
    return out


def generate_scenario_text() -> str:
    """Return the LANL-format file content (sorted by time, stable, '\\n' endings)."""
    rows = [row for day in range(ROUTINE_DAYS) for row in _routine(day)]
    rows += _scenarios(SCENARIO_DAY)
    rows.sort(key=lambda row: row[0])  # stable: equal times keep insertion order
    return "".join(line + "\n" for _, line in rows)
