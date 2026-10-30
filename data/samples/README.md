# Sample data

## `lanl_format_synthetic_sample.txt` — SYNTHETIC

Hand-written by the project team in the **format** of the LANL `auth.txt` file. It is **not** LANL
data and must never be reported as such. Identifiers (`U22@DOM1`, `C625`, …) only imitate LANL's
anonymisation style.

Purpose: a small, fully-known input for parser tests and demonstrations. It deliberately contains:

| Lines | Content | Expected result |
|---|---|---|
| 1–12 | well-formed records, incl. `?` unknowns, machine accounts, `ANONYMOUS LOGON` | accepted |
| 7, 10 | exact duplicates of lines 6 and 9 | accepted, counted as duplicates |
| 13 | blank line | skipped |
| 14–15 | 8 and 10 fields | rejected `WRONG_FIELD_COUNT` |
| 16–17 | `abc`, `-3` as time | rejected `INVALID_TIMESTAMP` |
| 18 | empty source user | rejected `MISSING_REQUIRED_FIELD` |
| 19 | prompt-injection text in a username | rejected `INVALID_FIELD` |
| 20 | orientation `LogIn` | rejected `INVALID_ORIENTATION` |
| 21 | outcome `Maybe` | rejected `INVALID_OUTCOME` |
| 22–25 | valid; line 23 is out of time order; 24 has empty auth type; 25 has empty destination user | accepted |

Totals: 25 lines read, 1 blank, 16 accepted, 8 rejected, 2 duplicates, 1 out of order.

## `auth_scenarios_synthetic.txt` — SYNTHETIC (generated)

Produced deterministically by `python scripts/generate_scenarios.py` (source:
`src/agentsoc/data_gen/scenarios.py`); a test fails if the committed file and the generator drift.
Four days of routine activity for five accounts in LANL format, with these day-3 scenarios:

| Scenario | Account | Content | Expected with `scenarios_detection_config.json` |
|---|---|---|---|
| A | alice.fin | 6 failures on unfamiliar WS-FIN-07, success, then WS-FIN-07 → SRV-APP-02 → DB-FIN-01 | 1 incident, **CRITICAL**, 7 rules |
| B | carol.fin | 3 failures then success on her own workstation | 1 incident, **MEDIUM**, `FAIL_THEN_SUCCESS` (benign explanation listed) |
| C | dave.it (configured admin) | first access to SRV-NEW-01..03 within 10 min | 1 incident, **LOW** (lowered from MEDIUM) |
| D | bob.hr | 40 repeated accesses to a familiar server; 2 failures then success | nothing |
| E | erin.ops | an exact duplicate record | nothing (1 duplicate collapsed) |

Machine-account TGT records (`WS-*$@CORP`) are included as noise and excluded by default.
Totals: 176 events → 15 findings, 3 incidents. These outcomes verify rule logic on a constructed
scenario; they are **not** a measure of detection accuracy.

`scenarios_detection_config.json` = defaults + `admin_users: ["dave.it@CORP"]` +
`sensitive_host_access.hosts: ["DB-FIN-01"]`.

## Real LANL data

Download `auth.txt.gz` from <https://csr.lanl.gov/data/cyber1/> (subject to the site's terms) into
`data/raw/` (gitignored), then:

```powershell
python scripts/ingest_lanl.py data/raw/auth.txt.gz --out data/processed/lanl_5k `
    --limit 5000 --label "LANL auth.txt, first 5000 lines"
```

Note: the first lines of LANL cover only the first seconds of the collection; use `--skip` to take
a window from later in the file if a more representative sample is needed, and record the window
in the label.
