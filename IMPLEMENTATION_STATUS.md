# Implementation Status

_Last updated: 2026-10-30 — end of Phase 2_

Status is reported per capability. "Done" means implemented **and** verified by tests.

## Phase overview

| Phase | Scope | Status |
|---|---|---|
| 0 | Engineering foundation | Done |
| 1 | Dataset engineering & ingestion | Done |
| 2 | Authentication threat detection & correlation | **Done — awaiting review** |
| 3 | Investigator Agent (NCE) + fallback | Not started |
| 4 | Graph validation engine (SSE) | Not started |
| 5 | Risk scoring & policy (RSEM) | Not started |
| 6 | SOC dashboard | Not started |
| 7 | Response simulation & integration | Not started |

## 50% review target — capability checklist

| # | Capability | Status |
|---|---|---|
| 1 | Authentication CSV ingestion | Done for LANL-format files (plain/.gz). Header-based CSV upload: not started |
| 2 | Event normalisation | Done |
| 3 | Suspicious authentication detection | **Done** — 7 configurable rules (ARCHITECTURE.md §9) |
| 4 | Incident correlation | **Done** — per (provenance, user), time gap / shared evidence |
| 5 | LLM investigation with fallback | Not started (**Groq key rejected — see Known issues**) |
| 6 | Multiple attack hypotheses | Not started |
| 7 | Benign alternative explanations | Partial — rule-level benign explanations attached to every incident; hypothesis-level in Phase 3 |
| 8 | NetworkX topology construction | Not started |
| 9 | Feasible / infeasible path validation | Not started |
| 10 | Risk scoring | Partial — incident triage severity (points/bands); RSEM Eq. 1 action scoring in Phase 5 |
| 11 | Defensive recommendations | Not started |
| 12 | Streamlit dashboard | Not started |
| 13 | Response simulation | Not started |
| 14 | Audit logging | Not started (hash-chained `AuditRecord` ready) |

## Phase 2 — completed

- `detection/inputs.py`: verified loading only (manifest hash + count, provenance agreement,
  no event-ID collisions across inputs).
- `detection/baseline.py`: per-user familiar source/destination hosts from successful access in
  the baseline window; first-seen annotation after it.
- `detection/rules.py`: `FAILURE_BURST`, `FAIL_THEN_SUCCESS`, `NEW_SRC_HOST`, `NEW_DST_HOST`,
  `MULTI_HOST_SPREAD`, `LATERAL_CHAIN`, `SENSITIVE_HOST_ACCESS`.
- `detection/correlate.py`: incident correlation and documented severity calculation.
- `detection/engine.py`: provenance partitioning, account exclusion, duplicate collapse,
  evidence verification.
- `detection/report.py` + `store/detections.py`: `detections.jsonl`, `incidents.jsonl`,
  `detection_summary.json`, `detection_report.md`; hash-verified loading.
- `config/detection.json` (defaults) and `data/samples/scenarios_detection_config.json`.
- `data_gen/scenarios.py` + `data/samples/auth_scenarios_synthetic.txt`: deterministic
  **synthetic** 4-day scenario in LANL format.
- CLIs: `scripts/detect.py`, `scripts/generate_scenarios.py`.
- **Interface change (Rule F):** `Finding` gained `user`, `hosts`, `metrics`; `Incident` gained
  `rule_ids`, `involved_users`, `datasets`, `severity`, `severity_rationale`,
  `benign_explanations`, `limitations`, `missing_information`. All dependants (fixtures, schema
  tests) updated. No Phase 1 code changed.

## Test results

```
pytest:   273 passed (174 Phase 0–1 incl. 4 new schema tests; 99 new Phase 2 incl. 7 integration)
coverage: 98% (1444 statements, 28 missed)
ruff:     All checks passed
```

Mutation spot-check: disabling the consecutive-failure reset and the lateral-chain loop guard each
made exactly the targeted test fail.

### Demonstration results (SYNTHETIC data — demonstrates logic, not real-world accuracy)

| Input | Findings | Incidents |
|---|---:|---|
| `auth_scenarios_synthetic.txt` (176 events) with scenario config | 15 | alice.fin **CRITICAL** (7 rules, chain WS-FIN-07 > SRV-APP-02 > DB-FIN-01); carol.fin **MEDIUM** (fail→success, forgot-password scenario); dave.it **LOW** (admin maintenance, lowered from MEDIUM) |
| `lanl_format_synthetic_sample.txt` (Phase 1 sample, 16 events) | 0 | none — all 10 s fall inside the baseline; failures below thresholds |

Benign scenarios (bob.hr repeated familiar access + 2 sub-threshold failures; erin.ops duplicate
record) produced no findings. Evidence check: 16 cited event IDs, 0 unknown. Two runs produced
byte-identical detections/incidents/report.

## Architectural decisions

| Decision | Rationale |
|---|---|
| Detection per provenance partition | Same identifier in synthetic and LANL data is not the same entity |
| Baseline-relative novelty, first-seen only | Avoids re-alerting; makes "unusual" explicit and measurable |
| Failed attempts don't build baselines | A failure must not make a host "familiar" |
| Admin accounts downgraded, not suppressed | Keeps evidence visible with a benign explanation |
| Machine/system accounts excluded by default | Noise reduction; documented coverage gap; counted |
| Duplicates collapsed before counting | Prevents LANL same-second duplicates inflating counts |
| Severity = banded sum of distinct-rule points | Transparent and explainable; known to over-count correlated rules |
| Deterministic sequential IDs (`INC-00001`) | Reproducible outputs |

## Known issues and limitations

1. **Groq: resolved at the key level, one machine setting pending.** The `.env` key is valid
   (test completion with `openai/gpt-oss-120b` succeeded, 1.46 s). All earlier 401s came from a stale
   Windows **machine-level** `GROQ_API_KEY` that overrides `.env`; it must be removed.
   `llama-3.3-70b-versatile` is not available to this account, so `GROQ_MODEL` is now `openai/gpt-oss-120b`.
   `scripts/check_environment.py` now warns when an OS variable shadows `.env`.
2. **No real LANL data processed yet.** Detection has only run on synthetic data. Behaviour on LANL
   (where machine accounts dominate and the first lines cover seconds) is untested; a longer
   window and `--skip` will be needed for any novelty rule to be meaningful.
3. **Severity over-counts correlated rules** (e.g. one event triggering NEW_DST_HOST,
   SENSITIVE_HOST_ACCESS and part of MULTI_HOST_SPREAD). To be addressed by the Phase 5 risk model.
4. Correlation is per user only; host-centric and cross-account correlation are not implemented.
5. Users without baseline activity are not evaluated by novelty rules (reported in the summary).
6. Excluded principals (machine accounts, ANONYMOUS LOGON, SYSTEM) are not analysed by default.
7. Sensitive hosts and admin accounts come from static configuration, not asset/identity data.
8. Nested `.git` in the parent folder and OneDrive sync — unresolved; nothing committed yet.

## Next milestone

Phase 3 — Investigator Agent (NCE): provider abstraction, Groq provider, prompt construction from
`Incident` evidence (untrusted data delimited), schema-validated hypotheses with citation checks,
deterministic fallback investigator.
