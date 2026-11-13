# Implementation Status

_Last updated: 2026-11-09 — Final dashboard integration (0.9.0)_

Status is reported per capability. "Done" means implemented **and** verified by tests.

## Phase overview

| Phase | Scope | Status |
|---|---|---|
| 0 | Engineering foundation | Done |
| 1 | Dataset engineering & ingestion | Done |
| 2 | Authentication threat detection & correlation | **Done; LANL validation complete — awaiting review** (see below) |
| 3 | Investigator Agent (NCE) + fallback | **MVP done — awaiting review** (demo milestone) |
| 4 | Graph validation engine (SSE) | **Done — awaiting review** (Target 2; observed logs only) |
| 5 | Risk scoring & policy (RSEM) | **Done — awaiting review** (Target 3; shown in the dashboard) |
| 6 | SOC dashboard | **Done — awaiting review** (attack graph, risk and response, path validation, provenance) |
| 7 | Response simulation & integration | Not started |

## 50% review target — capability checklist

| # | Capability | Status |
|---|---|---|
| 1 | Authentication CSV ingestion | Done for LANL-format files (plain/.gz). Header-based CSV upload: not started |
| 2 | Event normalisation | Done |
| 3 | Suspicious authentication detection | **Done** — 8 configurable rules (ARCHITECTURE.md §9) |
| 4 | Incident correlation | **Done** — per (provenance, user), time gap / shared evidence |
| 5 | LLM investigation with fallback | **Done (MVP)** — Groq `openai/gpt-oss-120b`, grounded, deterministic fallback |
| 6 | Multiple attack hypotheses | **Done (MVP)** — ≥1 malicious + ≥1 benign enforced; LLM typically returns 2, fallback 2–3 |
| 7 | Benign alternative explanations | **Done** — rule-level (detection) and hypothesis-level (investigation) |
| 8 | NetworkX topology construction | **Done** — per-incident graphs from observed authentication events; no enterprise topology is assumed |
| 9 | Feasible / infeasible path validation | **Done** — observed/inferred paths, finding validation, and post-LLM checks of proposed paths |
| 10 | Risk scoring | **Done** — RSEM incident risk and investigation confidence, above unchanged detection severity |
| 11 | Defensive recommendations | **Done** — ranked, gated, dry-run proposals; nothing executes |
| 12 | SOC dashboard | **Done** — React web app over a REST API (Streamlit deprecated) |
| 13 | Response simulation | Not started |
| 14 | Audit logging | Not started (hash-chained `AuditRecord` ready) |

## Final dashboard integration (0.9.0) — awaiting review

**Implemented and tested:** separate detection severity and RSEM risk throughout; risk
distribution; attack graph (React Flow + dagre over the NetworkX builder) with observed, inferred
and weak-evidence paths; Risk & response; validated AI paths; Provenance with audit trail; labelled
synthetic and LANL demo sources; explicit not-assessed, stale, unavailable and truncated states.
**Not implemented, by decision:** approval or execution of actions.

| Check | Result |
|---|---|
| Python suite | **927 passed**, ruff clean |
| Frontend suite | **80 passed** (15 existing + 65 new), type-check clean |
| Fault injection | 28/28 deliberate faults caught |
| Browser (Edge, 1440 and 390 px) | 12 views each: no page overflow, 0 axe violations (`npm run test:e2e`) |
| Historical integrity | all stored outputs byte-identical |
| Bundle | Initial JS +42 kB (+11 kB gzip) over 826 kB; graph chunk 226 kB (74 kB gzip) loads only with the Attack graph tab |

**Known limitations**
- Actions cannot be approved: there is no persisted, audited lifecycle.
- Phase 2 LANL sources have no assessments and show "not assessed".
- Graph edges are keyboard-reachable through the connections table, not on the canvas itself.
- Path validation only appears for language-model investigations. The deterministic fallback
  proposes no path.
- The first request needing evidence from a 400,000-line LANL window takes several seconds,
  because the whole file is hash-verified once.

## Target 3 (0.8.0) — Risk Scoring and Evaluation Module — awaiting review

**Implemented and tested:** evidence attribution ledger, deterministic risk score, separate
investigation confidence, ranked and gated dry-run actions, independent verifier, hash-bound
persistence, API (`GET /api/incidents/{id}/risk`) and CLI (`scripts/assess_risk.py`).
**Deferred by decision:** dashboard integration.

| Check | Result |
|---|---|
| Python suite | **872 passed** (708 existing + 164 new), ruff clean; `risk/` at 96% line coverage |
| Synthetic scenarios (19) | all match hand-worked scores: [docs/target3_synthetic_results.md](docs/target3_synthetic_results.md) |
| Fault injection | 35 deliberate faults (double credit, inferred as observed, removed caps and gates, LLM confidence used, verifier bypassed, stale or tampered data) all caught |
| Historical integrity | all 40 stored detection and structural files byte-identical before and after |
| Scale (synthetic) | 23,660 / 118,300 / 236,600 events: risk stage 0.16 / 0.49 / 0.88 s, 57 / 74 / 95 MB (single runs) |

**LANL (real, sampled, one 400,000-line window):** see
[docs/target3_lanl_results.md](docs/target3_lanl_results.md). Short-baseline sensitivity run: 560
Low, 5 Medium, none higher, against detection severity 376 Low, 186 Medium, 3 High. LANL has no
sensitive-host data, so that component contributes nothing. Red Team comparison, kept separate and
read after scoring: the 1 of 3 labels cited by an incident sits in an incident scored 10.0 (Low).
**This does not establish detection ability or calibration**; no precision, recall or accuracy is
claimed. Stability of bands under changed weights is a property of the arithmetic only.

**Known limitations (Target 3)**
- Weights, bands and action values are starting defaults, unvalidated against ground truth.
- Monotonicity is guaranteed for RSEM's own inputs (dropping a path, shortening one, dropping a
  finding). Re-running the whole pipeline after deleting an event can raise a score when earlier
  stages produce new evidence: on dense random graphs 53 of 812 removals did, all traced to new
  findings, new paths or cleared truncation, and none to RSEM.
- Credential-only incidents score Low by design; their detection severity stays visible.
- RSEM needs a structural assessment. Stored Phase 2 LANL runs have none, so they have no risk
  records unless the SSE and risk CLIs are run on them.
- The demo rebuilds a missing or tampered risk file instead of serving it. Other sources return
  404 until it is rebuilt.

## Target 2 (0.7.0) — Structural Simulation Engine — awaiting review

**Implemented and tested:** shared streaming event index; authentication graph and time-expanded
event graph; path, finding, disconnection and choke-host analysis; independent verifier; pre-LLM
structural evidence (as untrusted data); post-LLM validation of proposed paths; persistence, API
(`GET /api/incidents/{id}/structure`) and CLI (`scripts/assess_structure.py`). **Deferred by
decision:** graph visualisation. **Not started:** RSEM (Target 3).

| Check | Result |
|---|---|
| Python suite | **708 passed** (554 existing + 154 new), ruff clean; `graph/` at 97% line coverage |
| Synthetic scenarios (17) | all match hand-written expectations: [docs/target2_synthetic_results.md](docs/target2_synthetic_results.md) |
| Acceptance | a naive findings-to-edges graph fails where the SSE succeeds: expansion through uncited events, rejecting time-invalid and over-limit paths, cycles, weak shared-server links, same-second chains, choke hosts |
| Fault injection | 25 deliberate faults (failed events as movement, invented or time-invalid links, hidden account switches, a neutered verifier, hidden truncation, stale data) all caught |
| Detection outputs | all 36 stored detection files byte-identical before and after |
| Scale (synthetic, worst-case shared server) | 23,660 / 118,300 / 236,600 events: whole stage 1.0 / 5.3 / 11.1 s, 82 / 208 / 361 MB; median 8 ms per incident at every size (single runs) |
| Live LLM (Groq, synthetic, throwaway folder) | 3 investigations used the structural evidence; proposed paths came back `FEASIBLE` or `CONDITIONALLY_FEASIBLE`, each hop checked. An invalid live proposal did not occur, so that path is covered by scripted tests only |

**LANL (real, sampled, one 400,000-line window):** see
[docs/target2_lanl_results.md](docs/target2_lanl_results.md). On the short-baseline sensitivity
run: 1,213 paths (34 inferred), 22 of 565 incidents had a path through an event no rule cited, 2
had an observed path longer than any rule chain, and 6 had truncated context. Whole stage 8.8 s,
121 MB. Red Team comparison, kept separate and read after the assessment: of 3 labels in the
window, 1 is on a reported path. **This does not establish detection ability**; no precision,
recall or accuracy is claimed.

**Known limitations (Target 2)**
- Validation is against observed logons only. It cannot show network reachability, privileges or
  who operated an account, and this differs from the paper's topology-based SSE.
- Paths depend on what was logged and on the link limit (1,800 s by default). Machine accounts are
  excluded, as in detection, so movement using them is invisible.
- The longest-route search reports one best route per rule-cited event, not every route.
- Most LANL incidents come from a too-short baseline, so these results describe behaviour on that
  sensitivity run, not typical operation.
- Saved investigations made before this version show no structural evidence until re-run.
- Stored Phase 2 LANL runs are untouched and have no assessments unless the CLI is run on them.

## Target 1 (0.6.0) — advanced lateral-movement detection — awaiting review

**Implemented and tested:** `CROSS_ACCOUNT_PIVOT` (new rule), path metrics on `LATERAL_CHAIN`
findings, `jump_hosts` context with transparent, conservative severity reduction, and no double
counting between the pivot and `NEW_SRC_HOST`. **Not started, pending approval:** Target 2
(NetworkX attack graph) and Target 3 (RSEM). The dashboard has no new views yet; new metrics
appear in the existing Detection analysis tab under their raw names.

| Check | Result |
|---|---|
| Python suite | **554 passed** (405 existing + 149 new), ruff clean; new `detection/lateral.py` and `correlate.py` at 100% line coverage |
| Synthetic scenarios (15) | all match hand-written expectations: [docs/target1_synthetic_results.md](docs/target1_synthetic_results.md) |
| Large batches (synthetic) | 23,660 / 118,300 / 236,600 events: every planted chain and pivot found; 236,600 events detected in 31.3 s, 577 MB peak (single runs) |
| LANL sensitivity (real, sampled) | separate report: [docs/target1_lanl_sensitivity.md](docs/target1_lanl_sensitivity.md) |
| Backward compatibility | `rules.py` unchanged; on all 6 stored runs the original seven rules reproduce the stored findings exactly, and stored outputs still load and verify |
| Mutation check | 11 deliberate faults in the safeguards (failed events as movement, window boundary, same-second order, own logon, domain handling, jump-host reduction, double counting) were all caught by the tests |

**LANL sensitivity, window lines 29,400,001–29,800,000.** Default 2-day baseline: 0 pivots and 0
chains, because no event falls after the baseline. Half-window baseline (1,027 s, far too short
to represent normal behaviour): 4 pivots, 2 chains, incident severities unchanged from Phase 2.
Red Team comparison, kept separate and run after detection: 3 labels in the window, 1 cited by a
finding, 0 cited by the pivot rule. **This does not establish detection ability.** No precision,
recall or accuracy is claimed.

**Known limitations (Target 1)**
- The pivot rule needs a baseline, so like the other novelty rules it cannot be properly
  evaluated on LANL until a streaming baseline exists.
- Only first-seen sources count, so a pivot through a host the account already used is missed.
- Arrivals inside the baseline window are not used, so a pivot straddling the boundary is missed.
- Co-occurrence on a busy shared host is weak evidence; `other_accounts_on_host` exposes this but
  the rule does not discount it.
- Without `jump_hosts`, no benign context is added. LANL has no host-role data to configure it.
- A run under engine 1.1 with an older config file enables the new rule by default; set
  `cross_account_pivot.enabled` to `false` to reproduce the seven-rule behaviour exactly.
- Chain findings gain metrics, so an incident re-detected under 1.1 has a new fingerprint and any
  saved investigation for it shows as stale. Existing stored outputs are not regenerated.

## Web application (0.5.0) — FastAPI REST API + React frontend

**Working:** backend and frontend start independently; overview, incidents (search, severity
and provenance filters, sorting, pagination), incident detail (overview, timeline, detection
analysis, evidence, AI investigation), investigations history, evidence explorer, data sources,
hash-chained system activity. Investigation runs the configured LLM automatically and falls back
to deterministic analysis on any failure; provider configuration is not exposed in the UI.

| Check | Result |
|---|---|
| Python suite | **405 passed** (372 + 33 API tests), ruff clean |
| Frontend | **15 passed** (Vitest), `tsc` strict clean, production build OK |
| Live stack | API :8000 + Vite :5173; live LLM investigation via the UI proxy (3.7 s, grounded) |
| Single process | built SPA served by FastAPI; deep links and assets OK; traversal probe served no files |
| Visual review | headless-Edge screenshots of all pages at 1440 px and 390 px; fixed empty charts (SVG `var()`), table overflow, mobile header |
| Mutation check | removing the per-incident lock makes the concurrency test fail |

**Known limitations (web app)**
- No authentication: a single local analyst (shown as such in the UI).
- Investigations are synchronous HTTP requests (up to the LLM timeout); the UI shows progress
  and blocks duplicate clicks, but there is no background job queue.
- "All events" browsing is limited to datasets ≤ 200,000 events (larger LANL runs: evidence scope).
- The activity log is local and append-only; hash-chained (tamper-evident), not tamper-proof.
- Frontend tests use mocked API responses; end-to-end browser automation is not part of the suite.

## Demo MVP — Investigator Agent (Phase 3 MVP) + SOC dashboard

**Working end to end:** verified dataset → Phase 2 detection → incident → Investigator Agent →
validated `InvestigationResult` → Streamlit dashboard (overview, incident explorer, details and
timeline, AI investigation, evidence explorer, provenance).

| Check | Result |
|---|---|
| Live Groq (`openai/gpt-oss-120b`) on the 3 synthetic incidents | all accepted by grounding, 4.0–6.5 s each; earlier runs 4.6–18.9 s. Alice → MALICIOUS 0.68 most plausible; Carol → BENIGN (mistyped password) 0.78; Dave → BENIGN (admin maintenance) 0.38 |
| Deterministic fallback | Alice H1 malicious 0.80; Carol misconfiguration/user error; Dave administrative — as designed |
| Dashboard (Streamlit AppTest, headless) | loads, metrics correct, investigation only on click, fallback/outage, per-incident results, zero-incident dataset |
| Real server | `streamlit run` → health `ok`, HTTP 200 |
| Tests | **372 passed** (302 + 11 schema + 59 investigator/dashboard), ruff clean, coverage 96% |

Saved real Groq investigations for the 3 demo incidents are in
`data/processed/demo/detection/investigations/` (offline backup; each records provider, model and
time; re-runnable).

**Known limitations (demo MVP)**
- The LLM usually returns 2 hypotheses, not 3 (allowed: three are requested "where evidence
  permits"; the fallback gives 3 when both benign families apply).
- LLM ATT&CK sub-techniques (e.g. `T1021.002` SMB) are interpretations: authentication logs do
  not record the remote-service protocol. The UI labels them as interpretation.
- LLM latency varies (4–19 s observed); confidence values are not calibrated.
- A stale Windows machine-level `GROQ_API_KEY` overrides `.env`; until removed, the app falls
  back (and says so).
- No graph feasibility, risk/action ranking, response simulation or audit trail yet (Phases 4–7).

## Phase 2 — validation on real LANL 2015 data (sampled)

**Scope:** an evaluation of the existing Phase 1/2 code on contiguous windows of the real LANL
2015 `auth.txt.gz` (7,626,505,158 bytes, SHA-256 `9c6b0cc2…a89bf672`, read-only). It is **not**
proof of production detection accuracy. Full report:
`data/processed/lanl_validation/validation_report.md` (+ four JSON files).

| Run | Lines | Config | Events | Findings | Incidents (L/M/H/C) | Integrity |
|---|---|---|---:|---:|---|---|
| first_100k | 1–100,000 (16 min of LANL time) | default | 100,000 | 18 | 13 (11/0/2/0) | passed (338/338 IDs) |
| first_500k | 1–500,000 (1.42 h) | default | 500,000 | 49 | 20 (16/0/4/0) | passed (1,716/1,716) |
| redteam_window | 29,400,001–29,800,000 (34 min) | default | 400,000 | 40 | 28 (26/0/2/0) | passed (808/808) |
| redteam_window_half_baseline | same window | **sensitivity**: baseline 1,027 s | 400,000 | 1,541 | 565 (376/186/3/0) | passed (2,021/2,021) |

### What the validation established
- **Ingestion** works on real LANL data: 0 rejections after the fix below, 0 duplicates, records in
  time order, provenance `lanl` on every event and manifest, hashes and counts re-verified.
- **Bug found and fixed:** `ScreenLock`/`ScreenUnlock` orientations (12,642 records in days 0–2)
  were wrongly rejected. Fixed in the `AuthOrientation` contract; regression tests use the
  verbatim LANL lines and fail without the fix. No rule logic changed.
- **Evidence integrity** passed on every run: every cited ID exists in the verified input, provenance
  and timestamps are consistent, grouping is explained, severity is reproducible from rules.
- **Failure rules** (`FAILURE_BURST`, `FAIL_THEN_SUCCESS`) fire on real data. They are dominated by
  a few accounts with persistent failures (e.g. U22@DOM1: 849 failures over 85 min from 6 hosts,
  mostly Kerberos TGS to a destination recorded as `U22`) — consistent with stale credentials or
  misconfigured services, but the data cannot distinguish that from guessing.

### What the validation could NOT establish
- **Baseline-dependent rules at default settings.** The 2-day baseline needs **33,303,179 lines**
  (day 0: 15.7M, day 1: 17.6M); every default run covered 0.56–2.96% of it, so `NEW_SRC_HOST`,
  `NEW_DST_HOST`, `MULTI_HOST_SPREAD` and `LATERAL_CHAIN` evaluated **0 events**. Memory measured at
  ~3.1 KB/event at ingest → ~100 GB for a full baseline; this machine has 7.3 GB.
- **Sensitivity run (not the default):** with a 17-minute baseline the novelty rules fired heavily —
  1,138 `NEW_DST_HOST` findings and 565 incidents in 34 minutes of data. A baseline this short does
  not represent normal behaviour; the volume shows these rules need a real baseline before their
  real-world false-positive rate can be judged.
- **`SENSITIVE_HOST_ACCESS`** is inert on LANL (no host criticality data).
- **Red Team:** 3 labels fall in the window; all 3 matched exactly to ingested events. Default
  config: 0 cited (all inside baseline). Sensitivity run: 1 cited (`NEW_SRC_HOST`, `NEW_DST_HOST`,
  `MULTI_HOST_SPREAD` on U748's first logon from C17693); 1 not cited because the user had no
  baseline; 1 not cited because its hosts were already flagged earlier. **No precision/recall/F1 is
  reported** — three labels and an unrepresentative baseline cannot support such metrics.

### Data observations (LANL-specific)
- 68.8–76.0% of events come from excluded machine/system accounts.
- Destination fields contain non-computer values (`TGT`, `U22`, …): 1,379 events in the first 100k.
- Users appear under multiple domains (`U73@DOM1` / `U73@?`); 2–4 users per run were split across
  incidents.
- Cross-rule shared evidence (severity inflation) in 2–4 incidents per default run and 228 of 565 in
  the sensitivity run.
- Truncated auth-type values (`MICROSOFT_AUTHENTICATION_PAC`) are accepted unrepaired.

### Performance (Windows, 12 logical CPUs, 7.3 GB RAM)
| Run | Ingest | Ingest peak | Detect | Detect peak |
|---|---|---|---|---|
| first_100k | 6.6 s (15.1k lines/s) | 300 MB | 3.2 s (31.2k events/s) | 244 MB |
| first_500k | 36.8 s (13.6k lines/s) | 1,359 MB | 18.9 s (26.4k events/s) | 1,067 MB |
| redteam_window | 63.7 s incl. skipping 29.4M lines | 1,106 MB | 15.6 s | 875 MB |

The 1M-line run was **not** attempted: extrapolation (~3 GB) against <1 GB free RAM.

### Phase 2 completion recommendation
Phase 2 is **functionally complete and evidence-safe**, and can close for the 50% review on the
basis of synthetic scenarios + real-data validation of ingestion, failure rules and integrity.
It is **not** validated for baseline-dependent detection on LANL. Before claiming that, a Phase 2.1
backlog is recommended (none blocks Phase 3, which consumes `Incident` objects):
1. Streaming per-user baseline (store host sets, not events) so a 2-day baseline fits in memory.
2. Explicit identity normalisation (`U73@?` ↔ `U73@DOM1`), keeping raw values as evidence.
3. Tag/exclude non-computer destination values from host-based rules.
4. Evidence-once severity (Phase 5 risk model) to remove cross-rule inflation.

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
pytest:   302 passed (273 at Phase 2 close + 4 parser regression tests for ScreenLock/ScreenUnlock
          + 25 evaluation-tooling tests); ruff clean
coverage: 96% overall (1948 statements). evaluation/measure.py reads 59% because its main()
          runs in subprocesses (not traced) and its POSIX branch cannot run on Windows.
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

1. **Groq works; one machine setting pending.** The `.env` key is valid
   (test completion with `openai/gpt-oss-120b` succeeded, 1.46 s). All earlier 401s came from a stale
   Windows **machine-level** `GROQ_API_KEY` that overrides `.env`; it must be removed.
   `llama-3.3-70b-versatile` is not available to this account, so `GROQ_MODEL` is now `openai/gpt-oss-120b`.
   `scripts/check_environment.py` now warns when an OS variable shadows `.env`.
2. **LANL validated on samples only** (see section above): baseline-dependent rules are not
   validated at default settings because a 2-day baseline does not fit in memory on this machine.
3. **Severity over-counts correlated rules** (e.g. one event triggering NEW_DST_HOST,
   SENSITIVE_HOST_ACCESS and part of MULTI_HOST_SPREAD). To be addressed by the Phase 5 risk model.
4. Correlation is per user only; host-centric and cross-account correlation are not implemented.
5. Users without baseline activity are not evaluated by novelty rules (reported in the summary).
6. Excluded principals (machine accounts, ANONYMOUS LOGON, SYSTEM) are not analysed by default.
7. Sensitive hosts and admin accounts come from static configuration, not asset/identity data.
8. Nested `.git` in the parent folder and OneDrive sync — unresolved; nothing committed yet.

## Next milestone

After review of the demo MVP: Phase 4 (graph feasibility, SSE) — not started.

_Web app delivered (0.5.0); Phase 4 not started._ _Previous:_ 
Phase 3 — Investigator Agent (NCE): provider abstraction, Groq provider, prompt construction from
`Incident` evidence (untrusted data delimited), schema-validated hypotheses with citation checks,
deterministic fallback investigator.
