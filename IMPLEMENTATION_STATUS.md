# Implementation Status

_Last updated: 2026-10-30 — demo MVP (Investigator Agent + SOC dashboard)_

Status is reported per capability. "Done" means implemented **and** verified by tests.

## Phase overview

| Phase | Scope | Status |
|---|---|---|
| 0 | Engineering foundation | Done |
| 1 | Dataset engineering & ingestion | Done |
| 2 | Authentication threat detection & correlation | **Done; LANL validation complete — awaiting review** (see below) |
| 3 | Investigator Agent (NCE) + fallback | **MVP done — awaiting review** (demo milestone) |
| 4 | Graph validation engine (SSE) | Not started |
| 5 | Risk scoring & policy (RSEM) | Not started |
| 6 | SOC dashboard | **MVP done** (Streamlit; Phases 4/5/7 views absent) |
| 7 | Response simulation & integration | Not started |

## 50% review target — capability checklist

| # | Capability | Status |
|---|---|---|
| 1 | Authentication CSV ingestion | Done for LANL-format files (plain/.gz). Header-based CSV upload: not started |
| 2 | Event normalisation | Done |
| 3 | Suspicious authentication detection | **Done** — 7 configurable rules (ARCHITECTURE.md §9) |
| 4 | Incident correlation | **Done** — per (provenance, user), time gap / shared evidence |
| 5 | LLM investigation with fallback | **Done (MVP)** — Groq `openai/gpt-oss-120b`, grounded, deterministic fallback |
| 6 | Multiple attack hypotheses | **Done (MVP)** — ≥1 malicious + ≥1 benign enforced; LLM typically returns 2, fallback 2–3 |
| 7 | Benign alternative explanations | **Done** — rule-level (detection) and hypothesis-level (investigation) |
| 8 | NetworkX topology construction | Not started |
| 9 | Feasible / infeasible path validation | Not started |
| 10 | Risk scoring | Partial — incident triage severity (points/bands); RSEM Eq. 1 action scoring in Phase 5 |
| 11 | Defensive recommendations | Not started |
| 12 | Streamlit dashboard | **Done (MVP)** |
| 13 | Response simulation | Not started |
| 14 | Audit logging | Not started (hash-chained `AuditRecord` ready) |

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

_Previous:_ 
Phase 3 — Investigator Agent (NCE): provider abstraction, Groq provider, prompt construction from
`Incident` evidence (untrusted data delimited), schema-validated hypotheses with citation checks,
deterministic fallback investigator.
