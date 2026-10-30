# AgentSOC — Architecture

Academic research prototype. Not a production SOC.

**Reference:** J. Roy and S. K. Singh, *"AgentSOC: A Multi-Layer Agentic AI Framework for
Security Operations Automation,"* 5th IEEE ICAIC, Feb 2026. arXiv:2604.20134v1.
(The PDF is kept locally in `docs/reference/` and gitignored; we link to arXiv rather than redistribute it.)

---

## 1. Design principle

> **The LLM proposes; deterministic code decides.**

Raw logs are untrusted input to Layer 1. LLM output is untrusted input to Layers 3–4. Neither can
trigger an action. A hallucinated hypothesis can at worst produce an `INFEASIBLE` verdict or a low score.

```
 CSV (synthetic / LANL / upload)
          │
 ┌────────▼─────────┐  deterministic
 │ L1 Perception    │  ingest → validate → normalise → baseline → detect → correlate
 └────────┬─────────┘
          │ Incident  (event_ids = the only citable evidence)
 ┌────────▼─────────┐  PROBABILISTIC (LLM) — fallback: rule-based investigator
 │ L2 Investigator  │  ≥1 malicious + ≥1 benign hypothesis, each citing event IDs
 │      (NCE)       │
 └────────┬─────────┘
 ┌────────▼─────────┐  deterministic (NetworkX)
 │ L3 Graph (SSE)   │  FEASIBLE / CONDITIONALLY_FEASIBLE / INFEASIBLE per hypothesis
 └────────┬─────────┘
 ┌────────▼─────────┐  deterministic
 │ L4 Risk (RSEM)   │  incident risk + action ranking: α·Containment − β·Impact
 └────────┬─────────┘
 ┌────────▼─────────┐  deterministic + human
 │ L5 Response      │  dry-run only, approval states, hash-chained audit
 └──────────────────┘
   All layers ↔ Knowledge Store (SQLite + JSON config)
```

Orchestration is a plain function pipeline (no LangGraph): the flow is linear with one fallback
branch, so a framework would add indirection without adding capability.

---

## 2. Paper ↔ implementation mapping

| Paper component (Sec. III) | Our package | Status legend |
|---|---|---|
| Perception: Alert Normalization | `perception/lanl`, `perception/quality`, `store/datasets` | **Done — Phase 1** (LANL-format auth logs) |
| Perception: Situational Contextualization | `detection/baseline` (per-user host profiles); asset context from topology | **Partial — Phase 2** (behavioural baseline only); asset context Phase 4 |
| Perception: Noise Reduction | `detection/engine` (exclusion, duplicate collapse), `detection/correlate` | **Done — Phase 2** |
| Agentic Reasoning: NCE | `investigator/` | **MVP done** — Groq LLM + grounding + deterministic fallback |
| Agentic Reasoning: SSE | `graph/` | Planned — Phase 4 |
| Agentic Reasoning: RSEM (Eq. 1) | `risk/` | Contract done (`ActionScore`); logic Phase 5 |
| Action: Adaptive Playbook Generator | `risk/` ranking + `response/` | Planned — Phases 5/7 |
| Action: Policy & Safety Guardrails | `risk/policy` + `ResponseAction` lifecycle | Lifecycle contract done; policy Phase 5 |
| Action: Execution Interface | `response/simulator` | **Simulated only** (dry-run) — Phase 7 |
| Internal Knowledge Store | `store/` (SQLite) + `config/*.json` | Planned — from Phase 1 |
| Real-Time Monitoring | dashboard + post-simulation verification | **Batch/replay only**; real-time is future work |

Package names describe function; only the Investigator is an "agent".

---

## 3. Inter-layer contracts (`src/agentsoc/schemas/`)

All contracts are immutable Pydantic v2 models that reject unknown fields. Changing one is an
interface change: update every consumer and test.

| Contract | Producer → Consumer | Key invariants enforced |
|---|---|---|
| `AuthEvent` | L1 → all | LANL auth.txt field set; tz-aware time; safe identifiers; `raw_ref` back to source line; orientations LogOn/LogOff/TGS/TGT/AuthMap/ScreenLock/ScreenUnlock (last two added after LANL validation) |
| `Finding` | detectors → correlator | ≥1 event; time window ordered; `metrics` (observations) separate from `description` (inference) |
| `Incident` | L1 → L2–5 | findings cite only the incident's events and lie inside its window; `rule_ids` = findings' rules; ≥1 provenance; severity + rationale; benign explanations, limitations, missing information |
| `Hypothesis` | L2 → L3/L4 | confidence ∈ [0,1]; ATT&CK IDs `T####(.###)`; benign ⇒ no techniques; an event cannot both support and contradict |
| `InvestigationResult` | L2 → L4/L5 | ≥1 BENIGN hypothesis required; unique IDs; LLM results record provider + model |
| `PathValidation` | L3 → L4 | ≥1 reason; FEASIBLE ⇒ no missing edges/conditions; CONDITIONAL ⇒ conditions stated |
| `ActionScore` | L4 → L5 | stored composite **must equal** α·C − β·I (paper Eq. 1) |
| `IncidentRiskAssessment` | L4 → L5 | score ∈ [0,100]; ≥1 explained component |
| `ResponseAction` | L4 → L5 | `dry_run` is `Literal[True]`; lifecycle state machine; approval cannot be skipped |
| `AuditRecord` | L5 → store | SHA-256 hash chain; `verify_chain` detects edit/delete/reorder |

### Why identifiers are restricted
User/host names come from untrusted logs and untrusted LLM output. `Identifier` allows only
`[A-Za-z0-9_.$@?-]` words separated by single spaces (max 128). This accepts LANL values
(`U1234@DOM1`, `C586$@DOM1`, `ANONYMOUS LOGON@C586`) but rejects quotes, braces, newlines and
angle brackets — the raw material of prompt- and log-injection payloads.

### Two different "risk" scores
The paper's RSEM scores **actions** (Eq. 1). Our design additionally scores **incidents**. They are
separate contracts so neither can be mistaken for the other.

---

## 4. LLM strategy

* **Provider:** Groq (groq.com), OpenAI-compatible endpoint, via the official `openai` SDK.
  *Note:* the project brief said "Grok" (xAI). The supplied key (`gsk_…`) is a **Groq** key.
  These are different companies. An xAI or Claude adapter is one additional provider file.
* **Abstraction (Phase 3):** `investigator/llm/base.py` defines the provider interface; the
  investigator depends only on it. Tests use a scripted `FakeProvider` (no network).
* **Fallback:** a deterministic `RuleBasedInvestigator` produces the same `InvestigationResult`
  with `source="fallback"`. Missing key, timeout, API error or invalid JSON → fallback, never a crash.
* **Bounds:** timeout, retries and max tokens come from `.env` (validated ranges in `config.py`).
* **Not the LLM's job:** connectivity, permissions, authorisation, command execution.

---

## 5. Security posture

| Threat | Control |
|---|---|
| API key leakage | `.env` gitignored; `SecretStr`; config errors never echo inputs; log redaction of configured secrets and key-shaped strings |
| Prompt injection via log fields | strict `Identifier` type at ingestion; evidence passed as delimited JSON data (Phase 3); schema-validated output; citations checked against incident evidence; **LLM has no tools** |
| Log injection | JSON-lines logging — embedded newlines are escaped inside one record |
| Unsafe response | `dry_run: Literal[True]`; approval state machine; no command execution anywhere |
| Audit tampering | hash chain (tamper-*evident*, not tamper-*proof*) |

These reduce prompt-injection risk; they do not eliminate it. The decisive control is that LLM output
cannot cause an action.

---

## 6. Data strategy and known gaps

* **Demo scenarios:** fully synthetic, users/hosts defined in the synthetic topology. Always labelled synthetic.
* **LANL:** used for ingestion robustness and detection behaviour on real traffic. LANL is anonymised
  (`U####`, `C####`), has relative-second timestamps, and **no IPs or geolocation**. A synthetic 50-node
  topology cannot validate paths between LANL hosts; building a graph from observed LANL edges is future work.
  LANL's `redteam.txt` provides labelled compromise events usable for evaluation later.
* **Processing:** batch over CSV (with optional replay), not streaming.

---

## 7. Critical reading notes on the reference paper

Recorded so our report does not inherit claims we cannot support.

1. **Reported, not reproduced:** 5,000-event LANL sample, 50-node synthetic topology, GPT-4 for
   hypotheses, ~506 ms total (480 ms LLM). These are the paper's results, not ours. We will measure
   and report our own timings separately.
2. **POC example vs. LANL data:** the worked example uses named entities (`user123`, `ws-fin-27`,
   `srv-fin-03`), a calendar timestamp, PowerShell use and credential-dumping indicators. LANL
   `auth.txt` is anonymised, uses relative time and contains no EDR/process data. The example is
   therefore best read as illustrative/enriched rather than raw LANL output.
3. **Geolocation:** Sec. IV-A lists "suspicious geolocation changes" as an alert source; LANL auth data
   has no location fields. We will not implement geolocation detection on LANL.
4. **Autonomy:** the paper describes autonomous execution of low-risk playbooks. Our scope is
   dry-run only, with human approval for high-impact actions — consistent with the paper's own
   stated limitation that responses were tested in dry-run mode (Sec. VI).
5. **Naming:** Sec. IV-C calls SSE "Structural Soundness Evaluation"; elsewhere it is the "Structural
   Simulation Engine". We use the latter.
6. **Verified:** Table V composites are arithmetically consistent with Eq. 1 at α=0.7, β=0.3
   (0.599, 0.498, 0.105). Our test suite reproduces them (`test_reproduces_paper_table_v`).
7. **Benign hypotheses in SSE:** the paper rejects benign H3 structurally ("no service/task associated
   with user123"). We will validate benign hypotheses too (e.g. an admin's scheduled task is a modelled edge).

---

## 8. Layer 1 ingestion (Phase 1)

```
auth.txt / auth.txt.gz / LANL-format file
   │  stream line by line (never loads the whole file), hash consumed bytes
   ▼
parse_lanl_line ──► AuthEvent        (validated; `?`/empty optionals → None)
   │            └─► RejectedRecord   (line, reason, field, detail, 200-char excerpt)
   ▼
IngestionResult  (events sorted by time; counts of blanks, duplicates, out-of-order)
   ├─► build_quality_report ──► DataQualityReport (JSON) + Markdown
   └─► write_processed_dataset ──► events.jsonl, rejected.jsonl, quality_report.*, manifest.json
```

| Decision | Rationale |
|---|---|
| Validate, never repair | Guessing a missing user or host would fabricate evidence. |
| Rejected lines kept with reason + excerpt | Data problems stay visible and auditable; excerpts never reach detection or the LLM. |
| Exact duplicates kept, counted | LANL legitimately logs identical auths within one second. |
| Output sorted by (time, source line) | Deterministic order for correlation and reproducibility. |
| LANL `time` → `base_time + offset` (default Unix epoch) | LANL time is anonymised; the base is recorded in the manifest so the offset is recoverable. |
| JSONL + manifest (not SQLite yet) | A processed dataset is an immutable artifact; JSONL is diffable and hashable. |
| `dataset` provenance threaded through parser | A synthetic file in LANL format is labelled `synthetic`, never `lanl`. |
| ASCII-digit time regex | `int()` accepts non-ASCII digits (e.g. `٥`); we don't. |

Rejection reasons: `WRONG_FIELD_COUNT`, `MISSING_REQUIRED_FIELD`, `INVALID_TIMESTAMP`,
`INVALID_ORIENTATION`, `INVALID_OUTCOME`, `INVALID_FIELD` (unsafe/oversized identifier),
`LINE_TOO_LONG` (>1024 chars), `ENCODING_ERROR` (invalid UTF-8).

---

## 9. Layer 1 detection and correlation (Phase 2)

```
processed dataset dir(s)
   │ load_verified_inputs: manifest hash + count (Phase 1 loader), provenance agreement,
   │                       no event_id collisions across inputs
   ▼
run_detection — per provenance partition (synthetic / lanl / upload never mixed):
   pre-process: sort → exclude machine/system accounts → collapse exact duplicates
   baseline:    [first event, first + baseline_seconds) → per-user familiar src/dst hosts
                (successful access events only)
   rules:       failure rules over the whole range; novelty rules after the baseline
   ▼
Findings (FND-xxxxx) ──► correlate by (provenance, user, time gap / shared evidence)
   ▼
Incidents (INC-xxxxx) ──► verify_evidence (every cited ID exists in the verified input)
   ▼
detections.jsonl, incidents.jsonl, detection_summary.json, detection_report.md
```

### Rules

All thresholds live in `config/detection.json` (unknown keys rejected) and are
**heuristics**, not empirically established attack boundaries.

| Rule | Logic | Defaults | Key assumptions / limitations | Tests |
|---|---|---|---|---|
| `FAILURE_BURST` | ≥ N failures (LogOn/TGT/TGS, outcome Fail) by one source user within W; overlapping windows merged into one finding | N=5, W=600 s, MEDIUM | Can't tell guessing from stale credentials; no failure reason codes | threshold, below threshold, spread beyond window, merge/split, LogOff ignored, missing optional fields |
| `FAIL_THEN_SUCCESS` | success (not LogOff) preceded by ≥ M **consecutive** failures, all within W before it | M=3, W=600 s, HIGH | Consistent with both guessing and legitimate recovery; source host need not match | fires, outside window, reset by intervening success, LogOff, configurable M |
| `NEW_SRC_HOST` | first post-baseline successful access from a source host absent from the user's baseline | LOW | Baseline-relative; users without baseline skipped (reported) | flagged once, inside-baseline never novel, no-baseline users, failures don't build baseline |
| `NEW_DST_HOST` | as above for destination host | LOW | same | same |
| `MULTI_HOST_SPREAD` | ≥ K first-seen destinations within W | K=3, W=3600 s, MEDIUM | Familiar hosts ignored | fires, beyond window, revisits not double-counted |
| `LATERAL_CHAIN` | remote hops (src≠dst) by one account where each hop starts on the previous hop's destination, gap ≤ G; maximal chains of ≥ H hops with ≥1 first-seen hop; no revisits | H=2, G=1800 s, HIGH | Sequential authentication ≠ host control; account switches and unlogged pivots missed | 2-hop, maximal only, star pattern, gap, all-familiar, loops, min hops |
| `SENSITIVE_HOST_ACCESS` | first-seen access to a host in a configured list | list empty, HIGH | Static list, not asset-criticality scoring | fires, familiar host silent, inert without list |

Every rule can be disabled (`enabled: false`; parametrised test).

### Pre-processing

* **Excluded accounts** (regex, full match): `.+\$@.+` (machine accounts), `ANONYMOUS LOGON@.+`,
  `(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)@.+`. Counted in the summary. Attacks via these
  principals are therefore not detected by default — a deliberate noise/coverage trade-off.
* **Exact duplicates** (same content, different line) are collapsed before counting so LANL's
  same-second duplicates don't inflate failure counts. Configurable.

### Correlation

Group by (provenance, principal = source user). Sort findings by first_seen; a finding joins the
current incident if it starts ≤ `correlation_gap_seconds` (3600) after the incident's latest event
or shares an evidence event. No cross-user or host-centric correlation yet.

### Incident severity (triage priority, not probability of compromise)

`severity = band(Σ points of DISTINCT rules)` with points FAILURE_BURST 2, FAIL_THEN_SUCCESS 3,
NEW_SRC_HOST 1, NEW_DST_HOST 1, MULTI_HOST_SPREAD 2, LATERAL_CHAIN 3, SENSITIVE_HOST_ACCESS 3 and
bands MEDIUM ≥ 3, HIGH ≥ 5, CRITICAL ≥ 8. Configured admin accounts are lowered one band (never
suppressed). The calculation is written into each incident's `severity_rationale`.

Known weakness: rules are **correlated signals** — one event can satisfy NEW_DST_HOST,
NEW_SRC_HOST, SENSITIVE_HOST_ACCESS and contribute to MULTI_HOST_SPREAD — so summing points
overstates independent evidence. Acceptable for ranking; to be replaced by the Phase 5 risk model.

Finding severity (per rule) and incident severity (per incident) are different quantities.

### Evidence-first guarantees

* Rules only return subsets of their input events; IDs and timestamps are copied, never created.
* `verify_evidence` runs in the engine and again before writing, against exactly the inputs recorded
  as provenance.
* Each incident carries per-rule benign explanations, limitations, missing information, dataset
  limitations (synthetic / LANL) and the statement that no endpoint, malware, PowerShell or
  credential-dumping evidence exists in authentication logs.

### Reproducibility

Finding and incident IDs are assigned after deterministic sorting. `detections.jsonl`,
`incidents.jsonl` and `detection_report.md` are byte-identical across runs;
`detection_summary.json` differs only in `generated_at` and records config SHA-256, input manifest
hashes and output hashes.

---

## 10. Investigator Agent and dashboard (demo MVP)

```
Incident + verified evidence events
   ▼ prompts.py: system rules + <incident_data> JSON block (untrusted), injection flagging
LLMProvider (Groq) ──text──► grounding.py: JSON parse → schema → cited IDs ⊆ incident,
   │                          ≥1 MALICIOUS + ≥1 BENIGN, ATT&CK format, telemetry-claim flags
   │   invalid → 1 repair round (errors fed back) → still invalid ─┐
   │   timeout / 429 / auth / unreachable ─────────────────────────┤
   ▼                                                               ▼
InvestigationResult (source=llm)                      fallback.py (source=fallback)
   ▼ store.py: saved per incident SHA-256 → dashboard (Streamlit), never re-called on refresh
```

* The agent never raises for LLM problems; the result always states its provider.
* `is_proof_of_compromise: Literal[False]`: the contract cannot express proof.
* Fallback confidences are fixed, documented heuristics (`fallback.py` docstring).
* Dashboard data comes only from hash-verified outputs; evidence is streamed by ID.

---

## 11. Directory layout

```
src/agentsoc/
  config.py           environment settings (pydantic-settings)
  logging_setup.py    JSON logs + secret redaction
  exceptions.py       AgentSOCError hierarchy
  schemas/            inter-layer contracts (this document §3)
  perception/         lanl.py (parser), records.py, quality.py      [Phase 1]
  detection/          catalog, config, baseline, rules, correlate,
                      engine, inputs, report                        [Phase 2]
  data_gen/           scenarios.py (synthetic LANL-format)          [Phase 2]
  store/              datasets.py [Phase 1], detections.py [Phase 2]
  evaluation/         measure, lanl_validation, report, validate    [Phase 2 validation;
                      reads outputs only, never feeds labels back]
  cli.py              command-line entry points
  # created in their own phases — never as empty stubs:
  investigator/       agent, prompts, grounding, fallback, store, llm/{base,groq}  [demo MVP]
  app_data.py         dashboard data access (verified sources)       [demo MVP]
  graph/  risk/  response/  pipeline.py
app/                  Streamlit SOC dashboard (demo MVP)
config/               detection.json (Phase 2); topology/policy (Phases 4–5)
data/samples/         small hand-written / generated inputs (committed, provenance in README)
data/raw/             LANL etc. (gitignored)
data/processed/       ingestion outputs (gitignored; regenerate with scripts/ingest_lanl.py)
docs/reference/       paper PDF (gitignored)
scripts/              CLI entry points
tests/unit, tests/integration
```
