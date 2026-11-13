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
          │ Incident
 ┌────────▼─────────┐  deterministic (NetworkX)
 │ L3 Graph (SSE)   │  pre-LLM: structural evidence from surrounding authentication events
 └────────┬─────────┘
          │ StructuralAssessment  (citable: incident events + events on validated paths)
 ┌────────▼─────────┐  PROBABILISTIC (LLM) — fallback: rule-based investigator
 │ L2 Investigator  │  ≥1 malicious + ≥1 benign hypothesis, each citing event IDs
 │      (NCE)       │
 └────────┬─────────┘
          │ proposed paths → SSE post-LLM check: FEASIBLE / CONDITIONALLY_FEASIBLE / INFEASIBLE
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
| Agentic Reasoning: SSE | `graph/` | **Done — Target 2** (observed logs only, no enterprise topology; runs before and after the LLM) |
| Agentic Reasoning: RSEM (Eq. 1) | `risk/` | **Done — Target 3** (incident risk, confidence, dry-run action ranking) |
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
  topology cannot validate paths between LANL hosts, so the SSE validates against observed LANL edges only (§12).
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
| `LATERAL_CHAIN` | remote hops (src≠dst) by one account where each hop starts on the previous hop's destination, gap ≤ G; maximal chains of ≥ H hops with ≥1 first-seen hop; no revisits | H=2, G=1800 s, HIGH | Sequential authentication ≠ host control; account switches and unlogged pivots missed. Findings also carry path metrics (see below) | 2-hop, maximal only, star pattern, gap (±1 s), all-familiar, loops, min hops, failed hops |
| `SENSITIVE_HOST_ACCESS` | first-seen access to a host in a configured list | list empty, HIGH | Static list, not asset-criticality scoring | fires, familiar host silent, inert without list |
| `CROSS_ACCOUNT_PIVOT` | account A arrives on host H (remote, successful); within W a **different** account B leaves H for another host, using H as a source for the first time since its baseline and without having logged on to H itself in W | W=1800 s, LOW, 1 point | Two accounts sharing a host in time; **does not show that credentials were transferred or compromised**. Shared hosts make it likely by chance (`other_accounts_on_host`) | window (±1 s), same second, failed arrival/departure, LogOff, local logon, own arrival, same name in another domain, no baseline, duplicates, evidence cap, provenance |

Every rule can be disabled (`enabled: false`; parametrised test).

### Lateral-movement context (`detection/lateral.py`, engine `auth-detect/1.1`)

`LATERAL_CHAIN` itself is unchanged (`rules.py`); `enrich_chains` wraps its output and adds
`distinct_hosts`, `longest_hop_gap_seconds`, `sensitive_hosts_on_path` and
`ends_on_sensitive_host`. The set of chains and their evidence do not change.

**Only successful access events are movement.** A failed logon never extends a chain and never
places an account on a host. Events in the same second have no known order, so a departure only
sees arrivals from earlier seconds. Account names are compared without the domain, because LANL
records one user under several domains.

**`jump_hosts`** (regexes, full match, empty by default) is context from the operator:

* Findings on jump hosts are never dropped. A host that is not configured gets no label at all,
  so it is treated as unknown, neither benign nor malicious.
* `benign_context` is added when the account acted from a configured jump host.
* Severity is lowered only if **every** transit host is a jump host and no sensitive host is on
  the path. The finding drops one band and `severity_adjustment` records it. The rule loses
  `jump_host_point_reduction` points (default 1, never below 1) only if all of its findings in
  the incident were adjusted, and the rationale states this.

### Pre-processing

* **Excluded accounts** (regex, full match): `.+\$@.+` (machine accounts), `ANONYMOUS LOGON@.+`,
  `(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)@.+`. Counted in the summary. Attacks via these
  principals are therefore not detected by default — a deliberate noise/coverage trade-off.
* **Exact duplicates** (same content, different line) are collapsed before counting so LANL's
  same-second duplicates don't inflate failure counts. Configurable.

### Correlation

Group by (provenance, principal = source user). Sort findings by first_seen; a finding joins the
current incident if it starts ≤ `correlation_gap_seconds` (3600) after the incident's latest event
or shares an evidence event. Incidents stay per account: a `CROSS_ACCOUNT_PIVOT` belongs to the
departing account and lists the arriving account in `involved_users`, but the two accounts'
incidents are not merged, so correlation never implies that one account compromised another.

### Incident severity (triage priority, not probability of compromise)

`severity = band(Σ points of DISTINCT rules)` with points FAILURE_BURST 2, FAIL_THEN_SUCCESS 3,
NEW_SRC_HOST 1, NEW_DST_HOST 1, MULTI_HOST_SPREAD 2, LATERAL_CHAIN 3, SENSITIVE_HOST_ACCESS 3 and
bands MEDIUM ≥ 3, HIGH ≥ 5, CRITICAL ≥ 8. Configured admin accounts are lowered one band (never
suppressed). The calculation is written into each incident's `severity_rationale`.

Known weakness: rules are **correlated signals** — one event can satisfy NEW_DST_HOST,
NEW_SRC_HOST, SENSITIVE_HOST_ACCESS and contribute to MULTI_HOST_SPREAD — so summing points
overstates independent evidence. Acceptable for immediate triage; RSEM (§13) sits above it and
credits each event once.
One overlap is removed now: a pivot's departure is also a `NEW_SRC_HOST` event, so the two rules
count once, and the rationale says which one was not scored. At default weights the pivot rule
therefore cannot raise an incident's band.

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

## 11. Web application (REST API + React)

```
React SPA (frontend/: Vite + TypeScript + Tailwind, React Query, Recharts)
   │  fetch /api/*   (dev: Vite proxy → :8000; built: same origin)
   ▼
FastAPI (agentsoc.api.app) — sync endpoints run in a worker pool, so a slow LLM call
   │                          never blocks other requests
   ▼
agentsoc.api.service.Service ── app_data (verified sources, streamed evidence)
   │                         ├─ investigator.agent (LLM → grounding → fallback)
   │                         ├─ investigator.store (results bound to incident SHA-256)
   │                         └─ AuditRecord hash chain → <data root>/activity_log.jsonl
   ▼
existing Phase 1/2 outputs (hash-verified on load)
```

| Endpoint | Purpose |
|---|---|
| `GET /api/health`, `/api/sources` | status (analysis available/limited); sources with provenance |
| `GET /api/overview` | counts, severity, rule activity, recent incidents — from detection output |
| `GET /api/incidents` | search `q`, `severity`, `provenance`, `rule`, sort, pagination |
| `GET /api/incidents/{id}`, `/evidence` | detail: timeline, findings, shared evidence |
| `GET /api/incidents/{id}/investigation`, `POST …/investigate?rerun=` | saved result; run |
| `GET /api/investigations`, `/{id}` | history across sources; open one |
| `GET /api/events` | evidence explorer (`scope=evidence` or `all`, filters, pagination) |
| `GET /api/datasets`, `/api/activity` | provenance + verification; hash-chained activity log |
| `GET /api/incidents/{id}/structure`, `/graph`, `/risk` | structural assessment; display graph; risk (§12–14) |

Design rules:
* **No security logic in the UI.** Every number and record comes from the API.
* **Automatic investigation path.** Provider selection is server-side. Agent warnings that
  describe the provider path (`DIAGNOSTIC_PREFIXES`) are logged server-side and never returned;
  the result carries `status: completed | completed_limited` and a collapsed `diagnostics` block.
* **Duplicate clicks:** per-(source, incident fingerprint) lock — concurrent requests wait and
  receive the saved result; the button is disabled while a run is pending.
* **Safe errors:** 404/400/422/503 with fixed messages; unexpected errors → generic 500 with
  details only in server logs.
* The Streamlit dashboard (`app/`) is deprecated.

---

## 12. Structural Simulation Engine (`graph/`, engine `sse/1.0`)

```
detection outputs + hash-verified events.jsonl
   │  build_event_index: one streaming pass, shared by all incidents of a run
   ▼
per incident: expand_context (bounded, forward-only and backward-only from rule-cited events)
   ├─ authentication graph (MultiDiGraph): user + host nodes, one edge per event
   └─ time-expanded event graph (DiGraph): arc = shared host + later time + gap within limit
   ▼
validate: paths, finding validation, sequences, disconnections, choke hosts, cycles
   ▼
verify_assessment: plain Python re-check against the original events (shares no graph code)
   ▼
<detection dir>/structural/{assessments.jsonl, structural_summary.json}
   │                                                  (detection files are never rewritten)
   ├─ pre-LLM: validated evidence enters the prompt as untrusted data
   └─ post-LLM: every proposed hop is checked against the graph and the original events
```

**Observed logs only.** The paper validates against an enterprise topology; LANL has none and
none is assumed. This is a deliberate difference from the paper. No link exists without a shared
host and a valid time order, and evidence is never invented or repaired.

| Verdict | Meaning |
|---|---|
| `FEASIBLE` | observed evidence supports every link |
| `CONDITIONALLY_FEASIBLE` | every hop was observed, but linking them needs a stated assumption (an account switch, or an unprovable same-second order) |
| `INFEASIBLE` | required evidence is missing or a claimed link is unsupported. **Not** proof that movement was impossible |

Every path and assessment carries `is_proof_of_compromise: false`.

**Graph rules.** Only successful access events with source ≠ destination are movement. Failed
attempts are separate edges that explain a gap but never form a path or relate an account to a
host. Time-order is strict, because events in one second have no known order. Events within one
partition only: provenance is never crossed. Exact duplicates collapse to one edge that keeps
every event ID.

**What it adds beyond the rules.** Upstream and downstream expansion through events no rule cited,
walks through revisited hosts (the event graph is acyclic even when hosts form cycles),
cross-account paths, reasons why suspicious events do not connect, and hosts every observed route
must cross (`immediate_dominators`). A test keeps a naive findings-to-edges graph and requires it
to fail where the SSE succeeds.

**Shared servers.** An account-switch link through a host that more than
`ambiguous_link_accounts` (default 3) other accounts reached in the window is marked `ambiguous`
and stated as weak evidence in the path's conditions.

**Bounds, all disclosed in `stats.truncation_reasons` when reached:** `max_expansion_hops` (3),
`max_links_per_event` (8; same-account links and links between two rule-cited events are always
kept), `max_context_events` (2,000), `max_paths` (20), `max_anchors_compared` (200).
Configuration is `config/structural.json`, with its own hash, separate from detection config.

**Post-LLM.** `Hypothesis.proposed_path` is checked hop by hop. `InvestigationResult` cannot be
built with a proposed path that has no validation, and the API returns a proposal only together
with its verdict. Structural results never change fallback confidence values or incident severity.

| Endpoint | Purpose |
|---|---|
| `GET /api/incidents/{id}/structure` | stored `StructuralAssessment`; 404 if none was built or it is stale |

---

## 13. Risk Scoring and Evaluation Module (`risk/`, engine `rsem/1.0`)

Three separate numbers: **incident risk** (how much evidence-supported risk), **investigation
confidence** (how far that assessment can be relied on) and **action priority** (which proposal
to consider first). None is a calibrated probability. Priority is computed after the risk and
never changes it. Detection severity is reported beside the risk, is not an input to it, and
stays the default dashboard sort.

```
stored detection + structural outputs (hash-verified)
   ▼
ledger: each event credited to at most one component → score → confidence → actions
   ▼
verify: plain recomputation that shares no code with the scorer
   ▼
<detection dir>/risk/{risk_records.jsonl, risk_summary.json}
```

```
base  = 100 × Σ weight × value        score = base × quality × admin, then caps
```

| Component | Weight | Value |
|---|---|---|
| `credential_pressure` | 15% | highest of fail-then-success .8, failure burst .5; credits failed events only |
| `access_novelty` | 10% | first-seen events not credited elsewhere ÷ 5 |
| `movement_depth` | 35% | effective hops of the selected route: 1→0, 2→.6, 3→.85, 4+→1 |
| `sequence_breadth` | 10% | connected suspicious events off the route ÷ 4; another account's event counts half, and only with non-ambiguous support |
| `sensitive_exposure` | 30% | observed path reaches a configured sensitive host 1; inferred .5; ambiguous .2 |

Bands: Low <20, Medium <45, High <70, Critical ≥70. `config/risk.json` has its own hash.

**Attribution.** The ledger picks the highest-value attribution among all allowed ones, where a
route is any contiguous stretch of a reported path. Removing evidence can only shrink that set,
which is what guarantees monotonicity. `sensitive_exposure` values the host reached; it is not an
event count, so it credits no event, and the event stays credited to one evidence component.

**Effective hops.** Same-account stretch + other hops × .5 (× .2 if a link is ambiguous). A route
through only configured jump hosts counts × .85, never if a sensitive host is on it.

**Adjustments, each recorded.** Quality: −.2 missing evidence, −.1 truncated context, −.1
infeasible finding, floor .6. Configured admin ×.85 unless a sensitive host is exposed. No
credential, first-seen or sensitive signal: capped below High, so graph structure alone cannot
reach High. No observed multi-hop route: capped below Critical.

**Investigation confidence** = 100 × (.30 evidence found + .25 structural support + .15 baseline
coverage + .10 context complete + .20 investigation quality). Missing baseline lowers this and
never raises risk. Investigation quality uses only facts about how the investigation was
produced; the model's numeric confidence is in no score and is returned separately, labelled.
Stored records hold the pre-investigation value; the API refines it when an investigation exists.

**Actions** use the paper's Eq. 1, `0.7×C − 0.3×I`. Isolate, disable and monitor use Table V
values; the other four are assumptions. Every action stays `PROPOSED` and `dry_run`, only
`MONITOR_ONLY` skips approval, and targets come only from the evidence. Isolate, disable and
quarantine need High band, confidence ≥ 50 and an observed multi-hop route; otherwise they are
listed as withheld, with reasons.

**Serving.** `GET /api/incidents/{id}/risk` returns a record only if its hashes match and its
scores reproduce under `verify_record`.

---

## 14. Integrated dashboard (0.9.0)

```
stored outputs (hash-verified)    detection · structural · risk · investigations
   ▼
api/service.py   verify, then report one state per stage:
                 available | not_assessed | stale | unavailable
   ▼
/graph → graph/view.py → build_authentication_graph (NetworkX) → nodes, bundled links, paths
/risk  → verified record + refined confidence + points per component
   ▼
React tabs (Attack graph, Risk & response, AI investigation, Provenance; URL ?tab= and ?path=)
   ▼
graph-model.ts + dagre: node positions only (lazy-loaded chunk with React Flow)
```

**One rule: the browser displays and positions.** It holds no scoring, path search or validity
logic. Every drawn edge is one server link, which lists its original event IDs. Path highlighting
reads the server's `link_ids`.

**Inferred paths add no edge.** Each hop is an observed event; the assumption is the account
switch between them, shown as a marked host with its stated condition. Failed attempts never join
a path. Local logons appear on their host. Styles do not rely on colour alone: selected observed
paths are solid, inferred paths dashed, weak-evidence paths dotted and labelled, failures dotted
with a ✕ label.

| Addition (all read-only and additive) | Purpose |
|---|---|
| `GET /api/incidents/{id}/graph` | nodes, bundled links, events, paths, findings, truncation |
| `IncidentSummary.risk_score`, `risk_band` | from verified records, else null |
| `Overview.risk_counts`, `risk_assessed`, `risk_status` | risk distribution, else null with a reason |
| `IncidentDetail.assessments` | per-stage state and truncation for this incident |
| `RiskView.contributions` | points per component, so the UI need not calculate them |
| `DatasetInfo.structural`, `.risk` | engine, configuration and output hashes, state |
| `GET /api/activity?subject=&source=` | server-side filter applied before the limit; the chain check still covers the whole log |

`scripts/prepare_demo_sources.py` builds the synthetic risk scenarios and writes
`data/processed/demo_sources.json`, which references existing LANL runs without writing to them.
A registry entry is refused if its path leaves the data root or its declared provenance differs
from the dataset manifest. Without the registry the dashboard shows only its default sources.

Proposed actions are display-only. No API route can change an action, and the only POST route is
the investigation.

---

## 15. Phase A foundations: accounts, credentials, event index

Groundwork for organisational data sources. No connector exists yet. Operator-facing detail is in
[docs/security_foundations.md](docs/security_foundations.md).

| Module | Responsibility |
|---|---|
| `store/appdb.py` | Application database (SQLite, WAL, foreign keys). Versioned with `PRAGMA user_version`; forward-only migrations; a newer schema is refused rather than downgraded. Tables: `users`, `sessions`, `credentials`. |
| `auth/passwords.py` | scrypt hashes (`scrypt$n$r$p$salt$hash`), bounded parameters on verify, constant-time compare, password policy. |
| `auth/service.py` | Accounts, roles (`admin`, `analyst`), lockout, sessions (token stored as SHA-256, idle and absolute expiry, per-session CSRF token). At least one active admin; no self role change or self disable; role change, disable and reset end the user's sessions. |
| `auth/api.py` | `/api/auth/*`, `/api/admin/users*`; `current_user`, `require_admin`, `require_csrf` dependencies; per-address failure limiter. |
| `audit.py` | One `AuditLog` for every writer: fixed `AuditEventType` catalogue, acting user from a `ContextVar` set by `current_user`, thread lock plus cross-process file lock around the hash chain. |
| `credentials.py` | `CredentialStore` protocol; `EncryptedCredentialStore` (Fernet/MultiFernet, key from `AGENTSOC_CREDENTIAL_KEY`, payload bound to its reference, rotation). Secrets are never returned by the API and are registered for log redaction when decrypted. |
| `store/eventdb.py` | Per-source SQLite event index built from a verified dataset (hash checked while streaming, built to a temporary file, then atomically replaced), opened read-only. Search, outcome histogram, allow-listed distinct values, and a JSONL export byte-identical to the source. |
| `app_data.py` | `Source.time_display`: `relative` (existing `Day N` labels) or `absolute` (UTC, zone stated). |

Every API route except `GET /api/health` requires a session; every state-changing route also
requires the CSRF header. The detection, SSE, RSEM and investigator engines are unchanged and
still read the verified JSONL datasets in memory. The event index is an additional read path,
not their input. Benchmark: [docs/phaseA_event_store_benchmark.md](docs/phaseA_event_store_benchmark.md).

**Known limits.** Detection runs remain immutable snapshots; incident IDs are not stable across
runs. Substring search on the index is a table scan (about 0.2–0.35 s at 400–500k events).
Rate limits are per process. There is no MFA or SSO.

---

## 16. Directory layout

```
src/agentsoc/
  config.py           environment settings (pydantic-settings)
  logging_setup.py    JSON logs + secret redaction
  exceptions.py       AgentSOCError hierarchy
  schemas/            inter-layer contracts (this document §3)
  perception/         lanl.py (parser), records.py, quality.py      [Phase 1]
  detection/          catalog, config, baseline, rules, correlate,
                      engine, inputs, report                        [Phase 2]
                      lateral (pivot rule, chain context)           [Target 1]
  data_gen/           scenarios.py (synthetic LANL-format)          [Phase 2]
                      lateral_scenarios.py                          [Target 1]
  store/              datasets.py [Phase 1], detections.py [Phase 2],
                      appdb.py, eventdb.py [Phase A]
  evaluation/         measure, lanl_validation, report, validate    [Phase 2 validation;
                      reads outputs only, never feeds labels back]
                      lateral_report                                [Target 1]
  cli.py              command-line entry points
  # created in their own phases — never as empty stubs:
  investigator/       agent, prompts, grounding, fallback, store, llm/{base,groq}  [demo MVP]
  app_data.py         verified data sources (API + legacy dashboard)
  auth/               passwords, service, api (accounts, sessions)   [Phase A]
  audit.py            shared hash-chained activity log               [Phase A]
  credentials.py      encrypted credential store                     [Phase A]
  api/                FastAPI app, service layer, response models    [web app]
  graph/              index, build, validate, verify, proposed, assess, store  [Target 2]
  risk/               ledger, score, confidence, actions, verify, assess, store  [Target 3]
  response/  pipeline.py
frontend/             React web application (Vite, TypeScript, Tailwind)  [web app]
app/                  Streamlit dashboard — deprecated
config/               detection.json (Phase 2); topology/policy (Phases 4–5)
data/samples/         small hand-written / generated inputs (committed, provenance in README)
data/raw/             LANL etc. (gitignored)
data/processed/       ingestion outputs (gitignored; regenerate with scripts/ingest_lanl.py)
docs/reference/       paper PDF (gitignored)
scripts/              CLI entry points
tests/unit, tests/integration
```
