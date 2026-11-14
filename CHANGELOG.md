# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Multi-agent investigation (proposed architecture) — awaiting review

#### Added
- **MySQL connector** (`connectors/mysql.py`, PyMySQL 1.1.1): read-only sessions verified
  with `@@transaction_read_only`, client-side read timeouts, backtick-quoted identifiers,
  listing limited to the configured database, fixed error messages. The Connections page
  offers PostgreSQL or MySQL, with each engine's default port. Application database schema 4
  allows MySQL sources; existing rows are copied unchanged. Verified against a simulated
  driver only; not yet verified against a real MySQL server.
- **How to stop this** (`agents/response.py`): a response plan after correlation. It sets
  the posture (contain now, verify first, monitor, or closed when dismissed) and lists steps in
  four phases (contain, investigate, recover, prevent). Each step names its evidence and the
  agents behind it, is marked disruptive when it needs approval, and is flagged when the risk
  engine proposed the same action. Nothing is executed. Shown on the Agents tab, in the
  pipeline, in the report and in the Markdown export.
- **Agent orchestrator** (`agents/orchestrator.py`) creates one task per specialised agent,
  runs them in parallel with a time limit, and isolates failures (a failed or slow agent is
  reported as such; the others still finish).
- **Specialised agents**, all deterministic and read-only:
  - Identity: the account against its own history (failure rate, first-time hosts and source
    hosts, unusual hours, administrator or service accounts).
  - Network / host: connections never seen before, fan-out, sensitive and jump hosts, SSE
    paths and choke points; with more evidence, other accounts on the same hosts, spraying
    patterns and possible account switches.
  - Threat intelligence: offline MITRE ATT&CK mapping and an optional local watchlist
    (`config/threat_intel.json`; see `.example.json`). No external feed is queried.
  - Endpoint: AgentSOC has no endpoint telemetry, so it reports *unavailable* and lists the
    endpoint records to request for each host. It never invents findings.
- **Incident correlation agent** combines findings by account and host: corroborated (two or
  more agents), conflicts (agents disagree), open questions.
- The **reasoning layer** (AI investigation) receives the correlated findings as an extra
  untrusted data block; without them its prompt is unchanged. The fallback is unchanged.
- **More evidence** re-runs the agents over ±1/6/24/72 h. `GET /api/incidents/{id}/agents`.
  New **Agents** tab with the pipeline, each agent's findings and gaps, and the correlation.
  The report includes the agents section.

#### Not changed
- Detection, SSE, RSEM; stored outputs; response actions stay dry-run.

### Analyst decisions (human in the loop) and a tidier workspace — awaiting review

#### Added
- Every incident has an **analyst decision**: Accept (confirmed, needs follow-up), Dismiss
  (reason required: expected activity, false positive, duplicate, authorised test, or other
  with a note), or **More evidence**. Decisions are append-only, tied to the incident's
  content hash, audited (`incident.*`), and can be reopened. They never execute anything.
- **More evidence:** AgentSOC searches the same verified data (±1/6/24/72 h). It finds the
  account's other activity, activity on the same hosts, whether each connection was ever seen
  before, and related incidents. It reports facts only.
- **Full report** per incident (`/incidents/:id/report`): decision history, summary, findings,
  timeline, attack paths, risk and dry-run proposals, investigation, wider context,
  limitations and provenance. Print or save as PDF, or download Markdown (escaped; audited).
- API: `GET/POST /api/incidents/{id}/review`, `GET …/context`, `GET …/report`,
  `GET …/report.md`, and `review=` filter on `/api/incidents`. Application database schema 3.

#### Changed
- Incident page: a decision bar above the tabs; 8 tabs merged into 6 (Summary now includes
  detection findings; Evidence holds the timeline, the table and the wider context). Old
  `?tab=timeline` and `?tab=detection` links still work.
- Incident list is a review queue with decision filters and a Decision column. The overview
  starts with the number of incidents awaiting a decision. The menu is grouped into Triage,
  Investigate, Data & audit, and Administration.

#### Not changed
- Detection, SSE, RSEM and investigator logic; stored outputs; response actions stay dry-run.

### Organisation databases: mapping (C) and PostgreSQL connector (D) — awaiting review

**The PostgreSQL connector is tested against a simulated database only. It is not yet
verified against a real PostgreSQL server.**

#### Added
- Column mapping (`ingest/mapping.py`): rows become events or rejections with a reason.
  Constants need explicit confirmation and are disclosed. Header CSV import
  (`ingest/csv_import.py`) gives detections identical to the LANL parser on the demo.
- Read-only PostgreSQL connector (`connectors/postgres.py`, psycopg 3.3.9).
- Polling sync with checkpoints, idempotent storage, look-back for late rows, capture of the
  original rows, and safe resume (`orgsource/`). Immutable snapshots analysed by the
  unchanged engines and shown as `organization` data sources with UTC times.
- Admin **Database Connections** page and `/api/admin/datasources*`. Analyst status at
  `/api/datasources/organisation`. AI investigation is off per source until an administrator
  allows it after a warning.
- `AGENTSOC_SYNC_SCHEDULER` (default on). Application database schema 2 (`data_sources`).
- `docs/organisation_databases.md`, `scripts/postgres_test_fixture.sql`.

#### Not changed
- Detection, SSE, RSEM and investigator logic; `RawRef`; existing datasets and outputs.

### Phase A — Foundations (awaiting review)

#### Added
- Local accounts with administrator and analyst roles; scrypt password hashes; HttpOnly,
  SameSite=Strict session cookies with idle and absolute expiry; CSRF tokens; account lockout
  and a per-address failure limit. Sign-in, Account and (administrators) Users pages.
- `scripts/manage_users.py` to create the first administrator; there is no default account.
- Encrypted credential store (Fernet, key from `AGENTSOC_CREDENTIAL_KEY`, rotation) and
  `scripts/manage_credentials.py`. Nothing uses it until Phase D.
- Versioned application database (`store/appdb.py`) and a shared audit log with an event-type
  catalogue, the signed-in user as actor, and a cross-process lock.
- Per-source SQLite event index (`store/eventdb.py`, `scripts/build_event_index.py`) and
  `scripts/benchmark_event_store.py`.
- Optional absolute (UTC) time display per source.
- `cryptography==50.0.2`.

#### Changed
- **Every API route except `/api/health` now requires sign-in.** The audit actor is the signed-in
  user instead of the fixed `analyst-local`.
- Security headers on all responses; `Cache-Control: no-store` on the API.

#### Not changed
- Detection, SSE, RSEM and investigator logic; `RawRef`; stored datasets, detections,
  assessments and investigations; relative `Day N` labels for existing sources.

## [0.9.0] — 2026-11-09 — Final dashboard integration

### Added
- Incident tabs: Attack graph, Risk & response, Provenance. Validated proposed paths in AI
  investigation. Risk distribution on the overview; risk in the incident list and header.
- `GET /api/incidents/{id}/graph`; additive risk, assessment-state and provenance fields;
  `GET /api/activity?subject=&source=`.
- `scripts/prepare_demo_sources.py` and a provenance-checked source registry.
- `@xyflow/react` and `@dagrejs/dagre`, loaded only with the Attack graph tab. Dev: `axe-core`,
  `puppeteer-core`, `npm run test:e2e`.

### Changed
- Darker text and status tokens, and focusable scrolling tables, after browser accessibility checks.

### Not changed
- Detection, structural and risk logic; stored outputs; severity as the default sort. Actions stay
  proposed and dry-run; nothing can approve or execute them.

## [0.8.0] — 2026-11-09 — Target 3: Risk Scoring and Evaluation Module

### Added
- `agentsoc.risk`: evidence attribution ledger, deterministic risk score (0-100), separate
  investigation confidence, ranked and gated dry-run actions, independent verifier, hash-bound
  persistence in `<detection dir>/risk/`.
- `config/risk.json` with its own hash; `scripts/assess_risk.py`;
  `GET /api/incidents/{id}/risk`; `scripts/evaluate_risk.py` with separate synthetic and LANL
  reports in `docs/`.
- `schemas.rsem`: `IncidentRiskRecord` and supporting types; reuses `IncidentRiskAssessment`,
  `RiskComponent`, `ActionScore` and `ResponseAction`.
- SYNTHETIC risk scenarios with hand-worked scores; 164 tests.

### Changed
- `generate_scenarios.py --set` accepts `risk`. The demo build also creates risk records.

### Not changed
- Detection engine, severity, structural engine, investigator, and all stored detection and
  structural outputs (40 files byte-identical). The model's numeric confidence is in no score.

## [0.7.0] — 2026-11-09 — Target 2: Structural Simulation Engine (NetworkX)

### Added
- `agentsoc.graph`: shared streaming event index, authentication graph and time-expanded event
  graph, path/finding/disconnection/choke-host validation, an independent verifier against the
  original events, post-LLM validation of proposed paths, hash-bound persistence.
- `config/structural.json` with its own hash; `scripts/assess_structure.py`;
  `GET /api/incidents/{id}/structure`; `scripts/evaluate_structure.py` with separate synthetic
  and LANL reports in `docs/`.
- `schemas.graph`: `GraphEdge`, `StructuralPath`, `FindingValidation`, `StructuralAssessment` and
  related types. Validation is against observed authentication logs only.
- `InvestigationResult.structural_sha256` and `path_validations`; a proposed path can no longer
  exist without a deterministic validation.
- Investigator prompt: structural evidence as untrusted data, `proposed_path`, and citation of
  events on validated paths.
- SYNTHETIC structural scenarios; 154 tests including a naive-graph acceptance comparison.

### Changed
- `generate_scenarios.py --set` accepts `structural`. The demo build also creates assessments.
- `incident_sha256` moved to `schemas.incidents` (still importable from `investigator.agent`).

### Not changed
- Detection rules, incident severity and all stored detection outputs (36 files byte-identical).
  RSEM is not implemented.

## [0.6.0] — 2026-11-09 — Target 1: advanced lateral-movement detection

### Added
- `CROSS_ACCOUNT_PIVOT` rule (`detection/lateral.py`): one account arrives on a host, a different
  account departs from it for the first time. Weight 1, severity LOW. It never claims credential
  transfer or compromise.
- Path metrics on `LATERAL_CHAIN` findings: `distinct_hosts`, `longest_hop_gap_seconds`,
  `sensitive_hosts_on_path`, `ends_on_sensitive_host`.
- `jump_hosts` config (regexes, empty by default): adds `benign_context`, never suppresses
  findings. Severity is reduced only when every transit host is a jump host and no sensitive host
  is on the path, recorded in `severity_adjustment` and the incident rationale.
- `SeverityPolicy.jump_host_point_reduction`; `correlate.severity_for_findings`.
- SYNTHETIC lateral scenarios (`data_gen/lateral_scenarios.py`,
  `data/samples/auth_lateral_scenarios_synthetic.txt`), `generate_scenarios.py --set lateral`.
- `scripts/evaluate_lateral.py`: separate synthetic and LANL reports in `docs/`.
- 149 tests.

### Changed
- Engine version `auth-detect/1.1`. A pivot and `NEW_SRC_HOST` rest on the same departure event
  and now count once in incident severity.
- `SeverityPolicy` fills in default points for rules added after 1.0, so older config files load.

### Not changed
- `detection/rules.py`, all existing rule IDs, and the demo scenario and its config. Stored
  outputs still verify, and the original seven rules reproduce them exactly.

## [0.5.0] — 2026-10-31 — Web application (FastAPI + React) replaces the Streamlit UI

### Added
- `agentsoc.api`: FastAPI REST API (`app.py`), service layer (`service.py`), response models
  (`models.py`): health, sources, overview, incidents (search/filter/sort/paginate), incident
  detail and evidence, investigations (run/saved/history/by id), events, datasets and a
  hash-chained activity log (`AuditRecord`). Automatic LLM → deterministic fallback with provider
  diagnostics kept server-side; per-incident lock against duplicate investigations; safe error
  responses; optional serving of the built frontend with SPA fallback.
- `frontend/`: React 19 + TypeScript + Vite + Tailwind v4 (shadcn-style components on Radix,
  Lucide, Recharts, React Router, React Query): Overview, Incidents, Incident detail (overview,
  timeline, detection analysis, evidence, AI investigation), Investigations, Evidence Explorer,
  Data Sources, System Activity. Collapsible sidebar, breadcrumbs, source context with
  provenance, live operational status, loading/empty/error/offline states, accessible controls,
  responsive layout.
- Tests: 33 API tests (pytest) and 15 frontend tests (Vitest + Testing Library).
- `investigator.store.investigation_id`.

### Changed
- LANL source keys are `lanl-<run>` (were `lanl:<run>`; `:` is not a valid audit identifier).
- `requirements.txt`: `fastapi`, `uvicorn`; `requirements-dev.txt`: `httpx` (TestClient).

### Deprecated
- Streamlit dashboard (`app/streamlit_app.py`) — still runs and shows a deprecation notice.

## [0.4.0] — 2026-10-30 — Demo MVP: Investigator Agent (Phase 3 MVP) + SOC dashboard

### Added
- `agentsoc.investigator`: provider interface (`llm/base.py`), Groq provider (`llm/groq.py`,
  OpenAI-compatible, JSON mode, low reasoning effort, SDK errors mapped to key-free errors),
  hardened prompts with untrusted-data block and injection flagging (`prompts.py`), output
  parsing + evidence grounding (`grounding.py`), deterministic fallback investigator
  (`fallback.py`), agent with one repair round and guaranteed fallback (`agent.py`),
  per-incident result store bound to the incident SHA-256 (`store.py`).
- `agentsoc.app_data` and `app/streamlit_app.py`: SOC dashboard (overview, incident explorer,
  details/timeline, AI investigation, evidence explorer, provenance); synthetic demo auto-built;
  LANL validation runs as clearly labelled real-data sources; simulated-outage switch.
- `.streamlit/config.toml` (dark theme), `DEMO_GUIDE.md`.
- 70 tests (schema extensions, grounding, injection, provider error mapping, fallback, store,
  evidence loading, dashboard via Streamlit AppTest). Suite: 372 passed.

### Changed
- `InvestigationResult`: + `incident_sha256`, `conclusion` (`InvestigationConclusion` with
  `is_proof_of_compromise: Literal[False]`); `Hypothesis`: + `evidence_notes`; `model` now accepts
  provider model names containing `/` (previously rejected `openai/gpt-oss-120b`).
- `.env.example`: `LLM_MAX_TOKENS=4000` (structured investigations exceed 2,000 tokens).

## [0.3.1] — 2026-10-30 — Phase 2 validation on real LANL 2015 data

### Fixed
- `AuthOrientation` lacked LANL's `ScreenLock` / `ScreenUnlock` values, so valid LANL records were
  rejected as `INVALID_ORIENTATION` (40 of 400,000 lines in one window; 12,642 in days 0-2).
  Regression tests use the verbatim rejected LANL lines. Detection rules are unaffected (neither
  value is an access or failure orientation).

### Added
- `agentsoc.evaluation`: per-stage runtime/peak-memory measurement (`measure`), streaming
  evidence-integrity and per-rule analysis (`lanl_validation`), separate Red Team exact-match
  comparison with reasons for uncited labels, report rendering, and the `validate` orchestrator.
- `scripts/validate_lanl.py`; outputs in `data/processed/lanl_validation/`.
- 25 tests for the evaluation tooling (incl. an end-to-end orchestrator run) and 4 parser
  regression tests. Suite: 302 passed, ruff clean, coverage 96%.
- `.gitignore` entries for extracted LANL files in the project root.

### Not changed
- Detection rules, thresholds, baseline logic, correlation and severity.

## [0.3.0] — 2026-10-30 — Phase 2: Authentication threat detection and incident correlation

### Added
- `agentsoc.detection`: rule catalogue, configuration (`DetectionConfig`, JSON, unknown keys
  rejected), behavioural baseline, seven rules (`FAILURE_BURST`, `FAIL_THEN_SUCCESS`,
  `NEW_SRC_HOST`, `NEW_DST_HOST`, `MULTI_HOST_SPREAD`, `LATERAL_CHAIN`, `SENSITIVE_HOST_ACCESS`),
  correlation with documented severity, verified input loading, evidence verification, summary
  and Markdown report.
- `agentsoc.store.detections`: reproducible detection outputs with hash-verified loading.
- `agentsoc.data_gen.scenarios` and committed `data/samples/auth_scenarios_synthetic.txt`
  (deterministic, synthetic) plus `scenarios_detection_config.json`.
- `config/detection.json` (defaults).
- CLIs `scripts/detect.py`, `scripts/generate_scenarios.py`.
- `DetectionError`.
- 99 tests (rules, engine, config, I/O, end-to-end pipeline).

### Changed
- `Finding`: added `user`, `hosts`, `metrics`.
- `Incident`: added `rule_ids`, `involved_users`, `datasets`, `severity`, `severity_rationale`,
  `benign_explanations`, `limitations`, `missing_information`; validates findings lie inside the
  incident window and `rule_ids` match findings.

## [0.2.0] — 2026-10-30 — Phase 1: Dataset engineering and event ingestion

### Added
- `agentsoc.perception.lanl`: streaming LANL `auth.txt` parser (plain/.gz) with skip/limit windows,
  input hashing, validation-without-repair and 8 rejection reasons.
- `agentsoc.perception.records`: `RejectedRecord`, `RejectReason`, `IngestionResult`.
- `agentsoc.perception.quality`: `DataQualityReport` and Markdown rendering.
- `agentsoc.store.datasets`: reproducible JSONL + manifest dataset format with integrity checks.
- `agentsoc.cli.ingest_main` and `scripts/ingest_lanl.py`.
- `IngestionError`, `DatasetIntegrityError`.
- Synthetic LANL-format sample `data/samples/lanl_format_synthetic_sample.txt` with documented expectations.
- `.gitattributes` to keep sample bytes (and hashes) identical across platforms.
- 73 tests (parser, ingestion, quality report, store, CLI integration).

## [0.1.0] — 2026-10-30 — Phase 0: Engineering foundation

### Added
- Project packaging (`pyproject.toml`, src layout) and pinned `requirements.txt` / `requirements-dev.txt`.
- Environment configuration (`agentsoc.config`) with `.env.example`; Groq provider settings.
- Structured JSON logging with secret redaction (`agentsoc.logging_setup`).
- Exception hierarchy (`agentsoc.exceptions`).
- Inter-layer contracts (`agentsoc.schemas`): `AuthEvent`, `Finding`, `Incident`, `Hypothesis`,
  `InvestigationResult`, `PathValidation`, `ActionScore`, `IncidentRiskAssessment`,
  `ResponseAction` (with lifecycle), `AuditRecord` (hash chain).
- `scripts/check_environment.py` for settings and LLM connectivity checks.
- 97 unit tests; ARCHITECTURE.md, IMPLEMENTATION_STATUS.md.
