# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
