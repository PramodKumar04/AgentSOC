# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
