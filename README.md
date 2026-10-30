# AgentSOC

**Multi-Layer Agentic AI Framework for Security Operations Automation** — an academic research
prototype that turns authentication events into explainable, risk-ranked security incidents.

Based on: J. Roy and S. K. Singh, *"AgentSOC: A Multi-Layer Agentic AI Framework for Security
Operations Automation,"* IEEE ICAIC 2026 ([arXiv:2604.20134](https://arxiv.org/abs/2604.20134)).
This repository is an independent implementation; results reported in the paper are not results of this code.

> **Scope:** credential misuse → suspicious authentication → lateral movement toward a sensitive
> server. Responses are **simulated (dry-run) only**. Do not connect to real accounts, sessions or hosts.

## Status

Phases 0 (foundation), 1 (ingestion) and 2 (detection & correlation) complete. See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for what
works today and [ARCHITECTURE.md](ARCHITECTURE.md) for the design.

## Setup (Windows, Python 3.11+)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
pip install -e . --no-deps
copy .env.example .env      # then edit .env and set GROQ_API_KEY
```

## Verify

```powershell
pytest                                  # unit tests
pytest --cov=agentsoc                   # with coverage
ruff check src tests scripts            # lint
python scripts/check_environment.py     # settings + LLM endpoint check
```

Without a valid LLM key the system runs on the deterministic fallback investigator.

## Ingest authentication data

```powershell
# Synthetic LANL-format sample (committed)
python scripts/ingest_lanl.py data/samples/lanl_format_synthetic_sample.txt `
    --out data/processed/synthetic_sample --source synthetic `
    --label "SYNTHETIC sample in LANL format"

# Real LANL data (download separately into data/raw/)
python scripts/ingest_lanl.py data/raw/auth.txt.gz --out data/processed/lanl_5k `
    --limit 5000 --label "LANL auth.txt, first 5000 lines"
```

Each run writes `events.jsonl`, `rejected.jsonl`, `quality_report.{json,md}` and `manifest.json`.
See [data/samples/README.md](data/samples/README.md).

## Detect suspicious authentication activity

```powershell
# 1. (Re)generate and ingest the SYNTHETIC 4-day scenario
python scripts/generate_scenarios.py --out data/samples/auth_scenarios_synthetic.txt
python scripts/ingest_lanl.py data/samples/auth_scenarios_synthetic.txt `
    --out data/processed/scenarios --source synthetic `
    --label "SYNTHETIC scenarios in LANL format"

# 2. Detect and correlate (only verified datasets are accepted)
python scripts/detect.py data/processed/scenarios `
    --config data/samples/scenarios_detection_config.json `
    --out data/processed/scenarios_detection
```

Outputs: `detections.jsonl`, `incidents.jsonl`, `detection_summary.json`, `detection_report.md`.
Default thresholds are in [config/detection.json](config/detection.json); every rule, its
assumptions and limitations are documented in [ARCHITECTURE.md](ARCHITECTURE.md) §9.

Detections are heuristic indicators of suspicious behaviour, not confirmation of compromise, and
results on synthetic data do not measure real-world detection accuracy.

## Layout

```
src/agentsoc/   config, logging, schemas (+ layer packages as phases land)
tests/          unit and integration tests
scripts/        command-line utilities
docs/reference/ reference paper (local only, gitignored)
```
