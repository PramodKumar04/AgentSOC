# AgentSOC

**Multi-Layer Agentic AI Framework for Security Operations Automation** — an academic research
prototype that turns authentication events into explainable, risk-ranked security incidents.

Based on: J. Roy and S. K. Singh, *"AgentSOC: A Multi-Layer Agentic AI Framework for Security
Operations Automation,"* IEEE ICAIC 2026 ([arXiv:2604.20134](https://arxiv.org/abs/2604.20134)).
This repository is an independent implementation; results reported in the paper are not results of this code.

> **Scope:** credential misuse → suspicious authentication → lateral movement toward a sensitive
> server. Responses are **simulated (dry-run) only**. Do not connect to real accounts, sessions or hosts.

## Status

Phases 0–2 complete (Phase 2 validated on sampled real LANL 2015 data); **demo MVP** adds the Investigator Agent (Groq LLM + deterministic fallback) and a Streamlit SOC dashboard — see [DEMO_GUIDE.md](DEMO_GUIDE.md). See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for what
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

## Run the SOC dashboard

```powershell
streamlit run app/streamlit_app.py
```

Synthetic demo data is built automatically on first launch. Select an incident and click
**Investigate with AI**; the result shows whether Groq or the deterministic fallback produced it.
Full walkthrough, fallback behaviour and scope: [DEMO_GUIDE.md](DEMO_GUIDE.md).

## Validate on real LANL 2015 data

```powershell
python scripts/validate_lanl.py --archive "$env:USERPROFILE/Downloads/auth.txt.gz" `
    --redteam "$env:USERPROFILE/Downloads/redteam.txt.gz" `
    --out data/processed/lanl_validation --scan-days 3 `
    --run first_100k:0:100000 --run first_500k:0:500000 `
    --run redteam_window:29400000:400000 `
    --run redteam_window_half_baseline:29400000:400000:half_window
```

Writes `ingestion_summary.json`, `detection_summary.json`, `rule_analysis.json`,
`performance_metrics.json` and `validation_report.md`. The archive is only read. This evaluates
behaviour on sampled windows; it does **not** establish real-world detection accuracy.
Key result: the default 2-day baseline needs ~33.3M LANL lines, which the current in-memory
pipeline cannot hold on an 8 GB machine, so baseline-dependent rules are not validated at
default settings (details in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)).

## Layout

```
src/agentsoc/   config, logging, schemas (+ layer packages as phases land)
tests/          unit and integration tests
scripts/        command-line utilities
docs/reference/ reference paper (local only, gitignored)
```
