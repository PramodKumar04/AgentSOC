# AgentSOC

**Multi-Layer Agentic AI Framework for Security Operations Automation** — an academic research
prototype that turns authentication events into explainable, risk-ranked security incidents.

Based on: J. Roy and S. K. Singh, *"AgentSOC: A Multi-Layer Agentic AI Framework for Security
Operations Automation,"* IEEE ICAIC 2026 ([arXiv:2604.20134](https://arxiv.org/abs/2604.20134)).
This repository is an independent implementation; results reported in the paper are not results of this code.

> **Scope:** credential misuse → suspicious authentication → lateral movement toward a sensitive
> server. Responses are **simulated (dry-run) only**. Do not connect to real accounts, sessions or hosts.

## Status

Phases 0–2 complete (Phase 2 validated on sampled real LANL 2015 data) plus the Investigator Agent (LLM + deterministic fallback) advanced lateral-movement detection (Target 1), the Structural Simulation Engine (Target 2) and the Risk Scoring and Evaluation Module (Target 3) and an integrated dashboard. The analyst interface is a **React web application backed by a FastAPI REST API** — see [DEMO_GUIDE.md](DEMO_GUIDE.md). See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for what
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
pytest                                  # Python unit + integration tests
cd frontend; npm test; cd ..            # frontend tests (Vitest)
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

## Lateral-movement scenarios and reports

```powershell
python scripts/generate_scenarios.py --out data/samples/auth_lateral_scenarios_synthetic.txt --set lateral
python scripts/evaluate_lateral.py synthetic --work $env:TEMP\agentsoc_t1
python scripts/evaluate_lateral.py lanl --redteam "$env:USERPROFILE/Downloads/redteam.txt.gz"
```

Results: [docs/target1_synthetic_results.md](docs/target1_synthetic_results.md) (synthetic only)
and [docs/target1_lanl_sensitivity.md](docs/target1_lanl_sensitivity.md) (real, sampled LANL; the
Red Team labels are read only after detection finishes). Neither report measures real-world
detection accuracy.

## Structural validation (SSE)

```powershell
python scripts/assess_structure.py data/processed/scenarios --detection data/processed/scenarios_detection
python scripts/generate_scenarios.py --out data/samples/auth_structural_scenarios_synthetic.txt --set structural
python scripts/evaluate_structure.py synthetic --work $env:TEMP\agentsoc_t2
python scripts/evaluate_structure.py lanl --redteam "$env:USERPROFILE/Downloads/redteam.txt.gz"
```

The SSE builds per-incident NetworkX graphs from **observed authentication events only**; no
enterprise topology is assumed. `INFEASIBLE` means the evidence was not observed, not that
movement was impossible, and a connected path is not evidence of compromise. Results:
[docs/target2_synthetic_results.md](docs/target2_synthetic_results.md) (synthetic only) and
[docs/target2_lanl_results.md](docs/target2_lanl_results.md) (real, sampled LANL).

## Risk assessment (RSEM)

```powershell
python scripts/assess_risk.py --detection data/processed/scenarios_detection
python scripts/evaluate_risk.py synthetic --work $env:TEMP\agentsoc_t3
python scripts/evaluate_risk.py lanl --redteam "$env:USERPROFILE/Downloads/redteam.txt.gz"
```

RSEM needs a stored structural assessment. It sits above detection severity, which stays visible
and unchanged. Scores are heuristic, not probabilities of compromise; proposed actions are dry-run
only. Results: [docs/target3_synthetic_results.md](docs/target3_synthetic_results.md) (synthetic
only) and [docs/target3_lanl_results.md](docs/target3_lanl_results.md) (real, sampled LANL).

## Prepare dashboard demo sources

```powershell
python scripts/prepare_demo_sources.py
```

Adds the synthetic risk scenarios and any already-assessed LANL runs to the data-source selector,
each labelled synthetic or real. Optional: without it the default sources still work.

## Run the web application

AgentSOC runs as a FastAPI backend (`src/agentsoc/api`) and a React frontend (`frontend/`).
All detection, evidence validation and investigation logic stays in Python; the UI only calls
the REST API.

**Terminal 1 — backend**

```powershell
cd C:\Users\pramo\OneDrive\Desktop\AgentSOC-Final_Year\AgentSOC
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt          # first time (adds FastAPI)
pip install -e . --no-deps
uvicorn agentsoc.api.app:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — frontend**

```powershell
cd C:\Users\pramo\OneDrive\Desktop\AgentSOC-Final_Year\AgentSOC\frontend
npm install                                  # first time
npm run dev
```

**Sign-in (once, before first use).** The application has no default account. Create the
first administrator on the server; the password is read from a hidden prompt:

```powershell
python scripts/manage_users.py create alice --role admin
```

Administrators add further accounts from **Users** in the app. Optional: credential encryption
key for database connectors (`python scripts/manage_credentials.py generate-key`, then set
`AGENTSOC_CREDENTIAL_KEY`) and a queryable event index per source
(`python scripts/build_event_index.py --all`). Details, session limits and key backup/rotation:
[docs/security_foundations.md](docs/security_foundations.md).

Open <http://localhost:5173> and sign in. The synthetic demo data is built automatically on first request.

**Single process (optional):** `cd frontend; npm run build`, then only the backend is needed —
open <http://127.0.0.1:8000>.

Investigations run automatically: the configured language model is tried first and, if it is
unavailable or its output fails validation, deterministic analysis is used; the UI then reports
"completed with limited analysis". Provider configuration is never shown in the UI.

API reference (OpenAPI): <http://127.0.0.1:8000/docs>. Walkthrough: [DEMO_GUIDE.md](DEMO_GUIDE.md).

The previous Streamlit dashboard (`streamlit run app/streamlit_app.py`) is **deprecated** and kept
only until the web application has been reviewed.

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
src/agentsoc/   config, logging, schemas, perception, detection, investigator, api
frontend/       React + TypeScript web application (Vite, Tailwind)
tests/          unit and integration tests
scripts/        command-line utilities
docs/reference/ reference paper (local only, gitignored)
```
