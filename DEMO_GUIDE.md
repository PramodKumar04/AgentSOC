# AgentSOC — Demo Guide (web application)

Verified dataset → Phase 2 detection → incident → AI investigation (language model, with
automatic deterministic fallback) → AgentSOC web application.

## 1. One-time setup

```powershell
cd C:\Users\pramo\OneDrive\Desktop\AgentSOC-Final_Year\AgentSOC
python -m venv .venv                      # skip if .venv already exists
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
pip install -e . --no-deps
cd frontend; npm install; cd ..
```

`.env` (not committed) must contain `LLM_PROVIDER=groq`, `GROQ_API_KEY=gsk_...`,
`GROQ_MODEL=openai/gpt-oss-120b`, `LLM_MAX_TOKENS=4000`.

**On this PC:** an old `GROQ_API_KEY` is set at Windows machine level and overrides `.env`.
Remove it once in an **Administrator** PowerShell and restart VS Code/terminals:

```powershell
[Environment]::SetEnvironmentVariable('GROQ_API_KEY', $null, 'Machine')
```

Until then, start the backend from a terminal where it is cleared for that session
(`Remove-Item Env:GROQ_API_KEY`). Otherwise the app still works, but investigations report
"completed with limited analysis". Check with `python scripts/check_environment.py`.

Create the first administrator (there is no default account; the password is prompted for and
must be 12+ characters, not containing the username):

```powershell
python scripts/manage_users.py create alice --role admin
```

For the demo, also create an analyst from **Users** in the app, or with
`python scripts/manage_users.py create analyst1 --role analyst`.

## 2. Start the application

**Terminal 1 — backend (API)**

```powershell
cd C:\Users\pramo\OneDrive\Desktop\AgentSOC-Final_Year\AgentSOC
.venv\Scripts\Activate.ps1
Remove-Item Env:GROQ_API_KEY -ErrorAction SilentlyContinue   # only while the stale machine key exists
uvicorn agentsoc.api.app:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — frontend**

```powershell
cd C:\Users\pramo\OneDrive\Desktop\AgentSOC-Final_Year\AgentSOC\frontend
npm run dev
```

Open **http://localhost:5173** and sign in.

**Fallback for demo day (one process):** `cd frontend; npm run build` once, then start only the
backend and open **http://127.0.0.1:8000**.

To show inferred paths, risk differences and real LANL graphs, once beforehand:

```powershell
python scripts/prepare_demo_sources.py
```

Then choose *SYNTHETIC risk scenarios* in the data-source selector, open `INC-00021`, select
**Attack graph**, and pick an *Inferred* path. For real data choose the *sensitivity run (short
baseline)* LANL source and open `INC-00076`, whose graph is truncated. *Risk & response* shows
proposals only: nothing can be approved or executed.

## 3. What you will see

The default data source is the **synthetic 4-day scenario** (purple *Synthetic* badge), built
automatically on first request: 3 incidents — alice.fin **Critical**, carol.fin **Medium**,
dave.it **Low**; 15 detection findings. LANL validation runs (real, sampled data) appear in the
data-source selector with a blue *LANL (real)* badge.

## 4. Demonstration script (~6 minutes)

1. **Overview** — KPI strip, severity distribution, incident activity, recent incidents, rule
   activity; point at the provenance badge (synthetic, 176 verified events).
2. **Incidents** — search `alice`, toggle severity filters, sort columns; open **INC-00002**.
3. **Incident → Overview** — summary, triggered rules, affected hosts, benign explanations,
   limitations, missing information.
4. **Timeline** — failures on WS-FIN-07 → success → WS-FIN-07 → SRV-APP-02 → DB-FIN-01, with
   the rules each event triggered.
5. **Detection analysis** — each rule's observations; severity calculation; shared-evidence
   note (why the summed severity can overstate independent evidence).
6. **Evidence** — real normalised events; expand one to show source file and line, and
   "missing (not recorded)" for absent optional fields.
7. **AI investigation** — select **Investigate Incident** (or **Re-run investigation**). Show the
   progress state, then: status banner, conclusion with confidence estimate and uncertainty,
   next steps, evidence gaps, competing hypotheses with supporting/contradicting events and
   ATT&CK links, and the *not proof of compromise* statement. *Technical details* (collapsed)
   shows which engine produced it.
8. **Investigations** — history; open the saved investigation.
9. **Evidence Explorer** — search by user/host/event ID, filter by result; switch dataset
   (synthetic vs LANL groups).
10. **Data Sources** — synthetic and real LANL sections, hashes, coverage, verification status.
11. **System Activity** — hash-chained log of verifications and investigations; *Integrity chain
    intact*.

**Fallback demonstration:** stop the backend, start it in a terminal where `GROQ_API_KEY` is
invalid (or set `LLM_PROVIDER=none` for that terminal), re-run an investigation: it completes
with *limited analysis*; the UI never shows provider settings.

## 5. What is and is not demonstrated

| Demonstrated | Not demonstrated |
|---|---|
| Verified ingestion, 7 detection rules, correlation, evidence integrity | Graph feasibility (SSE, Phase 4) |
| LLM investigation with grounding, repair round, automatic fallback | Risk scoring / action ranking (RSEM, Phase 5) |
| Synthetic vs real (LANL) provenance on every page | Response actions and approvals (Phase 7) |
| Hash-chained activity log | Authentication / multi-user access (prototype: local analyst) |

Confidence values are investigative estimates, not probabilities. Authentication logs contain no
malware, PowerShell or endpoint data and none is shown. Synthetic results do not measure
real-world accuracy. The paper's reported 506 ms is not our measurement (our LLM investigations
take roughly 4–20 s).

The previous Streamlit dashboard is deprecated (`streamlit run app/streamlit_app.py` still works).
