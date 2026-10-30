"""AgentSOC SOC dashboard (demo MVP).

Run from the project root:  streamlit run app/streamlit_app.py

Data comes only from verified pipeline outputs. The LLM is called only when the
analyst clicks "Investigate with AI"; results are saved per incident fingerprint.
"""

from __future__ import annotations

import os
import re

import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import dotenv_values

from agentsoc.app_data import (
    LoadedSource,
    Source,
    data_root,
    discover_sources,
    load_evidence,
    load_source,
    relative_time,
)
from agentsoc.config import PROJECT_ROOT, get_settings
from agentsoc.detection.catalog import CATALOG, RuleId
from agentsoc.exceptions import AgentSOCError
from agentsoc.investigator.agent import InvestigatorAgent, build_provider, incident_sha256
from agentsoc.investigator.llm.base import SimulatedOutageProvider
from agentsoc.investigator.store import (
    count_investigations,
    load_investigation,
    save_investigation,
)
from agentsoc.schemas import AuthEvent, DatasetSource, Incident, InvestigationResult

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_COLORS = {"CRITICAL": "#EF4444", "HIGH": "#F97316", "MEDIUM": "#EAB308",
                   "LOW": "#38BDF8"}
KIND_COLORS = {"MALICIOUS": "#EF4444", "BENIGN": "#22C55E"}
ATTACK_NAMES = {  # MITRE ATT&CK Enterprise technique names (reference data)
    "T1078": "Valid Accounts", "T1078.002": "Valid Accounts: Domain Accounts",
    "T1078.003": "Valid Accounts: Local Accounts", "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing", "T1110.003": "Brute Force: Password Spraying",
    "T1110.004": "Brute Force: Credential Stuffing", "T1021": "Remote Services",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1021.006": "Remote Services: Windows Remote Management",
    "T1550": "Use Alternate Authentication Material",
    "T1550.002": "Use Alternate Authentication Material: Pass the Hash",
    "T1550.003": "Use Alternate Authentication Material: Pass the Ticket",
    "T1558": "Steal or Forge Kerberos Tickets", "T1003": "OS Credential Dumping",
    "T1570": "Lateral Tool Transfer", "T1087": "Account Discovery",
}
NOT_PROOF = ("Investigation recommendation only — **not proof of compromise**. Confidence values "
             "are investigative estimates, not calibrated probabilities.")

st.set_page_config(page_title="AgentSOC", page_icon="🛡️", layout="wide")
st.markdown(
    """<style>
    .block-container {padding-top: 1.6rem;}
    div[data-testid="stMetric"] {background:#111A2E;border:1px solid #1E293B;border-radius:8px;
        padding:10px 14px;}
    .sev {display:inline-block;padding:1px 8px;border-radius:4px;font-weight:600;font-size:.8rem;
        color:#0B1220;}
    .banner {padding:8px 14px;border-radius:6px;margin-bottom:10px;font-size:.92rem;}
    .synthetic {background:#3B2F0B;border:1px solid #EAB308;color:#FDE68A;}
    .lanl {background:#0C2A3F;border:1px solid #38BDF8;color:#BAE6FD;}
    </style>""",
    unsafe_allow_html=True,  # static CSS only; no data is ever rendered as HTML
)


def esc(text: str) -> str:
    """Render untrusted text (logs, LLM output) as literal Markdown: no links/formatting."""
    return re.sub(r"([\\`*_{}\[\]()#+\-.!|<>~])", r"\\\1", text)


def sev_badge(severity: str) -> str:
    return (f"<span class='sev' style='background:{SEVERITY_COLORS[severity]}'>"
            f"{severity}</span>")


@st.cache_resource(show_spinner="Preparing data sources…")
def cached_sources(root: str) -> list[Source]:
    return discover_sources(data_root())


@st.cache_data(show_spinner="Loading verified detection results…")
def cached_load(key: str, detection_dir: str, _source: Source) -> LoadedSource:
    return load_source(_source)


@st.cache_data(show_spinner="Loading verified evidence events…")
def cached_evidence(key: str, events_sha: str, _source: Source,
                    _ids: frozenset[str]) -> dict[str, AuthEvent]:
    return load_evidence(_source.dataset_dir, set(_ids))


def llm_status() -> tuple[str, str | None]:
    settings = get_settings()
    shadow = None
    file_key = dotenv_values(PROJECT_ROOT / ".env").get("GROQ_API_KEY")
    os_key = os.environ.get("GROQ_API_KEY")
    if file_key and os_key and file_key != os_key:
        shadow = ("A GROQ_API_KEY set in the operating-system environment overrides the key in "
                  ".env. If it is stale, LLM calls fail and the fallback is used.")
    if not settings.llm_enabled:
        return f"LLM disabled: {settings.llm_disabled_reason}", shadow
    return f"Groq · {settings.groq_model}", shadow


def sidebar(sources: list[Source]) -> tuple[Source, str, bool]:
    st.sidebar.markdown("## 🛡️ AgentSOC")
    st.sidebar.caption("Agentic AI framework for authentication-centric SOC triage — "
                       "academic research prototype")
    labels = {s.key: s.label for s in sources}
    key = st.sidebar.selectbox("Data source", list(labels), format_func=labels.get,
                               key="source_key")
    st.sidebar.divider()
    st.sidebar.markdown("**Investigator**")
    mode = st.sidebar.radio("Mode", ["Groq LLM (with deterministic fallback)",
                                     "Deterministic fallback only"], key="mode",
                            label_visibility="collapsed")
    outage = st.sidebar.toggle("Simulate LLM outage (demo)", key="outage",
                               help="Makes the LLM call fail without sending a request, to "
                                    "demonstrate graceful fallback.")
    status, shadow = llm_status()
    st.sidebar.caption(f"Configured: {status}")
    if shadow:
        st.sidebar.warning(shadow)
    return next(s for s in sources if s.key == key), mode, outage


def provenance_banner(source: Source) -> None:
    if source.provenance is DatasetSource.SYNTHETIC:
        st.markdown("<div class='banner synthetic'>🧪 <b>SYNTHETIC demonstration data</b> — "
                    "generated scenario; incidents are not real attacks.</div>",
                    unsafe_allow_html=True)
    else:
        st.markdown("<div class='banner lanl'>🏛️ <b>REAL LANL 2015 authentication data</b> — "
                    "sampled window, anonymised identities; no ground truth except sparse Red "
                    "Team labels.</div>", unsafe_allow_html=True)


def incidents_frame(incidents: list[Incident]) -> pd.DataFrame:
    return pd.DataFrame([{
        "Incident": i.incident_id, "User": i.principal_user, "Severity": i.severity.value,
        "Rules": ", ".join(i.rule_ids), "Hosts": ", ".join(i.involved_hosts),
        "First seen": relative_time(i.first_seen), "Last seen": relative_time(i.last_seen),
        "Evidence": len(i.event_ids), "Provenance": ", ".join(d.value for d in i.datasets),
    } for i in incidents])


def severity_rank(incident: Incident) -> tuple:
    return (SEVERITY_ORDER.index(incident.severity.value), incident.first_seen)


# ------------------------------------------------------------------------------- tabs

def tab_overview(data: LoadedSource, investigations: int) -> None:
    sev = {s: sum(i.severity.value == s for i in data.incidents) for s in SEVERITY_ORDER}
    cols = st.columns(7)
    cols[0].metric("Incidents", len(data.incidents))
    for col, s in zip(cols[1:5], SEVERITY_ORDER, strict=True):
        col.metric(s.title(), sev[s])
    cols[5].metric("Detections", data.summary["findings_total"])
    cols[6].metric("Investigations", investigations)
    st.caption(f"Dataset: **{data.manifest.dataset_label}** · provenance "
               f"`{data.manifest.dataset.value}` · {data.manifest.event_count:,} verified events")
    if not data.incidents:
        st.info("This dataset produced no incidents. Detection ran and its outputs are verified; "
                "zero incidents is a valid result, not an error.")
        return
    left, right = st.columns(2)
    sev_df = pd.DataFrame({"Severity": SEVERITY_ORDER,
                           "Incidents": [sev[s] for s in SEVERITY_ORDER]})
    fig = px.bar(sev_df, x="Severity", y="Incidents", color="Severity",
                 color_discrete_map=SEVERITY_COLORS, title="Incidents by severity")
    left.plotly_chart(fig.update_layout(showlegend=False, height=320), key="sev_chart")
    rules = pd.DataFrame([{"Rule": r, "Findings": n}
                          for r, n in data.summary["findings_by_rule"].items()])
    fig = px.bar(rules.sort_values("Findings"), x="Findings", y="Rule", orientation="h",
                 title="Detections by rule", color_discrete_sequence=["#38BDF8"])
    right.plotly_chart(fig.update_layout(height=320), key="rule_chart")


def _select_from_table(df_key: str) -> None:
    rows = st.session_state[df_key].selection.rows
    if rows:
        st.session_state["incident_id"] = st.session_state["_table_ids"][rows[0]]


def tab_incidents(data: LoadedSource) -> None:
    if not data.incidents:
        st.info("No incidents to explore.")
        return
    c1, c2, c3 = st.columns([2, 3, 3])
    severities = c1.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER)
    all_rules = sorted({r for i in data.incidents for r in i.rule_ids})
    rules = c2.multiselect("Detection rule", all_rules)
    query = c3.text_input("Search user or host", "")
    shown = [i for i in sorted(data.incidents, key=severity_rank)
             if i.severity.value in severities
             and (not rules or set(rules) & set(i.rule_ids))
             and (not query or query.lower() in (i.principal_user + " "
                                                  + " ".join(i.involved_hosts)).lower())]
    st.session_state["_table_ids"] = [i.incident_id for i in shown]
    st.caption(f"{len(shown)} of {len(data.incidents)} incidents — select a row to open it.")
    st.dataframe(incidents_frame(shown) if shown else pd.DataFrame(), hide_index=True,
                 key="incident_table", on_select=lambda: _select_from_table("incident_table"),
                 selection_mode="single-row",
                 column_config={"Severity": st.column_config.TextColumn(width="small")})


def tab_details(inc: Incident, evidence: dict[str, AuthEvent]) -> None:
    st.markdown(f"### {inc.incident_id} · {esc(inc.principal_user)} "
                f"{sev_badge(inc.severity.value)}", unsafe_allow_html=True)
    st.caption(f"{relative_time(inc.first_seen)} → {relative_time(inc.last_seen)} · "
               f"provenance: {', '.join(d.value for d in inc.datasets)} · "
               f"{len(inc.event_ids)} evidence events")
    rows = [e for eid in inc.event_ids if (e := evidence.get(eid))]
    if rows:
        t0 = inc.first_seen
        tl = pd.DataFrame([{
            "Seconds since first event": (e.timestamp - t0).total_seconds(),
            "Path": f"{e.src_host} → {e.dst_host}", "Outcome": e.outcome.value,
            "Orientation": e.orientation.value, "Event": e.event_id,
        } for e in rows])
        fig = px.scatter(tl, x="Seconds since first event", y="Path", color="Outcome",
                         symbol="Orientation", hover_data=["Event"], title="Evidence timeline",
                         color_discrete_map={"Fail": "#EF4444", "Success": "#22C55E"})
        st.plotly_chart(fig.update_traces(marker_size=11).update_layout(height=330),
                        key="timeline")
    c1, c2 = st.columns(2)
    c1.markdown("**Affected users**  \n" + "  \n".join(f"`{u}`" for u in inc.involved_users))
    c2.markdown("**Affected hosts**  \n" + "  \n".join(f"`{h}`" for h in inc.involved_hosts))
    st.markdown("**Detection reasons**")
    for f in inc.findings:
        info = CATALOG[RuleId(f.rule_id)]
        with st.expander(f"{f.rule_id} — {info.title} ({f.severity.value})"):
            st.markdown(esc(f.description))
            st.caption("Evidence: " + ", ".join(f.event_ids))
            st.json(f.metrics, expanded=False)
    st.markdown(f"**Severity rationale** — {esc(inc.severity_rationale)}")
    c1, c2, c3 = st.columns(3)
    c1.markdown("**Possible benign explanations**  \n" + "  \n".join(
        f"• {esc(x)}" for x in inc.benign_explanations))
    c2.markdown("**Limitations**  \n" + "  \n".join(f"• {esc(x)}" for x in inc.limitations))
    c3.markdown("**Missing information**  \n" + "  \n".join(
        f"• {esc(x)}" for x in inc.missing_information))


def _event_rows(ids: list[str], notes: dict[str, str],
                evidence: dict[str, AuthEvent]) -> pd.DataFrame:
    return pd.DataFrame([{
        "Event": eid,
        "Time": relative_time(e.timestamp) if (e := evidence.get(eid)) else "not loaded",
        "Path": f"{e.src_host} → {e.dst_host}" if e else "",
        "Orientation": e.orientation.value if e else "", "Outcome": e.outcome.value if e else "",
        "Why it matters": notes.get(eid, ""),
    } for eid in ids])


def render_investigation(result: InvestigationResult, evidence: dict[str, AuthEvent]) -> None:
    llm = result.source.value == "llm"
    c1, c2, c3 = st.columns([3, 2, 2])
    with c1:
        if llm:
            st.badge(f"Generated by Groq LLM · {result.model}", icon="🤖", color="green")
        else:
            st.badge("Generated by deterministic fallback (no LLM)", icon="⚙️", color="orange")
    c2.caption(f"Latency: {result.latency_ms:,.0f} ms")
    c3.caption(f"Created: {result.created_at:%Y-%m-%d %H:%M:%S} UTC")
    for w in result.warnings:
        st.warning(w)
    hyps = {h.hypothesis_id: h for h in result.hypotheses}
    c = result.conclusion
    best = hyps[c.most_plausible_hypothesis_id]
    with st.container(border=True):
        st.markdown(f"#### Conclusion — most plausible: {best.hypothesis_id} · {esc(best.title)}")
        st.progress(c.confidence, text=f"Confidence (investigative estimate): {c.confidence:.2f}")
        st.markdown(esc(c.summary))
        st.markdown(f"**Uncertainty:** {esc(c.uncertainty)}")
        if c.alternative_hypothesis_ids:
            st.markdown("**Alternatives:** " + ", ".join(
                f"{h} ({hyps[h].confidence:.2f})" for h in c.alternative_hypothesis_ids))
        a, b = st.columns(2)
        a.markdown("**Recommended next steps**  \n" + "  \n".join(
            f"{n}. {esc(s)}" for n, s in enumerate(c.next_steps, 1)))
        b.markdown("**Evidence gaps**  \n" + "  \n".join(f"• {esc(g)}" for g in c.evidence_gaps))
        st.info(NOT_PROOF)

    df = pd.DataFrame([{"Hypothesis": f"{h.hypothesis_id} · {h.title[:60]}",
                        "Confidence": h.confidence, "Kind": h.kind.value}
                       for h in result.hypotheses])
    fig = px.bar(df, x="Confidence", y="Hypothesis", color="Kind", orientation="h",
                 range_x=[0, 1], color_discrete_map=KIND_COLORS,
                 title="Competing hypotheses (estimates, not probabilities)")
    st.plotly_chart(fig.update_layout(height=120 + 50 * len(df)), key="hyp_chart")

    for h in result.hypotheses:
        icon = "🔴" if h.kind.value == "MALICIOUS" else "🟢"
        with st.expander(f"{icon} {h.hypothesis_id} · {h.kind.value} · {h.title} — "
                         f"{h.confidence:.2f}", expanded=h is best):
            if h.attack_techniques:
                st.markdown("**MITRE ATT&CK (interpretation of authentication evidence):** "
                            + " · ".join(
                                f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)"
                                f" {ATTACK_NAMES.get(t, '')}" for t in h.attack_techniques))
            st.markdown(esc(h.narrative))
            notes = {n.event_id: n.relevance for n in h.evidence_notes}
            st.markdown(f"**Supporting evidence ({len(h.supporting_event_ids)})**")
            st.dataframe(_event_rows(h.supporting_event_ids, notes, evidence), hide_index=True,
                         key=f"sup_{h.hypothesis_id}")
            if h.contradicting_event_ids:
                st.markdown(f"**Contradicting evidence ({len(h.contradicting_event_ids)})**")
                st.dataframe(_event_rows(h.contradicting_event_ids, notes, evidence),
                             hide_index=True, key=f"con_{h.hypothesis_id}")
            if h.missing_information:
                st.markdown("**Missing information**  \n" + "  \n".join(
                    f"• {esc(m)}" for m in h.missing_information))


def tab_investigation(data: LoadedSource, inc: Incident, evidence: dict[str, AuthEvent],
                      mode: str, outage: bool) -> None:
    st.markdown(f"### AI investigation · {inc.incident_id} · {esc(inc.principal_user)} "
                f"{sev_badge(inc.severity.value)}", unsafe_allow_html=True)
    sha = incident_sha256(inc)
    cache_key = f"{data.source.key}|{inc.incident_id}|{sha}"
    store = st.session_state.setdefault("investigations", {})
    result = store.get(cache_key) or load_investigation(data.source.detection_dir, inc)
    fallback_only = mode.startswith("Deterministic")
    label = ("Investigate with AI" if not result else "Re-run investigation")
    where = ("deterministic fallback" if fallback_only
             else "simulated LLM outage → fallback" if outage else llm_status()[0])
    clicked = st.button(label, type="primary", icon="🔎", key=f"inv_{inc.incident_id}")
    st.caption(f"Runs only when clicked · will use: {where}")
    if clicked:
        if fallback_only:
            provider, reason = None, "deterministic fallback selected by the analyst"
        elif outage:
            provider, reason = SimulatedOutageProvider(), None
        else:
            provider, reason = build_provider(get_settings())
        agent = InvestigatorAgent(provider, disabled_reason=reason)
        with st.spinner(f"Investigating {inc.incident_id} ({where})… LLM calls can take "
                        "5–20 s"):
            result = agent.investigate(inc, evidence.values(),
                                       is_admin=inc.principal_user in data.admin_users)
        save_investigation(data.source.detection_dir, inc, result)
        store[cache_key] = result
    if result is None:
        st.info("No investigation yet for this incident. Click **Investigate with AI**.")
        return
    if not clicked:
        st.caption("Showing the saved investigation for this exact incident content.")
    render_investigation(result, evidence)


def tab_evidence(inc: Incident, evidence: dict[str, AuthEvent]) -> None:
    missing = [e for e in inc.event_ids if e not in evidence]
    if missing:
        st.error(f"{len(missing)} cited events were not found in the verified dataset: "
                 f"{', '.join(missing[:10])}")
    cited_by: dict[str, list[str]] = {}
    for f in inc.findings:
        for e in f.event_ids:
            cited_by.setdefault(e, []).append(f.rule_id)
    rows = [{
        "Event": e.event_id, "Time": relative_time(e.timestamp), "Source user": e.src_user,
        "Destination user": e.dst_user, "Source host": e.src_host, "Destination host": e.dst_host,
        "Auth type": e.auth_type, "Logon type": e.logon_type, "Orientation": e.orientation.value,
        "Outcome": e.outcome.value, "Cited by": ", ".join(cited_by.get(e.event_id, [])),
        "Provenance": e.dataset.value, "Raw file": e.raw_ref.file, "Raw line": e.raw_ref.line,
    } for eid in inc.event_ids if (e := evidence.get(eid))]
    st.caption(f"{len(rows)} normalised events for {inc.incident_id}, read from the "
               "hash-verified dataset. `?`/empty optional fields are shown as missing, never "
               "filled in.")
    outcome = st.segmented_control("Outcome", ["All", "Success", "Fail"], default="All",
                                   key="ev_outcome")
    df = pd.DataFrame(rows)
    if rows and outcome in ("Success", "Fail"):
        df = df[df["Outcome"] == outcome]
    st.dataframe(df, hide_index=True, key="evidence_table")


def tab_provenance(data: LoadedSource) -> None:
    m, s = data.manifest, data.summary
    if m.dataset is DatasetSource.SYNTHETIC:
        st.markdown("**Synthetic data.** Generated deterministically by "
                    "`src/agentsoc/data_gen/scenarios.py`. It demonstrates detection and "
                    "investigation logic; results say nothing about real-world accuracy.")
    else:
        st.markdown("**Real LANL 2015 data** (A. D. Kent, *Comprehensive, Multi-Source "
                    "Cyber-Security Events*). Sampled contiguous window; identities anonymised; "
                    "times are offsets. See `data/processed/lanl_validation/validation_report.md`.")
    c1, c2 = st.columns(2)
    with c1, st.container(border=True):
        st.markdown("**Dataset manifest (verified)**")
        st.json({"label": m.dataset_label, "provenance": m.dataset.value,
                 "source_file": m.source_file, "parser": m.parser_version,
                 "window": {"skip": m.skip, "limit": m.limit}, "events": m.event_count,
                 "rejected": m.rejected_count, "input_sha256": m.input_sha256,
                 "events_sha256": m.events_sha256})
    with c2, st.container(border=True):
        st.markdown("**Detection run (verified)**")
        st.json({"engine": s["engine_version"], "config_sha256": s["config_sha256"],
                 "findings": s["findings_total"], "incidents": s["incidents_total"],
                 "detections_sha256": s["detections_sha256"],
                 "incidents_sha256": s["incidents_sha256"],
                 "baseline_seconds": s["config"]["baseline_seconds"],
                 "admin_users": s["config"]["admin_users"],
                 "sensitive_hosts": s["config"]["sensitive_host_access"]["hosts"]})


# ------------------------------------------------------------------------------- main

def main() -> None:
    try:
        sources = cached_sources(str(data_root()))
    except AgentSOCError as exc:
        st.error(f"Could not prepare data sources: {exc}")
        return
    source, mode, outage = sidebar(sources)
    try:
        data = cached_load(source.key, str(source.detection_dir), source)
    except AgentSOCError as exc:
        st.error(f"Detection outputs for this source failed verification: {exc}")
        return

    st.title("AgentSOC — Authentication Threat Investigation")
    provenance_banner(source)
    incidents = sorted(data.incidents, key=severity_rank)
    ids = [i.incident_id for i in incidents]
    if ids and st.session_state.get("incident_id") not in ids:
        st.session_state["incident_id"] = ids[0]
    by_id = {i.incident_id: i for i in incidents}
    if ids:
        st.sidebar.divider()
        st.sidebar.selectbox(
            "Selected incident", ids, key="incident_id",
            format_func=lambda i: f"{i} · {by_id[i].principal_user} · {by_id[i].severity.value}")

    evidence: dict[str, AuthEvent] = {}
    if incidents:
        try:
            evidence = cached_evidence(source.key, data.manifest.events_sha256, source,
                                       frozenset(e for i in incidents for e in i.event_ids))
        except AgentSOCError as exc:
            st.error(f"Evidence could not be verified: {exc}")

    tabs = st.tabs(["Overview", "Incident explorer", "Incident details", "AI investigation",
                    "Evidence", "Provenance"])
    with tabs[0]:
        tab_overview(data, count_investigations(source.detection_dir))
    with tabs[1]:
        tab_incidents(data)
    inc = by_id.get(st.session_state.get("incident_id"))
    for tab, render in ((tabs[2], lambda: tab_details(inc, evidence)),
                        (tabs[3], lambda: tab_investigation(data, inc, evidence, mode, outage)),
                        (tabs[4], lambda: tab_evidence(inc, evidence))):
        with tab:
            if inc is None:
                st.info("No incident selected — this dataset has no incidents.")
            else:
                render()
    with tabs[5]:
        tab_provenance(data)


main()
