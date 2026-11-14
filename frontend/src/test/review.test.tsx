import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, it } from "vitest";

import type { AgentAnalysis, ContextView, ReportView, ReviewState } from "@/lib/api";

import { ALICE, ALICE_DETAIL, CAROL, EVENT, OVERVIEW, SOURCES } from "./fixtures";
import { json, mockApi, renderApp, type Handler } from "./render";

const OPEN: ReviewState = { status: "open", latest: null, history: [] };
const accepted = (note: string | null = null): ReviewState => {
  const entry = { decision: "accepted" as const, reason: null, note, window_hours: null, analyst: "analyst1",
                  created_at: "2026-11-14T09:00:00Z", current_version: true };
  return { status: "accepted", latest: entry, history: [entry] };
};
const CONTEXT: ContextView = {
  window_hours: 24, window_start_label: "Day 2 10:30:00", window_end_label: "Day 4 10:55:00",
  account: "alice.fin@CORP", account_events: 9, account_failures: 3, account_before: 4, account_after: 2,
  account_src_hosts: ["WS-FIN-07"], account_dst_hosts: ["DB-FIN-01"], account_first_seen_label: "Day 0 08:00:00",
  events: [{ ...EVENT, event_id: "auth.txt-99", time_label: "Day 3 09:00:00" }], events_truncated: false,
  hosts: [{ host: "DB-FIN-01", events: 5, failures: 1, other_accounts: [{ label: "svc.backup@CORP", count: 2 }] }],
  pairs: [{ src_host: "SRV-APP-02", dst_host: "DB-FIN-01", before: 0, first_seen_label: "Day 3 10:55:00", after: 1 }],
  related: [{ incident_id: "INC-00001", principal_user: "carol.fin@CORP", severity: "MEDIUM", first_seen_label: "Day 3 09:00:00",
              last_seen_label: "Day 3 09:30:00", relation: "shares host(s): DB-FIN-01", review_status: "open" }],
  observations: ["SRV-APP-02 → DB-FIN-01 does not occur in this data source before the incident."],
  limitations: ["Only authentication events in this data source are searched."],
};

export const AGENTS: AgentAnalysis = {
  incident_id: "INC-00002", source_key: "demo", mode: "standard", window_hours: null,
  generated_at: "2026-11-14T09:00:00Z", duration_ms: 12,
  agents: [
    { agent: "identity", title: "Identity agent", purpose: "Account behaviour.", status: "completed", examined: ["9 incident events"],
      findings: [{ statement: "6 of 9 incident events failed (67%), against 0 of 14 before.", stance: "suspicious", strength: "strong",
                   accounts: ["alice.fin@CORP"], hosts: [], event_ids: ["auth.txt-116"], techniques: [], expanded: false }],
      gaps: ["Identity-provider records are not available."], duration_ms: 2 },
    { agent: "network", title: "Network / host agent", purpose: "Host relationships.", status: "completed", examined: [],
      findings: [{ statement: "SRV-APP-02 → DB-FIN-01 never occurs earlier.", stance: "suspicious", strength: "moderate",
                   accounts: [], hosts: ["DB-FIN-01"], event_ids: [], techniques: [], expanded: false }], gaps: [], duration_ms: 3 },
    { agent: "threat_intel", title: "Threat intelligence agent", purpose: "ATT&CK and watchlist.", status: "completed", examined: [],
      findings: [{ statement: "Consistent with ATT&CK T1110 Brute Force.", stance: "context", strength: "weak", accounts: [], hosts: [],
                   event_ids: [], techniques: [{ id: "T1110", name: "Brute Force", url: "https://attack.mitre.org/techniques/T1110/" }], expanded: false }],
      gaps: ["No external threat-intelligence feed is queried."], duration_ms: 1 },
    { agent: "endpoint", title: "Endpoint investigation agent", purpose: "Endpoint telemetry.", status: "unavailable",
      examined: ["Endpoint data sources connected to AgentSOC: none"], findings: [],
      gaps: ["On DB-FIN-01, around Day 3 10:55:00: process creation and command lines."], duration_ms: 0 },
  ],
  correlation: {
    summary: "3 of 4 specialised agents ran on this incident's data.", corroborated: ["Host DB-FIN-01 is flagged by the Identity and Network / host agents."],
    conflicts: [], techniques: [{ id: "T1110", name: "Brute Force", url: "https://attack.mitre.org/techniques/T1110/" }],
    open_questions: [], unavailable_agents: ["Endpoint investigation agent"], counts: { suspicious: 2, benign: 0, context: 1 },
    entities: [{ kind: "host", name: "DB-FIN-01", suspicious_agents: ["identity", "network"], benign_agents: [], findings: 2 }],
  },
  response_plan: {
    posture: "contain_now", summary: "Contain now: more than one agent points to access that worked.",
    notes: ["AgentSOC does not carry out any of these steps."],
    steps: [
      { phase: "contain", action: "End every active session of alice.fin@CORP and reset its password.", target: "alice.fin@CORP",
        why: "Flagged as suspicious by the Identity agent and Network / host agent.", based_on: ["Identity agent", "Network / host agent"],
        action_type: "REVOKE_SESSION", risk_engine_proposed: true, disruptive: true },
      { phase: "investigate", action: "Collect: On DB-FIN-01, process creation and command lines.", target: null,
        why: "The endpoint agent has no telemetry.", based_on: ["Endpoint investigation agent"], action_type: null, risk_engine_proposed: false, disruptive: false },
      { phase: "prevent", action: "Enforce account lockout and multi-factor authentication for remote sign-ins.", target: null,
        why: "Consistent with ATT&CK T1110 (Brute Force).", based_on: ["Threat intelligence agent"], action_type: "ENABLE_MFA", risk_engine_proposed: false, disruptive: false },
    ],
  },
};

function routes(extra: Record<string, Handler> = {}): Record<string, Handler> {
  return {
    "GET /api/health": () => ({ status: "ok", version: "0.9.0", analysis: "available", sources: 1 }),
    "GET /api/sources": () => SOURCES,
    "GET /api/overview": () => ({ ...OVERVIEW, review_counts: { open: 2, more_evidence: 0, accepted: 1, dismissed: 0 } }),
    "GET /api/incidents": (url: URL) => {
      const review = url.searchParams.get("review");
      const items = [{ ...ALICE, review_status: "accepted" }, { ...CAROL, review_status: "open" }]
        .filter((i) => !review || i.review_status === review);
      return { items, total: items.length, page: 1, page_size: 20 };
    },
    "GET /api/incidents/INC-00002": () => ALICE_DETAIL,
    "GET /api/incidents/INC-00002/review": () => OPEN,
    "GET /api/incidents/INC-00002/investigation": () => json({ detail: "none" }, 404),
    "GET /api/incidents/INC-00002/context": () => CONTEXT,
    "GET /api/incidents/INC-00002/agents": (url: URL) => {
      const w = url.searchParams.get("window_hours");
      return w ? { ...AGENTS, mode: "expanded", window_hours: Number(w) } : AGENTS;
    },
    ...extra,
  };
}

const bodyOf = (calls: { method: string; url: URL; init?: RequestInit }[], method: string, path: string) =>
  JSON.parse(String(calls.filter((c) => c.method === method && c.url.pathname === path).at(-1)!.init!.body));

describe("analyst decision", () => {
  it("accepts with a note and shows who decided", async () => {
    const { calls } = mockApi(routes({ "POST /api/incidents/INC-00002/review": () => accepted("Owner confirmed.") }));
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002");
    await user.click(await screen.findByRole("button", { name: "Accept" }));
    expect(screen.getByText(/does not take any action/)).toBeInTheDocument();
    await user.type(screen.getByLabelText(/Note/), "Owner confirmed.");
    await user.click(screen.getByRole("button", { name: "Accept incident" }));
    expect(await screen.findByText(/Accepted by analyst1/)).toBeInTheDocument();
    expect(bodyOf(calls, "POST", "/api/incidents/INC-00002/review")).toEqual({ decision: "accepted", note: "Owner confirmed." });
    const post = calls.find((c) => c.method === "POST")!;
    expect((post.init!.headers as Record<string, string>)["X-CSRF-Token"]).toBe("csrf-test-token");
    expect(screen.getByRole("button", { name: "Reopen" })).toBeInTheDocument();
  });

  it("will not dismiss without a reason, and needs a note for 'other'", async () => {
    const { calls } = mockApi(routes({ "POST /api/incidents/INC-00002/review": () => OPEN }));
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002");
    await user.click(await screen.findByRole("button", { name: "Dismiss" }));
    await user.click(screen.getByRole("button", { name: "Dismiss incident" }));
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    await user.click(screen.getByLabelText(/Other/));
    expect(screen.getByLabelText(/Note \(required\)/)).toBeRequired();
    await user.click(screen.getByLabelText("False positive"));
    await user.click(screen.getByRole("button", { name: "Dismiss incident" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    expect(bodyOf(calls, "POST", "/api/incidents/INC-00002/review")).toEqual({ decision: "dismissed", reason: "false_positive" });
  });

  it("asks for more evidence: the agents re-run over the wider window", async () => {
    const more: ReviewState = { status: "more_evidence", latest: { decision: "more_evidence", reason: null, note: null, window_hours: 6,
      analyst: "analyst1", created_at: "2026-11-14T09:00:00Z", current_version: true }, history: [] };
    const { calls } = mockApi(routes({ "POST /api/incidents/INC-00002/review": () => more }));
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002");
    await user.click(await screen.findByRole("button", { name: "More evidence" }));
    await user.selectOptions(screen.getByLabelText(/Look this far/), "6");
    await user.click(screen.getByRole("button", { name: "Gather more evidence" }));
    expect(await screen.findByText("Wider context")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Agents/, selected: true })).toBeInTheDocument();
    expect(await screen.findByText("Expanded to ±6 h at your request")).toBeInTheDocument();
    const agentsCall = calls.find((c) => c.url.pathname.endsWith("/agents"))!;
    expect(agentsCall.url.searchParams.get("window_hours")).toBe("6");
    expect(await screen.findByText(/does not occur in this data source before/)).toBeInTheDocument();
    expect(screen.getByText("never")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "INC-00001" })).toBeInTheDocument();
    expect(bodyOf(calls, "POST", "/api/incidents/INC-00002/review")).toEqual({ decision: "more_evidence", window_hours: 6 });
    const ctx = calls.find((c) => c.url.pathname.endsWith("/context"))!;
    expect(ctx.url.searchParams.get("window_hours")).toBe("6");
    // The analyst can still decide after reading the context.
    expect(screen.getByRole("button", { name: "Accept" })).toBeInTheDocument();
  });

  it("shows a refused decision", async () => {
    mockApi(routes({ "POST /api/incidents/INC-00002/review": () => json({ detail: "Explain the reason in the note." }, 400) }));
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002");
    await user.click(await screen.findByRole("button", { name: "Accept" }));
    await user.click(screen.getByRole("button", { name: "Accept incident" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Explain the reason in the note.");
  });

  it("has no accessibility violations with the decision form open", async () => {
    mockApi(routes());
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002");
    await user.click(await screen.findByRole("button", { name: "Dismiss" }));
    await screen.findByText("Why is it not a concern?");
    const result = await axe.run(document.body, { resultTypes: ["violations"] });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

describe("queue", () => {
  it("filters the incident list by decision", async () => {
    const { calls } = mockApi(routes());
    const user = userEvent.setup();
    renderApp("/incidents");
    expect(await screen.findByText("carol.fin@CORP")).toBeInTheDocument();
    const filters = screen.getByRole("group", { name: "Filter by decision" });
    await user.click(within(filters).getByRole("button", { name: /Awaiting decision/ }));
    await waitFor(() => expect(screen.queryByText("alice.fin@CORP")).not.toBeInTheDocument());
    expect(calls.at(-1)!.url.searchParams.get("review")).toBe("open");
  });

  it("puts the decision queue first on the overview", async () => {
    mockApi(routes());
    renderApp("/");
    expect(await screen.findByText(/awaiting your decision/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Review the queue/ })).toHaveAttribute("href", "/incidents?review=open");
  });

  it("groups the menu by task", async () => {
    mockApi(routes());
    renderApp("/");
    const nav = await screen.findByRole("navigation", { name: "Primary" });
    for (const heading of ["Triage", "Investigate", "Data & audit"]) expect(within(nav).getByText(heading)).toBeInTheDocument();
    expect(within(nav).queryByText("Administration")).not.toBeInTheDocument();
  });
});

describe("report", () => {
  const REPORT: ReportView = {
    generated_at: "2026-11-14T09:10:00Z", generated_by: "analyst1", source_label: "Synthetic demo scenario",
    dataset_label: "SYNTHETIC 4-day enterprise scenario", dataset_sha256: "a".repeat(64), detection_engine: "detect/2.1",
    incident: ALICE_DETAIL, review: accepted("Owner confirmed."), risk: null, risk_unavailable: "No verified risk assessment for this incident.",
    paths: [], paths_unavailable: null, investigation: null, context: CONTEXT, agents: AGENTS,
    notices: ["SYNTHETIC DATA: generated for demonstration; not real activity.", "Proposed response actions are dry-run proposals."],
  };

  it("collects the decision, evidence, context and provenance, and downloads Markdown", async () => {
    const { calls } = mockApi(routes({
      "GET /api/incidents/INC-00002/report": () => REPORT,
      "GET /api/incidents/INC-00002/report.md": () => new Response("# Incident report", { headers: { "Content-Type": "text/markdown" } }),
    }));
    URL.createObjectURL = () => "blob:report";
    URL.revokeObjectURL = () => undefined;
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002/report?source=demo");
    expect(await screen.findByText("SYNTHETIC DATA: generated for demonstration; not real activity.")).toBeInTheDocument();
    for (const heading of ["Analyst decision", "Summary", "Detection findings", "Timeline", "Attack paths",
                           "Risk and proposed response", "Investigation", "Specialised agents", "How to stop this: Contain now",
                           "Wider context (±24 h)", "Provenance"]) {
      expect(screen.getByRole("heading", { name: heading })).toBeInTheDocument();
    }
    expect(screen.getByText("Owner confirmed.")).toBeInTheDocument();
    expect(screen.getByText("No investigation has been run for this incident.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Download Markdown/ }));
    await waitFor(() => expect(calls.some((c) => c.url.pathname.endsWith("/report.md"))).toBe(true));
    expect(calls.find((c) => c.url.pathname.endsWith("/report.md"))!.init!.credentials).toBe("same-origin");
  });

  it("is linked from every incident", async () => {
    mockApi(routes());
    renderApp("/incidents/INC-00002");
    expect(await screen.findByRole("link", { name: /Full report/ })).toHaveAttribute("href", "/incidents/INC-00002/report?source=demo");
  });
});


describe("specialised agents", () => {
  it("shows the pipeline, each agent and the correlation", async () => {
    mockApi(routes());
    renderApp("/incidents/INC-00002?tab=agents");
    const pipeline = await screen.findByRole("group", { name: "Investigation pipeline" });
    for (const step of ["Orchestrator", "Identity", "Network / host", "Threat intelligence", "Endpoint investigation", "Correlation", "Report"]) {
      expect(within(pipeline).getByText(step)).toBeInTheDocument();
    }
    expect(screen.getByText("Host DB-FIN-01 is flagged by the Identity and Network / host agents.")).toBeInTheDocument();
    expect(screen.getByText(/6 of 9 incident events failed/)).toBeInTheDocument();
    expect(screen.getAllByText("No data available").length).toBeGreaterThan(0);
    expect(screen.getByText("Evidence to request")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "T1110" })).toHaveAttribute("rel", "noreferrer noopener");
  });

  it("re-runs the agents when the analyst widens the search", async () => {
    const { calls } = mockApi(routes());
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002?tab=agents");
    await screen.findByText("Standard run");
    await user.selectOptions(screen.getByLabelText("Search"), "72");
    expect(await screen.findByText("Expanded to ±72 h at your request")).toBeInTheDocument();
    expect(calls.filter((c) => c.url.pathname.endsWith("/agents")).at(-1)!.url.searchParams.get("window_hours")).toBe("72");
  });

  it("has no accessibility violations", async () => {
    mockApi(routes());
    renderApp("/incidents/INC-00002?tab=agents");
    await screen.findByText("Standard run");
    const result = await axe.run(document.body, { resultTypes: ["violations"] });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });

  it("says how to stop the activity, phase by phase, without executing anything", async () => {
    mockApi(routes());
    renderApp("/incidents/INC-00002?tab=agents");
    const plan = await screen.findByRole("heading", { name: /How to stop this/ });
    expect(within(plan).getByText("Contain now")).toBeInTheDocument();
    const contain = screen.getByRole("region", { name: "1. Contain" });
    expect(within(contain).getByText(/End every active session of alice.fin@CORP/)).toBeInTheDocument();
    expect(within(contain).getByText("Disruptive: needs approval")).toBeInTheDocument();
    expect(within(contain).getByText("Also proposed by the risk engine")).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "2. Investigate" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "4. Prevent" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "3. Recover" })).not.toBeInTheDocument();
    expect(screen.getByText("AgentSOC does not carry out any of these steps.")).toBeInTheDocument();
    expect(within(screen.getByRole("group", { name: "Investigation pipeline" })).getByText("Response plan")).toBeInTheDocument();
    // Recommendations only: the card offers no button that would act on anything.
    expect(within(contain).queryByRole("button")).not.toBeInTheDocument();
  });
});
