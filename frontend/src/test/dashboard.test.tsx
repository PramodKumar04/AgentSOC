import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, it, vi } from "vitest";

import type { IncidentDetail } from "@/lib/api";
import { AMBIGUOUS, AVAILABLE, DETAIL, GRAPH, INFERRED, OBSERVED, RISK, RUN, withPath } from "./dashboard-fixtures";
import { ALICE, CAROL, DATASETS, OVERVIEW, SOURCES } from "./fixtures";
import { json, mockApi, renderApp, type Handler } from "./render";

// jsdom has no layout, so React Flow itself is replaced. The real canvas module, node
// component and edge mapping still run, and each drawn edge is exposed as a button.
vi.mock("@xyflow/react", async () => {
  const { createElement: h, Fragment } = await import("react");
  type Props = Record<string, any>;
  return {
    Position: { Left: "left", Right: "right" }, MarkerType: { ArrowClosed: "arrowclosed" },
    Background: () => null, Controls: () => null, Handle: () => null, BaseEdge: () => null,
    EdgeLabelRenderer: () => null, getBezierPath: () => ["", 0, 0],
    ReactFlow: ({ nodes, edges, nodeTypes, onEdgeClick }: Props) => h("div", { "data-testid": "canvas" },
      nodes.map((n: Props) => h(Fragment, { key: n.id }, h(nodeTypes[n.type], { id: n.id, data: n.data }))),
      edges.map((e: Props) => h("button", {
        key: e.id, type: "button", "data-testid": "edge", "data-id": e.id, "data-state": e.data.state,
        onClick: (ev: unknown) => onEdgeClick(ev, e),
      }, e.ariaLabel))),
  };
});

const HEALTH = { status: "ok", version: "0.9.0", analysis: "available", sources: 2 };
const INC = "/api/incidents/INC-00002";
const NONE = () => json({ detail: "none" }, 404);

function routes(extra: Record<string, Handler> = {}): Record<string, Handler> {
  return {
    "GET /api/health": () => HEALTH,
    "GET /api/sources": () => SOURCES,
    "GET /api/overview": () => OVERVIEW,
    "GET /api/incidents": () => ({ items: [{ ...ALICE, risk_score: 37.5, risk_band: "MEDIUM" }, CAROL], total: 2, page: 1, page_size: 20 }),
    [`GET ${INC}`]: () => DETAIL,
    [`GET ${INC}/graph`]: () => GRAPH,
    [`GET ${INC}/risk`]: () => RISK,
    [`GET ${INC}/investigation`]: NONE,
    "GET /api/datasets": () => [{ ...DATASETS[0], structural: { ...RUN, engine_version: "sse/1.0" }, risk: RUN }],
    "GET /api/activity": () => ({ entries: [], total: 0, chain_intact: true }),
    ...extra,
  };
}

const edges = () => screen.getAllByTestId("edge");
const edge = (id: string) => edges().find((e) => e.dataset.id === id)!;
const detailWith = (patch: Partial<IncidentDetail>) => () => ({ ...DETAIL, ...patch });

async function noAxeViolations(container: HTMLElement) {
  const { violations } = await axe.run(container, { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } });
  expect(violations.map((v) => `${v.id}: ${v.nodes[0]?.html}`)).toEqual([]);
}

describe("severity and risk stay separate", () => {
  it("labels both in the incident header", async () => {
    mockApi(routes());
    renderApp("/incidents/INC-00002");
    expect(await screen.findByText("Detection severity")).toBeInTheDocument();
    const severity = screen.getByText("Detection severity").parentElement!;
    const risk = screen.getByText("RSEM risk").parentElement!;
    expect(within(severity).getByText("Critical")).toBeInTheDocument();
    expect(within(risk).getByText("37.5")).toBeInTheDocument();
    expect(within(risk).queryByText("Critical")).not.toBeInTheDocument();
  });

  it("shows risk in the incident list without changing the default sort", async () => {
    const { calls } = mockApi(routes());
    renderApp("/incidents");
    expect(await screen.findByText("37.5")).toBeInTheDocument();
    expect(screen.getByText("Not assessed")).toBeInTheDocument();
    const call = calls.find((c) => c.url.pathname === "/api/incidents")!;
    expect(call.url.searchParams.get("sort")).toBe("severity");
    expect(screen.queryByRole("button", { name: /^Risk/ })).not.toBeInTheDocument();
  });

  it("shows the risk distribution from the API", async () => {
    mockApi(routes({ "GET /api/overview": () => ({ ...OVERVIEW, risk_status: AVAILABLE, risk_assessed: 3,
                                                  risk_counts: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 2 } }) }));
    renderApp("/");
    expect(await screen.findByRole("img", { name: /Risk distribution: Critical 0, High 1, Medium 0, Low 2/ })).toBeInTheDocument();
    expect(screen.getByText(/3 of 3 incidents scored/)).toBeInTheDocument();
    expect(screen.getByText("Severity distribution")).toBeInTheDocument();
  });

  it.each([
    ["not_assessed", /Risk: not assessed/],
    ["stale", /Risk: assessment out of date/],
    ["unavailable", /Risk: assessment unavailable/],
  ] as const)("explains a %s risk distribution", async (state, title) => {
    mockApi(routes({ "GET /api/overview": () => ({ ...OVERVIEW, risk_counts: null, risk_assessed: 0, risk_status: { state, detail: "Stated by the API." } }) }));
    renderApp("/");
    expect(await screen.findByText(title)).toBeInTheDocument();
    expect(screen.getByText("Stated by the API.")).toBeInTheDocument();
    expect(screen.queryByRole("img", { name: /Risk distribution/ })).not.toBeInTheDocument();
  });
});

describe("URL tab navigation", () => {
  it.each([
    ["graph", "Reported paths (3)"], ["risk", "Risk breakdown"], ["provenance", "Audit trail"],
  ])("opens ?tab=%s directly", async (tab, text) => {
    mockApi(routes());
    renderApp(`/incidents/INC-00002?tab=${tab}`);
    expect(await screen.findByText(text)).toBeInTheDocument();
  });

  it("keeps the original tabs and falls back on an unknown tab", async () => {
    mockApi(routes());
    renderApp("/incidents/INC-00002?tab=nonsense");
    expect(await screen.findByRole("tab", { name: /Overview/, selected: true })).toBeInTheDocument();
    for (const name of [/Timeline/, /Detection analysis/, /Evidence/, /Attack graph/, /Risk & response/, /AI investigation/, /Provenance/]) {
      expect(screen.getByRole("tab", { name })).toBeInTheDocument();
    }
  });

  it("highlights a path named in the URL", async () => {
    mockApi(routes());
    renderApp("/incidents/INC-00002?tab=graph&path=P-INF");
    await screen.findAllByTestId("edge");
    expect(edge("MOVEMENT|host:WS1|host:SRV1").dataset.state).toBe("path-inferred");
  });
});

describe("attack graph", () => {
  it("draws only links returned by the API", async () => {
    mockApi(routes());
    renderApp("/incidents/INC-00002?tab=graph");
    await screen.findAllByTestId("edge");
    const allowed = new Set(GRAPH.links.filter((k) => k.kind !== "LOCAL").map((k) => k.link_id));
    expect(new Set(edges().map((e) => e.dataset.id))).toEqual(allowed);
  });

  it("shows the original events behind a selected connection", async () => {
    mockApi(routes());
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002?tab=graph");
    await screen.findAllByTestId("edge");
    await user.click(edge("MOVEMENT|host:WS1|host:SRV1"));
    const details = screen.getByRole("region", { name: "Selected graph item" });
    expect(within(details).getByText("E1")).toBeInTheDocument();
    expect(within(details).getByText("auth.txt:1")).toBeInTheDocument();
    expect(within(details).queryByText("E4")).not.toBeInTheDocument();
  });

  it("selects a node with the keyboard", async () => {
    mockApi(routes());
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002?tab=graph");
    const node = await screen.findByRole("button", { name: /Host DB1/ });
    node.focus();
    await user.keyboard("{Enter}");
    const details = screen.getByRole("region", { name: "Selected graph item" });
    expect(within(details).getByText("E2")).toBeInTheDocument();
  });

  it("offers every connection in a keyboard-reachable table", async () => {
    mockApi(routes());
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002?tab=graph");
    await user.click(await screen.findByRole("button", { name: /All connections as a table \(6\)/ }));
    await user.click(screen.getByRole("button", { name: "SRV1 → APP1" }));
    expect(within(screen.getByRole("region", { name: "Selected graph item" })).getByText("E3")).toBeInTheDocument();
  });

  it("labels each kind of path in words", async () => {
    mockApi(routes());
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002?tab=graph");
    const inferred = (await screen.findAllByRole("button", { pressed: false, name: /Inferred/ }))[0];
    expect(screen.getByRole("button", { name: /Observed.*Validated against logs/ })).toBeInTheDocument();
    expect(within(inferred).getByText("Conditionally feasible")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Inferred.*Weak evidence/ })).toBeInTheDocument();
    await user.click(inferred);
    expect(screen.getByText(INFERRED.conditions[0])).toBeInTheDocument();
    expect(edge("ATTEMPT|host:WS1|host:SRV1").dataset.state).toBe("dimmed");
  });

  it("clears the highlight when a path is pressed again", async () => {
    mockApi(routes());
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002?tab=graph");
    const button = await screen.findByRole("button", { name: /Observed.*Validated/ });
    await user.click(button);
    expect(edge(OBSERVED.link_ids[0]).dataset.state).toBe("path-observed");
    await user.click(screen.getByRole("button", { name: /Observed.*Validated/, pressed: true }));
    await waitFor(() => expect(edge(OBSERVED.link_ids[0]).dataset.state).toBe("default"));
  });

  it("toggles failed attempts", async () => {
    mockApi(routes());
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002?tab=graph");
    await screen.findAllByTestId("edge");
    await user.click(screen.getByRole("checkbox", { name: "Failed attempts" }));
    await waitFor(() => expect(edges().some((e) => e.dataset.id?.startsWith("ATTEMPT"))).toBe(false));
  });

  it("states truncation and missing events", async () => {
    mockApi(routes({ [`GET ${INC}/graph`]: () => ({
      ...GRAPH, missing_event_ids: ["E99"],
      stats: { ...GRAPH.stats, truncated: true, truncation_reasons: ["Context stops at 6 hops."] },
    }) }));
    renderApp("/incidents/INC-00002?tab=graph");
    expect(await screen.findByText("This graph is truncated")).toBeInTheDocument();
    expect(screen.getByText("Context stops at 6 hops.")).toBeInTheDocument();
    expect(screen.getByText(/1 cited event\(s\) could not be found/)).toBeInTheDocument();
  });

  it("handles an incident with no paths", async () => {
    mockApi(routes({ [`GET ${INC}/graph`]: () => ({ ...GRAPH, paths: [] }) }));
    renderApp("/incidents/INC-00002?tab=graph");
    expect(await screen.findByText(/No multi-event movement path was found/)).toBeInTheDocument();
  });

  it.each([
    ["not_assessed", /Attack graph: not assessed/], ["stale", /Attack graph: assessment out of date/], ["unavailable", /Attack graph: assessment unavailable/],
  ] as const)("explains a %s structural assessment", async (state, title) => {
    mockApi(routes({
      [`GET ${INC}`]: detailWith({ assessments: { structural: { state, detail: "From the API." }, risk: AVAILABLE, truncated: false, truncation_reasons: [] } }),
      [`GET ${INC}/graph`]: NONE,
    }));
    renderApp("/incidents/INC-00002?tab=graph");
    expect(await screen.findByText(title)).toBeInTheDocument();
    expect(screen.getByText("From the API.")).toBeInTheDocument();
    expect(screen.queryByTestId("canvas")).not.toBeInTheDocument();
  });

  it("offers retry on a server error", async () => {
    mockApi(routes({ [`GET ${INC}/graph`]: () => json({ detail: "Data could not be loaded." }, 500) }));
    renderApp("/incidents/INC-00002?tab=graph");
    expect(await screen.findByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("does not load graph data until the tab is opened", async () => {
    const { calls } = mockApi(routes());
    renderApp("/incidents/INC-00002");
    await screen.findByText("Detection severity");
    expect(calls.some((c) => c.url.pathname.endsWith("/graph"))).toBe(false);
  });
});

describe("risk and response", () => {
  it("shows server values without recalculating them", async () => {
    mockApi(routes());
    renderApp("/incidents/INC-00002?tab=risk");
    // 0.6 × 0.35 and 0.8 × 0.15 would give 21.0 and 12.0. The fixture says 16.5 on purpose.
    expect(await screen.findByText("16.5 pts")).toBeInTheDocument();
    expect(screen.getByText("21.0 pts")).toBeInTheDocument();
    expect(screen.getByText(/Base score 41\.7/)).toBeInTheDocument();
    expect(screen.getByText("0.36")).toBeInTheDocument();
  });

  it("keeps the three quantities apart", async () => {
    mockApi(routes());
    renderApp("/incidents/INC-00002?tab=risk");
    expect(await screen.findByText("RSEM incident risk")).toBeInTheDocument();
    expect(screen.getAllByText("Investigation confidence").length).toBeGreaterThan(0);
    expect(screen.getByText(/Priority orders these proposals and has no effect on incident risk/)).toBeInTheDocument();
    expect(screen.getByText("Risk is lower than severity")).toBeInTheDocument();
  });

  it("labels model output as an estimate used in no score", async () => {
    mockApi(routes());
    renderApp("/incidents/INC-00002?tab=risk");
    expect(await screen.findByText("Model-generated estimates")).toBeInTheDocument();
    expect(screen.getByText(/Used in no score/)).toBeInTheDocument();
  });

  it("keeps actions display-only", async () => {
    const { calls } = mockApi(routes());
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002?tab=risk");
    expect(await screen.findByText("Enable MFA")).toBeInTheDocument();
    expect(screen.getAllByText("Proposed")).toHaveLength(2);
    expect(screen.getAllByText("Dry run")).toHaveLength(2);
    expect(screen.getByText("Requires approval")).toBeInTheDocument();
    expect(screen.getByText(/Display only/)).toBeInTheDocument();
    expect(screen.queryAllByRole("button", { name: /approve|execute|apply|run action|isolate|disable|revoke/i })).toEqual([]);
    await user.click(screen.getByText("Enable MFA"));
    expect(calls.filter((c) => c.method !== "GET")).toEqual([]);
  });

  it("gives the reasons for withheld actions", async () => {
    mockApi(routes());
    renderApp("/incidents/INC-00002?tab=risk");
    expect(await screen.findByText("Isolate host")).toBeInTheDocument();
    expect(screen.getByText(/Risk is below High\./)).toBeInTheDocument();
  });

  it("warns when the score rests on truncated context", async () => {
    mockApi(routes({ [`GET ${INC}`]: detailWith({ assessments: { structural: AVAILABLE, risk: AVAILABLE, truncated: true, truncation_reasons: ["Cut short."] } }) }));
    renderApp("/incidents/INC-00002?tab=risk");
    expect(await screen.findByText("Based on truncated context")).toBeInTheDocument();
  });

  it.each([
    ["not_assessed", /Risk: not assessed/], ["stale", /Risk: assessment out of date/], ["unavailable", /Risk: assessment unavailable/],
  ] as const)("explains a %s risk record", async (state, title) => {
    mockApi(routes({
      [`GET ${INC}`]: detailWith({ risk_score: null, risk_band: null,
                                   assessments: { structural: AVAILABLE, risk: { state, detail: "From the API." }, truncated: false, truncation_reasons: [] } }),
      [`GET ${INC}/risk`]: NONE,
    }));
    renderApp("/incidents/INC-00002?tab=risk");
    expect(await screen.findByText(title)).toBeInTheDocument();
    expect(screen.queryByText("Proposed response actions")).not.toBeInTheDocument();
    expect(within(screen.getByText("Detection severity").parentElement!).getByText("Critical")).toBeInTheDocument();
  });

  it("copes with an API that omits assessment status", async () => {
    mockApi(routes({ [`GET ${INC}`]: detailWith({ assessments: undefined, risk_score: undefined, risk_band: undefined }), [`GET ${INC}/risk`]: NONE }));
    renderApp("/incidents/INC-00002?tab=risk");
    expect(await screen.findByText(/Risk: not assessed/)).toBeInTheDocument();
  });
});

describe("AI investigation path validation", () => {
  const open = (result: unknown) => {
    mockApi(routes({ [`GET ${INC}/investigation`]: () => result }));
    renderApp("/incidents/INC-00002?tab=investigation");
  };
  const validation = { hypothesis_id: "H1", checked_path: ["WS1", "DB1"], missing_edges: [], conditions: [], reasons: ["Checked."], evidence_event_ids: [] };

  it("shows a supported path as validated", async () => {
    open(withPath({ proposed_path: ["WS1", "SRV1"], path_validation: { ...validation, verdict: "FEASIBLE", evidence_event_ids: ["E1"] } }));
    expect(await screen.findByText("Validated against logs")).toBeInTheDocument();
    expect(screen.getByText("WS1 → SRV1")).toBeInTheDocument();
    expect(screen.getByText(/not proof of compromise\./)).toBeInTheDocument();
  });

  it("never presents an unsupported path as validated", async () => {
    open(withPath({ proposed_path: ["WS1", "PAYROLL"], path_validation: { ...validation, verdict: "INFEASIBLE", missing_edges: [{ source: "WS1", target: "PAYROLL" }] } }));
    expect(await screen.findByText("Not validated")).toBeInTheDocument();
    expect(screen.queryByText("Validated against logs")).not.toBeInTheDocument();
    expect(screen.getByText(/does not prove the movement was impossible/)).toBeInTheDocument();
    expect(screen.getByText(/not observed in these logs/)).toBeInTheDocument();
  });

  it("states the conditions of a conditional path", async () => {
    open(withPath({ proposed_path: ["WS1", "SRV1"], path_validation: { ...validation, verdict: "CONDITIONALLY_FEASIBLE", conditions: ["Two accounts, one operator."] } }));
    expect(await screen.findByText("Conditionally feasible")).toBeInTheDocument();
    expect(screen.getByText("Two accounts, one operator.")).toBeInTheDocument();
  });

  it("does not imply validation when none happened", async () => {
    open(withPath({ proposed_path: ["WS1", "SRV1"], path_validation: null }));
    expect(await screen.findByText("Not checked")).toBeInTheDocument();
    expect(screen.queryByText("Validated against logs")).not.toBeInTheDocument();
  });

  it("omits the section when no path was proposed", async () => {
    open(withPath({ proposed_path: [], path_validation: null }));
    expect(await screen.findByText("Investigation completed")).toBeInTheDocument();
    expect(screen.queryByText("Model-proposed path")).not.toBeInTheDocument();
  });

  it("labels the model's number as a model-generated estimate", async () => {
    open(withPath({}));
    expect(await screen.findByText("Model-generated estimate")).toBeInTheDocument();
  });
});

describe("provenance and audit", () => {
  it("asks the server for this incident's audit trail", async () => {
    const { calls } = mockApi(routes());
    renderApp("/incidents/INC-00002?tab=provenance");
    await screen.findByText("Audit trail");
    await waitFor(() => expect(calls.some((c) => c.url.pathname === "/api/activity")).toBe(true));
    const call = calls.find((c) => c.url.pathname === "/api/activity")!;
    expect(call.url.searchParams.get("subject")).toBe("INC-00002");
    expect(call.url.searchParams.get("source")).toBe("demo");
  });

  it("shows hashes and engines for each stage", async () => {
    mockApi(routes());
    renderApp("/incidents/INC-00002?tab=provenance");
    expect(await screen.findByText("sse/1.0")).toBeInTheDocument();
    expect(screen.getByText("rsem/1.0")).toBeInTheDocument();
    expect(screen.getByTitle("e".repeat(64))).toBeInTheDocument();
    expect(screen.getByTitle("f".repeat(64))).toBeInTheDocument();
  });

  it("shows entries and reports an intact chain", async () => {
    mockApi(routes({ "GET /api/activity": () => ({ total: 1, chain_intact: true, entries: [
      { sequence: 4, timestamp: "2026-11-09T06:00:00Z", actor: "analyst-local", event_type: "investigation.completed", subject_id: "INC-00002", details: { engine: "llm" } }] }) }));
    renderApp("/incidents/INC-00002?tab=provenance");
    expect(await screen.findByText("investigation.completed")).toBeInTheDocument();
    expect(screen.getByText("Log chain intact")).toBeInTheDocument();
  });

  it("flags a broken log chain", async () => {
    mockApi(routes({ "GET /api/activity": () => ({ entries: [], total: 0, chain_intact: false }) }));
    renderApp("/incidents/INC-00002?tab=provenance");
    expect(await screen.findByText("Log chain broken")).toBeInTheDocument();
  });

  it("shows an empty audit state", async () => {
    mockApi(routes());
    renderApp("/incidents/INC-00002?tab=provenance");
    expect(await screen.findByText("No recorded activity for this incident")).toBeInTheDocument();
  });

  it("shows analysis states in Data Sources", async () => {
    mockApi(routes({ "GET /api/datasets": () => [{ ...DATASETS[0],
      structural: { state: "not_assessed", detail: "x" }, risk: { state: "stale", detail: "y" } }] }));
    renderApp("/data-sources");
    expect(await screen.findByText("Not assessed")).toBeInTheDocument();
    expect(screen.getByText("Out of date")).toBeInTheDocument();
  });
});

describe("accessibility", () => {
  it.each([
    ["overview", "/", "Security overview"],
    ["incidents", "/incidents", "Incidents"],
  ])("%s page has no axe violations", async (_, path, heading) => {
    mockApi(routes());
    const { container } = renderApp(path);
    await screen.findByRole("heading", { name: heading });
    await noAxeViolations(container);
  });

  it.each([
    ["graph", "Reported paths (3)", "Selection"],
    ["risk", "Risk breakdown", "Proposed response actions"],
    ["provenance", "Audit trail", "No recorded activity for this incident"],
  ])("%s tab has no axe violations", async (tab, text, settled) => {
    mockApi(routes());
    const { container } = renderApp(`/incidents/INC-00002?tab=${tab}&path=${AMBIGUOUS.path_id}`);
    await screen.findByText(text);
    await screen.findByText(settled);  // content that only appears once the tab has loaded
    await noAxeViolations(container);
  });

  it("describes graph nodes to assistive technology", async () => {
    mockApi(routes());
    renderApp("/incidents/INC-00002?tab=graph");
    expect(await screen.findByRole("button", { name: /Host SRV1, 4 events, Choke point, Account switch, Weak evidence/ })).toBeInTheDocument();
    expect(screen.getByRole("group", { name: /connections table below/ })).toBeInTheDocument();
  });

  it("exposes risk components as named meters", async () => {
    mockApi(routes());
    renderApp("/incidents/INC-00002?tab=risk");
    expect(await screen.findByRole("meter", { name: /Risk: Movement depth 60%/ })).toBeInTheDocument();
  });
});
