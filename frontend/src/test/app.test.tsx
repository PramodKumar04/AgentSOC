import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import {
  ALICE, ALICE_DETAIL, CAROL, DATASETS, EVENT, INVESTIGATIONS, investigation, OVERVIEW, SOURCES,
} from "./fixtures";
import { json, mockApi, renderApp, type Handler } from "./render";

const HEALTH = { status: "ok", version: "0.5.0", analysis: "available", sources: 2 };

function baseRoutes(extra: Record<string, Handler> = {}) {
  return {
    "GET /api/health": () => HEALTH,
    "GET /api/sources": () => SOURCES,
    "GET /api/overview": () => OVERVIEW,
    "GET /api/incidents": (url: URL) => {
      const q = (url.searchParams.get("q") ?? "").toLowerCase();
      const sev = url.searchParams.getAll("severity");
      const items = [ALICE, CAROL].filter((i) => (!q || i.principal_user.includes(q) || i.incident_id.toLowerCase().includes(q))
        && (!sev.length || sev.includes(i.severity)));
      return { items, total: items.length, page: 1, page_size: 20 };
    },
    "GET /api/incidents/INC-00002": () => ALICE_DETAIL,
    "GET /api/incidents/INC-00002/investigation": () => json({ detail: "none" }, 404),
    "GET /api/investigations": () => INVESTIGATIONS,
    "GET /api/datasets": () => DATASETS,
    "GET /api/events": () => ({ items: [EVENT], total: 1, page: 1, page_size: 25 }),
    "GET /api/activity": () => ({ entries: [], total: 0, chain_intact: true }),
    ...extra,
  };
}

describe("navigation and overview", () => {
  it("shows real statistics and navigates via the sidebar", async () => {
    mockApi(baseRoutes());
    const user = userEvent.setup();
    renderApp("/");
    expect(await screen.findByRole("heading", { name: "Security overview" })).toBeInTheDocument();
    const stats = screen.getByText("Total incidents").closest("div")!;
    expect(within(stats).getByText("3")).toBeInTheDocument();
    expect(screen.getByText("Detection findings")).toBeInTheDocument();

    const nav = screen.getByRole("navigation", { name: "Primary" });
    for (const label of ["Overview", "Incidents", "Investigations", "Evidence Explorer", "Data Sources", "System Activity"]) {
      expect(within(nav).getByRole("link", { name: label })).toBeInTheDocument();
    }
    await user.click(within(nav).getByRole("link", { name: "Incidents" }));
    expect(await screen.findByRole("heading", { name: "Incidents" })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: "Incidents" })).toHaveAttribute("aria-current", "page");
  });

  it("shows the provenance of the selected data source", async () => {
    mockApi(baseRoutes());
    renderApp("/");
    expect(await screen.findAllByText(/Synthetic/)).not.toHaveLength(0);
    expect(screen.getByLabelText("Data source")).toHaveValue("demo");
  });

  it("collapses the sidebar", async () => {
    mockApi(baseRoutes());
    const user = userEvent.setup();
    renderApp("/");
    await user.click(await screen.findByRole("button", { name: "Collapse sidebar" }));
    expect(screen.getByRole("button", { name: "Expand sidebar" })).toBeInTheDocument();
  });
});

describe("incidents", () => {
  it("searches and filters through the API", async () => {
    const { calls } = mockApi(baseRoutes());
    const user = userEvent.setup();
    renderApp("/incidents");
    expect(await screen.findByText("carol.fin@CORP")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Search incidents"), "alice");
    await waitFor(() => expect(screen.queryByText("carol.fin@CORP")).not.toBeInTheDocument());
    expect(calls.some((c) => c.url.pathname === "/api/incidents" && c.url.searchParams.get("q") === "alice")).toBe(true);

    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    const medium = await screen.findByRole("button", { name: "Medium" });
    await user.click(medium);
    expect(medium).toHaveAttribute("aria-pressed", "true");
    await waitFor(() => expect(screen.queryByText("alice.fin@CORP")).not.toBeInTheDocument());
    expect(calls.some((c) => c.url.searchParams.getAll("severity").includes("MEDIUM"))).toBe(true);
  });

  it("opens the incident detail page", async () => {
    mockApi(baseRoutes());
    const user = userEvent.setup();
    renderApp("/incidents");
    await user.click(await screen.findByRole("link", { name: "INC-00002" }));
    expect(await screen.findByRole("heading", { name: "INC-00002" })).toBeInTheDocument();
    expect(screen.getByText(/not a confirmed compromise/)).toBeInTheDocument();
  });

  it("renders the timeline and detection analysis tabs", async () => {
    mockApi(baseRoutes());
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002");
    await user.click(await screen.findByRole("tab", { name: /Timeline/ }));
    expect(await screen.findByText("SRV-APP-02 → DB-FIN-01")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: /Detection analysis/ }));
    expect(await screen.findByText("Sequential host-to-host authentication chain")).toBeInTheDocument();
    expect(screen.getByText(/FAILURE_BURST=2 \+ LATERAL_CHAIN=3/)).toBeInTheDocument();
  });

  it("shows real evidence with expandable details and missing fields marked", async () => {
    mockApi(baseRoutes());
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002?tab=evidence");
    await user.click(await screen.findByRole("button", { name: "auth.txt-116" }));
    expect(screen.getByText("Source line")).toBeInTheDocument();
    expect(screen.getByText("missing (not recorded)")).toBeInTheDocument();
  });
});

describe("AI investigation", () => {
  it("investigates on click, disables the button while running, and shows the result", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    let posts = 0;
    mockApi(baseRoutes({
      "POST /api/incidents/INC-00002/investigate": async () => { posts += 1; await gate; return investigation("completed"); },
    }));
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002?tab=investigation");
    const button = await screen.findByRole("button", { name: "Investigate Incident" });
    await user.click(button);
    expect(await screen.findByText(/Investigation in progress/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Investigating/ })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: /Investigating/ }));
    release();
    expect(await screen.findByText("Investigation completed")).toBeInTheDocument();
    expect(posts).toBe(1);
    expect(screen.getAllByText("Credential misuse leading to lateral movement").length).toBeGreaterThan(0);
    expect(screen.getByText("T1078")).toBeInTheDocument();
    expect(screen.getByText(/not proof of compromise/)).toBeInTheDocument();
    // Provider configuration is not part of the analyst view.
    expect(screen.queryByText(/groq/i)).not.toBeInTheDocument();
    expect(screen.queryByText("openai/gpt-oss-120b")).not.toBeInTheDocument();
  });

  it("communicates limited analysis when the deterministic path was used", async () => {
    mockApi(baseRoutes({
      "GET /api/incidents/INC-00002/investigation": () => ({ ...investigation("completed_limited"), cached: true }),
    }));
    renderApp("/incidents/INC-00002?tab=investigation");
    expect(await screen.findByText("Investigation completed with limited analysis")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Re-run investigation" })).toBeEnabled();
  });

  it("shows a clear error when the investigation cannot be completed", async () => {
    mockApi(baseRoutes({
      "POST /api/incidents/INC-00002/investigate": () =>
        json({ detail: "The investigation could not be completed. Please try again later." }, 503),
    }));
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002?tab=investigation");
    await user.click(await screen.findByRole("button", { name: "Investigate Incident" }));
    expect(await screen.findByText("Investigation could not be completed")).toBeInTheDocument();
  });
});

describe("other pages and states", () => {
  it("lists saved investigations and opens one", async () => {
    mockApi(baseRoutes({
      "GET /api/investigations/INC-00002-aac7316fc0b11f44": () => ({ ...investigation("completed"), cached: true }),
    }));
    const user = userEvent.setup();
    renderApp("/investigations");
    await user.click(await screen.findByRole("link", { name: "INC-00002-aac7316fc0b11f44" }));
    expect(await screen.findByRole("heading", { name: "Investigation of INC-00002" })).toBeInTheDocument();
  });

  it("shows evidence explorer records and data sources with provenance", async () => {
    mockApi(baseRoutes());
    renderApp("/evidence");
    expect(await screen.findByRole("button", { name: "auth.txt-116" })).toBeInTheDocument();
  });

  it("separates synthetic and real data sources", async () => {
    mockApi(baseRoutes());
    renderApp("/data-sources");
    expect(await screen.findByRole("heading", { name: "Synthetic demonstration data" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Real LANL 2015 authentication data" })).toBeInTheDocument();
    expect(screen.getByText("Verified")).toBeInTheDocument();
  });

  it("handles an empty incident list", async () => {
    mockApi(baseRoutes({ "GET /api/incidents": () => ({ items: [], total: 0, page: 1, page_size: 20 }) }));
    renderApp("/incidents");
    expect(await screen.findByText("No incidents in this data source")).toBeInTheDocument();
  });

  it("shows a backend-unavailable state with retry", async () => {
    mockApi({});
    const fetchMock = globalThis.fetch as unknown as { mockImplementation: (f: () => Promise<never>) => void };
    fetchMock.mockImplementation(() => Promise.reject(new TypeError("Failed to fetch")));
    renderApp("/");
    expect(await screen.findByText("AgentSOC service unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });
});
