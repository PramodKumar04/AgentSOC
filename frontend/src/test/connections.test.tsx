import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, it } from "vitest";

import { OVERVIEW, SOURCES } from "./fixtures";
import { mockApi, renderApp, type Handler } from "./render";

const ADMIN = { user: { username: "boss", role: "admin" }, csrf_token: "admin-csrf" };
const CONNECTION = { host: "db.example.test", port: 5432, database: "security", username: "reader", sslmode: "verify-full" };
const SOURCE = {
  key: "hr-auth", dashboard_key: "org-hr-auth", name: "HR authentication log", kind: "postgresql",
  mode: "Polling every 60 s, then a new snapshot at most every 300 s. Not real-time.",
  sync_enabled: false, sync_interval_seconds: 60, ai_enabled: false,
  disclosures: ["orientation is not read from the source: every event is set to 'LogOn' (confirmed by an administrator)."],
  stats: { accepted: 176, rejected: 3, changed: 0, rejected_by_reason: { INVALID_TIMESTAMP: 3 }, first_event: "2026-11-01T08:00:00+00:00", last_event: "2026-11-04T17:00:00+00:00" },
  last_run: null, snapshot: null,
  connection: CONNECTION, table: { schema: "public", name: "auth_events" }, cursor_column: "id", lookback: 0,
  batch_size: 1000, max_rows_per_sync: 50000,
  mapping: { record_id: "id", timestamp: { column: "ts", format: "iso8601" }, fields: {}, confirmed_constants: [] },
  has_password: true, ai_changed_by: null, ai_changed_at: null,
  ai_warning: "Investigating an incident from this source with AI sends the incident's evidence to the external language-model provider.",
  created_by: "boss", created_at: "2026-11-13T09:00:00+00:00", runs: [], connection_warnings: [],
};

function base(extra: Record<string, Handler> = {}): Record<string, Handler> {
  return {
    "GET /api/auth/session": () => ADMIN,
    "GET /api/health": () => ({ status: "ok", version: "0.9.0", analysis: "available", sources: 1 }),
    "GET /api/sources": () => SOURCES,
    "GET /api/overview": () => OVERVIEW,
    "GET /api/admin/datasources": () => [SOURCE],
    ...extra,
  };
}

const bodyOf = (calls: { method: string; url: URL; init?: RequestInit }[], method: string, path: string) =>
  JSON.parse(String(calls.find((c) => c.method === method && c.url.pathname === path)!.init!.body));

describe("database connections", () => {
  it("is for administrators only", async () => {
    const { calls } = mockApi({ ...base(), "GET /api/auth/session": () => ({ user: { username: "a", role: "analyst" }, csrf_token: "x" }) });
    renderApp("/admin/connections");
    expect(await screen.findByText("Administrator access is required.")).toBeInTheDocument();
    expect(within(screen.getByRole("navigation", { name: "Primary" })).queryByRole("link", { name: "Database Connections" })).not.toBeInTheDocument();
    expect(calls.some((c) => c.url.pathname.startsWith("/api/admin/datasources"))).toBe(false);
  });

  it("shows status, the polling mode and every fixed value", async () => {
    mockApi(base());
    renderApp("/admin/connections");
    expect(await screen.findByText("HR authentication log")).toBeInTheDocument();
    expect(screen.getByText(/Not real-time/)).toBeInTheDocument();
    expect(screen.getByText(/every event is set to 'LogOn'/)).toBeInTheDocument();
    expect(screen.getByText(/INVALID_TIMESTAMP 3/)).toBeInTheDocument();
  });

  it("allows AI only after the warning is acknowledged", async () => {
    const { calls } = mockApi(base({
      "PATCH /api/admin/datasources/hr-auth": () => ({ ...SOURCE, ai_enabled: true }),
    }));
    const user = userEvent.setup();
    renderApp("/admin/connections");
    await user.click(await screen.findByRole("button", { name: "Allow…" }));
    expect(screen.getByText(/external language-model provider/)).toBeInTheDocument();
    const allow = screen.getByRole("button", { name: "Allow AI investigation" });
    expect(allow).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: /my organisation permits/ }));
    await user.click(allow);
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    expect(bodyOf(calls, "PATCH", "/api/admin/datasources/hr-auth")).toEqual({ ai_enabled: true, ai_risk_acknowledged: true });
    const patch = calls.find((c) => c.method === "PATCH")!;
    expect((patch.init!.headers as Record<string, string>)["X-CSRF-Token"]).toBe("admin-csrf");
  });

  it("walks through connect, map, preview and save; a fixed value needs confirmation", async () => {
    const { calls } = mockApi(base({
      "GET /api/admin/datasources": () => [],
      "POST /api/admin/datasources/test": () => ({ server_version: "16.4", account: "reader", read_only_session: true, warnings: [] }),
      "POST /api/admin/datasources/tables": () => [{ schema: "public", name: "auth_events" }],
      "POST /api/admin/datasources/columns": () => ["id", "ts", "account", "client", "server", "result"].map((name) => ({ name, data_type: "text", nullable: false })),
      "POST /api/admin/datasources/preview": () => ({ rows_read: 2, accepted: [{ event_id: "hr-auth.1", time: "2026-11-13T09:00:05+00:00", src_user: "alice@CORP", dst_user: null, src_host: "WS-1", dst_host: "SRV", auth_type: null, logon_type: null, orientation: "LogOn", outcome: "Success" }],
                                                     rejected: [{ row: 2, reason: "INVALID_OUTCOME", field: "outcome", detail: "outcome value is not mapped to an AgentSOC value" }],
                                                     disclosures: ["orientation is not read from the source: every event is set to 'LogOn' (confirmed by an administrator)."] }),
      "POST /api/admin/datasources": () => SOURCE,
    }));
    const user = userEvent.setup();
    renderApp("/admin/connections");
    await user.click(await screen.findByRole("button", { name: "Connect a PostgreSQL database" }));
    await user.type(screen.getByLabelText("Name shown to analysts"), "HR auth");
    await user.type(screen.getByLabelText("Host"), "db.example.test");
    await user.type(screen.getByLabelText("Database"), "security");
    await user.type(screen.getByLabelText("Account"), "reader");
    await user.type(screen.getByLabelText("Password"), "Db-pass-123456");
    await user.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText(/read-only session/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Show tables this account can read" }));
    await user.selectOptions(await screen.findByLabelText("Table or view"), "public.auth_events");
    await user.selectOptions(await screen.findByLabelText("Record identifier"), "id");
    await user.selectOptions(screen.getByLabelText("Read new rows in order of"), "id");
    await user.selectOptions(screen.getByLabelText("Event time"), "ts");
    await user.selectOptions(screen.getByLabelText("Column for User (who signed in)"), "account");
    await user.selectOptions(screen.getByLabelText("Column for Source host (from)"), "client");
    await user.selectOptions(screen.getByLabelText("Column for Destination host (to)"), "server");
    await user.selectOptions(screen.getByLabelText("Column for Outcome"), "result");
    await user.type(screen.getByLabelText(/Translate values/), "1 = Success\n0 = Fail");
    await user.selectOptions(screen.getByLabelText("Column for Event kind"), "__constant__");
    await user.type(screen.getByLabelText("Fixed value for Event kind"), "LogOn");
    const previewButton = screen.getByRole("button", { name: "Preview first 50 rows" });
    expect(previewButton).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: /every event from this source gets/ }));
    await user.click(previewButton);
    expect(await screen.findByText("INVALID_OUTCOME")).toBeInTheDocument();
    expect(screen.getByText(/Nothing has been stored/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save data source" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url.pathname === "/api/admin/datasources")).toBe(true));
    const saved = bodyOf(calls, "POST", "/api/admin/datasources");
    expect(saved.key).toBe("hr-auth");
    expect(saved.config.mapping.fields.orientation).toEqual({ constant: "LogOn" });
    expect(saved.config.mapping.confirmed_constants).toEqual(["orientation"]);
    expect(saved.config.mapping.fields.outcome).toEqual({ column: "result", values: { "1": "Success", "0": "Fail" } });
    expect(saved.config.mapping.fields.dst_user).toBeUndefined();
    // The password is sent, then cleared from the page.
    expect(saved.password).toBe("Db-pass-123456");
    expect(document.body.innerHTML).not.toContain("Db-pass-123456");
  });

  it("has no accessibility violations", async () => {
    mockApi(base());
    renderApp("/admin/connections");
    await screen.findByText("HR authentication log");
    const result = await axe.run(document.body, { resultTypes: ["violations"] });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});
