import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, it } from "vitest";

import { investigation, OVERVIEW, SOURCES } from "./fixtures";
import { ALICE_DETAIL } from "./fixtures";
import { json, mockApi, renderApp, SIGNED_IN, type Handler } from "./render";

const ADMIN = { user: { username: "boss", role: "admin" }, csrf_token: "admin-csrf" };
const SIGNED_OUT = () => json({ detail: "Sign in to continue." }, 401);
const USERS = [
  { username: "boss", role: "admin", disabled: false, locked: false, created_at: "2026-11-13T09:00:00Z", password_changed_at: "2026-11-13T09:00:00Z" },
  { username: "analyst1", role: "analyst", disabled: false, locked: false, created_at: "2026-11-13T09:00:00Z", password_changed_at: "2026-11-13T09:00:00Z" },
];

function base(extra: Record<string, Handler> = {}): Record<string, Handler> {
  return {
    "GET /api/health": () => ({ status: "ok", version: "0.9.0", analysis: "available", sources: 1 }),
    "GET /api/sources": () => SOURCES,
    "GET /api/overview": () => OVERVIEW,
    "GET /api/activity": () => ({ entries: [], total: 0, chain_intact: true }),
    ...extra,
  };
}

const header = (init: RequestInit | undefined, name: string) =>
  (init?.headers as Record<string, string> | undefined)?.[name];

describe("signing in", () => {
  it("shows the sign-in page when there is no session, then the workspace", async () => {
    let signedIn = false;
    const { calls } = mockApi(base({
      "GET /api/auth/session": () => (signedIn ? SIGNED_IN : SIGNED_OUT()),
      "POST /api/auth/login": () => { signedIn = true; return SIGNED_IN; },
    }));
    const user = userEvent.setup();
    renderApp("/");
    expect(await screen.findByRole("heading", { name: "Sign in to AgentSOC" })).toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Primary" })).not.toBeInTheDocument();
    await user.type(screen.getByLabelText("Username"), "analyst1");
    await user.type(screen.getByLabelText("Password"), "Analyst-pass-123");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Security overview" })).toBeInTheDocument();
    const login = calls.find((c) => c.url.pathname === "/api/auth/login")!;
    expect(header(login.init, "Content-Type")).toBe("application/json");
    expect(JSON.parse(String(login.init!.body))).toEqual({ username: "analyst1", password: "Analyst-pass-123" });
  });

  it("keeps the session token out of page-readable storage", async () => {
    mockApi(base());
    renderApp("/");
    await screen.findByRole("heading", { name: "Security overview" });
    const stored = JSON.stringify({ ...window.localStorage }) + JSON.stringify({ ...window.sessionStorage }) + document.cookie;
    expect(stored).not.toContain(SIGNED_IN.csrf_token);
    expect(stored).not.toMatch(/agentsoc_session/);
  });

  it("shows the server's message for a failed sign-in and clears the password", async () => {
    mockApi(base({
      "GET /api/auth/session": SIGNED_OUT,
      "POST /api/auth/login": () => json({ detail: "Incorrect username or password." }, 401),
    }));
    const user = userEvent.setup();
    renderApp("/");
    await user.type(await screen.findByLabelText("Username"), "analyst1");
    await user.type(screen.getByLabelText("Password"), "wrong-password-1");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Incorrect username or password.");
    expect(screen.getByLabelText("Password")).toHaveValue("");
  });

  it("explains how to create the first administrator", async () => {
    mockApi(base({ "GET /api/auth/session": SIGNED_OUT, "GET /api/auth/status": () => ({ setup_required: true }) }));
    renderApp("/");
    expect(await screen.findByText("No accounts exist yet")).toBeInTheDocument();
    expect(screen.getByText(/manage_users.py create NAME --role admin/)).toBeInTheDocument();
  });

  it("returns to sign-in when the session ends mid-use", async () => {
    let expired = false;
    mockApi(base({
      "GET /api/auth/session": () => (expired ? SIGNED_OUT() : SIGNED_IN),
      "GET /api/incidents": () => (expired ? SIGNED_OUT() : { items: [], total: 0, page: 1, page_size: 20 }),
    }));
    const user = userEvent.setup();
    renderApp("/");
    await screen.findByRole("heading", { name: "Security overview" });
    expired = true;
    await user.click(within(screen.getByRole("navigation", { name: "Primary" })).getByRole("link", { name: "Incidents" }));
    expect(await screen.findByRole("heading", { name: "Sign in to AgentSOC" })).toBeInTheDocument();
  });

  it("signs out with the CSRF token", async () => {
    const { calls } = mockApi(base({ "POST /api/auth/logout": () => new Response(null, { status: 204 }) }));
    const user = userEvent.setup();
    renderApp("/");
    await user.click(await screen.findByRole("button", { name: "Sign out" }));
    expect(await screen.findByRole("heading", { name: "Sign in to AgentSOC" })).toBeInTheDocument();
    const logout = calls.find((c) => c.url.pathname === "/api/auth/logout")!;
    expect(header(logout.init, "X-CSRF-Token")).toBe(SIGNED_IN.csrf_token);
  });

  it("sends the CSRF token with an investigation request", async () => {
    const { calls } = mockApi(base({
      "GET /api/incidents/INC-00002": () => ALICE_DETAIL,
      "GET /api/incidents/INC-00002/investigation": () => json({ detail: "none" }, 404),
      "POST /api/incidents/INC-00002/investigate": () => investigation("completed"),
    }));
    const user = userEvent.setup();
    renderApp("/incidents/INC-00002?tab=investigation");
    await user.click(await screen.findByRole("button", { name: "Investigate Incident" }));
    await screen.findByText("Investigation completed");
    const post = calls.find((c) => c.method === "POST")!;
    expect(header(post.init, "X-CSRF-Token")).toBe(SIGNED_IN.csrf_token);
  });

  it("has no accessibility violations on the sign-in page", async () => {
    mockApi(base({ "GET /api/auth/session": SIGNED_OUT }));
    const { container } = renderApp("/");
    await screen.findByRole("heading", { name: "Sign in to AgentSOC" });
    const { violations } = await axe.run(container, { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } });
    expect(violations.map((v) => v.id)).toEqual([]);
  });
});

describe("roles", () => {
  it("hides user management from analysts and refuses the page", async () => {
    const { calls } = mockApi(base());
    renderApp("/admin/users");
    expect(await screen.findByText("Administrator access is required.")).toBeInTheDocument();
    expect(within(screen.getByRole("navigation", { name: "Primary" })).queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
    expect(calls.some((c) => c.url.pathname === "/api/admin/users")).toBe(false);
  });

  it("lets an administrator add an account", async () => {
    const { calls } = mockApi(base({
      "GET /api/auth/session": () => ADMIN,
      "GET /api/admin/users": () => USERS,
      "POST /api/admin/users": () => ({ ...USERS[1], username: "newbie" }),
    }));
    const user = userEvent.setup();
    renderApp("/admin/users");
    expect(await screen.findByText("analyst1")).toBeInTheDocument();
    expect(within(screen.getByRole("navigation", { name: "Primary" })).getByRole("link", { name: "Users" })).toBeInTheDocument();
    expect(screen.getByLabelText("Role for boss")).toBeDisabled();
    await user.type(screen.getByLabelText("Username"), "newbie");
    await user.type(screen.getByLabelText("Initial password"), "Fresh-start-77");
    await user.click(screen.getByRole("button", { name: "Add account" }));
    expect(await screen.findByText("Account created.")).toBeInTheDocument();
    const post = calls.find((c) => c.method === "POST" && c.url.pathname === "/api/admin/users")!;
    expect(header(post.init, "X-CSRF-Token")).toBe("admin-csrf");
    expect(JSON.parse(String(post.init!.body))).toEqual({ username: "newbie", password: "Fresh-start-77", role: "analyst" });
  });

  it("shows a refused change", async () => {
    mockApi(base({
      "GET /api/auth/session": () => ADMIN,
      "GET /api/admin/users": () => USERS,
      "PATCH /api/admin/users/analyst1": () => json({ detail: "At least one active administrator must remain." }, 400),
    }));
    const user = userEvent.setup();
    renderApp("/admin/users");
    const row = (await screen.findByText("analyst1")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: "Disable" }));
    expect(await screen.findByText("At least one active administrator must remain.")).toBeInTheDocument();
  });

  it("changes the user's own password and keeps them signed in", async () => {
    const { calls } = mockApi(base({ "POST /api/auth/password": () => ({ ...SIGNED_IN, csrf_token: "fresh" }) }));
    const user = userEvent.setup();
    renderApp("/account");
    await user.type(await screen.findByLabelText("Current password"), "Old-password-123");
    await user.type(screen.getByLabelText("New password"), "New-password-456");
    await user.click(screen.getByRole("button", { name: "Change password" }));
    expect(await screen.findByText("Password changed.")).toBeInTheDocument();
    await waitFor(() => expect(calls.filter((c) => c.method === "POST")).toHaveLength(1));
  });
});
