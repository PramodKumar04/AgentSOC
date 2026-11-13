import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { vi } from "vitest";

import { AppRoutes } from "@/App";

export type Handler = (url: URL, init?: RequestInit) => unknown | Promise<unknown>;

export function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

/** Mock fetch: `routes` maps "METHOD /api/path" to a handler returning a body or a Response. */
/** A signed-in analyst unless a test overrides the session routes. */
export const SIGNED_IN = { user: { username: "analyst1", role: "analyst" }, csrf_token: "csrf-test-token" };
const AUTH_DEFAULTS: Record<string, Handler> = {
  "GET /api/auth/session": () => SIGNED_IN,
  "GET /api/auth/status": () => ({ setup_required: false }),
};

export function mockApi(given: Record<string, Handler>) {
  const routes = { ...AUTH_DEFAULTS, ...given };
  const calls: { method: string; url: URL; init?: RequestInit }[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://localhost");
    const method = init?.method ?? "GET";
    calls.push({ method, url, init });
    const handler = routes[`${method} ${url.pathname}`];
    if (!handler) return json({ detail: `no mock for ${method} ${url.pathname}` }, 404);
    const result = await handler(url, init);
    return result instanceof Response ? result : json(result);
  });
  vi.stubGlobal("fetch", fetchMock);
  return { fetchMock, calls };
}

export function renderApp(path = "/") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
