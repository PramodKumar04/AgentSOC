// Real-browser check of the running dashboard at desktop and phone widths: no horizontal
// page overflow, no axe violations, and a screenshot of each view.
//
//   BASE_URL=http://127.0.0.1:8000 E2E_USER=name E2E_PASSWORD=secret //   BROWSER=<path to Edge or Chrome> node e2e/responsive.mjs [screenshot dir]
//
// Signs in with an existing analyst account (credentials only from the environment), then
// only reads. Point it at a server with the prepared demo sources.
import axe from "axe-core";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import puppeteer from "puppeteer-core";

const BASE = process.env.BASE_URL ?? "http://127.0.0.1:8000";
const BROWSER = process.env.BROWSER ?? "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
const OUT = path.resolve(process.argv[2] ?? "../docs/screenshots");
const SOURCE = "synthetic-risk";
const LANL = "lanl-assessed-redteam_window_half_baseline";
const VIEWPORTS = [{ name: "1440", width: 1440, height: 900 }, { name: "390", width: 390, height: 844, isMobile: true, hasTouch: true }];

let cookie = "";

async function signIn() {
  const { E2E_USER: username, E2E_PASSWORD: password } = process.env;
  if (!username || !password) throw new Error("Set E2E_USER and E2E_PASSWORD.");
  const response = await fetch(`${BASE}/api/auth/login`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password }),
  });
  if (!response.ok) throw new Error(`sign-in failed: ${response.status}`);
  cookie = response.headers.get("set-cookie").split(";")[0];
}

const getJson = async (url) => {
  const response = await fetch(`${BASE}${url}`, { headers: { Cookie: cookie } });
  if (!response.ok) throw new Error(`${url}: ${response.status}`);
  return response.json();
};

async function pickIncidents() {
  const { items } = await getJson(`/api/incidents?source=${SOURCE}&page_size=200`);
  const highest = [...items].sort((a, b) => b.risk_score - a.risk_score)[0].incident_id;
  let inferred = null;
  let observed = null;
  for (const { incident_id: id } of items) {
    const graph = await getJson(`/api/incidents/${id}/graph?source=${SOURCE}`);
    const path = graph.paths.find((p) => p.kind === "INFERRED");
    if (path && (!inferred || graph.links.length > inferred.size)) inferred = { id, path: path.path_id, size: graph.links.length };
    const multi = graph.paths.find((p) => p.kind === "OBSERVED" && p.event_ids.length >= 3);
    if (multi && !observed) observed = { id, path: multi.path_id };
  }
  return { highest, inferred, observed };
}

const incidentUrl = (source, id, tab, extra = "") =>
  `/incidents/${id}?source=${source}${tab ? `&tab=${tab}` : ""}${extra}`;

async function views() {
  const { highest, inferred, observed } = await pickIncidents();
  const saved = (await getJson("/api/investigations")).find((i) => i.source_key === SOURCE);
  return [
    { name: "overview", url: `/?source=${SOURCE}`, ready: "Risk distribution" },
    { name: "incidents", url: "/incidents", ready: "Affected hosts" },
    { name: "incident-header", url: incidentUrl(SOURCE, highest), ready: "RSEM risk" },
    { name: "graph-observed", url: incidentUrl(SOURCE, observed.id, "graph", `&path=${observed.path}`), ready: "Reported paths", canvas: true },
    { name: "graph-inferred", url: incidentUrl(SOURCE, inferred.id, "graph", `&path=${inferred.path}`), ready: "Reported paths", canvas: true },
    { name: "graph-lanl-truncated", url: incidentUrl(LANL, "INC-00076", "graph"), ready: "This graph is truncated", canvas: true, optional: true },
    { name: "graph-lanl-largest", url: incidentUrl(LANL, "INC-00133", "graph"), ready: "Reported paths", canvas: true, optional: true },
    { name: "risk-response", url: incidentUrl(SOURCE, highest, "risk"), ready: "Proposed response actions" },
    { name: "investigation", url: incidentUrl(SOURCE, saved?.incident_id ?? inferred.id, "investigation"), ready: "Model-proposed path", expand: true, optional: !saved },
    { name: "provenance", url: incidentUrl(SOURCE, highest, "provenance"), ready: "Audit trail" },
    { name: "not-assessed", url: incidentUrl("lanl-redteam_window", "INC-00001", "risk"), ready: "Risk: not assessed", optional: true },
    { name: "data-sources", url: "/data-sources", ready: "Risk assessment" },
    { name: "account", url: "/account", ready: "Change password" },
  ];
}

async function waitForText(page, text) {
  await page.waitForFunction((t) => document.body.innerText.toLowerCase().includes(t.toLowerCase()), { timeout: 30000 }, text);
}

async function check(page, view, viewport) {
  const started = performance.now();
  await page.goto(`${BASE}${view.url}`, { waitUntil: "domcontentloaded" });
  await waitForText(page, view.ready);
  if (view.canvas) await page.waitForSelector(".react-flow__node", { timeout: 30000 });
  const readyMs = Math.round(performance.now() - started);
  if (view.expand) await page.evaluate(() => document.querySelectorAll('button[aria-expanded="false"]').forEach((b) => b.click()));
  await new Promise((resolve) => setTimeout(resolve, 400));

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  await page.evaluate(axe.source);
  const violations = await page.evaluate(async () => {
    const result = await window.axe.run(document, { resultTypes: ["violations"] });
    return result.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.slice(0, 8).map((n) => n.target.join(" ")).join(" | ")}`);
  });
  await page.screenshot({ path: path.join(OUT, `${view.name}-${viewport.name}.png`), fullPage: true });
  return { view: view.name, viewport: viewport.name, readyMs, overflow, violations };
}

mkdirSync(OUT, { recursive: true });
const browser = await puppeteer.launch({ executablePath: BROWSER, headless: true });
const results = [];
let failed = false;
await signIn();
const all = await views();
const [name, value] = cookie.split("=");
for (const viewport of VIEWPORTS) {
  // The sign-in page, seen by someone without a session.
  const anonymous = await browser.createBrowserContext();
  const signedOut = await anonymous.newPage();
  await signedOut.setViewport(viewport);
  try {
    const result = await check(signedOut, { name: "sign-in", url: "/", ready: "Sign in to AgentSOC" }, viewport);
    results.push(result);
    if (result.overflow > 0 || result.violations.length > 0) failed = true;
    console.log(`${result.viewport} sign-in: ${result.readyMs} ms, overflow ${result.overflow}px, axe ${result.violations.length}`);
    for (const v of result.violations) console.log(`   ${v}`);
  } catch (error) {
    failed = true;
    console.log(`${viewport.name} sign-in: FAILED (${error.message})`);
  }
  await anonymous.close();
  const page = await browser.newPage();
  await page.setViewport(viewport);
  await page.setCookie({ name, value, url: BASE, httpOnly: true, sameSite: "Strict" });
  for (const view of all) {
    try {
      const result = await check(page, view, viewport);
      results.push(result);
      if (result.overflow > 0 || result.violations.length > 0) failed = true;
      console.log(`${result.viewport} ${result.view}: ${result.readyMs} ms, overflow ${result.overflow}px, axe ${result.violations.length}`);
      for (const v of result.violations) console.log(`   ${v}`);
    } catch (error) {
      console.log(`${viewport.name} ${view.name}: ${view.optional ? "skipped" : "FAILED"} (${error.message})`);
      if (!view.optional) failed = true;
    }
  }
  await page.close();
}
await browser.close();
writeFileSync(path.join(OUT, "e2e-results.json"), JSON.stringify(results, null, 2));
process.exit(failed ? 1 : 0);
