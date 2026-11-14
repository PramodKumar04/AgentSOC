// The multi-agent investigation: the orchestrator runs the identity, network/host,
// threat-intelligence and endpoint agents in parallel; the correlation agent combines their
// findings; the reasoning layer (AI investigation) and the report use the result.
import { useQuery } from "@tanstack/react-query";
import {
  ArrowRight, Brain, Fingerprint, Laptop, Layers, Network, OctagonX, ScrollText, ShieldQuestion, Workflow,
} from "lucide-react";
import type { ReactNode } from "react";

import { ContextPanel, WINDOWS } from "@/components/review";
import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Select } from "@/components/ui/form";
import { ErrorState, LoadingBlock } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { api, type AgentAnalysis, type AgentFinding, type AgentReport, type ContextWindow, type ResponsePlan } from "@/lib/api";
import { cn } from "@/lib/utils";

const ICONS: Record<string, ReactNode> = {
  identity: <Fingerprint className="size-4" aria-hidden />, network: <Network className="size-4" aria-hidden />,
  threat_intel: <ShieldQuestion className="size-4" aria-hidden />, endpoint: <Laptop className="size-4" aria-hidden />,
};
const STATUS: Record<AgentReport["status"], { text: string; tone: "ok" | "neutral" | "warn" | "critical" }> = {
  completed: { text: "Completed", tone: "ok" }, no_findings: { text: "Nothing found", tone: "neutral" },
  unavailable: { text: "No data available", tone: "warn" }, failed: { text: "Failed", tone: "critical" },
};
const STANCE: Record<AgentFinding["stance"], { text: string; tone: "critical" | "ok" | "neutral" }> = {
  suspicious: { text: "Suspicious", tone: "critical" }, benign: { text: "Benign", tone: "ok" }, context: { text: "Context", tone: "neutral" },
};

function Step({ icon, label, detail, tone = "neutral" }: { icon: ReactNode; label: string; detail?: string; tone?: "neutral" | "warn" | "brand" }) {
  return (
    <div className={cn("flex min-w-0 items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs",
      tone === "warn" ? "border-warn/40 bg-warn-soft" : tone === "brand" ? "border-brand/40 bg-brand-soft" : "border-border bg-surface")}>
      <span className="text-muted">{icon}</span>
      <span className="min-w-0"><span className="block font-medium text-ink">{label}</span>{detail && <span className="block text-muted">{detail}</span>}</span>
    </div>
  );
}

const Arrow = () => <ArrowRight className="size-4 shrink-0 text-faint max-md:rotate-90" aria-hidden />;

/** The pipeline from the design, with the live status of each stage for this incident. */
function Pipeline({ data }: { data: AgentAnalysis }) {
  return (
    <div aria-label="Investigation pipeline" role="group" className="flex flex-col gap-2 md:flex-row md:flex-wrap md:items-center">
      <Step icon={<Workflow className="size-4" aria-hidden />} label="Orchestrator" detail={`${data.agents.length} tasks, ${Math.round(data.duration_ms)} ms`} />
      <Arrow />
      <div className="grid grid-cols-1 gap-1.5 rounded-lg border border-dashed border-border p-1.5 sm:grid-cols-2 md:flex">
        {data.agents.map((a) => (
          <Step key={a.agent} icon={ICONS[a.agent] ?? <Layers className="size-4" aria-hidden />} label={a.title.replace(" agent", "")}
            detail={STATUS[a.status].text} tone={a.status === "unavailable" || a.status === "failed" ? "warn" : "neutral"} />
        ))}
      </div>
      <Arrow />
      <Step icon={<Layers className="size-4" aria-hidden />} label="Correlation" detail={`${data.correlation.corroborated.length} corroborated`} tone="brand" />
      <Arrow />
      <Step icon={<Brain className="size-4" aria-hidden />} label="Reasoning (AI investigation)" />
      <Arrow />
      <Step icon={<OctagonX className="size-4" aria-hidden />} label="Response plan"
        detail={data.response_plan ? POSTURE[data.response_plan.posture].short : undefined} />
      <Arrow />
      <Step icon={<ScrollText className="size-4" aria-hidden />} label="Report" />
    </div>
  );
}

export const POSTURE: Record<ResponsePlan["posture"], { title: string; short: string; tone: "critical" | "warn" | "neutral" | "ok" }> = {
  contain_now: { title: "Contain now", short: "Contain now", tone: "critical" },
  verify_first: { title: "Verify first", short: "Verify first", tone: "warn" },
  monitor: { title: "Monitor", short: "Monitor only", tone: "neutral" },
  closed: { title: "No response needed", short: "Dismissed", tone: "ok" },
};
export const PHASES: { key: ResponsePlan["steps"][number]["phase"]; title: string; hint: string }[] = [
  { key: "contain", title: "1. Contain", hint: "Stop it spreading" },
  { key: "investigate", title: "2. Investigate", hint: "Confirm or rule out" },
  { key: "recover", title: "3. Recover", hint: "Restore access safely" },
  { key: "prevent", title: "4. Prevent", hint: "Stop it happening again" },
];

/** "How to stop this": the response plan, grouped by phase. Nothing here is executed. */
export function ResponsePlanCard({ plan }: { plan: ResponsePlan }) {
  return (
    <Card>
      <CardHeader
        title={<span className="flex flex-wrap items-center gap-2"><OctagonX className="size-4" aria-hidden />How to stop this<Badge tone={POSTURE[plan.posture].tone}>{POSTURE[plan.posture].title}</Badge></span>}
        description="Recommended response, built from the agents' evidence. AgentSOC does not carry out any of it." />
      <CardBody className="space-y-4">
        <p className="text-sm text-ink">{plan.summary}</p>
        {plan.steps.length > 0 && (
          <div className="grid gap-4 lg:grid-cols-2">
            {PHASES.map(({ key, title, hint }) => {
              const steps = plan.steps.filter((s) => s.phase === key);
              if (steps.length === 0) return null;
              return (
                <section key={key} aria-label={title} className={cn("rounded-md border p-3", key === "contain" && plan.posture === "contain_now" ? "border-critical/30 bg-critical-soft/40" : "border-border")}>
                  <h3 className="text-sm font-semibold text-ink">{title} <span className="font-normal text-muted">— {hint}</span></h3>
                  <ol className="mt-2 space-y-2.5">
                    {steps.map((s, i) => (
                      <li key={i} className="text-sm">
                        <p className="text-ink">{s.action}</p>
                        <p className="mt-0.5 text-xs text-muted">Why: {s.why}</p>
                        <p className="mt-1 flex flex-wrap gap-1">
                          {s.disruptive && <Badge tone="warn">Disruptive: needs approval</Badge>}
                          {s.risk_engine_proposed && <Badge tone="brand">Also proposed by the risk engine</Badge>}
                          {s.based_on.map((b) => <Badge key={b} tone="neutral">{b}</Badge>)}
                        </p>
                      </li>
                    ))}
                  </ol>
                </section>
              );
            })}
          </div>
        )}
        <ul className="list-disc space-y-0.5 pl-5 text-xs text-muted">{plan.notes.map((n) => <li key={n}>{n}</li>)}</ul>
      </CardBody>
    </Card>
  );
}

function FindingRow({ f }: { f: AgentFinding }) {
  return (
    <li className="flex gap-2 text-sm">
      <span className="mt-0.5 flex shrink-0 flex-col items-start gap-1">
        <Badge tone={STANCE[f.stance].tone}>{STANCE[f.stance].text}</Badge>
      </span>
      <span className="min-w-0 text-ink-2">
        {f.statement}{" "}
        <span className="text-xs text-muted">({f.strength}{f.expanded ? ", wider window" : ""})</span>
        {f.techniques.length > 0 && (
          <span className="ml-1 inline-flex flex-wrap gap-1 align-middle">
            {f.techniques.map((t) => (
              <a key={t.id} href={t.url} target="_blank" rel="noreferrer noopener" className="font-mono text-xs text-brand hover:underline">{t.id}</a>
            ))}
          </span>
        )}
      </span>
    </li>
  );
}

function AgentCard({ report }: { report: AgentReport }) {
  return (
    <Card>
      <CardHeader
        title={<span className="flex flex-wrap items-center gap-2">{ICONS[report.agent]}{report.title}<Badge tone={STATUS[report.status].tone}>{STATUS[report.status].text}</Badge></span>}
        description={report.purpose} />
      <CardBody className="space-y-3">
        {report.findings.length > 0
          ? <ul className="space-y-2">{report.findings.map((f, i) => <FindingRow key={i} f={f} />)}</ul>
          : <p className="text-sm text-muted">{report.status === "unavailable" ? "This agent has no data to examine." : "No findings."}</p>}
        {report.gaps.length > 0 && (
          <div>
            <h3 className="mb-1 text-xs font-semibold text-muted">{report.status === "unavailable" ? "Evidence to request" : "Could not check"}</h3>
            <ul className="list-disc space-y-0.5 pl-5 text-xs text-muted">{report.gaps.map((g) => <li key={g}>{g}</li>)}</ul>
          </div>
        )}
        {report.examined.length > 0 && <p className="text-xs text-faint">Examined: {report.examined.join("; ")}.</p>}
      </CardBody>
    </Card>
  );
}

export function AgentsTab({ sourceKey, incidentId, window, onWindow }: {
  sourceKey: string; incidentId: string; window: ContextWindow | null; onWindow: (w: ContextWindow | null) => void;
}) {
  const query = useQuery({ queryKey: ["agents", sourceKey, incidentId, window], queryFn: () => api.agents(sourceKey, incidentId, window) });
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-2xl text-sm text-muted">
          Specialised agents examine the incident in parallel; the correlation agent combines what they found. Agents report facts, never conclusions, and say when they have no data.
        </p>
        <div className="flex items-center gap-2">
          <label htmlFor="agent-window" className="text-xs text-muted">Search</label>
          <Select id="agent-window" value={window ?? ""} onChange={(e) => onWindow(e.target.value ? Number(e.target.value) as ContextWindow : null)} className="h-8 text-xs">
            <option value="">Incident and history (standard)</option>
            {WINDOWS.map((w) => <option key={w} value={w}>More evidence: ±{w} h</option>)}
          </Select>
        </div>
      </div>
      {query.isLoading ? <LoadingBlock label="Running the agents…" />
        : query.error || !query.data ? <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        : (() => {
          const d = query.data;
          const c = d.correlation;
          return (
            <>
              <Card><CardBody><Pipeline data={d} /></CardBody></Card>
              {d.response_plan && <ResponsePlanCard plan={d.response_plan} />}
              <Card>
                <CardHeader title="Correlation" description={d.mode === "expanded" ? `Expanded to ±${d.window_hours} h at your request` : "Standard run"} />
                <CardBody className="space-y-4">
                  <p className="text-sm text-ink">{c.summary}</p>
                  {c.corroborated.length > 0 && (
                    <div><h3 className="mb-1 text-xs font-semibold text-muted">Flagged by more than one agent</h3>
                      <ul className="list-disc space-y-0.5 pl-5 text-sm text-ink-2">{c.corroborated.map((x) => <li key={x}>{x}</li>)}</ul></div>
                  )}
                  {c.conflicts.length > 0 && (
                    <div><h3 className="mb-1 text-xs font-semibold text-muted">Agents disagree</h3>
                      <ul className="list-disc space-y-0.5 pl-5 text-sm text-ink-2">{c.conflicts.map((x) => <li key={x}>{x}</li>)}</ul></div>
                  )}
                  {c.entities.length > 0 && (
                    <Table>
                      <thead><tr><Th>Entity</Th><Th>Suspicious to</Th><Th>Innocent explanation from</Th><Th>Findings</Th></tr></thead>
                      <tbody>{c.entities.slice(0, 10).map((e) => (
                        <Tr key={`${e.kind}-${e.name}`}>
                          <Td><span className="text-xs text-muted">{e.kind}</span> <span className="font-mono text-[12.5px]">{e.name}</span></Td>
                          <Td>{e.suspicious_agents.join(", ") || "—"}</Td><Td>{e.benign_agents.join(", ") || "—"}</Td>
                          <Td className="tabular">{e.findings}</Td>
                        </Tr>
                      ))}</tbody>
                    </Table>
                  )}
                </CardBody>
              </Card>
              <div className="grid items-start gap-6 lg:grid-cols-2">{d.agents.map((a) => <AgentCard key={a.agent} report={a} />)}</div>
              {window !== null && <ContextPanel sourceKey={sourceKey} incidentId={incidentId} window={window} onWindow={(w) => onWindow(w)} />}
            </>
          );
        })()}
    </div>
  );
}
