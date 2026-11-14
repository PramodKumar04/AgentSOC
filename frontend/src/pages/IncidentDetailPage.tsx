import { useQuery } from "@tanstack/react-query";
import {
  ArrowLeft, CheckCircle2, ClipboardList, FileCheck2, FileText, Gauge, Network, ScanSearch,
  Workflow, XCircle,
} from "lucide-react";
import { Fragment, useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";

import { AttackGraphTab } from "@/components/graph/AttackGraphTab";
import { AgentsTab } from "@/components/agents";
import { DecisionPanel, ReviewBadge, WINDOWS } from "@/components/review";
import { IncidentInvestigation } from "@/components/investigation";
import { ProvenanceTab } from "@/components/provenance";
import { RiskResponseTab } from "@/components/risk";
import { InvestigationBadge, Mono, ProvenanceBadge, RiskBadge, SeverityBadge } from "@/components/domain";
import { useSource } from "@/components/layout/source-context";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { ErrorState, LoadingBlock } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api, ApiError, type ContextWindow, type EventView, type IncidentDetail } from "@/lib/api";
import { cn } from "@/lib/utils";

const METRIC_LABELS: Record<string, string> = {
  failure_count: "Failures", span_seconds: "Span (s)", threshold_failures: "Threshold (failures)",
  threshold_window_seconds: "Threshold window (s)", distinct_source_hosts: "Distinct source hosts",
  failures_before_success: "Failures before success", seconds_from_last_failure: "Seconds after last failure",
  success_src_host: "Success source host", success_dst_host: "Success destination host",
  success_from_a_failing_source: "Success from a failing source", src_host: "Source host",
  dst_host: "Destination host", baseline_src_hosts: "Known source hosts (baseline)",
  baseline_dst_hosts: "Known destination hosts (baseline)", new_destination_hosts: "First-seen destinations",
  threshold_hosts: "Threshold (hosts)", hops: "Hops", path: "Path", first_seen_hops: "First-seen hops",
  threshold_max_hop_gap_seconds: "Max hop gap (s)",
};

function List({ items, initial = 4 }: { items: string[]; initial?: number }) {
  const [all, setAll] = useState(false);
  const shown = all ? items : items.slice(0, initial);
  return (
    <>
      <ul className="list-disc space-y-1.5 pl-5 text-sm text-ink-2 marker:text-faint">
        {shown.map((i) => <li key={i}>{i}</li>)}
      </ul>
      {items.length > initial && (
        <button type="button" onClick={() => setAll(!all)} className="mt-2 text-xs font-medium text-brand hover:underline">
          {all ? "Show fewer" : `Show all ${items.length}`}
        </button>
      )}
    </>
  );
}

function SummaryTab({ inc }: { inc: IncidentDetail }) {
  return (
    <div className="grid items-start gap-6 lg:grid-cols-3">
      <div className="space-y-6 lg:col-span-2">
        <Card>
          <CardHeader title="What happened" />
          <CardBody className="space-y-4">
            <p className="text-sm text-ink-2">{inc.description}</p>
            <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
              <div><dt className="text-xs text-muted">Affected users</dt>
                <dd className="mt-0.5 flex flex-wrap gap-1.5">{inc.involved_users.map((u) => <Mono key={u}>{u}</Mono>)}</dd></div>
              <div><dt className="text-xs text-muted">Affected hosts</dt>
                <dd className="mt-0.5 flex flex-wrap gap-x-2 gap-y-1">{inc.involved_hosts.map((h) => <Mono key={h}>{h}</Mono>)}</dd></div>
              <div><dt className="text-xs text-muted">Evidence events</dt><dd className="tabular mt-0.5 text-ink">{inc.evidence_count}</dd></div>
              <div><dt className="text-xs text-muted">Detection findings</dt><dd className="tabular mt-0.5 text-ink">{inc.finding_count} across {inc.rule_ids.length} rules</dd></div>
            </dl>
          </CardBody>
        </Card>
        <DetectionTab inc={inc} />
      </div>
      <Card>
        <CardHeader title="Before you decide" description="What the detection cannot tell you" />
        <CardBody className="space-y-5">
          <section><h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Possible benign explanations</h3><List items={inc.benign_explanations} initial={3} /></section>
          <section><h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Missing information</h3><List items={inc.missing_information} initial={3} /></section>
          <section><h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Limitations</h3><List items={inc.limitations} initial={3} /></section>
        </CardBody>
      </Card>
    </div>
  );
}

function TimelineTab({ inc }: { inc: IncidentDetail }) {
  return (
    <Card>
      <CardHeader title="Authentication timeline" description={`${inc.timeline.length} events in chronological order`} />
      <ol className="relative px-5 py-4">
        {inc.timeline.map((e, idx) => {
          const fail = e.outcome === "Fail";
          return (
            <li key={e.event_id} className="relative flex gap-4 pb-4 last:pb-0">
              {idx < inc.timeline.length - 1 && <span className="absolute left-[9px] top-6 h-full w-px bg-border" aria-hidden />}
              {fail ? <XCircle className="relative size-5 shrink-0 bg-surface text-critical" aria-label="Failed" />
                    : <CheckCircle2 className="relative size-5 shrink-0 bg-surface text-ok" aria-label="Succeeded" />}
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                  <span className="tabular text-xs font-medium text-muted">{e.time_label}</span>
                  <span className="font-mono text-[13px] text-ink">{e.src_host} → {e.dst_host}</span>
                  <span className="text-xs text-muted">{e.orientation}{e.logon_type ? ` · ${e.logon_type}` : ""}{e.auth_type ? ` · ${e.auth_type}` : ""}</span>
                  <Badge tone={fail ? "critical" : "ok"}>{e.outcome}</Badge>
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-1.5 text-xs">
                  <Mono className="text-[11.5px] text-faint">{e.event_id}</Mono>
                  {e.cited_by.map((r) => <Badge key={r} tone="brand">{r}</Badge>)}
                </div>
              </div>
            </li>
          );
        })}
      </ol>
    </Card>
  );
}

function DetectionTab({ inc }: { inc: IncidentDetail }) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader title="Triggered rules" description="Deterministic detections and the observations behind them" />
        <Accordion type="multiple">
          {inc.findings.map((f) => (
            <AccordionItem key={f.finding_id} value={f.finding_id}>
              <AccordionTrigger>
                <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1">
                  <SeverityBadge severity={f.severity} />
                  <span className="font-medium text-ink">{f.rule_title}</span>
                  <span className="text-xs text-faint">{f.rule_id} · {f.finding_id}</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-3">
                <p className="text-sm text-ink-2">{f.description}</p>
                <dl className="grid grid-cols-1 gap-x-6 gap-y-1.5 rounded-md bg-subtle px-3 py-2.5 text-xs sm:grid-cols-2">
                  {Object.entries(f.metrics).map(([k, v]) => (
                    <div key={k} className="flex justify-between gap-3">
                      <dt className="text-muted">{METRIC_LABELS[k] ?? k}</dt>
                      <dd className="tabular font-medium text-ink">{typeof v === "boolean" ? (v ? "Yes" : "No") : String(v)}</dd>
                    </div>
                  ))}
                </dl>
                <p className="text-xs text-muted">Evidence: {f.event_ids.length} event(s) · {f.first_seen_label} → {f.last_seen_label}</p>
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </Card>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader title="Severity calculation" description="Triage priority — not a probability of compromise" />
          <CardBody><p className="text-sm text-ink-2">{inc.severity_rationale}</p></CardBody>
        </Card>
        <Card>
          <CardHeader title="Shared evidence" description="Events that contribute to more than one rule" />
          <CardBody>
            {inc.shared_evidence.length === 0 ? (
              <p className="text-sm text-muted">Each event supports a single rule.</p>
            ) : (
              <>
                <p className="mb-3 text-sm text-ink-2">
                  {inc.shared_evidence.length} event(s) are counted by several rules, so the summed severity may overstate independent evidence.
                </p>
                <ul className="space-y-1.5 text-xs">
                  {inc.shared_evidence.slice(0, 8).map((s) => (
                    <li key={s.event_id} className="flex flex-wrap items-center gap-1.5">
                      <Mono className="text-[11.5px]">{s.event_id}</Mono>
                      {s.rule_ids.map((r) => <Badge key={r} tone="neutral">{r}</Badge>)}
                    </li>
                  ))}
                </ul>
              </>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}

export function EventDetails({ e }: { e: EventView }) {
  const rows: [string, string | number | null][] = [
    ["Event ID", e.event_id], ["Time (dataset)", e.time_label], ["Source user", e.src_user],
    ["Destination user", e.dst_user], ["Source host", e.src_host], ["Destination host", e.dst_host],
    ["Authentication type", e.auth_type], ["Logon type", e.logon_type], ["Orientation", e.orientation],
    ["Outcome", e.outcome], ["Provenance", e.provenance], ["Source file", e.raw_file], ["Source line", e.raw_line],
    ["Cited by rules", e.cited_by.join(", ") || null],
  ];
  return (
    <dl className="grid grid-cols-1 gap-x-8 gap-y-1.5 text-xs sm:grid-cols-2">
      {rows.map(([k, v]) => (
        <div key={k} className="flex justify-between gap-3 border-b border-border/60 py-1">
          <dt className="text-muted">{k}</dt>
          <dd className={cn("text-right font-mono text-[12px]", v === null ? "text-faint" : "text-ink")}>
            {v === null ? "missing (not recorded)" : String(v)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function EvidenceTab({ inc, onMore }: { inc: IncidentDetail; onMore: () => void }) {
  const [view, setView] = useState<"timeline" | "table">("timeline");
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div role="group" aria-label="Evidence view" className="inline-flex rounded-md border border-border bg-surface p-0.5">
          {(["timeline", "table"] as const).map((v) => (
            <button key={v} type="button" aria-pressed={view === v} onClick={() => setView(v)}
              className={cn("rounded px-3 py-1 text-xs font-medium", view === v ? "bg-brand text-white" : "text-ink-2 hover:bg-subtle")}>
              {v === "timeline" ? "Timeline" : "Table"}
            </button>
          ))}
        </div>
        <button type="button" onClick={onMore} className="text-xs font-medium text-brand hover:underline">
          Ask the agents for more evidence
        </button>
      </div>
      {view === "timeline" ? <TimelineTab inc={inc} /> : <EvidenceTable inc={inc} />}
    </div>
  );
}

function EvidenceTable({ inc }: { inc: IncidentDetail }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <Card>
      <CardHeader title="Evidence events" description="Normalised records read from the hash-verified dataset. Missing optional fields are shown as missing, never filled in." />
      {inc.missing_evidence_ids.length > 0 && (
        <p role="alert" className="border-b border-border bg-critical-soft px-5 py-2 text-xs text-critical">
          {inc.missing_evidence_ids.length} cited event(s) were not found in the verified dataset.
        </p>
      )}
      <Table>
        <thead><tr><Th>Event</Th><Th>Time</Th><Th>User</Th><Th>Source → destination</Th><Th>Orientation</Th><Th>Outcome</Th><Th>Line</Th><Th>Provenance</Th></tr></thead>
        <tbody>
          {inc.timeline.map((e) => (
            <Fragment key={e.event_id}>
              <Tr className="cursor-pointer" onClick={() => setOpen(open === e.event_id ? null : e.event_id)}>
                <Td><button type="button" aria-expanded={open === e.event_id} className="font-mono text-[12.5px] text-brand hover:underline">{e.event_id}</button></Td>
                <Td className="tabular whitespace-nowrap text-muted">{e.time_label}</Td>
                <Td>{e.src_user}</Td>
                <Td className="font-mono text-[12.5px] whitespace-nowrap">{e.src_host} → {e.dst_host}</Td>
                <Td>{e.orientation}</Td>
                <Td><Badge tone={e.outcome === "Fail" ? "critical" : "ok"}>{e.outcome}</Badge></Td>
                <Td className="tabular text-muted">{e.raw_line.toLocaleString()}</Td>
                <Td><ProvenanceBadge provenance={e.provenance} /></Td>
              </Tr>
              {open === e.event_id && (
                <tr><td colSpan={8} className="border-b border-border bg-subtle px-5 py-4"><EventDetails e={e} /></td></tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </Table>
    </Card>
  );
}

const TABS = ["overview", "agents", "evidence", "graph", "risk", "investigation", "provenance"];
// Links made before the tabs were merged keep working.
const LEGACY_TABS: Record<string, string> = { timeline: "evidence", detection: "overview" };

export function IncidentDetailPage() {
  const { incidentId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const requested = params.get("tab") ?? "";
  const named = LEGACY_TABS[requested] ?? requested;
  const tab = TABS.includes(named) ? named : "overview";
  const contextParam = Number(params.get("context"));
  const contextWindow = WINDOWS.includes(contextParam as ContextWindow) ? contextParam as ContextWindow : null;
  const setTab = (value: string) => {
    const next = new URLSearchParams(params);
    if (value === "overview") next.delete("tab"); else next.set("tab", value);
    setParams(next, { replace: true });
  };
  // "More evidence": the agents re-run over the chosen window (none = standard run).
  const showContext = (window: ContextWindow | null) => {
    const next = new URLSearchParams(params);
    next.set("tab", "agents");
    if (window === null) next.delete("context"); else next.set("context", String(window));
    setParams(next, { replace: true });
  };
  const { source, setSource } = useSource();
  const key = params.get("source") ?? source!.key;
  // A link from another data source carries ?source=…; keep the header context in sync.
  useEffect(() => { if (key !== source?.key) setSource(key); }, [key, source?.key, setSource]);
  const query = useQuery({
    queryKey: ["incident", key, incidentId], queryFn: () => api.incident(key, incidentId),
  });

  if (query.isLoading) return <LoadingBlock label="Loading incident…" />;
  if (query.error || !query.data) {
    const notFound = query.error instanceof ApiError && query.error.status === 404;
    return notFound ? (
      <Card><CardBody className="py-10 text-center">
        <p className="font-medium text-ink">Incident {incidentId} was not found in this data source.</p>
        <Link to="/incidents" className="mt-2 inline-block text-sm text-brand hover:underline">Back to incidents</Link>
      </CardBody></Card>
    ) : <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  }
  const inc = query.data;

  return (
    <>
      <Link to="/incidents" className="mb-3 inline-flex items-center gap-1 text-xs font-medium text-muted hover:text-ink">
        <ArrowLeft className="size-3.5" aria-hidden />All incidents
      </Link>
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="font-mono text-xl font-semibold tracking-tight text-ink">{inc.incident_id}</h1>
            {inc.provenance.map((p) => <ProvenanceBadge key={p} provenance={p} long />)}
            <InvestigationBadge status={inc.investigation_status} />
            <ReviewBadge status={inc.review_status} />
          </div>
          <p className="mt-1.5 text-sm text-muted">
            <span className="font-medium text-ink-2">{inc.principal_user}</span> · {inc.first_seen_label} → {inc.last_seen_label}
          </p>
          <dl className="mt-3 flex flex-wrap gap-x-8 gap-y-2">
            <div className="flex items-center gap-2">
              <dt className="text-xs font-medium text-muted">Detection severity</dt>
              <dd><SeverityBadge severity={inc.severity} /></dd>
            </div>
            <div className="flex items-center gap-2">
              <dt className="text-xs font-medium text-muted">RSEM risk</dt>
              <dd><RiskBadge band={inc.risk_band} score={inc.risk_score} /></dd>
            </div>
          </dl>
        </div>
      </div>

      <div className="mb-5"><DecisionPanel sourceKey={key} incidentId={inc.incident_id} onEvidence={showContext} /></div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList aria-label="Incident sections" className="overflow-x-auto">
          <TabsTrigger value="overview"><ClipboardList aria-hidden />Summary</TabsTrigger>
          <TabsTrigger value="agents"><Workflow aria-hidden />Agents</TabsTrigger>
          <TabsTrigger value="evidence"><FileText aria-hidden />Evidence</TabsTrigger>
          <TabsTrigger value="graph"><Network aria-hidden />Attack graph</TabsTrigger>
          <TabsTrigger value="risk"><Gauge aria-hidden />Risk &amp; response</TabsTrigger>
          <TabsTrigger value="investigation"><ScanSearch aria-hidden />AI investigation</TabsTrigger>
          <TabsTrigger value="provenance"><FileCheck2 aria-hidden />Provenance</TabsTrigger>
        </TabsList>
        <TabsContent value="overview"><SummaryTab inc={inc} /></TabsContent>
        <TabsContent value="agents"><AgentsTab sourceKey={key} incidentId={inc.incident_id} window={contextWindow} onWindow={showContext} /></TabsContent>
        <TabsContent value="evidence"><EvidenceTab inc={inc} onMore={() => showContext(24)} /></TabsContent>
        <TabsContent value="graph"><AttackGraphTab sourceKey={key} inc={inc} /></TabsContent>
        <TabsContent value="risk"><RiskResponseTab sourceKey={key} inc={inc} /></TabsContent>
        <TabsContent value="investigation"><IncidentInvestigation sourceKey={key} incidentId={inc.incident_id} /></TabsContent>
        <TabsContent value="provenance"><ProvenanceTab sourceKey={key} inc={inc} /></TabsContent>
      </Tabs>
    </>
  );
}
