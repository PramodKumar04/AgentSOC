import { useQuery } from "@tanstack/react-query";
import {
  ArrowLeft, CheckCircle2, ClipboardList, FileCheck2, FileText, Gauge, GitBranch, Network, ScanSearch,
  ShieldAlert, XCircle,
} from "lucide-react";
import { Fragment, useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";

import { AttackGraphTab } from "@/components/graph/AttackGraphTab";
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
import { api, ApiError, type EventView, type IncidentDetail } from "@/lib/api";
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

function OverviewTab({ inc }: { inc: IncidentDetail }) {
  return (
    <div className="grid items-start gap-6 lg:grid-cols-3">
      <Card className="lg:col-span-2">
        <CardHeader title="Summary" />
        <CardBody className="space-y-4">
          <p className="text-sm text-ink-2">{inc.description}</p>
          <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
            <div><dt className="text-xs text-muted">Affected users</dt>
              <dd className="mt-0.5 flex flex-wrap gap-1.5">{inc.involved_users.map((u) => <Mono key={u}>{u}</Mono>)}</dd></div>
            <div><dt className="text-xs text-muted">Affected hosts</dt>
              <dd className="mt-0.5 flex flex-wrap gap-x-2 gap-y-1">{inc.involved_hosts.map((h) => <Mono key={h}>{h}</Mono>)}</dd></div>
            <div><dt className="text-xs text-muted">Evidence events</dt><dd className="tabular mt-0.5 text-ink">{inc.evidence_count}</dd></div>
            <div><dt className="text-xs text-muted">Detection findings</dt><dd className="tabular mt-0.5 text-ink">{inc.finding_count} across {inc.rule_ids.length} rules</dd></div>
            <div className="sm:col-span-2"><dt className="text-xs text-muted">Triggered rules</dt>
              <dd className="mt-1 flex flex-wrap gap-1.5">{inc.findings.filter((f, i, a) => a.findIndex((x) => x.rule_id === f.rule_id) === i)
                .map((f) => <Badge key={f.rule_id} tone="neutral" title={f.rule_id}>{f.rule_title}</Badge>)}</dd></div>
          </dl>
        </CardBody>
      </Card>
      <Card>
        <CardHeader title="Possible benign explanations" description="From the detection rules" />
        <CardBody><List items={inc.benign_explanations} /></CardBody>
      </Card>
      <Card className="lg:col-span-2">
        <CardHeader title="Limitations" />
        <CardBody><List items={inc.limitations} /></CardBody>
      </Card>
      <Card>
        <CardHeader title="Missing information" />
        <CardBody><List items={inc.missing_information} /></CardBody>
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

function EvidenceTab({ inc }: { inc: IncidentDetail }) {
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

const TABS = ["overview", "timeline", "detection", "evidence", "graph", "risk", "investigation", "provenance"];

export function IncidentDetailPage() {
  const { incidentId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = TABS.includes(params.get("tab") ?? "") ? params.get("tab")! : "overview";
  const setTab = (value: string) => {
    const next = new URLSearchParams(params);
    if (value === "overview") next.delete("tab"); else next.set("tab", value);
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

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList aria-label="Incident sections" className="overflow-x-auto">
          <TabsTrigger value="overview"><ClipboardList aria-hidden />Overview</TabsTrigger>
          <TabsTrigger value="timeline"><GitBranch aria-hidden />Timeline</TabsTrigger>
          <TabsTrigger value="detection"><ShieldAlert aria-hidden />Detection analysis</TabsTrigger>
          <TabsTrigger value="evidence"><FileText aria-hidden />Evidence</TabsTrigger>
          <TabsTrigger value="graph"><Network aria-hidden />Attack graph</TabsTrigger>
          <TabsTrigger value="risk"><Gauge aria-hidden />Risk &amp; response</TabsTrigger>
          <TabsTrigger value="investigation"><ScanSearch aria-hidden />AI investigation</TabsTrigger>
          <TabsTrigger value="provenance"><FileCheck2 aria-hidden />Provenance</TabsTrigger>
        </TabsList>
        <TabsContent value="overview"><OverviewTab inc={inc} /></TabsContent>
        <TabsContent value="timeline"><TimelineTab inc={inc} /></TabsContent>
        <TabsContent value="detection"><DetectionTab inc={inc} /></TabsContent>
        <TabsContent value="evidence"><EvidenceTab inc={inc} /></TabsContent>
        <TabsContent value="graph"><AttackGraphTab sourceKey={key} inc={inc} /></TabsContent>
        <TabsContent value="risk"><RiskResponseTab sourceKey={key} inc={inc} /></TabsContent>
        <TabsContent value="investigation"><IncidentInvestigation sourceKey={key} incidentId={inc.incident_id} /></TabsContent>
        <TabsContent value="provenance"><ProvenanceTab sourceKey={key} inc={inc} /></TabsContent>
      </Tabs>
    </>
  );
}
