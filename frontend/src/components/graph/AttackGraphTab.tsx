// Attack graph tab: an accessible path list and connections table, with the canvas beside
// them. Everything shown is from /graph; the browser only positions nodes.
import { Component, lazy, Suspense, useMemo, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router";

import { AssessmentNotice, HostPath, Notice, useOptionalQuery, VerdictBadge } from "@/components/assessment";
import { Mono, ProvenanceBadge } from "@/components/domain";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { api, type GraphEvent, type GraphLink, type GraphPath, type IncidentDetail, type IncidentGraph } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { GraphSelection } from "./graph-model";

const AttackGraphCanvas = lazy(() => import("./AttackGraphCanvas"));
const ACCOUNT_LINKS_SHOWN_UP_TO = 30;

const LINK_LABEL = { MOVEMENT: "Observed movement", ATTEMPT: "Failed attempt", LOCAL: "Local logon", ACCOUNT: "Account activity" };
const EVENT_LABEL = { MOVEMENT: "Movement", ATTEMPT: "Failed attempt", LOCAL: "Local logon" };
const nodeName = (id: string) => id.slice(id.indexOf(":") + 1);

class CanvasBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    return this.state.failed
      ? <EmptyState title="The graph view could not be loaded">The paths and connections listed here are unaffected.</EmptyState>
      : this.props.children;
  }
}

function Sample({ dash, color, width = 2.5, label }: { dash?: string; color: string; width?: number; label: string }) {
  return (
    <li className="flex items-center gap-1.5">
      <svg width="30" height="8" aria-hidden><line x1="0" y1="4" x2="30" y2="4" stroke={color} strokeWidth={width} strokeDasharray={dash} /></svg>
      {label}
    </li>
  );
}

function Legend() {
  return (
    <ul aria-label="Graph legend" className="flex flex-wrap gap-x-4 gap-y-1 border-b border-border px-5 py-2.5 text-xs text-ink-2">
      <Sample color="#475569" width={1.75} label="Observed event" />
      <Sample color="#2563eb" width={3.5} label="Selected observed path" />
      <Sample color="#7c3aed" width={3.5} dash="9 6" label="Selected inferred path" />
      <Sample color="#b45309" width={3.5} dash="2 7" label="Inferred, weak evidence" />
      <Sample color="#dc2626" width={1} dash="1 4" label="✕ Failed attempt (never on a path)" />
      <Sample color="#cbd5e1" width={1} label="Account activity" />
    </ul>
  );
}

function EventTable({ events }: { events: GraphEvent[] }) {
  return (
    <Table>
      <thead><tr><Th>Event</Th><Th>Time</Th><Th>Account</Th><Th>Source → destination</Th><Th>Type</Th><Th>Source line</Th><Th>Cited by</Th></tr></thead>
      <tbody>
        {events.map((e) => (
          <Tr key={e.event_id}>
            <Td><Mono className="text-[12px]">{e.event_id}</Mono></Td>
            <Td className="tabular whitespace-nowrap text-muted">{e.time_label}</Td>
            <Td>{e.account}</Td>
            <Td className="font-mono text-[12.5px] whitespace-nowrap">{e.src_host} → {e.dst_host}</Td>
            <Td>{EVENT_LABEL[e.kind]}{e.auth_type ? ` · ${e.auth_type}` : ""}</Td>
            <Td className="tabular text-muted">{e.raw_file}:{e.raw_line}{e.duplicate_event_ids.length > 0 && ` (+${e.duplicate_event_ids.length} duplicate)`}</Td>
            <Td className="text-xs">{e.rule_ids.join(", ") || <span className="text-muted">Context event</span>}</Td>
          </Tr>
        ))}
      </tbody>
    </Table>
  );
}

function SelectionDetails({ graph, selection }: { graph: IncidentGraph; selection: GraphSelection }) {
  const byId = useMemo(() => new Map(graph.events.map((e) => [e.event_id, e])), [graph]);
  if (!selection) return <p className="px-5 py-4 text-sm text-muted">Select a node or a connection to see its original events.</p>;
  let title: string;
  let events: GraphEvent[];
  if (selection.kind === "link") {
    const link = graph.links.find((k) => k.link_id === selection.id);
    if (!link) return null;
    title = `${LINK_LABEL[link.kind]}: ${nodeName(link.source)} → ${nodeName(link.target)}`;
    events = link.event_ids.flatMap((id) => byId.get(id) ?? []);
  } else {
    const node = graph.nodes.find((n) => n.node_id === selection.id);
    if (!node) return null;
    title = `${node.kind === "host" ? "Host" : "Account"}: ${node.label}`;
    events = graph.events.filter((e) => node.kind === "host"
      ? e.src_host === node.label || e.dst_host === node.label : e.account === node.label);
  }
  return (
    <section aria-label="Selected graph item" aria-live="polite">
      <p className="px-5 py-3 text-sm font-medium text-ink">{title} <span className="font-normal text-muted">· {events.length} original event(s)</span></p>
      <EventTable events={events} />
    </section>
  );
}

function PathCard({ path, active, onToggle }: { path: GraphPath; active: boolean; onToggle: () => void }) {
  return (
    <li className={cn("rounded-md border", active ? "border-brand bg-brand-soft" : "border-border")}>
      <button type="button" aria-pressed={active} onClick={onToggle} className="block w-full px-3 py-2.5 text-left">
        <span className="mb-1 flex flex-wrap items-center gap-1.5">
          <Badge tone={path.kind === "OBSERVED" ? "brand" : "synthetic"}>{path.kind === "OBSERVED" ? "Observed" : "Inferred"}</Badge>
          <VerdictBadge verdict={path.verdict} />
          {path.ambiguous && <Badge tone="warn">Weak evidence</Badge>}
        </span>
        <HostPath hosts={path.hosts} />
        <span className="mt-1 block text-xs text-muted">{path.event_ids.length} {path.event_ids.length === 1 ? "hop" : "hops"} · {path.accounts.join(", ")}</span>
      </button>
      {active && (
        <div className="space-y-1.5 border-t border-brand/20 px-3 py-2 text-xs text-ink-2">
          {path.switches.map((s) => (
            <p key={s.from_event_id + s.to_event_id}>
              <span className="font-medium">Account switch at <Mono className="text-[12px]">{s.host}</Mono>.</span>
              {" "}{s.other_accounts_arriving} other account(s) arrived there in the window{s.ambiguous ? ", so this link is weak evidence." : "."}
            </p>
          ))}
          {path.conditions.map((c) => <p key={c}><span className="font-medium">Assumes: </span>{c}</p>)}
          {path.reasons.map((r) => <p key={r} className="text-muted">{r}</p>)}
        </div>
      )}
    </li>
  );
}

function ConnectionsTable({ links, onSelect }: { links: GraphLink[]; onSelect: (s: GraphSelection) => void }) {
  return (
    <Table>
      <thead><tr><Th>Connection</Th><Th>Type</Th><Th>Accounts</Th><Th>Events</Th><Th>Seen</Th></tr></thead>
      <tbody>
        {links.map((k) => (
          <Tr key={k.link_id}>
            <Td>
              <button type="button" onClick={() => onSelect({ kind: "link", id: k.link_id })} className="font-mono text-[12.5px] whitespace-nowrap text-brand hover:underline">
                {nodeName(k.source)} → {nodeName(k.target)}
              </button>
            </Td>
            <Td>{LINK_LABEL[k.kind]}</Td>
            <Td className="max-w-48 truncate" title={k.accounts.join(", ")}>{k.accounts.join(", ")}</Td>
            <Td className="tabular">{k.event_ids.length}</Td>
            <Td className="tabular whitespace-nowrap text-muted">{k.first_seen_label}{k.event_ids.length > 1 ? ` → ${k.last_seen_label}` : ""}</Td>
          </Tr>
        ))}
      </tbody>
    </Table>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="inline-flex items-center gap-1.5 text-xs font-medium text-ink-2">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="size-3.5 accent-brand" />
      {label}
    </label>
  );
}

function StructuralFindings({ graph }: { graph: IncidentGraph }) {
  const sections: [string, string, ReactNode, number][] = [
    ["validations", "Detection findings re-checked", graph.finding_validations.map((v) => (
      <li key={v.finding_id} className="space-y-1">
        <span className="flex flex-wrap items-center gap-2"><Mono className="text-[12px]">{v.rule_id}</Mono><VerdictBadge verdict={v.verdict} /></span>
        {v.checked_path.length > 0 && <HostPath hosts={v.checked_path} />}
        {v.reasons.map((r) => <p key={r} className="text-xs text-muted">{r}</p>)}
      </li>
    )), graph.finding_validations.length],
    ["disconnected", "Events not joined to a path", graph.disconnected.map((d) => (
      <li key={d.event_id}><Mono className="text-[12px]">{d.event_id}</Mono> <span className="text-xs text-muted">{d.detail}</span></li>
    )), graph.disconnected.length],
    ["choke", "Choke points", graph.choke_points.map((c) => (
      <li key={c.target_event_id + c.target_host} className="text-sm text-ink-2">
        Every observed route to <Mono>{c.target_host}</Mono> from <Mono>{c.entry_hosts.join(", ")}</Mono> passes through <Mono>{c.via_hosts.join(", ")}</Mono>.
      </li>
    )), graph.choke_points.length],
    ["bridges", "Accounts on unconnected host groups", graph.account_bridges.map((b) => (
      <li key={b.account}><Mono>{b.account}</Mono> <span className="text-xs text-muted">{b.host_groups.map((g) => g.join(", ")).join(" | ")}</span></li>
    )), graph.account_bridges.length],
  ];
  return (
    <Card>
      <Accordion type="multiple">
        {sections.filter(([, , , n]) => n > 0).map(([id, title, body, n]) => (
          <AccordionItem key={id} value={id}>
            <AccordionTrigger><span className="font-medium text-ink">{title} ({n})</span></AccordionTrigger>
            <AccordionContent><ul className="space-y-3 text-sm">{body}</ul></AccordionContent>
          </AccordionItem>
        ))}
        <AccordionItem value="limitations">
          <AccordionTrigger><span className="font-medium text-ink">Limitations</span></AccordionTrigger>
          <AccordionContent>
            <ul className="list-disc space-y-1.5 pl-5 text-sm text-ink-2 marker:text-faint">{graph.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
          </AccordionContent>
        </AccordionItem>
      </Accordion>
    </Card>
  );
}

export function AttackGraphTab({ sourceKey, inc }: { sourceKey: string; inc: IncidentDetail }) {
  const query = useOptionalQuery(["graph", sourceKey, inc.incident_id], () => api.graph(sourceKey, inc.incident_id));
  const [params, setParams] = useSearchParams();
  const [accounts, setAccounts] = useState<boolean | null>(null);
  const [attempts, setAttempts] = useState(true);
  const [selection, setSelection] = useState<GraphSelection>(null);

  if (query.isLoading) return <LoadingBlock label="Loading attack graph…" />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) return <Card><AssessmentNotice name="Attack graph" status={inc.assessments?.structural} /></Card>;

  const graph = query.data;
  const showAccounts = accounts ?? graph.links.length <= ACCOUNT_LINKS_SHOWN_UP_TO;
  const requested = params.get("path");
  const pathId = graph.paths.some((p) => p.path_id === requested) ? requested : null;
  const setPath = (id: string | null) => {
    const next = new URLSearchParams(params);
    if (id) next.set("path", id); else next.delete("path");
    setParams(next, { replace: true });
  };

  return (
    <div className="space-y-4">
      <Notice title="Observed authentication evidence, not proof of compromise">
        <span className="inline-flex flex-wrap items-center gap-2">
          Every connection is a logged event. No network topology is assumed.
          {graph.datasets.map((d) => <ProvenanceBadge key={d} provenance={d} />)}
        </span>
      </Notice>
      {graph.stats.truncated && (
        <Notice tone="warn" title="This graph is truncated">
          <ul className="list-disc pl-4">{graph.stats.truncation_reasons.map((r) => <li key={r}>{r}</li>)}</ul>
        </Notice>
      )}
      {graph.missing_event_ids.length > 0 && (
        <Notice tone="warn" title={`${graph.missing_event_ids.length} cited event(s) could not be found`}>
          They are not drawn: <Mono>{graph.missing_event_ids.join(", ")}</Mono>
        </Notice>
      )}

      <div className="grid items-start gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader title={`Reported paths (${graph.paths.length})`} description="Select one to highlight it" />
          <CardBody className="max-h-[22rem] overflow-y-auto lg:max-h-[34rem]">
            {graph.paths.length === 0 ? <p className="text-sm text-muted">No multi-event movement path was found in this incident's logs.</p> : (
              <ul className="space-y-2">
                {graph.paths.map((p) => (
                  <PathCard key={p.path_id} path={p} active={pathId === p.path_id} onToggle={() => setPath(pathId === p.path_id ? null : p.path_id)} />
                ))}
              </ul>
            )}
          </CardBody>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader title="Attack graph" description={`${graph.nodes.length} nodes · ${graph.links.length} connections · ${graph.events.length} events`}
            action={<div className="flex flex-wrap gap-3">
              <Toggle label="Accounts" checked={showAccounts} onChange={setAccounts} />
              <Toggle label="Failed attempts" checked={attempts} onChange={setAttempts} />
            </div>} />
          <Legend />
          <div className="h-80 lg:h-[30rem]" role="group" aria-label="Interactive attack graph. The connections table below lists the same data.">
            <CanvasBoundary>
              <Suspense fallback={<LoadingBlock label="Loading graph view…" />}>
                <AttackGraphCanvas key={`${showAccounts}-${attempts}`} graph={graph} showAccounts={showAccounts} showAttempts={attempts}
                  pathId={pathId} selection={selection} onSelect={setSelection} />
              </Suspense>
            </CanvasBoundary>
          </div>
        </Card>
      </div>

      <Card>
        <CardHeader title="Selection" />
        <SelectionDetails graph={graph} selection={selection} />
      </Card>

      <Card>
        <Accordion type="multiple">
          <AccordionItem value="connections">
            <AccordionTrigger><span className="font-medium text-ink">All connections as a table ({graph.links.length})</span></AccordionTrigger>
            <AccordionContent className="px-0"><ConnectionsTable links={graph.links} onSelect={setSelection} /></AccordionContent>
          </AccordionItem>
        </Accordion>
      </Card>

      <StructuralFindings graph={graph} />
    </div>
  );
}
