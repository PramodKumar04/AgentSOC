// Human in the loop: the analyst decides what happens to each incident. AgentSOC records the
// decision, gathers wider context when asked, and produces the report. Nothing is executed.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, CircleDot, FileText, History, RotateCcw, SearchCheck, XCircle } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link } from "react-router";

import { Mono, SeverityBadge } from "@/components/domain";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Select } from "@/components/ui/form";
import { ErrorState, LoadingBlock } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import {
  api, type ContextWindow, type DismissReason, type ReviewDecision, type ReviewEntry, type ReviewStatus,
} from "@/lib/api";
import { cn, formatDateTime } from "@/lib/utils";

export const STATUS_TEXT: Record<ReviewStatus, string> = {
  open: "Awaiting decision", accepted: "Accepted", dismissed: "Dismissed", more_evidence: "More evidence requested",
};
const DECISION_TEXT: Record<ReviewDecision, string> = {
  accepted: "Accepted", dismissed: "Dismissed", more_evidence: "Requested more evidence", reopened: "Reopened",
};
export const REASON_TEXT: Record<DismissReason, string> = {
  expected_activity: "Expected activity", false_positive: "False positive", duplicate: "Duplicate of another incident",
  authorised_test: "Authorised test", other: "Other (explain in the note)",
};
export const WINDOWS: ContextWindow[] = [1, 6, 24, 72];

export function ReviewBadge({ status }: { status: ReviewStatus | undefined }) {
  const s = status ?? "open";
  const tone = s === "accepted" ? "critical" : s === "more_evidence" ? "warn" : s === "dismissed" ? "ok" : "neutral";
  return <Badge tone={tone}>{STATUS_TEXT[s]}</Badge>;
}

function HistoryList({ items }: { items: ReviewEntry[] }) {
  return (
    <ol className="space-y-2 text-sm">
      {items.map((e, i) => (
        <li key={`${e.created_at}-${i}`} className="border-l-2 border-border pl-3">
          <p className="text-ink">
            <span className="font-medium">{DECISION_TEXT[e.decision]}</span>
            {e.reason && <> · {REASON_TEXT[e.reason]}</>}
            {e.window_hours && <> · {e.window_hours} h window</>}
          </p>
          <p className="text-xs text-muted">{e.analyst}, {formatDateTime(e.created_at)}
            {!e.current_version && " · on an earlier version of this incident number"}</p>
          {e.note && <p className="mt-1 whitespace-pre-wrap text-xs text-ink-2">{e.note}</p>}
        </li>
      ))}
    </ol>
  );
}

type Mode = "accepted" | "dismissed" | "more_evidence" | null;

/** The decision bar at the top of every incident. */
export function DecisionPanel({ sourceKey, incidentId, onEvidence }: {
  sourceKey: string; incidentId: string; onEvidence: (window: ContextWindow) => void;
}) {
  const client = useQueryClient();
  const query = useQuery({ queryKey: ["review", sourceKey, incidentId], queryFn: () => api.review(sourceKey, incidentId) });
  const [mode, setMode] = useState<Mode>(null);
  const [note, setNote] = useState("");
  const [reason, setReason] = useState<DismissReason | "">("");
  const [window, setWindow] = useState<ContextWindow>(24);
  const [showHistory, setShowHistory] = useState(false);
  const submit = useMutation({
    mutationFn: (decision: ReviewDecision) => api.submitReview(sourceKey, incidentId, {
      decision, note: note.trim() || undefined,
      reason: decision === "dismissed" && reason ? reason : undefined,
      window_hours: decision === "more_evidence" ? window : undefined,
    }),
    onSuccess: (state, decision) => {
      client.setQueryData(["review", sourceKey, incidentId], state);
      void client.invalidateQueries({ queryKey: ["incidents"] });
      void client.invalidateQueries({ queryKey: ["overview"] });
      setMode(null); setNote(""); setReason("");
      if (decision === "more_evidence") onEvidence(window);
    },
  });
  const choose = (next: Mode) => { setMode(mode === next ? null : next); submit.reset(); };
  const onSubmit = (e: FormEvent) => { e.preventDefault(); if (mode) submit.mutate(mode); };

  if (query.isLoading) return <LoadingBlock label="Loading decision…" className="py-4" />;
  if (query.error || !query.data) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  const state = query.data;
  const decided = state.status !== "open";
  const earlier = state.latest && !state.latest.current_version;

  return (
    <section aria-labelledby="decision-heading" className="rounded-lg border border-border bg-surface shadow-sm">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-3 px-4 py-3">
        <div className="min-w-0 flex-1">
          <h2 id="decision-heading" className="flex flex-wrap items-center gap-2 text-sm font-semibold text-ink">
            Analyst decision <ReviewBadge status={state.status} />
          </h2>
          <p className="mt-0.5 text-xs text-muted">
            {state.latest && state.latest.current_version
              ? `${DECISION_TEXT[state.latest.decision]} by ${state.latest.analyst}, ${formatDateTime(state.latest.created_at)}`
              : earlier ? "A decision exists for an earlier version of this incident number; this version is undecided."
              : "Review the evidence, then accept, dismiss, or ask AgentSOC for more context."}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {!decided || state.status === "more_evidence" ? (
            <>
              <Button size="sm" variant={mode === "accepted" ? "primary" : "secondary"} aria-expanded={mode === "accepted"} onClick={() => choose("accepted")}>
                <CheckCircle2 className="size-4" aria-hidden />Accept
              </Button>
              <Button size="sm" variant={mode === "dismissed" ? "primary" : "secondary"} aria-expanded={mode === "dismissed"} onClick={() => choose("dismissed")}>
                <XCircle className="size-4" aria-hidden />Dismiss
              </Button>
              <Button size="sm" variant={mode === "more_evidence" ? "primary" : "secondary"} aria-expanded={mode === "more_evidence"} onClick={() => choose("more_evidence")}>
                <SearchCheck className="size-4" aria-hidden />More evidence
              </Button>
            </>
          ) : (
            <Button size="sm" onClick={() => submit.mutate("reopened")} disabled={submit.isPending}>
              <RotateCcw className="size-4" aria-hidden />Reopen
            </Button>
          )}
          <Link to={`/incidents/${encodeURIComponent(incidentId)}/report?source=${encodeURIComponent(sourceKey)}`}
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-surface px-3 text-xs font-medium text-ink hover:bg-subtle">
            <FileText className="size-4" aria-hidden />Full report
          </Link>
        </div>
      </div>

      {mode && (
        <form onSubmit={onSubmit} className="space-y-3 border-t border-border bg-subtle px-4 py-3">
          {mode === "accepted" && (
            <p className="text-sm text-ink-2">Confirms this incident needs follow-up by your team. AgentSOC records the decision; it does not take any action.</p>
          )}
          {mode === "dismissed" && (
            <fieldset>
              <legend className="mb-1.5 text-sm font-medium text-ink">Why is it not a concern?</legend>
              <div className="flex flex-wrap gap-x-5 gap-y-1.5">
                {(Object.keys(REASON_TEXT) as DismissReason[]).map((r) => (
                  <label key={r} className="flex items-center gap-1.5 text-sm text-ink">
                    <input type="radio" name="dismiss-reason" value={r} checked={reason === r} onChange={() => setReason(r)} required />
                    {REASON_TEXT[r]}
                  </label>
                ))}
              </div>
            </fieldset>
          )}
          {mode === "more_evidence" && (
            <div className="flex flex-wrap items-end gap-3">
              <div>
                <label htmlFor="context-window" className="text-sm font-medium text-ink">Look this far either side of the incident</label>
                <Select id="context-window" value={window} onChange={(e) => setWindow(Number(e.target.value) as ContextWindow)} className="mt-1 block w-40">
                  {WINDOWS.map((w) => <option key={w} value={w}>{w} hour{w > 1 ? "s" : ""}</option>)}
                </Select>
              </div>
              <p className="max-w-md text-xs text-muted">AgentSOC searches this data source for the account's other activity, the same hosts, earlier sightings of each connection, and related incidents.</p>
            </div>
          )}
          <div>
            <label htmlFor="decision-note" className="text-sm font-medium text-ink">
              Note {mode === "dismissed" && reason === "other" ? "(required)" : "(optional)"}
            </label>
            <textarea id="decision-note" value={note} onChange={(e) => setNote(e.target.value)} maxLength={1000} rows={2}
              required={mode === "dismissed" && reason === "other"}
              className="mt-1 block w-full rounded-md border border-border bg-surface px-2.5 py-1.5 text-sm text-ink"
              placeholder={mode === "more_evidence" ? "What are you trying to establish?" : "Visible to other analysts and in the report"} />
          </div>
          {submit.error && <p role="alert" className="text-sm text-critical">{submit.error instanceof Error ? submit.error.message : "Not saved."}</p>}
          <div className="flex gap-2">
            <Button type="submit" variant="primary" size="sm" disabled={submit.isPending}>
              {mode === "accepted" ? "Accept incident" : mode === "dismissed" ? "Dismiss incident" : "Gather more evidence"}
            </Button>
            <Button type="button" size="sm" onClick={() => setMode(null)}>Cancel</Button>
          </div>
        </form>
      )}

      {state.history.length > 0 && (
        <div className="border-t border-border px-4 py-2">
          <button type="button" onClick={() => setShowHistory(!showHistory)} aria-expanded={showHistory}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-muted hover:text-ink">
            <History className="size-3.5" aria-hidden />Decision history ({state.history.length})
          </button>
          {showHistory && <div className="mt-2 pb-1"><HistoryList items={state.history} /></div>}
        </div>
      )}
    </section>
  );
}

/** What AgentSOC found when asked for more evidence. Facts only, no conclusions. */
export function ContextPanel({ sourceKey, incidentId, window, onWindow }: {
  sourceKey: string; incidentId: string; window: ContextWindow; onWindow: (w: ContextWindow) => void;
}) {
  const query = useQuery({
    queryKey: ["context", sourceKey, incidentId, window], queryFn: () => api.context(sourceKey, incidentId, window),
  });
  return (
    <Card>
      <CardHeader title="Wider context" description="Gathered from this data source on request. Facts for you to weigh; AgentSOC draws no conclusion."
        action={
          <div className="flex items-center gap-2">
            <label htmlFor="ctx-window" className="text-xs text-muted">Window</label>
            <Select id="ctx-window" value={window} onChange={(e) => onWindow(Number(e.target.value) as ContextWindow)} className="h-8 text-xs">
              {WINDOWS.map((w) => <option key={w} value={w}>±{w} h</option>)}
            </Select>
          </div>
        } />
      <CardBody className="space-y-5">
        {query.isLoading ? <LoadingBlock label="Searching the data source…" />
          : query.error || !query.data ? <ErrorState error={query.error} onRetry={() => void query.refetch()} />
          : (() => {
            const c = query.data;
            return (
              <>
                <ul className="space-y-1.5 text-sm text-ink-2">
                  {c.observations.map((o) => <li key={o} className="flex gap-2"><CircleDot className="mt-1 size-3 shrink-0 text-brand" aria-hidden />{o}</li>)}
                </ul>
                <div className="grid gap-5 lg:grid-cols-2">
                  <div>
                    <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Connections seen before?</h3>
                    {c.pairs.length === 0 ? <p className="text-sm text-muted">No host-to-host connections in this incident.</p> : (
                      <Table>
                        <thead><tr><Th>Connection</Th><Th>Before</Th><Th>First seen</Th><Th>After</Th></tr></thead>
                        <tbody>{c.pairs.map((p) => (
                          <Tr key={`${p.src_host}-${p.dst_host}`}>
                            <Td className="font-mono text-[12.5px]">{p.src_host} → {p.dst_host}</Td>
                            <Td className={cn("tabular", p.before === 0 && "font-semibold text-critical")}>{p.before === 0 ? "never" : p.before}</Td>
                            <Td className="whitespace-nowrap text-muted">{p.first_seen_label ?? "—"}</Td>
                            <Td className="tabular">{p.after}</Td>
                          </Tr>
                        ))}</tbody>
                      </Table>
                    )}
                  </div>
                  <div>
                    <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Activity on the incident's hosts</h3>
                    <Table>
                      <thead><tr><Th>Host</Th><Th>Events</Th><Th>Failed</Th><Th>Other accounts</Th></tr></thead>
                      <tbody>{c.hosts.map((h) => (
                        <Tr key={h.host}>
                          <Td className="font-mono text-[12.5px]">{h.host}</Td><Td className="tabular">{h.events}</Td>
                          <Td className="tabular">{h.failures}</Td>
                          <Td className="text-xs">{h.other_accounts.length === 0 ? "none" : h.other_accounts.map((a) => `${a.label} (${a.count})`).join(", ")}</Td>
                        </Tr>
                      ))}</tbody>
                    </Table>
                  </div>
                </div>
                <div>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Related incidents ({c.related.length})</h3>
                  {c.related.length === 0 ? <p className="text-sm text-muted">None in this data source.</p> : (
                    <Table>
                      <thead><tr><Th>Incident</Th><Th>Account</Th><Th>Severity</Th><Th>When</Th><Th>Relation</Th><Th>Decision</Th></tr></thead>
                      <tbody>{c.related.map((r) => (
                        <Tr key={r.incident_id}>
                          <Td><Link className="font-mono text-[12.5px] text-brand hover:underline" to={`/incidents/${r.incident_id}?source=${encodeURIComponent(sourceKey)}`}>{r.incident_id}</Link></Td>
                          <Td>{r.principal_user}</Td><Td><SeverityBadge severity={r.severity} /></Td>
                          <Td className="whitespace-nowrap text-muted">{r.first_seen_label}</Td><Td className="text-xs">{r.relation}</Td>
                          <Td><ReviewBadge status={r.review_status} /></Td>
                        </Tr>
                      ))}</tbody>
                    </Table>
                  )}
                </div>
                <div>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
                    Other events for <Mono>{c.account}</Mono> ({c.window_start_label} → {c.window_end_label})
                  </h3>
                  {c.events.length === 0 ? <p className="text-sm text-muted">No other events in this window.</p> : (
                    <Table>
                      <thead><tr><Th>Time</Th><Th>Event</Th><Th>From → to</Th><Th>Kind</Th><Th>Outcome</Th></tr></thead>
                      <tbody>{c.events.map((e) => (
                        <Tr key={e.event_id}>
                          <Td className="tabular whitespace-nowrap text-muted">{e.time_label}</Td>
                          <Td className="font-mono text-[12px]">{e.event_id}</Td>
                          <Td className="font-mono text-[12.5px] whitespace-nowrap">{e.src_host} → {e.dst_host}</Td>
                          <Td>{e.orientation}</Td>
                          <Td><Badge tone={e.outcome === "Fail" ? "critical" : "ok"}>{e.outcome}</Badge></Td>
                        </Tr>
                      ))}</tbody>
                    </Table>
                  )}
                  {c.events_truncated && <p className="mt-2 text-xs text-muted">Showing the first 100. Use the Evidence Explorer for the rest.</p>}
                </div>
                <ul className="space-y-1 border-t border-border pt-3 text-xs text-muted">
                  {c.limitations.map((l) => <li key={l}>{l}</li>)}
                </ul>
              </>
            );
          })()}
      </CardBody>
    </Card>
  );
}
