// The full incident report: everything AgentSOC knows about one incident and every analyst
// decision on it, in one printable document. Read-only.
import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowLeft, Download, Printer } from "lucide-react";
import type { ReactNode } from "react";
import { Link, useParams, useSearchParams } from "react-router";

import { Mono, ProvenanceBadge, RiskBadge, SeverityBadge } from "@/components/domain";
import { PHASES, POSTURE } from "@/components/agents";
import { REASON_TEXT, ReviewBadge, STATUS_TEXT } from "@/components/review";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingBlock } from "@/components/ui/states";
import { useSource } from "@/components/layout/source-context";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/utils";

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="break-inside-avoid-page border-t border-border pt-5">
      <h2 className="mb-3 text-base font-semibold text-ink">{title}</h2>
      {children}
    </section>
  );
}

function Grid({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-8 gap-y-1.5 text-sm sm:grid-cols-2">
      {rows.map(([k, v]) => (
        <div key={k} className="flex justify-between gap-4 border-b border-border/60 py-1">
          <dt className="text-muted">{k}</dt><dd className="text-right text-ink">{v ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}

function SimpleTable({ head, rows }: { head: string[]; rows: ReactNode[][] }) {
  if (rows.length === 0) return <p className="text-sm text-muted">None.</p>;
  return (
    // Focusable so keyboard users can scroll a wide table on a narrow screen.
    <div className="overflow-x-auto" tabIndex={0} role="region" aria-label={`Table: ${head.join(", ")}`}>
      <table className="w-full border-collapse text-left text-xs">
        <thead><tr>{head.map((h) => <th key={h} scope="col" className="border-b border-border px-2 py-1.5 font-semibold text-muted">{h}</th>)}</tr></thead>
        <tbody>{rows.map((r, i) => (
          <tr key={i} className="align-top">{r.map((c, j) => <td key={j} className="border-b border-border/60 px-2 py-1.5 text-ink-2">{c}</td>)}</tr>
        ))}</tbody>
      </table>
    </div>
  );
}

export function ReportPage() {
  const { incidentId = "" } = useParams();
  const [params] = useSearchParams();
  const { source } = useSource();
  const key = params.get("source") ?? source!.key;
  const query = useQuery({ queryKey: ["report", key, incidentId], queryFn: () => api.report(key, incidentId) });
  const download = useMutation({
    mutationFn: () => api.reportMarkdown(key, incidentId),
    onSuccess: (blob) => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `agentsoc-${key}-${incidentId}.md`;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    },
  });
  if (query.isLoading) return <LoadingBlock label="Assembling the report…" />;
  if (query.error || !query.data) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  const r = query.data;
  const inc = r.incident;
  const back = `/incidents/${encodeURIComponent(incidentId)}?source=${encodeURIComponent(key)}`;

  return (
    <article className="mx-auto max-w-4xl space-y-6 rounded-lg border border-border bg-surface p-6 shadow-sm print:border-0 print:p-0 print:shadow-none">
      <div className="flex flex-wrap items-center justify-between gap-3 print:hidden">
        <Link to={back} className="inline-flex items-center gap-1 text-xs font-medium text-muted hover:text-ink">
          <ArrowLeft className="size-3.5" aria-hidden />Back to the incident
        </Link>
        <div className="flex gap-2">
          <Button size="sm" onClick={() => window.print()}><Printer aria-hidden />Print or save as PDF</Button>
          <Button size="sm" onClick={() => download.mutate()} disabled={download.isPending}><Download aria-hidden />Download Markdown</Button>
        </div>
      </div>
      {download.error && <p role="alert" className="text-sm text-critical print:hidden">{download.error instanceof Error ? download.error.message : "Export failed."}</p>}

      <header className="space-y-2">
        <p className="text-xs font-semibold uppercase tracking-wider text-muted">AgentSOC incident report</p>
        <h1 className="flex flex-wrap items-center gap-3 font-mono text-2xl font-semibold text-ink">
          {inc.incident_id} {inc.provenance.map((p) => <ProvenanceBadge key={p} provenance={p} long />)}
        </h1>
        <p className="text-sm text-ink-2">{inc.principal_user} · {inc.first_seen_label} → {inc.last_seen_label}</p>
        <ul className="space-y-1 rounded-md border border-warn/30 bg-warn-soft p-3 text-xs text-ink">
          {r.notices.map((n) => <li key={n}>{n}</li>)}
        </ul>
      </header>

      <Section title="Analyst decision">
        <p className="mb-3 flex items-center gap-2 text-sm text-ink">Current status: <ReviewBadge status={r.review.status} /></p>
        <SimpleTable head={["When", "Analyst", "Decision", "Reason", "Note"]} rows={r.review.history.map((e) => [
          formatDateTime(e.created_at), e.analyst,
          <>{e.decision === "reopened" ? "Reopened" : STATUS_TEXT[e.decision]}{e.window_hours ? ` (±${e.window_hours} h)` : ""}{!e.current_version && <Badge tone="neutral" className="ml-1">earlier version</Badge>}</>,
          e.reason ? REASON_TEXT[e.reason] : "—", <span className="whitespace-pre-wrap">{e.note ?? "—"}</span>,
        ])} />
      </Section>

      <Section title="Summary">
        <p className="mb-3 text-sm text-ink-2">{inc.description}</p>
        <Grid rows={[
          ["Detection severity", <SeverityBadge severity={inc.severity} />],
          ["Risk", <RiskBadge band={inc.risk_band} score={inc.risk_score} />],
          ["Accounts", inc.involved_users.join(", ")], ["Hosts", inc.involved_hosts.join(", ")],
          ["Evidence events", inc.evidence_count], ["Findings", inc.finding_count],
        ]} />
        <p className="mt-3 text-xs text-muted">{inc.severity_rationale}</p>
      </Section>

      <Section title="Detection findings">
        <SimpleTable head={["Rule", "Severity", "Description", "Period"]} rows={inc.findings.map((f) => [
          f.rule_title, f.severity, f.description, `${f.first_seen_label} → ${f.last_seen_label}`])} />
      </Section>

      <Section title="Timeline">
        <SimpleTable head={["Time", "Event", "From → to", "Kind", "Outcome", "Rules"]} rows={inc.timeline.map((e) => [
          e.time_label, <Mono>{e.event_id}</Mono>, `${e.src_host} → ${e.dst_host}`, e.orientation, e.outcome, e.cited_by.join(", ")])} />
      </Section>

      <Section title="Attack paths">
        {r.paths_unavailable ? <p className="text-sm text-muted">{r.paths_unavailable}</p> : (
          <SimpleTable head={["Path", "Kind", "Verdict", "Hosts", "Why"]} rows={r.paths.map((p) => [
            p.path_id, p.kind, p.verdict, p.hosts.join(" → "), p.reasons.join("; ")])} />
        )}
      </Section>

      <Section title="Risk and proposed response">
        {r.risk === null ? <p className="text-sm text-muted">{r.risk_unavailable}</p> : (
          <>
            <p className="mb-3 text-sm text-ink-2">Risk {r.risk.record.risk.score.toFixed(1)} ({r.risk.record.risk.band}); investigation confidence {r.risk.record.confidence.score.toFixed(1)} ({r.risk.record.confidence.level}). Proposed actions are dry-run; none has been carried out.</p>
            <SimpleTable head={["Action", "Target", "Needs approval", "Rationale"]} rows={r.risk.record.actions.map((a) => [
              a.action_type, a.target, a.requires_approval ? "yes" : "no", a.rationale])} />
          </>
        )}
      </Section>

      <Section title="Investigation">
        {r.investigation === null ? <p className="text-sm text-muted">No investigation has been run for this incident.</p> : (
          <div className="space-y-3 text-sm">
            <p className="text-xs text-muted">Produced by {r.investigation.diagnostics.engine === "llm" ? "a language model" : "deterministic analysis"}, {formatDateTime(r.investigation.created_at)}.</p>
            <p className="text-ink"><span className="font-medium">Most plausible:</span> {r.investigation.conclusion.most_plausible_title} (confidence {r.investigation.conclusion.confidence.toFixed(2)})</p>
            <p className="text-ink-2">{r.investigation.conclusion.summary}</p>
            <p className="text-ink-2"><span className="font-medium text-ink">Uncertainty:</span> {r.investigation.conclusion.uncertainty}</p>
            <SimpleTable head={["Hypothesis", "Kind", "Confidence"]} rows={r.investigation.hypotheses.map((h) => [h.title, h.kind, h.confidence.toFixed(2)])} />
            {r.investigation.conclusion.next_steps.length > 0 && (
              <div><p className="font-medium text-ink">Suggested next steps</p>
                <ul className="list-disc pl-5 text-ink-2">{r.investigation.conclusion.next_steps.map((s) => <li key={s}>{s}</li>)}</ul></div>
            )}
          </div>
        )}
      </Section>

      {r.agents && (
        <Section title={r.agents.mode === "expanded" ? `Specialised agents (expanded to ±${r.agents.window_hours} h)` : "Specialised agents"}>
          <p className="mb-3 text-sm text-ink-2">{r.agents.correlation.summary}</p>
          {r.agents.correlation.corroborated.length > 0 && (
            <ul className="mb-3 list-disc space-y-1 pl-5 text-sm text-ink-2">{r.agents.correlation.corroborated.map((x) => <li key={x}>{x}</li>)}</ul>
          )}
          <SimpleTable head={["Agent", "Status", "Finding", "Weight"]} rows={r.agents.agents.flatMap((a) =>
            a.findings.length === 0
              ? [[a.title, a.status, a.status === "unavailable" ? "No data available to this agent." : "No findings.", "—"]]
              : a.findings.map((f, i) => [i === 0 ? a.title : "", i === 0 ? a.status : "",
                  `${f.statement}${f.expanded ? " (wider window)" : ""}`, `${f.stance}, ${f.strength}`]))} />
        </Section>
      )}

      {r.agents?.response_plan && (
        <Section title={`How to stop this: ${POSTURE[r.agents.response_plan.posture].title}`}>
          <p className="mb-3 text-sm text-ink-2">{r.agents.response_plan.summary}</p>
          <SimpleTable head={["Phase", "Step", "Why", "Approval"]} rows={PHASES.flatMap(({ key, title }) =>
            r.agents!.response_plan!.steps.filter((s) => s.phase === key).map((s, i) => [
              i === 0 ? title : "", s.action, s.why,
              `${s.disruptive ? "Disruptive: needs approval" : "—"}${s.risk_engine_proposed ? " (also proposed by the risk engine)" : ""}`]))} />
          <ul className="mt-3 list-disc space-y-1 pl-5 text-xs text-muted">{r.agents.response_plan.notes.map((n) => <li key={n}>{n}</li>)}</ul>
        </Section>
      )}

      {r.context && (
        <Section title={`Wider context (±${r.context.window_hours} h)`}>
          <ul className="mb-3 list-disc space-y-1 pl-5 text-sm text-ink-2">{r.context.observations.map((o) => <li key={o}>{o}</li>)}</ul>
          <SimpleTable head={["Related incident", "Account", "Severity", "Relation", "Decision"]} rows={r.context.related.map((x) => [
            x.incident_id, x.principal_user, x.severity, x.relation, STATUS_TEXT[x.review_status]])} />
        </Section>
      )}

      <Section title="Limitations and missing information">
        <ul className="list-disc space-y-1 pl-5 text-sm text-ink-2">
          {[...inc.limitations, ...inc.missing_information].map((x) => <li key={x}>{x}</li>)}
        </ul>
      </Section>

      <Section title="Provenance">
        <Grid rows={[
          ["Data source", r.source_label], ["Dataset", r.dataset_label],
          ["Dataset SHA-256", <Mono className="break-all text-[11px]">{r.dataset_sha256}</Mono>],
          ["Detection engine", r.detection_engine || "—"],
          ["Generated", formatDateTime(r.generated_at)], ["Generated by", r.generated_by],
        ]} />
      </Section>
    </article>
  );
}
