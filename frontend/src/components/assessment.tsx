// Shared handling of optional assessments: missing, stale, truncated or unavailable results
// are stated plainly, and a proposed path is only ever described by its backend verdict.
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, CircleSlash, Clock, HelpCircle, ShieldX } from "lucide-react";

import { Mono } from "@/components/domain";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/states";
import { ApiError, type AssessmentStatus, type Feasibility, type HypothesisView } from "@/lib/api";

/** A resource that may legitimately not exist: 404 becomes null, other errors surface. */
export function useOptionalQuery<T>(queryKey: unknown[], fetcher: () => Promise<T>) {
  return useQuery<T | null>({
    queryKey,
    queryFn: async () => {
      try { return await fetcher(); }
      catch (err) { if (err instanceof ApiError && err.status === 404) return null; throw err; }
    },
    retry: false,
  });
}

const NOTICE = {
  not_assessed: { title: "not assessed", Icon: CircleSlash },
  stale: { title: "assessment out of date", Icon: Clock },
  unavailable: { title: "assessment unavailable", Icon: ShieldX },
};

export function AssessmentNotice({ name, status, compact = false }: {
  name: string; status?: AssessmentStatus; compact?: boolean;
}) {
  const shown = !status || status.state === "available"
    ? { state: "not_assessed" as const, detail: `No ${name.toLowerCase()} assessment is available for this incident.` }
    : status;
  const { title, Icon } = NOTICE[shown.state as keyof typeof NOTICE];
  return (
    <div className={compact ? "[&>div]:py-8" : undefined}>
      <EmptyState title={`${name}: ${title}`} icon={<Icon className="size-6 text-faint" aria-hidden />}>
        <p>{shown.detail}</p>
        <p className="mt-1">Detection severity and evidence are unaffected.</p>
      </EmptyState>
    </div>
  );
}

export function Notice({ tone = "info", title, children }: {
  tone?: "info" | "warn"; title: string; children?: React.ReactNode;
}) {
  const warn = tone === "warn";
  return (
    <div role={warn ? "alert" : "note"} className={`flex items-start gap-2.5 rounded-lg border px-4 py-3 text-sm ${warn ? "border-medium/30 bg-medium-soft" : "border-border bg-subtle"}`}>
      {warn ? <AlertTriangle className="mt-0.5 size-4 shrink-0 text-medium" aria-hidden /> : <HelpCircle className="mt-0.5 size-4 shrink-0 text-muted" aria-hidden />}
      <div className="min-w-0">
        <p className="font-medium text-ink">{title}</p>
        {children && <div className="text-ink-2">{children}</div>}
      </div>
    </div>
  );
}

export const VERDICT_LABEL: Record<Feasibility, string> = {
  FEASIBLE: "Validated against logs",
  CONDITIONALLY_FEASIBLE: "Conditionally feasible",
  INFEASIBLE: "Not validated",
};

const VERDICT_NOTE: Record<Feasibility, string> = {
  FEASIBLE: "Every hop matches an observed authentication event. This is not proof of compromise.",
  CONDITIONALLY_FEASIBLE: "Every hop was observed, but linking them relies on the assumption stated here.",
  INFEASIBLE: "These logs do not show this path. That does not prove the movement was impossible.",
};

export function VerdictBadge({ verdict }: { verdict: Feasibility }) {
  const tone = verdict === "FEASIBLE" ? "ok" : verdict === "CONDITIONALLY_FEASIBLE" ? "warn" : "neutral";
  const Icon = verdict === "FEASIBLE" ? CheckCircle2 : verdict === "CONDITIONALLY_FEASIBLE" ? AlertTriangle : CircleSlash;
  return <Badge tone={tone}><Icon className="size-3" aria-hidden />{VERDICT_LABEL[verdict]}</Badge>;
}

export function HostPath({ hosts }: { hosts: string[] }) {
  return <span className="font-mono text-[12.5px] break-all text-ink">{hosts.join(" → ")}</span>;
}

/** The model proposes; this shows what deterministic validation concluded. */
export function PathValidationPanel({ hypothesis }: { hypothesis: HypothesisView }) {
  const validation = hypothesis.path_validation;
  const proposed = hypothesis.proposed_path ?? [];
  if (!validation && proposed.length === 0) return null;
  return (
    <section aria-label={`Proposed path validation for ${hypothesis.hypothesis_id}`} className="rounded-md border border-border bg-subtle px-3 py-3">
      <div className="mb-1.5 flex flex-wrap items-center gap-2">
        <h4 className="text-xs font-semibold text-muted">Model-proposed path</h4>
        {validation ? <VerdictBadge verdict={validation.verdict} /> : <Badge tone="neutral">Not checked</Badge>}
      </div>
      {proposed.length > 0 && <p className="mb-2"><HostPath hosts={proposed} /></p>}
      {validation ? (
        <div className="space-y-2 text-xs text-ink-2">
          <p>{VERDICT_NOTE[validation.verdict]}</p>
          {validation.conditions.length > 0 && (
            <ul className="list-disc space-y-1 pl-4 marker:text-faint">
              {validation.conditions.map((c) => <li key={c}><span className="font-medium">Condition: </span>{c}</li>)}
            </ul>
          )}
          {validation.missing_edges.length > 0 && (
            <ul className="space-y-1">
              {validation.missing_edges.map((e) => (
                <li key={`${e.source}-${e.target}`}><Mono className="text-[12px]">{e.source} → {e.target}</Mono> <span className="text-muted">not observed in these logs</span></li>
              ))}
            </ul>
          )}
          <ul className="list-disc space-y-1 pl-4 text-muted marker:text-faint">
            {validation.reasons.map((r) => <li key={r}>{r}</li>)}
          </ul>
          {validation.evidence_event_ids.length > 0 && (
            <p className="text-muted">Supporting events: <Mono className="text-[12px]">{validation.evidence_event_ids.join(", ")}</Mono></p>
          )}
        </div>
      ) : <p className="text-xs text-muted">No structural validation is available, so this path has not been confirmed.</p>}
    </section>
  );
}
