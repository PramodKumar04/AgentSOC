// Rendering of a validated investigation result. Provider attribution lives only in the
// collapsed "Technical details" section; analysts see status, not configuration.
import * as Collapsible from "@radix-ui/react-collapsible";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle, CheckCircle2, ChevronRight, ExternalLink, Info, ListChecks, Loader2,
  RotateCcw, ScanSearch, SearchX,
} from "lucide-react";
import { useEffect, useState } from "react";

import { PathValidationPanel } from "@/components/assessment";
import { ConfidenceBar, Mono } from "@/components/domain";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { ErrorState, LoadingBlock } from "@/components/ui/states";
import { api, ApiError, type EvidenceRef, type InvestigationView } from "@/lib/api";
import { cn, formatDateTime } from "@/lib/utils";

function StatusBanner({ result }: { result: InvestigationView }) {
  const limited = result.status === "completed_limited";
  return (
    <div role="status" className={cn("flex items-start gap-3 rounded-lg border px-4 py-3 text-sm",
      limited ? "border-medium/30 bg-medium-soft" : "border-ok/25 bg-ok-soft")}>
      {limited ? <AlertTriangle className="mt-0.5 size-4 shrink-0 text-medium" aria-hidden />
               : <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-ok" aria-hidden />}
      <div>
        <p className="font-medium text-ink">
          {limited ? "Investigation completed with limited analysis" : "Investigation completed"}
        </p>
        <p className="text-ink-2">
          {limited
            ? "Automated reasoning was unavailable, so this result comes from deterministic rule-based analysis of the same evidence."
            : "Competing hypotheses were generated and every cited event was verified against this incident's evidence."}
          {" "}<span className="text-muted">{result.cached ? "Saved" : "Generated"} {formatDateTime(result.created_at)}.</span>
        </p>
      </div>
    </div>
  );
}

function EvidenceList({ items, empty }: { items: EvidenceRef[]; empty: string }) {
  if (items.length === 0) return <p className="text-xs text-faint">{empty}</p>;
  return (
    <ul className="divide-y divide-border rounded-md border border-border">
      {items.map((e) => (
        <li key={e.event_id} className="grid gap-x-4 gap-y-0.5 px-3 py-2 text-xs xl:grid-cols-[auto_1fr]">
          <div className="flex items-center gap-2 whitespace-nowrap">
            <Mono className="text-[12px]">{e.event_id}</Mono>
            {e.outcome && <Badge tone={e.outcome === "Fail" ? "critical" : "ok"}>{e.outcome}</Badge>}
          </div>
          <div className="text-ink-2">
            {e.time_label && <span className="tabular text-muted">{e.time_label} · </span>}
            {e.path && <span className="font-mono text-[12px]">{e.path}</span>}
            {e.relevance && <p className="mt-0.5 text-muted">{e.relevance}</p>}
          </div>
        </li>
      ))}
    </ul>
  );
}

export function InvestigationResultView({ result }: { result: InvestigationView }) {
  const c = result.conclusion;
  const byId = Object.fromEntries(result.hypotheses.map((h) => [h.hypothesis_id, h]));
  const ranked = [...result.hypotheses].sort((a, b) => b.confidence - a.confidence);
  return (
    <div className="space-y-5">
      <StatusBanner result={result} />
      {result.analyst_notes.length > 0 && (
        <div className="space-y-2">
          {result.analyst_notes.map((n) => (
            <div key={n} className="flex items-start gap-2 rounded-md border border-border bg-subtle px-3 py-2 text-xs text-ink-2">
              <Info className="mt-0.5 size-3.5 shrink-0 text-muted" aria-hidden />{n}
            </div>
          ))}
        </div>
      )}

      <Card>
        <CardHeader title="Conclusion" description="Most plausible explanation and recommended next steps" />
        <CardBody className="space-y-4">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0 flex-1">
              <div className="mb-1 flex items-center gap-2">
                <Badge tone={byId[c.most_plausible_hypothesis_id]?.kind === "MALICIOUS" ? "critical" : "ok"}>
                  {byId[c.most_plausible_hypothesis_id]?.kind === "MALICIOUS" ? "Malicious" : "Benign"}
                </Badge>
                <span className="text-xs text-muted">{c.most_plausible_hypothesis_id}</span>
              </div>
              <p className="font-semibold text-ink">{c.most_plausible_title}</p>
              <p className="mt-2 text-sm text-ink-2">{c.summary}</p>
            </div>
            <div className="w-44 shrink-0">
              <p className="mb-1 text-xs text-muted">Model-generated estimate</p>
              <ConfidenceBar value={c.confidence} />
            </div>
          </div>
          <div className="rounded-md bg-subtle px-3 py-2.5 text-sm">
            <span className="font-medium text-ink">Uncertainty. </span>
            <span className="text-ink-2">{c.uncertainty}</span>
          </div>
          <div className="grid gap-5 md:grid-cols-2">
            <div>
              <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted">
                <ListChecks className="size-3.5" aria-hidden />Recommended next steps
              </h3>
              <ol className="list-decimal space-y-1.5 pl-5 text-sm text-ink-2 marker:text-faint">
                {c.next_steps.map((s) => <li key={s}>{s}</li>)}
              </ol>
            </div>
            <div>
              <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted">
                <SearchX className="size-3.5" aria-hidden />Evidence gaps
              </h3>
              <ul className="list-disc space-y-1.5 pl-5 text-sm text-ink-2 marker:text-faint">
                {c.evidence_gaps.map((g) => <li key={g}>{g}</li>)}
              </ul>
            </div>
          </div>
          <p className="border-t border-border pt-3 text-xs text-muted">
            This is an investigation recommendation, <strong className="font-semibold text-ink-2">not proof of compromise</strong>.
            Model-generated estimates are not calibrated probabilities and are used in no risk or confidence score.
          </p>
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Competing hypotheses" description={`${result.hypotheses.length} explanations evaluated against the incident evidence`} />
        <Accordion type="multiple" defaultValue={[c.most_plausible_hypothesis_id]}>
          {ranked.map((h) => (
            <AccordionItem key={h.hypothesis_id} value={h.hypothesis_id}>
              <AccordionTrigger>
                <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1">
                  <Badge tone={h.kind === "MALICIOUS" ? "critical" : "ok"}>{h.kind === "MALICIOUS" ? "Malicious" : "Benign"}</Badge>
                  <span className="min-w-0 flex-1 truncate font-medium text-ink">{h.title}</span>
                  <ConfidenceBar value={h.confidence} tone={h.kind === "MALICIOUS" ? "malicious" : "benign"} className="w-36" />
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4">
                <p className="text-sm text-ink-2">{h.narrative}</p>
                <PathValidationPanel hypothesis={h} />
                {h.attack_techniques.length > 0 && (
                  <div>
                    <h4 className="mb-1.5 text-xs font-semibold text-muted">MITRE ATT&CK mapping
                      <span className="font-normal text-faint"> — interpretation of authentication evidence</span></h4>
                    <div className="flex flex-wrap gap-2">
                      {h.attack_techniques.map((t) => (
                        <a key={t.id} href={t.url} target="_blank" rel="noreferrer noopener"
                          className="inline-flex items-center gap-1.5 rounded-md border border-border bg-subtle px-2 py-1 text-xs hover:border-brand">
                          <Mono className="text-[11.5px]">{t.id}</Mono>
                          {t.name && <span className="text-ink-2">{t.name}</span>}
                          <ExternalLink className="size-3 text-faint" aria-hidden />
                        </a>
                      ))}
                    </div>
                  </div>
                )}
                <div className="grid gap-4 lg:grid-cols-2">
                  <div>
                    <h4 className="mb-1.5 text-xs font-semibold text-muted">Supporting evidence ({h.supporting.length})</h4>
                    <EvidenceList items={h.supporting} empty="No supporting events cited." />
                  </div>
                  <div>
                    <h4 className="mb-1.5 text-xs font-semibold text-muted">Contradicting evidence ({h.contradicting.length})</h4>
                    <EvidenceList items={h.contradicting} empty="No contradicting events cited." />
                  </div>
                </div>
                {h.missing_information.length > 0 && (
                  <div>
                    <h4 className="mb-1.5 text-xs font-semibold text-muted">Missing information</h4>
                    <ul className="list-disc space-y-1 pl-5 text-sm text-ink-2 marker:text-faint">
                      {h.missing_information.map((m) => <li key={m}>{m}</li>)}
                    </ul>
                  </div>
                )}
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </Card>

      <Collapsible.Root>
        <Collapsible.Trigger className="group inline-flex items-center gap-1 text-xs font-medium text-muted hover:text-ink">
          <ChevronRight className="size-3.5 transition-transform group-data-[state=open]:rotate-90" aria-hidden />
          Technical details
        </Collapsible.Trigger>
        <Collapsible.Content>
          <dl className="mt-2 grid max-w-xl grid-cols-[10rem_1fr] gap-y-1 rounded-md border border-border bg-surface px-4 py-3 text-xs">
            <dt className="text-muted">Analysis engine</dt>
            <dd>{result.diagnostics.engine === "llm" ? "Language model (validated)" : "Deterministic rule-based analysis"}</dd>
            <dt className="text-muted">Model</dt><dd className="font-mono">{result.diagnostics.model ?? "—"}</dd>
            <dt className="text-muted">Processing time</dt><dd className="tabular">{(result.diagnostics.latency_ms / 1000).toFixed(1)} s</dd>
            <dt className="text-muted">Investigation ID</dt><dd className="font-mono">{result.investigation_id}</dd>
            <dt className="text-muted">Structural evidence</dt>
            <dd>{result.structural_evidence === "used" ? "Used: proposed paths were checked against the stored assessment" : "Unavailable when this investigation ran"}</dd>
          </dl>
        </Collapsible.Content>
      </Collapsible.Root>
    </div>
  );
}

function Elapsed() {
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setSeconds((s) => s + 1), 1000);
    return () => clearInterval(id);
  }, []);
  return <span className="tabular">{seconds}s</span>;
}

export function IncidentInvestigation({ sourceKey, incidentId }: { sourceKey: string; incidentId: string }) {
  const client = useQueryClient();
  const savedKey = ["investigation", sourceKey, incidentId];
  const saved = useQuery({
    queryKey: savedKey,
    queryFn: async () => {
      try { return await api.savedInvestigation(sourceKey, incidentId); }
      catch (err) { if (err instanceof ApiError && err.status === 404) return null; throw err; }
    },
    retry: false,
  });
  const mutation = useMutation({
    mutationKey: ["investigate", sourceKey, incidentId],
    mutationFn: (rerun: boolean) => api.investigate(sourceKey, incidentId, rerun),
    onSuccess: (result) => {
      client.setQueryData(savedKey, result);
      for (const key of ["incidents", "overview", "investigations", "activity", "incident", "risk"]) {
        void client.invalidateQueries({ queryKey: [key] });
      }
    },
  });

  const result = saved.data ?? null;
  const pending = mutation.isPending;

  return (
    <div className="space-y-5">
      <Card>
        <CardBody className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="flex size-9 items-center justify-center rounded-md bg-brand-soft text-brand">
              <ScanSearch className="size-5" aria-hidden />
            </div>
            <div>
              <p className="font-medium text-ink">AI-assisted investigation</p>
              <p className="text-sm text-muted">
                Evaluates competing explanations — malicious and benign — strictly against this incident's verified evidence.
              </p>
            </div>
          </div>
          {result ? (
            <Button onClick={() => mutation.mutate(true)} disabled={pending}>
              {pending ? <Loader2 className="animate-spin" aria-hidden /> : <RotateCcw aria-hidden />}
              {pending ? "Investigating…" : "Re-run investigation"}
            </Button>
          ) : (
            <Button variant="primary" onClick={() => mutation.mutate(false)} disabled={pending || saved.isLoading}>
              {pending ? <Loader2 className="animate-spin" aria-hidden /> : <ScanSearch aria-hidden />}
              {pending ? "Investigating…" : "Investigate Incident"}
            </Button>
          )}
        </CardBody>
      </Card>

      {pending && (
        <div role="status" aria-live="polite" className="flex items-center gap-3 rounded-lg border border-brand/20 bg-brand-soft px-4 py-3 text-sm">
          <Loader2 className="size-4 animate-spin text-brand" aria-hidden />
          <div>
            <p className="font-medium text-ink">Investigation in progress <span className="font-normal text-muted">· <Elapsed /></span></p>
            <p className="text-ink-2">Analysing evidence and validating every cited event. This usually takes 5–30 seconds.</p>
          </div>
        </div>
      )}
      {mutation.isError && !pending && (
        <div role="alert" className="flex items-start gap-3 rounded-lg border border-critical/25 bg-critical-soft px-4 py-3 text-sm">
          <AlertTriangle className="mt-0.5 size-4 text-critical" aria-hidden />
          <div>
            <p className="font-medium text-ink">Investigation could not be completed</p>
            <p className="text-ink-2">{mutation.error instanceof Error ? mutation.error.message : "Please try again."}</p>
          </div>
        </div>
      )}

      {saved.isLoading ? <LoadingBlock label="Checking for a saved investigation…" />
        : saved.error ? <ErrorState error={saved.error} onRetry={() => void saved.refetch()} />
        : result ? <InvestigationResultView result={result} />
        : !pending && (
          <Card><CardBody className="py-10 text-center text-sm text-muted">
            No investigation has been run for this incident yet. Select <strong className="text-ink-2">Investigate Incident</strong> to start one.
          </CardBody></Card>
        )}
    </div>
  );
}
