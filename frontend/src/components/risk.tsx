// Risk & response. Every number comes from the verified record returned by the API: nothing
// is scored here, and proposed actions are display-only.
import { Ban, Eye, Gauge, ShieldCheck } from "lucide-react";

import { AssessmentNotice, HostPath, Notice, useOptionalQuery } from "@/components/assessment";
import { Mono, RiskBadge, SeverityBadge } from "@/components/domain";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { ErrorState, LoadingBlock } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { api, type ConfidenceAssessment, type IncidentDetail, type RiskComponent, type RiskView } from "@/lib/api";
import { percent, titleCase } from "@/lib/utils";

const humanise = (name: string) => titleCase(name.replaceAll("_", " ").toUpperCase());
const actionName = (type: string) => humanise(type).replace(/mfa/i, "MFA");
const RELATION = { SAME: "Same level", RISK_HIGHER: "Risk is higher than severity", RISK_LOWER: "Risk is lower than severity" };

function ComponentBars({ components, contributions, label }: {
  components: RiskComponent[]; contributions?: Record<string, number>; label: string;
}) {
  return (
    <ul className="space-y-4">
      {components.map((c) => (
        <li key={c.name}>
          <div className="mb-1 flex flex-wrap items-baseline justify-between gap-x-3 text-sm">
            <span className="font-medium text-ink">{humanise(c.name)}</span>
            <span className="tabular text-xs text-muted">
              {percent(c.value)} · weight {percent(c.weight)}
              {contributions?.[c.name] !== undefined && <> · <strong className="font-semibold text-ink-2">{contributions[c.name].toFixed(1)} pts</strong></>}
            </span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-border" role="meter" aria-valuemin={0} aria-valuemax={1}
            aria-valuenow={c.value} aria-label={`${label}: ${humanise(c.name)} ${percent(c.value)}`}>
            <div className="h-full rounded-full bg-brand" style={{ width: `${c.value * 100}%` }} />
          </div>
          <p className="mt-1 text-xs text-muted">{c.explanation}</p>
        </li>
      ))}
    </ul>
  );
}

function Headline({ view }: { view: RiskView }) {
  const { record, investigation_confidence: confidence, detection_severity: severity } = view;
  return (
    <div className="grid gap-4 md:grid-cols-3">
      <Card><CardBody>
        <p className="text-xs font-medium text-muted">Detection severity</p>
        <div className="mt-2"><SeverityBadge severity={severity} /></div>
        <p className="mt-2 text-xs text-muted">Rule-based triage level. Unchanged by RSEM.</p>
      </CardBody></Card>
      <Card><CardBody>
        <p className="text-xs font-medium text-muted">RSEM incident risk</p>
        <p className="tabular mt-1 text-2xl font-semibold tracking-tight text-ink">{record.risk.score.toFixed(1)}<span className="text-sm font-normal text-muted"> / 100</span></p>
        <div className="mt-1"><RiskBadge band={record.risk.band} score={record.risk.score} /></div>
        <p className="mt-2 text-xs text-muted">How much evidence-supported risk this incident shows.</p>
      </CardBody></Card>
      <Card><CardBody>
        <p className="text-xs font-medium text-muted">Investigation confidence</p>
        <p className="tabular mt-1 text-2xl font-semibold tracking-tight text-ink">{confidence.score.toFixed(1)}<span className="text-sm font-normal text-muted"> / 100</span></p>
        <Badge tone="neutral" className="mt-1">{titleCase(confidence.level)}</Badge>
        <p className="mt-2 text-xs text-muted">How far the assessment can be relied on.</p>
      </CardBody></Card>
    </div>
  );
}

function ConfidenceCard({ confidence, estimates }: { confidence: ConfidenceAssessment; estimates: Record<string, number> }) {
  const rows = Object.entries(estimates);
  return (
    <Card>
      <CardHeader title="Investigation confidence" description={confidence.includes_investigation
        ? "Includes how the saved investigation was produced" : "No investigation has contributed yet"} />
      <CardBody className="space-y-5">
        <ComponentBars components={confidence.components} label="Confidence" />
        <div className="border-t border-border pt-4">
          <h3 className="text-xs font-semibold text-muted">Model-generated estimates</h3>
          <p className="mt-0.5 text-xs text-muted">What the model reported about its own hypotheses. Used in no score.</p>
          {rows.length === 0 ? <p className="mt-2 text-xs text-faint">No model estimates are recorded for this incident.</p> : (
            <dl className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-4">
              {rows.map(([id, value]) => (
                <div key={id} className="flex justify-between gap-2"><dt className="text-muted">{id}</dt><dd className="tabular text-ink">{percent(value)}</dd></div>
              ))}
            </dl>
          )}
        </div>
      </CardBody>
    </Card>
  );
}

function Actions({ view }: { view: RiskView }) {
  const { actions, withheld_actions: withheld } = view.record;
  return (
    <Card>
      <CardHeader title="Proposed response actions"
        description="Ranked by action priority. Priority orders these proposals and has no effect on incident risk." />
      <div className="px-5 pt-4 pb-3">
        <Notice title="Display only: nothing here can be approved or executed">
          Every action stays proposed and dry-run. Decisions and any real change happen outside AgentSOC.
        </Notice>
      </div>
      <Table>
        <thead><tr><Th>Action priority</Th><Th>Action</Th><Th>Target</Th><Th>Containment</Th><Th>Business impact</Th><Th>Status</Th></tr></thead>
        <tbody>
          {actions.map((a) => (
            <Tr key={a.action_id}>
              <Td className="tabular font-medium text-ink">{a.score ? a.score.composite.toFixed(2) : "—"}</Td>
              <Td>
                <span className="font-medium text-ink">{actionName(a.action_type)}</span>
                <p className="max-w-sm text-xs text-muted">{a.rationale}</p>
              </Td>
              <Td><Mono>{a.target}</Mono></Td>
              <Td className="tabular">{a.score ? a.score.containment.toFixed(2) : "—"}</Td>
              <Td className="tabular">{a.score ? a.score.business_impact.toFixed(2) : "—"}</Td>
              <Td>
                <div className="flex flex-wrap gap-1">
                  <Badge tone="brand">Proposed</Badge>
                  <Badge tone="neutral">Dry run</Badge>
                  <Badge tone={a.requires_approval ? "warn" : "neutral"}>{a.requires_approval ? "Requires approval" : "No approval needed"}</Badge>
                </div>
              </Td>
            </Tr>
          ))}
        </tbody>
      </Table>
      {withheld.length > 0 && (
        <div className="border-t border-border px-5 py-4">
          <h3 className="flex items-center gap-1.5 text-sm font-semibold text-ink"><Ban className="size-4 text-muted" aria-hidden />Withheld actions</h3>
          <p className="mb-2 text-xs text-muted">Disruptive actions are not proposed until the evidence supports them.</p>
          <ul className="space-y-2 text-sm">
            {withheld.map((w) => (
              <li key={w.action_type}>
                <span className="font-medium text-ink-2">{actionName(w.action_type)}</span>
                <span className="text-muted"> — {w.reasons.join(" ")}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}

export function RiskResponseTab({ sourceKey, inc }: { sourceKey: string; inc: IncidentDetail }) {
  const query = useOptionalQuery(["risk", sourceKey, inc.incident_id], () => api.risk(sourceKey, inc.incident_id));
  if (query.isLoading) return <LoadingBlock label="Loading risk assessment…" />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) return <Card><AssessmentNotice name="Risk" status={inc.assessments?.risk} /></Card>;
  const view = query.data;
  const { record } = view;
  const attributed = new Map<string, string[]>();
  for (const a of record.attributions) attributed.set(a.component, [...(attributed.get(a.component) ?? []), a.event_id]);
  return (
    <div className="space-y-6">
      <Headline view={view} />
      {inc.assessments?.truncated && (
        <Notice tone="warn" title="Based on truncated context">
          The structural context behind this score was cut short: {inc.assessments.truncation_reasons.join(" ")}
        </Notice>
      )}
      <Notice title={RELATION[record.severity_comparison.relation]}>{record.severity_comparison.explanation}</Notice>

      <div className="grid items-start gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader title="Risk breakdown" description={`Base score ${record.base_score.toFixed(1)} before adjustments`} />
          <CardBody className="space-y-5">
            <ComponentBars components={record.risk.components} contributions={view.contributions} label="Risk" />
            <div className="border-t border-border pt-4">
              <h3 className="text-xs font-semibold text-muted">Adjustments</h3>
              {record.adjustments.length === 0 ? <p className="mt-1 text-xs text-faint">No adjustments applied.</p> : (
                <ul className="mt-2 space-y-2 text-xs">
                  {record.adjustments.map((a) => (
                    <li key={a.name}>
                      <span className="font-medium text-ink-2">{humanise(a.name)}</span>
                      <span className="tabular text-muted"> ({a.kind === "CAP" ? "cap" : "factor"} {a.value}): {a.before.toFixed(1)} → {a.after.toFixed(1)}</span>
                      <p className="text-muted">{a.explanation}</p>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div className="border-t border-border pt-4">
              <h3 className="text-xs font-semibold text-muted">Selected route</h3>
              {record.route ? (
                <div className="mt-1 space-y-1">
                  <HostPath hosts={record.route.hosts} />
                  <p className="text-xs text-muted">
                    {titleCase(record.route.kind)} route · {record.route.effective_hops.toFixed(2)} effective hops
                    {record.route.reduced_jump_route && " · reduced: configured jump hosts only"}
                  </p>
                </div>
              ) : <p className="mt-1 text-xs text-faint">No multi-hop route was found.</p>}
            </div>
          </CardBody>
        </Card>
        <ConfidenceCard confidence={view.investigation_confidence} estimates={view.model_generated_estimates} />
      </div>

      <Actions view={view} />

      <Card>
        <Accordion type="multiple">
          <AccordionItem value="attribution">
            <AccordionTrigger><span className="flex items-center gap-2 font-medium text-ink"><Eye className="size-4 text-muted" aria-hidden />Evidence credited to each component ({record.attributions.length} events)</span></AccordionTrigger>
            <AccordionContent>
              <p className="mb-3 text-xs text-muted">Each event is credited to at most one component.</p>
              {attributed.size === 0 ? <p className="text-xs text-faint">No events were credited.</p> : (
                <dl className="space-y-2 text-xs">
                  {[...attributed].map(([component, items]) => (
                    <div key={component}>
                      <dt className="font-medium text-ink-2">{humanise(component)}</dt>
                      <dd className="font-mono text-[12px] break-all text-muted">{items.join(", ")}</dd>
                    </div>
                  ))}
                </dl>
              )}
            </AccordionContent>
          </AccordionItem>
          <AccordionItem value="limits">
            <AccordionTrigger><span className="flex items-center gap-2 font-medium text-ink"><ShieldCheck className="size-4 text-muted" aria-hidden />Limitations</span></AccordionTrigger>
            <AccordionContent>
              <ul className="list-disc space-y-1.5 pl-5 text-sm text-ink-2 marker:text-faint">
                {record.limitations.map((l) => <li key={l}>{l}</li>)}
              </ul>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
        <p className="flex items-center gap-1.5 border-t border-border px-5 py-3 text-xs text-muted">
          <Gauge className="size-3.5" aria-hidden />Scores are heuristic, not probabilities, and are not proof of compromise.
        </p>
      </Card>
    </div>
  );
}
