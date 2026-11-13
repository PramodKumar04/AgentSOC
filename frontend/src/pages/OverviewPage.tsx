import { useQuery } from "@tanstack/react-query";
import { ArrowRight } from "lucide-react";
import { Link, useNavigate } from "react-router";
import { Bar, BarChart, CartesianGrid, Cell, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { AssessmentNotice } from "@/components/assessment";
import { CHART, InvestigationBadge, ProvenanceBadge, RiskBadge, SEVERITY_COLOR, SeverityBadge } from "@/components/domain";
import { PageHeader } from "@/components/layout/app-shell";
import { useSource } from "@/components/layout/source-context";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { api, type Overview, type Severity } from "@/lib/api";
import { cn, SEVERITIES, titleCase } from "@/lib/utils";

function Stat({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div className="flex flex-col gap-1 px-5 py-4">
      <dt className="flex items-center gap-1.5 text-xs font-medium text-muted">
        {accent && <span className="size-2 rounded-full" style={{ background: accent }} aria-hidden />}
        {label}
      </dt>
      <dd className="tabular text-2xl font-semibold tracking-tight text-ink">{value.toLocaleString()}</dd>
    </div>
  );
}

function RiskDistribution({ data }: { data: Overview }) {
  const counts = data.risk_counts;
  if (!counts) {
    return (
      <Card>
        <CardHeader title="Risk distribution" description="RSEM incident risk, separate from detection severity" />
        <AssessmentNotice name="Risk" status={data.risk_status} compact />
      </Card>
    );
  }
  const rows = SEVERITIES.map((s) => ({ band: titleCase(s), key: s, count: counts[s] }));
  return (
    <Card>
      <CardHeader title="Risk distribution"
        description={`RSEM incident risk · ${(data.risk_assessed ?? 0).toLocaleString()} of ${data.incidents_total.toLocaleString()} incidents scored`} />
      <CardBody className="h-56">
        <div role="img" aria-label={`Risk distribution: ${rows.map((r) => `${r.band} ${r.count}`).join(", ")}`} className="size-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={rows} layout="vertical" margin={{ left: 8, right: 28 }}>
              <CartesianGrid horizontal={false} stroke={CHART.grid} />
              <XAxis type="number" allowDecimals={false} tick={{ fontSize: 12, fill: CHART.muted }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="band" width={70} tick={{ fontSize: 12, fill: CHART.ink }} axisLine={false} tickLine={false} />
              <Tooltip cursor={{ fill: CHART.hover }} contentStyle={{ fontSize: 12, borderRadius: 8 }} />
              <Bar dataKey="count" name="Incidents" radius={[0, 4, 4, 0]} barSize={18} isAnimationActive={false}>
                {rows.map((d) => <Cell key={d.key} fill={SEVERITY_COLOR[d.key]} />)}
                <LabelList dataKey="count" position="right" style={{ fontSize: 12, fill: CHART.ink }} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardBody>
    </Card>
  );
}

export function OverviewPage() {
  const { source } = useSource();
  const navigate = useNavigate();
  const key = source!.key;
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["overview", key], queryFn: () => api.overview(key),
  });

  if (isLoading) return <LoadingBlock label="Loading overview…" />;
  if (error || !data) return <ErrorState error={error} onRetry={() => void refetch()} />;

  const severityData = SEVERITIES.map((s) => ({ severity: titleCase(s), key: s, count: data.severity_counts[s] }));
  const maxRule = Math.max(1, ...data.rule_activity.map((r) => r.findings));

  return (
    <>
      <PageHeader
        title="Security overview"
        description={<span className="inline-flex flex-wrap items-center gap-2">
          {data.dataset.label} <ProvenanceBadge provenance={data.dataset.provenance} long />
          <span className="tabular text-faint">{data.dataset.event_count.toLocaleString()} verified events</span>
        </span>}
      />

      <Card className="mb-6">
        <dl className="grid grid-cols-2 divide-border sm:grid-cols-4 lg:grid-cols-7 lg:divide-x [&>div]:border-border max-lg:[&>div]:border-b">
          <Stat label="Total incidents" value={data.incidents_total} />
          {SEVERITIES.map((s) => (
            <Stat key={s} label={titleCase(s)} value={data.severity_counts[s]} accent={SEVERITY_COLOR[s]} />
          ))}
          <Stat label="Detection findings" value={data.findings_total} />
          <Stat label="Investigations" value={data.investigations_completed} />
        </dl>
      </Card>

      {data.incidents_total === 0 ? (
        <Card><EmptyState title="No incidents in this data source">
          Detection ran on {data.dataset.event_count.toLocaleString()} verified events and produced no incidents.
          That is a valid result, not an error.
        </EmptyState></Card>
      ) : (
        <>
          <div className="mb-6 grid gap-6 lg:grid-cols-3">
            <Card>
              <CardHeader title="Severity distribution" description="Incidents by detection severity (triage)" />
              <CardBody className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={severityData} layout="vertical" margin={{ left: 8, right: 28 }}>
                    <CartesianGrid horizontal={false} stroke={CHART.grid} />
                    <XAxis type="number" allowDecimals={false} tick={{ fontSize: 12, fill: CHART.muted }} axisLine={false} tickLine={false} />
                    <YAxis type="category" dataKey="severity" width={70} tick={{ fontSize: 12, fill: CHART.ink }} axisLine={false} tickLine={false} />
                    <Tooltip cursor={{ fill: CHART.hover }} contentStyle={{ fontSize: 12, borderRadius: 8 }} />
                    <Bar dataKey="count" name="Incidents" radius={[0, 4, 4, 0]} barSize={18} isAnimationActive={false}>
                      {severityData.map((d) => <Cell key={d.key} fill={SEVERITY_COLOR[d.key as Severity]} />)}
                      <LabelList dataKey="count" position="right" style={{ fontSize: 12, fill: CHART.ink }} />
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </CardBody>
            </Card>
            <RiskDistribution data={data} />
            <Card>
              <CardHeader title="Incident activity" description="New incidents by first-observed hour (dataset time)" />
              <CardBody className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={data.activity} margin={{ left: -12, right: 8 }}>
                    <CartesianGrid vertical={false} stroke={CHART.grid} />
                    <XAxis dataKey="label" tick={{ fontSize: 11, fill: CHART.muted }} axisLine={false} tickLine={false} />
                    <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: CHART.muted }} axisLine={false} tickLine={false} />
                    <Tooltip cursor={{ fill: CHART.hover }} contentStyle={{ fontSize: 12, borderRadius: 8 }} />
                    <Bar dataKey="count" name="Incidents" fill={CHART.brand} radius={[4, 4, 0, 0]} maxBarSize={36} isAnimationActive={false} />
                  </BarChart>
                </ResponsiveContainer>
              </CardBody>
            </Card>
          </div>

          <div className="grid items-start gap-6 lg:grid-cols-5">
            <Card className="lg:col-span-3">
              <CardHeader
                title="Recent incidents"
                description="Most recently active"
                action={<Link to="/incidents" className="inline-flex items-center gap-1 text-xs font-medium text-brand hover:underline">
                  View all <ArrowRight className="size-3.5" aria-hidden /></Link>}
              />
              <Table>
                <thead><tr><Th>Incident</Th><Th>User</Th><Th>Severity</Th><Th>Risk</Th><Th>Last observed</Th><Th>Status</Th></tr></thead>
                <tbody>
                  {data.recent_incidents.map((i) => (
                    <Tr key={i.incident_id} className="cursor-pointer" onClick={() => navigate(`/incidents/${i.incident_id}`)}>
                      <Td><Link to={`/incidents/${i.incident_id}`} className="font-mono text-[12.5px] font-medium text-brand hover:underline" onClick={(e) => e.stopPropagation()}>{i.incident_id}</Link></Td>
                      <Td className="text-ink">{i.principal_user}</Td>
                      <Td><SeverityBadge severity={i.severity} /></Td>
                      <Td><RiskBadge band={i.risk_band} score={i.risk_score} /></Td>
                      <Td className="tabular text-muted">{i.last_seen_label}</Td>
                      <Td><InvestigationBadge status={i.investigation_status} /></Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </Card>
            <Card className="lg:col-span-2">
              <CardHeader title="Detection rule activity" description="Findings per deterministic rule" />
              <CardBody className="space-y-3">
                {data.rule_activity.map((r) => (
                  <div key={r.rule_id}>
                    <div className="mb-1 flex items-baseline justify-between gap-3 text-xs">
                      <span className="truncate text-ink-2" title={r.rule_id}>{r.title}</span>
                      <span className="tabular font-medium text-ink">{r.findings}</span>
                    </div>
                    <div className="h-1.5 overflow-hidden rounded-full bg-subtle">
                      <div className={cn("h-full rounded-full", r.findings ? "bg-brand/70" : "bg-transparent")} style={{ width: `${(r.findings / maxRule) * 100}%` }} />
                    </div>
                  </div>
                ))}
              </CardBody>
            </Card>
          </div>
        </>
      )}
    </>
  );
}
