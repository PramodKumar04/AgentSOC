import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, XCircle } from "lucide-react";

import { Mono, ProvenanceBadge } from "@/components/domain";
import { PageHeader } from "@/components/layout/app-shell";
import { useSource } from "@/components/layout/source-context";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { ErrorState, LoadingBlock } from "@/components/ui/states";
import type { AnalysisRunInfo, DatasetInfo, OrgSource } from "@/lib/api";
import { api } from "@/lib/api";
import { formatDateTime, formatDuration, shortHash } from "@/lib/utils";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-1.5 text-sm">
      <dt className="text-muted">{label}</dt>
      <dd className="text-right text-ink">{children}</dd>
    </div>
  );
}

const STATE_LABEL = { not_assessed: "Not assessed", stale: "Out of date", unavailable: "Failed verification" };

function AnalysisRow({ label, run }: { label: string; run?: AnalysisRunInfo | null }) {
  return (
    <Row label={label}>
      {!run ? "—" : run.state === "available"
        ? <span title={run.output_sha256 ?? undefined}><Mono>{run.engine_version}</Mono> · {run.records?.toLocaleString()} records</span>
        : <span title={run.detail}>{STATE_LABEL[run.state]}</span>}
    </Row>
  );
}

function DatasetCard({ d, active, onUse }: { d: DatasetInfo; active: boolean; onUse: () => void }) {
  const ok = d.status === "verified";
  return (
    <Card className={active ? "ring-1 ring-brand/40" : ""}>
      <CardHeader
        title={<span className="flex flex-wrap items-center gap-2">{d.label}<ProvenanceBadge provenance={d.provenance} long /></span>}
        description={d.dataset_label || undefined}
        action={active ? <span className="text-xs font-medium text-brand">In use</span>
          : <Button size="sm" onClick={onUse}>Use this source</Button>}
      />
      <CardBody className="grid gap-x-10 md:grid-cols-2">
        <dl className="divide-y divide-border">
          <Row label="Status">
            <span className="inline-flex items-center gap-1.5">
              {ok ? <CheckCircle2 className="size-4 text-ok" aria-hidden /> : <XCircle className="size-4 text-critical" aria-hidden />}
              {ok ? "Verified" : "Verification failed"}
            </span>
          </Row>
          <Row label="Source file"><Mono>{d.source_file || "—"}</Mono></Row>
          <Row label="Lines processed"><span className="tabular">{d.lines_read.toLocaleString()}</span></Row>
          <Row label="Accepted events"><span className="tabular">{d.event_count.toLocaleString()}</span></Row>
          <Row label="Rejected records"><span className="tabular">{d.rejected_count.toLocaleString()}</span></Row>
          <Row label="Time coverage">
            {d.time_start_label ? <span className="tabular">{d.time_start_label} → {d.time_end_label} ({formatDuration(d.time_coverage_seconds)})</span> : "—"}
          </Row>
        </dl>
        <dl className="divide-y divide-border">
          <Row label="Input SHA-256"><Mono>{shortHash(d.input_sha256, 16)}</Mono></Row>
          <Row label="Events SHA-256"><Mono>{shortHash(d.events_sha256, 16)}</Mono></Row>
          <Row label="Parser"><Mono>{d.parser_version || "—"}</Mono></Row>
          <Row label="Detection run">{ok ? `${d.detection.findings} findings · ${d.detection.incidents} incidents` : "—"}</Row>
          <Row label="Detection engine"><Mono>{d.detection.engine_version || "—"}</Mono></Row>
          <Row label="Last processed">{ok ? formatDateTime(d.detection.generated_at) : "—"}</Row>
          <AnalysisRow label="Structural assessment" run={d.structural} />
          <AnalysisRow label="Risk assessment" run={d.risk} />
        </dl>
        <p className="mt-3 text-xs text-muted md:col-span-2">{d.status_detail}</p>
      </CardBody>
    </Card>
  );
}

function OrgStatus({ org }: { org: OrgSource }) {
  const run = org.last_run;
  return (
    <div className="mb-3 rounded-md border border-border bg-subtle p-3 text-sm">
      <p className="font-medium text-ink">{org.name}</p>
      <p className="text-xs text-muted">{org.mode}</p>
      <dl className="mt-2 grid gap-x-8 gap-y-1 md:grid-cols-2">
        <Row label="Scheduled sync">{org.sync_enabled ? `on, every ${org.sync_interval_seconds} s` : "off"}</Row>
        <Row label="Last sync">{run ? `${run.status}, ${formatDateTime(run.finished_at ?? run.started_at)}` : "never"}</Row>
        <Row label="Stored / rejected rows"><span className="tabular">{org.stats.accepted.toLocaleString()} / {org.stats.rejected.toLocaleString()}</span></Row>
        <Row label="Snapshot shown">{org.snapshot ? formatDateTime(org.snapshot.created_at) : "none yet"}</Row>
        <Row label="AI investigation">{org.ai_enabled ? "allowed by an administrator" : "off (deterministic analysis only)"}</Row>
      </dl>
      {org.disclosures.map((d) => <p key={d} className="mt-2 text-xs text-warn">{d}</p>)}
      {run?.error && <p className="mt-2 text-xs text-critical">Last sync failed: {run.error}</p>}
    </div>
  );
}

export function DataSourcesPage() {
  const { source, setSource } = useSource();
  const query = useQuery({ queryKey: ["datasets"], queryFn: api.datasets });
  const orgQuery = useQuery({ queryKey: ["datasources", "organisation"], queryFn: api.orgSources });
  if (query.isLoading) return <LoadingBlock label="Verifying data sources…" />;
  if (query.error || !query.data) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  const synthetic = query.data.filter((d) => d.provenance === "synthetic");
  const real = query.data.filter((d) => d.provenance === "lanl" || d.provenance === "upload");
  const organisation = query.data.filter((d) => d.provenance === "organization");
  const orgs = orgQuery.data ?? [];
  return (
    <>
      <PageHeader title="Data sources" description="Processed datasets and their detection runs. Statistics are never combined across sources." />
      <section aria-labelledby="syn-heading" className="mb-8">
        <h2 id="syn-heading" className="mb-1 text-sm font-semibold text-ink">Synthetic demonstration data</h2>
        <p className="mb-3 text-xs text-muted">Generated scenarios that demonstrate detection and investigation logic. They are not real activity and do not measure real-world accuracy.</p>
        <div className="space-y-4">{synthetic.map((d) => <DatasetCard key={d.key} d={d} active={d.key === source?.key} onUse={() => setSource(d.key)} />)}</div>
      </section>
      <section aria-labelledby="real-heading">
        <h2 id="real-heading" className="mb-1 text-sm font-semibold text-ink">Real LANL 2015 authentication data</h2>
        <p className="mb-3 text-xs text-muted">Sampled windows of the Los Alamos National Laboratory dataset. Identities are anonymised and times are relative offsets.</p>
        {real.length === 0 ? <p className="text-sm text-muted">No LANL validation runs are available on this installation.</p>
          : <div className="space-y-4">{real.map((d) => <DatasetCard key={d.key} d={d} active={d.key === source?.key} onUse={() => setSource(d.key)} />)}</div>}
      </section>
      {(orgs.length > 0 || organisation.length > 0) && (
        <section aria-labelledby="org-heading" className="mt-8">
          <h2 id="org-heading" className="mb-1 text-sm font-semibold text-ink">Organisation databases</h2>
          <p className="mb-3 text-xs text-muted">Read from connected databases on a schedule and analysed in snapshots. Times are real and shown in UTC. Incident numbers restart in each snapshot.</p>
          {orgs.map((o) => <OrgStatus key={o.key} org={o} />)}
          <div className="space-y-4">{organisation.map((d) => <DatasetCard key={d.key} d={d} active={d.key === source?.key} onUse={() => setSource(d.key)} />)}</div>
          {orgQuery.error && <ErrorState error={orgQuery.error} onRetry={() => void orgQuery.refetch()} />}
        </section>
      )}
    </>
  );
}
