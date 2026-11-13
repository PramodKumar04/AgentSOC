// Where this incident's data came from, which runs produced its results, and what happened
// to it. Hashes and log entries are shown exactly as the API reports them.
import { useQuery } from "@tanstack/react-query";
import { ShieldAlert, ShieldCheck } from "lucide-react";

import { useOptionalQuery } from "@/components/assessment";
import { Mono, ProvenanceBadge } from "@/components/domain";
import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { api, type AnalysisRunInfo, type IncidentDetail } from "@/lib/api";
import { formatDateTime, shortHash } from "@/lib/utils";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap justify-between gap-x-4 gap-y-0.5 py-1.5 text-sm">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 text-right break-all text-ink">{children}</dd>
    </div>
  );
}

const Hash = ({ value }: { value?: string | null }) =>
  value ? <span title={value}><Mono>{shortHash(value, 16)}</Mono></span> : <>—</>;

function RunCard({ title, run }: { title: string; run?: AnalysisRunInfo | null }) {
  return (
    <Card>
      <CardHeader title={title} />
      <CardBody>
        {!run || run.state !== "available" ? <p className="text-sm text-muted">{run?.detail ?? "No information is available for this stage."}</p> : (
          <dl className="divide-y divide-border">
            <Row label="Engine"><Mono>{run.engine_version}</Mono></Row>
            <Row label="Configuration hash"><Hash value={run.config_sha256} /></Row>
            <Row label="Output hash"><Hash value={run.output_sha256} /></Row>
            <Row label="Records"><span className="tabular">{run.records?.toLocaleString()}</span></Row>
            {run.truncated_records != null && <Row label="Truncated"><span className="tabular">{run.truncated_records.toLocaleString()}</span></Row>}
            <Row label="Generated">{run.generated_at ? formatDateTime(run.generated_at) : "—"}</Row>
          </dl>
        )}
      </CardBody>
    </Card>
  );
}

export function ProvenanceTab({ sourceKey, inc }: { sourceKey: string; inc: IncidentDetail }) {
  const datasets = useQuery({ queryKey: ["datasets"], queryFn: api.datasets });
  const risk = useOptionalQuery(["risk", sourceKey, inc.incident_id], () => api.risk(sourceKey, inc.incident_id));
  const audit = useQuery({
    queryKey: ["activity", sourceKey, inc.incident_id],
    queryFn: () => api.activity(200, { subject: inc.incident_id, source: sourceKey }),
  });
  const dataset = datasets.data?.find((d) => d.key === sourceKey);
  const files = [...new Set(inc.timeline.map((e) => e.raw_file))];

  return (
    <div className="space-y-6">
      {datasets.isLoading ? <LoadingBlock label="Verifying data source…" />
        : datasets.error ? <ErrorState error={datasets.error} onRetry={() => void datasets.refetch()} />
        : !dataset ? <Card><EmptyState title="This data source is not listed" /></Card> : (
          <>
            <Card>
              <CardHeader title={<span className="flex flex-wrap items-center gap-2">Data lineage<ProvenanceBadge provenance={dataset.provenance} long /></span>}
                description={dataset.dataset_label} />
              <CardBody className="grid gap-x-10 md:grid-cols-2">
                <dl className="divide-y divide-border">
                  <Row label="Source file"><Mono>{dataset.source_file || "—"}</Mono></Row>
                  <Row label="Input hash"><Hash value={dataset.input_sha256} /></Row>
                  <Row label="Events hash"><Hash value={dataset.events_sha256} /></Row>
                  <Row label="Parser"><Mono>{dataset.parser_version || "—"}</Mono></Row>
                </dl>
                <dl className="divide-y divide-border">
                  <Row label="Detection engine"><Mono>{dataset.detection.engine_version || "—"}</Mono></Row>
                  <Row label="Detection configuration"><Hash value={dataset.detection.config_sha256} /></Row>
                  <Row label="Verification">{dataset.status === "verified" ? "Hashes match" : "Failed"}</Row>
                  <Row label="Evidence lines from"><Mono>{files.join(", ") || "—"}</Mono></Row>
                </dl>
              </CardBody>
            </Card>
            <div className="grid items-start gap-6 md:grid-cols-2">
              <RunCard title="Structural assessment" run={dataset.structural} />
              <RunCard title="Risk assessment" run={dataset.risk} />
            </div>
          </>
        )}

      <Card>
        <CardHeader title="Incident binding" description="The exact inputs this incident's risk record was computed from" />
        <CardBody>
          {risk.isLoading ? <LoadingBlock label="Loading…" />
            : risk.error ? <ErrorState error={risk.error} onRetry={() => void risk.refetch()} />
            : !risk.data ? <p className="text-sm text-muted">{inc.assessments?.risk.detail ?? "No risk record exists for this incident."}</p> : (
              <dl className="divide-y divide-border">
                <Row label="Incident hash"><Hash value={risk.data.record.incident_sha256} /></Row>
                <Row label="Structural assessment hash"><Hash value={risk.data.record.structural_sha256} /></Row>
              </dl>
            )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Audit trail" description="Recorded events for this incident in this data source"
          action={audit.data && (audit.data.chain_intact
            ? <Badge tone="ok"><ShieldCheck className="size-3" aria-hidden />Log chain intact</Badge>
            : <Badge tone="critical"><ShieldAlert className="size-3" aria-hidden />Log chain broken</Badge>)} />
        {audit.isLoading ? <LoadingBlock label="Loading audit trail…" />
          : audit.error ? <ErrorState error={audit.error} onRetry={() => void audit.refetch()} />
          : !audit.data || audit.data.entries.length === 0 ? (
            <EmptyState title="No recorded activity for this incident">An entry is added each time it is investigated.</EmptyState>
          ) : (
            <Table>
              <thead><tr><Th>#</Th><Th>Time</Th><Th>Actor</Th><Th>Event</Th><Th>Details</Th></tr></thead>
              <tbody>
                {audit.data.entries.map((e) => (
                  <Tr key={e.sequence}>
                    <Td className="tabular text-muted">{e.sequence}</Td>
                    <Td className="whitespace-nowrap">{formatDateTime(e.timestamp)}</Td>
                    <Td>{e.actor}</Td>
                    <Td><Mono>{e.event_type}</Mono></Td>
                    <Td className="text-xs text-muted">{Object.entries(e.details).map(([k, v]) => `${k}: ${v}`).join(" · ")}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          )}
      </Card>
    </div>
  );
}
