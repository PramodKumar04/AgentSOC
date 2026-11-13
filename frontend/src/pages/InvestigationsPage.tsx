import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, BrainCircuit } from "lucide-react";
import { useEffect } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";

import { ConfidenceBar, InvestigationBadge, ProvenanceBadge, SeverityBadge } from "@/components/domain";
import { InvestigationResultView } from "@/components/investigation";
import { PageHeader } from "@/components/layout/app-shell";
import { useSource } from "@/components/layout/source-context";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/utils";

export function InvestigationsPage() {
  const navigate = useNavigate();
  const query = useQuery({ queryKey: ["investigations"], queryFn: api.investigations });
  const open = (sourceKey: string, id: string) =>
    navigate(`/investigations/${encodeURIComponent(id)}?source=${encodeURIComponent(sourceKey)}`);

  return (
    <>
      <PageHeader title="Investigations" description="Saved investigation results across all data sources. Each result is bound to the exact incident content it analysed." />
      <Card>
        {query.isLoading ? <LoadingBlock label="Loading investigations…" />
          : query.error ? <ErrorState error={query.error} onRetry={() => void query.refetch()} />
          : !query.data?.length ? (
            <EmptyState title="No investigations yet" icon={<BrainCircuit className="size-6 text-faint" aria-hidden />}>
              Open an incident and select <strong className="text-ink-2">Investigate Incident</strong>.
            </EmptyState>
          ) : (
            <Table>
              <thead><tr><Th>Investigation</Th><Th>Incident</Th><Th>Conclusion</Th><Th>Confidence</Th><Th>Source</Th><Th>Completed</Th><Th>Status</Th></tr></thead>
              <tbody>
                {query.data.map((s) => {
                  const stale = s.status === "stale";
                  return (
                    <Tr key={`${s.source_key}/${s.investigation_id}`} className={stale ? "" : "cursor-pointer"}
                      onClick={() => !stale && open(s.source_key, s.investigation_id)}>
                      <Td className="font-mono text-[12px] text-muted">
                        {stale ? s.investigation_id : (
                          <Link to={`/investigations/${encodeURIComponent(s.investigation_id)}?source=${encodeURIComponent(s.source_key)}`}
                            onClick={(e) => e.stopPropagation()} className="text-brand hover:underline">{s.investigation_id}</Link>
                        )}
                      </Td>
                      <Td>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[12.5px] text-ink">{s.incident_id}</span>
                          {s.severity && <SeverityBadge severity={s.severity} />}
                        </div>
                        {s.principal_user && <div className="text-xs text-muted">{s.principal_user}</div>}
                      </Td>
                      <Td className="max-w-80">
                        <Badge tone={s.conclusion_kind === "MALICIOUS" ? "critical" : "ok"} className="mr-2">
                          {s.conclusion_kind === "MALICIOUS" ? "Malicious" : "Benign"}
                        </Badge>
                        <span className="text-ink">{s.conclusion}</span>
                      </Td>
                      <Td className="w-40"><ConfidenceBar value={s.confidence} /></Td>
                      <Td><ProvenanceBadge provenance={s.provenance} /></Td>
                      <Td className="whitespace-nowrap text-muted">{formatDateTime(s.created_at)}</Td>
                      <Td><InvestigationBadge status={s.status} /></Td>
                    </Tr>
                  );
                })}
              </tbody>
            </Table>
          )}
      </Card>
    </>
  );
}

export function InvestigationDetailPage() {
  const { investigationId = "" } = useParams();
  const [params] = useSearchParams();
  const { source, setSource } = useSource();
  const key = params.get("source") ?? source!.key;
  useEffect(() => { if (key !== source?.key) setSource(key); }, [key, source?.key, setSource]);
  const query = useQuery({
    queryKey: ["investigation-by-id", key, investigationId],
    queryFn: () => api.investigation(key, investigationId),
  });

  return (
    <>
      <Link to="/investigations" className="mb-3 inline-flex items-center gap-1 text-xs font-medium text-muted hover:text-ink">
        <ArrowLeft className="size-3.5" aria-hidden />All investigations
      </Link>
      {query.isLoading ? <LoadingBlock label="Loading investigation…" />
        : query.error || !query.data ? <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        : (
          <>
            <PageHeader
              title={`Investigation of ${query.data.incident_id}`}
              description={<Link to={`/incidents/${query.data.incident_id}?source=${encodeURIComponent(key)}`} className="text-brand hover:underline">Open incident {query.data.incident_id}</Link>}
            />
            <InvestigationResultView result={query.data} />
          </>
        )}
    </>
  );
}
