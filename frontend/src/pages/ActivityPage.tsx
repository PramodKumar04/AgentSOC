import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, ShieldX } from "lucide-react";

import { PageHeader } from "@/components/layout/app-shell";
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/utils";

const EVENT_LABELS: Record<string, { label: string; tone: "ok" | "warn" | "neutral" | "critical" }> = {
  "investigation.completed": { label: "Investigation completed", tone: "ok" },
  "investigation.completed_limited": { label: "Investigation completed (limited)", tone: "warn" },
  "investigation.failed": { label: "Investigation failed", tone: "critical" },
  "dataset.verified": { label: "Dataset verified", tone: "neutral" },
};

function detailText(details: Record<string, unknown>) {
  const parts: string[] = [];
  if (details.source) parts.push(`source ${details.source}`);
  if (details.incidents !== undefined) parts.push(`${details.incidents} incidents`);
  if (typeof details.latency_ms === "number") parts.push(`${(details.latency_ms / 1000).toFixed(1)} s`);
  if (details.rerun === true) parts.push("re-run");
  return parts.join(" · ");
}

export function ActivityPage() {
  const query = useQuery({ queryKey: ["activity"], queryFn: () => api.activity(200), refetchInterval: 15_000 });
  return (
    <>
      <PageHeader title="System activity" description="Server-side record of dataset verification and investigations. Entries are hash-chained so edits or deletions are detectable." />
      <Card>
        <CardHeader
          title="Activity log"
          description={query.data ? `${query.data.total.toLocaleString()} entries` : undefined}
          action={query.data && (query.data.chain_intact
            ? <Badge tone="ok"><CheckCircle2 className="size-3" aria-hidden />Integrity chain intact</Badge>
            : <Badge tone="critical"><ShieldX className="size-3" aria-hidden />Integrity chain broken</Badge>)}
        />
        {query.isLoading ? <LoadingBlock label="Loading activity…" />
          : query.error ? <ErrorState error={query.error} onRetry={() => void query.refetch()} />
          : !query.data?.entries.length ? <EmptyState title="No activity recorded yet" />
          : (
            <Table>
              <thead><tr><Th>#</Th><Th>Time</Th><Th>Event</Th><Th>Subject</Th><Th>Details</Th><Th>Actor</Th></tr></thead>
              <tbody>
                {query.data.entries.map((e) => {
                  const meta = EVENT_LABELS[e.event_type] ?? { label: e.event_type, tone: "neutral" as const };
                  return (
                    <Tr key={e.sequence}>
                      <Td className="tabular text-faint">{e.sequence}</Td>
                      <Td className="whitespace-nowrap text-muted">{formatDateTime(e.timestamp)}</Td>
                      <Td><Badge tone={meta.tone}>{meta.label}</Badge></Td>
                      <Td className="font-mono text-[12.5px] text-ink">{e.subject_id}</Td>
                      <Td className="text-xs text-muted">{detailText(e.details)}</Td>
                      <Td className="text-xs text-muted">{e.actor}</Td>
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
