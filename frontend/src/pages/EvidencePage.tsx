import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Fragment, useEffect, useState } from "react";

import { ProvenanceBadge } from "@/components/domain";
import { PageHeader } from "@/components/layout/app-shell";
import { useSource } from "@/components/layout/source-context";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/form";
import { Pagination } from "@/components/ui/pagination";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { EventDetails } from "./IncidentDetailPage";

const PAGE_SIZE = 25;

function useDebounced(value: string, ms = 250) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => { const id = setTimeout(() => setDebounced(value), ms); return () => clearTimeout(id); }, [value, ms]);
  return debounced;
}

export function EvidencePage() {
  const { source, sources, setSource } = useSource();
  const [scope, setScope] = useState<"evidence" | "all">("evidence");
  const [eventText, setEventText] = useState("");
  const [userText, setUserText] = useState("");
  const [hostText, setHostText] = useState("");
  const [outcome, setOutcome] = useState("");
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState<string | null>(null);
  const q = useDebounced(eventText), user = useDebounced(userText), host = useDebounced(hostText);
  const key = source!.key;
  useEffect(() => setPage(1), [key, scope, q, user, host, outcome]);

  const query = useQuery({
    queryKey: ["events", key, scope, q, user, host, outcome, page],
    queryFn: () => api.events(key, { scope, q, user, host, outcome: outcome || null, page, page_size: PAGE_SIZE }),
    placeholderData: keepPreviousData, retry: false,
  });

  const synthetic = sources.filter((s) => s.provenance === "synthetic");
  const real = sources.filter((s) => s.provenance !== "synthetic");

  return (
    <>
      <PageHeader title="Evidence Explorer" description="Normalised authentication events from verified datasets. Records are shown exactly as ingested; nothing is generated." />
      <Card>
        <div className="grid gap-3 border-b border-border px-4 py-3 sm:grid-cols-2 lg:grid-cols-6">
          <div className="lg:col-span-2">
            <label htmlFor="ev-source" className="mb-1 block text-xs font-medium text-muted">Dataset</label>
            <Select id="ev-source" value={key} onChange={(e) => setSource(e.target.value)} className="w-full">
              <optgroup label="Synthetic demonstration data">
                {synthetic.map((s) => <option key={s.key} value={s.key}>{s.label}</option>)}
              </optgroup>
              {real.length > 0 && (
                <optgroup label="Real LANL 2015 data">
                  {real.map((s) => <option key={s.key} value={s.key}>{s.label}</option>)}
                </optgroup>
              )}
            </Select>
          </div>
          <div>
            <label htmlFor="ev-scope" className="mb-1 block text-xs font-medium text-muted">Scope</label>
            <Select id="ev-scope" value={scope} onChange={(e) => setScope(e.target.value as "evidence" | "all")} className="w-full">
              <option value="evidence">Incident evidence</option>
              <option value="all">All events</option>
            </Select>
          </div>
          <div>
            <label htmlFor="ev-id" className="mb-1 block text-xs font-medium text-muted">Event ID</label>
            <Input id="ev-id" value={eventText} onChange={(e) => setEventText(e.target.value)} placeholder="e.g. 116" className="w-full" />
          </div>
          <div>
            <label htmlFor="ev-user" className="mb-1 block text-xs font-medium text-muted">User</label>
            <Input id="ev-user" value={userText} onChange={(e) => setUserText(e.target.value)} placeholder="Username" className="w-full" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label htmlFor="ev-host" className="mb-1 block text-xs font-medium text-muted">Host</label>
              <Input id="ev-host" value={hostText} onChange={(e) => setHostText(e.target.value)} placeholder="Host" className="w-full" />
            </div>
            <div>
              <label htmlFor="ev-outcome" className="mb-1 block text-xs font-medium text-muted">Result</label>
              <Select id="ev-outcome" value={outcome} onChange={(e) => setOutcome(e.target.value)} className="w-full">
                <option value="">Any</option><option value="Success">Success</option><option value="Fail">Fail</option>
              </Select>
            </div>
          </div>
        </div>

        {query.isLoading ? <LoadingBlock label="Loading events…" />
          : query.error ? <ErrorState error={query.error} onRetry={() => void query.refetch()} />
          : query.data && query.data.total === 0 ? (
            <EmptyState title="No events match">Adjust the search, the result filter or the scope.</EmptyState>
          ) : query.data && (
            <>
              <Table>
                <thead><tr><Th>Event</Th><Th>Time</Th><Th>Source user</Th><Th>Source → destination</Th><Th>Orientation</Th><Th>Result</Th><Th>Cited by</Th><Th>Provenance</Th></tr></thead>
                <tbody className={cn(query.isFetching && "opacity-60")}>
                  {query.data.items.map((e) => (
                    <Fragment key={e.event_id}>
                      <Tr className="cursor-pointer" onClick={() => setOpen(open === e.event_id ? null : e.event_id)}>
                        <Td><button type="button" aria-expanded={open === e.event_id} className="font-mono text-[12.5px] text-brand hover:underline">{e.event_id}</button></Td>
                        <Td className="tabular whitespace-nowrap text-muted">{e.time_label}</Td>
                        <Td>{e.src_user}</Td>
                        <Td className="font-mono text-[12.5px] whitespace-nowrap">{e.src_host} → {e.dst_host}</Td>
                        <Td>{e.orientation}</Td>
                        <Td><Badge tone={e.outcome === "Fail" ? "critical" : "ok"}>{e.outcome}</Badge></Td>
                        <Td>{e.cited_by.length ? <span className="text-xs text-ink-2">{e.cited_by.length} rule(s)</span> : <span className="text-xs text-faint">—</span>}</Td>
                        <Td><ProvenanceBadge provenance={e.provenance} /></Td>
                      </Tr>
                      {open === e.event_id && (
                        <tr><td colSpan={8} className="border-b border-border bg-subtle px-5 py-4"><EventDetails e={e} /></td></tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </Table>
              <Pagination page={page} pageSize={PAGE_SIZE} total={query.data.total} noun="events" onPage={setPage} />
            </>
          )}
      </Card>
    </>
  );
}
