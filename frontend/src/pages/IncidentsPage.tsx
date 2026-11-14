import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Search, X } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";

import { InvestigationBadge, RiskBadge, SeverityBadge } from "@/components/domain";
import { ReviewBadge, STATUS_TEXT } from "@/components/review";
import { PageHeader } from "@/components/layout/app-shell";
import { useSource } from "@/components/layout/source-context";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/form";
import { Pagination } from "@/components/ui/pagination";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/ui/states";
import { SortableTh, Table, Td, Th, Tr } from "@/components/ui/table";
import { api, type ReviewStatus, type Severity } from "@/lib/api";
import { cn, SEVERITIES, titleCase } from "@/lib/utils";

const PAGE_SIZE = 20;
type SortKey = "severity" | "incident_id" | "user" | "first_seen" | "last_seen" | "findings";

function useDebounced<T>(value: T, ms = 250) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return debounced;
}

export function IncidentsPage() {
  const { source } = useSource();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [text, setText] = useState(params.get("q") ?? "");
  const q = useDebounced(text);
  const severities = params.getAll("severity") as Severity[];
  const provenance = params.get("provenance") ?? "";
  const sort = (params.get("sort") ?? "severity") as SortKey;
  const order = (params.get("order") ?? "asc") as "asc" | "desc";
  const page = Number(params.get("page") ?? "1") || 1;
  const review = (params.get("review") ?? "") as ReviewStatus | "";

  const update = (patch: Record<string, string | string[] | null>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      next.delete(k);
      if (Array.isArray(v)) v.forEach((x) => next.append(k, x));
      else if (v) next.set(k, v);
    }
    if (!("page" in patch)) next.delete("page");
    setParams(next, { replace: true });
  };

  useEffect(() => { if (q !== (params.get("q") ?? "")) update({ q: q || null }); },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [q]);

  const key = source!.key;
  const query = useQuery({
    queryKey: ["incidents", key, q, severities, provenance, review, sort, order, page],
    queryFn: () => api.incidents(key, { q, severity: severities, provenance: provenance || null,
                                        review: review || null, sort, order, page, page_size: PAGE_SIZE }),
    placeholderData: keepPreviousData,
  });
  const overview = useQuery({ queryKey: ["overview", key], queryFn: () => api.overview(key) });
  const counts = overview.data?.review_counts ?? {};
  const total = overview.data?.incidents_total;

  const toggleSeverity = (s: Severity) =>
    update({ severity: severities.includes(s) ? severities.filter((x) => x !== s) : [...severities, s] });
  const sortBy = (k: SortKey) =>
    update({ sort: k, order: sort === k && order === "asc" ? "desc" : "asc" });
  const filtered = q || severities.length > 0 || provenance;

  return (
    <>
      <PageHeader title="Incidents" description="Your review queue. Each incident is suspicious activity, not confirmed compromise, until an analyst decides." />
      <div role="group" aria-label="Filter by decision" className="mb-4 flex flex-wrap gap-1 border-b border-border">
        {([["", "All", total], ["open", STATUS_TEXT.open, counts.open], ["more_evidence", STATUS_TEXT.more_evidence, counts.more_evidence],
           ["accepted", STATUS_TEXT.accepted, counts.accepted], ["dismissed", STATUS_TEXT.dismissed, counts.dismissed]] as const).map(([value, label, n]) => (
          <button key={value || "all"} type="button" aria-pressed={review === value} onClick={() => update({ review: value || null })}
            className={cn("-mb-px border-b-2 px-3 py-2 text-sm font-medium transition-colors",
              review === value ? "border-brand text-brand" : "border-transparent text-muted hover:text-ink")}>
            {label}{n !== undefined && <span className="ml-1.5 rounded-full bg-subtle px-1.5 text-xs tabular text-ink-2">{n}</span>}
          </button>
        ))}
      </div>
      <Card>
        <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
          <div className="relative min-w-56 flex-1 sm:max-w-sm">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-faint" aria-hidden />
            <label htmlFor="incident-search" className="sr-only">Search incidents</label>
            <Input id="incident-search" value={text} onChange={(e) => setText(e.target.value)}
              placeholder="Search incident ID, user or host" className="w-full pl-9" />
          </div>
          <div className="flex items-center gap-1" role="group" aria-label="Filter by severity">
            {SEVERITIES.map((s) => (
              <button key={s} type="button" onClick={() => toggleSeverity(s)} aria-pressed={severities.includes(s)}
                className={cn("h-8 rounded-md border px-2.5 text-xs font-medium transition-colors",
                  severities.includes(s) ? "border-brand bg-brand-soft text-brand" : "border-border bg-surface text-ink-2 hover:bg-subtle")}>
                {titleCase(s)}
              </button>
            ))}
          </div>
          <label htmlFor="prov-filter" className="sr-only">Filter by provenance</label>
          <Select id="prov-filter" value={provenance} onChange={(e) => update({ provenance: e.target.value || null })} className="h-8 text-xs">
            <option value="">All provenance</option>
            <option value="synthetic">Synthetic</option>
            <option value="lanl">LANL (real)</option>
          </Select>
          {filtered && (
            <Button size="sm" variant="ghost" onClick={() => { setText(""); update({ q: null, severity: [], provenance: null }); }}>
              <X aria-hidden />Clear filters
            </Button>
          )}
        </div>

        {query.isLoading ? <LoadingBlock label="Loading incidents…" />
          : query.error ? <ErrorState error={query.error} onRetry={() => void query.refetch()} />
          : query.data && query.data.total === 0 ? (
            <EmptyState title={filtered ? "No incidents match these filters" : "No incidents in this data source"}>
              {filtered ? "Adjust the search or filters." : "Detection produced no incidents for this dataset."}
            </EmptyState>
          ) : query.data && (
            <>
              <Table aria-busy={query.isFetching}>
                <thead>
                  <tr>
                    <SortableTh label="Incident" active={sort === "incident_id"} order={order} onSort={() => sortBy("incident_id")} />
                    <SortableTh label="User" active={sort === "user"} order={order} onSort={() => sortBy("user")} />
                    <SortableTh label="Severity" active={sort === "severity"} order={order} onSort={() => sortBy("severity")} />
                    <Th>Risk</Th>
                    <SortableTh label="Findings" active={sort === "findings"} order={order} onSort={() => sortBy("findings")} />
                    <Th>Affected hosts</Th>
                    <SortableTh label="Last observed" active={sort === "last_seen"} order={order} onSort={() => sortBy("last_seen")} />
                    <Th>Decision</Th>
                    <Th>Investigation</Th>
                  </tr>
                </thead>
                <tbody className={cn(query.isFetching && "opacity-60")}>
                  {query.data.items.map((i) => (
                    <Tr key={i.incident_id} className="cursor-pointer" onClick={() => navigate(`/incidents/${i.incident_id}`)}>
                      <Td>
                        <Link to={`/incidents/${i.incident_id}`} onClick={(e) => e.stopPropagation()} className="font-mono text-[12.5px] font-medium text-brand hover:underline">
                          {i.incident_id}
                        </Link>
                      </Td>
                      <Td className="font-medium text-ink">{i.principal_user}</Td>
                      <Td><SeverityBadge severity={i.severity} /></Td>
                      <Td><RiskBadge band={i.risk_band} score={i.risk_score} /></Td>
                      <Td className="tabular" title={i.rule_ids.join(", ")}>{i.finding_count} <span className="text-faint">· {i.rule_ids.length} rules</span></Td>
                      <Td className="max-w-44 truncate" title={i.involved_hosts.join(", ")}>
                        {i.involved_hosts.slice(0, 2).join(", ")}{i.involved_hosts.length > 2 && <span className="text-faint"> +{i.involved_hosts.length - 2}</span>}
                      </Td>
                      <Td className="tabular whitespace-nowrap text-muted" title={`First observed ${i.first_seen_label}`}>{i.last_seen_label}</Td>
                      <Td><ReviewBadge status={i.review_status} /></Td>
                      <Td><InvestigationBadge status={i.investigation_status} /></Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
              <Pagination page={page} pageSize={PAGE_SIZE} total={query.data.total} noun="incidents"
                onPage={(p) => update({ page: String(p) })} />
            </>
          )}
      </Card>
    </>
  );
}
