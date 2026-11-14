// Administrators connect organisational databases (PostgreSQL or MySQL), map their columns, and
// control synchronisation and AI permission. Every rule is enforced by the server; this page
// collects input and shows results. Passwords are sent once and never shown again.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Database, ShieldAlert } from "lucide-react";
import { useMemo, useState, type FormEvent, type ReactNode } from "react";

import { PageHeader } from "@/components/layout/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/form";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/ui/states";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import {
  api, type AdminOrgSource, type ConnectionReport, type DbColumn, type FieldMapping, type MappedField,
  type Engine, type Mapping, type MappingPreview, type PgConnection, type SslMode, type TableName, type TimestampFormat,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatDateTime } from "@/lib/utils";

const FIELDS: { key: MappedField; label: string; required: boolean; hint: string }[] = [
  { key: "src_user", label: "User (who signed in)", required: true, hint: "e.g. alice@CORP" },
  { key: "src_host", label: "Source host (from)", required: true, hint: "client computer" },
  { key: "dst_host", label: "Destination host (to)", required: true, hint: "server signed in to" },
  { key: "orientation", label: "Event kind", required: true, hint: "LogOn, LogOff, TGS, TGT, AuthMap, ScreenLock, ScreenUnlock, ?" },
  { key: "outcome", label: "Outcome", required: true, hint: "Success or Fail" },
  { key: "dst_user", label: "Target account", required: false, hint: "optional" },
  { key: "auth_type", label: "Authentication type", required: false, hint: "optional, e.g. Kerberos" },
  { key: "logon_type", label: "Logon type", required: false, hint: "optional, e.g. Network" },
];
const ENUM_FIELDS: MappedField[] = ["orientation", "outcome"];
const CONSTANT = "__constant__";

function Field({ id, label, hint, children }: { id: string; label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="text-sm font-medium text-ink">{label}</label>
      {children}
      {hint && <p className="text-xs text-muted">{hint}</p>}
    </div>
  );
}

function Problem({ error }: { error: unknown }) {
  if (!error) return null;
  return <p role="alert" className="text-sm text-critical">{error instanceof Error ? error.message : "Request failed."}</p>;
}

function Warnings({ items }: { items: string[] }) {
  if (items.length === 0) return null;
  return (
    <ul className="space-y-1 rounded-md border border-warn/30 bg-warn-soft p-3 text-sm text-ink">
      {items.map((w) => <li key={w} className="flex gap-2"><AlertTriangle className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />{w}</li>)}
    </ul>
  );
}

function parseValueMap(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const at = line.indexOf("=");
    if (at > 0) out[line.slice(0, at).trim()] = line.slice(at + 1).trim();
  }
  return out;
}

const slug = (name: string) => name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 31);

const ENGINE_NAME: Record<Engine, string> = { postgresql: "PostgreSQL", mysql: "MySQL" };

interface FieldChoice { column: string; constant: string; confirmed: boolean; values: string }
const emptyChoice: FieldChoice = { column: "", constant: "", confirmed: false, values: "" };

function NewSourceWizard({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("");
  const [conn, setConn] = useState<PgConnection>({ engine: "postgresql", host: "", port: 5432, database: "", username: "", sslmode: "verify-full" });
  const engineName = ENGINE_NAME[conn.engine ?? "postgresql"];
  const [password, setPassword] = useState("");
  const [report, setReport] = useState<ConnectionReport | null>(null);
  const [tables, setTables] = useState<TableName[] | null>(null);
  const [table, setTable] = useState<TableName | null>(null);
  const [columns, setColumns] = useState<DbColumn[] | null>(null);
  const [recordId, setRecordId] = useState("");
  const [cursor, setCursor] = useState("");
  const [lookback, setLookback] = useState(0);
  const [interval, setIntervalSeconds] = useState(60);
  const [ts, setTs] = useState<{ column: string; format: TimestampFormat; zone: string }>({ column: "", format: "iso8601", zone: "" });
  const [choices, setChoices] = useState<Record<MappedField, FieldChoice>>(
    Object.fromEntries(FIELDS.map((f) => [f.key, { ...emptyChoice }])) as Record<MappedField, FieldChoice>);
  const [preview, setPreview] = useState<MappingPreview | null>(null);

  const request = { connection: conn, password };
  const reset = (from: "conn" | "table" | "mapping") => {
    if (from === "conn") { setReport(null); setTables(null); setTable(null); setColumns(null); }
    if (from === "table") setColumns(null);
    setPreview(null);
  };
  const test = useMutation({ mutationFn: () => api.testConnection(request), onSuccess: setReport });
  const loadTables = useMutation({ mutationFn: () => api.listTables(request), onSuccess: setTables });
  const loadColumns = useMutation({
    mutationFn: (t: TableName) => api.listColumns({ ...request, table: t }),
    onSuccess: setColumns,
  });

  const mapping = useMemo<Mapping>(() => {
    const fields: Mapping["fields"] = {};
    const confirmed: MappedField[] = [];
    for (const f of FIELDS) {
      const c = choices[f.key];
      if (c.column === CONSTANT) {
        fields[f.key] = { constant: c.constant };
        if (c.confirmed) confirmed.push(f.key);
      } else if (c.column) {
        const m: FieldMapping = { column: c.column };
        if (ENUM_FIELDS.includes(f.key) && c.values.trim()) m.values = parseValueMap(c.values);
        fields[f.key] = m;
      }
    }
    return { record_id: recordId, timestamp: { column: ts.column, format: ts.format, naive_timezone: ts.zone || null },
             fields, confirmed_constants: confirmed };
  }, [choices, recordId, ts]);

  const previewRun = useMutation({
    mutationFn: () => api.previewMapping({ ...request, table: table!, cursor_column: cursor, mapping }),
    onSuccess: setPreview,
  });
  const save = useMutation({
    mutationFn: () => api.createOrgSource({
      key: slug(name), name: name.trim(), password,
      config: { connection: conn, table: table!, cursor_column: cursor, lookback, sync_interval_seconds: interval, mapping },
    }),
    onSuccess: () => { setPassword(""); onDone(); },
  });

  const setChoice = (key: MappedField, patch: Partial<FieldChoice>) => {
    setChoices((all) => ({ ...all, [key]: { ...all[key], ...patch } }));
    setPreview(null);
  };
  const columnOptions = (columns ?? []).map((c) => <option key={c.name} value={c.name}>{c.name} ({c.data_type})</option>);
  const unconfirmed = FIELDS.filter((f) => choices[f.key].column === CONSTANT && !choices[f.key].confirmed);

  return (
    <Card>
      <CardHeader title={`Connect a ${engineName} database`} description="Read-only. Use an account that is granted SELECT on one table only." />
      <CardBody className="space-y-8">
        <form className="space-y-4" onSubmit={(e: FormEvent) => { e.preventDefault(); test.mutate(); }}>
          <h3 className="text-sm font-semibold text-ink">1. Connection</h3>
          <div className="grid gap-4 md:grid-cols-2">
            <Field id="ds-name" label="Name shown to analysts" hint={name ? `Key: ${slug(name) || "—"}` : undefined}>
              <Input id="ds-name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={80} className="w-full" />
            </Field>
            <Field id="ds-engine" label="Database type">
              <Select id="ds-engine" value={conn.engine ?? "postgresql"} onChange={(e) => {
                const engine = e.target.value as Engine;
                // Each engine's default port, and verify-full, which every engine supports.
                setConn({ ...conn, engine, port: engine === "mysql" ? 3306 : 5432, sslmode: "verify-full" });
                reset("conn");
              }} className="w-full">
                <option value="postgresql">PostgreSQL</option>
                <option value="mysql">MySQL</option>
              </Select>
            </Field>
            <Field id="ds-host" label="Host">
              <Input id="ds-host" value={conn.host} onChange={(e) => { setConn({ ...conn, host: e.target.value.trim() }); reset("conn"); }}
                required autoComplete="off" spellCheck={false} className="w-full" />
            </Field>
            <Field id="ds-port" label="Port">
              <Input id="ds-port" type="number" min={1} max={65535} value={conn.port}
                onChange={(e) => { setConn({ ...conn, port: Number(e.target.value) }); reset("conn"); }} className="w-full" />
            </Field>
            <Field id="ds-db" label="Database">
              <Input id="ds-db" value={conn.database} onChange={(e) => { setConn({ ...conn, database: e.target.value.trim() }); reset("conn"); }}
                required autoComplete="off" spellCheck={false} className="w-full" />
            </Field>
            <Field id="ds-user" label="Account">
              <Input id="ds-user" value={conn.username} onChange={(e) => { setConn({ ...conn, username: e.target.value.trim() }); reset("conn"); }}
                required autoComplete="off" spellCheck={false} className="w-full" />
            </Field>
            <Field id="ds-password" label="Password" hint="Stored encrypted. It is never shown again.">
              <Input id="ds-password" type="password" value={password} onChange={(e) => { setPassword(e.target.value); reset("conn"); }}
                required autoComplete="new-password" className="w-full" />
            </Field>
            <Field id="ds-tls" label="Encryption (TLS)">
              <Select id="ds-tls" value={conn.sslmode} onChange={(e) => { setConn({ ...conn, sslmode: e.target.value as SslMode }); reset("conn"); }} className="w-full">
                <option value="verify-full">Verify server certificate and name (recommended)</option>
                <option value="verify-ca">Verify server certificate</option>
                <option value="require">Encrypt, do not verify the server</option>
                {conn.engine !== "mysql" && <option value="prefer">Encrypt if possible (test networks only)</option>}
                <option value="disable">No encryption (test networks only)</option>
              </Select>
            </Field>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" variant="primary" disabled={test.isPending}>{test.isPending ? "Testing…" : "Test connection"}</Button>
            {report && <span className="inline-flex items-center gap-1.5 text-sm text-ok" role="status"><CheckCircle2 className="size-4" aria-hidden />
              Connected to {engineName} {report.server_version} as {report.account}{report.read_only_session ? ", read-only session" : ""}</span>}
          </div>
          <Problem error={test.error} />
          {report && <Warnings items={report.warnings} />}
        </form>

        {report && (
          <section className="space-y-4" aria-labelledby="step-table">
            <h3 id="step-table" className="text-sm font-semibold text-ink">2. Table</h3>
            {!tables ? <Button onClick={() => loadTables.mutate()} disabled={loadTables.isPending}>Show tables this account can read</Button> : (
              <Field id="ds-table" label="Table or view">
                <Select id="ds-table" value={table ? `${table.schema}.${table.name}` : ""} className="w-full md:w-96"
                  onChange={(e) => { const t = tables.find((x) => `${x.schema}.${x.name}` === e.target.value) ?? null; setTable(t); reset("table"); if (t) loadColumns.mutate(t); }}>
                  <option value="">Choose…</option>
                  {tables.map((t) => <option key={`${t.schema}.${t.name}`} value={`${t.schema}.${t.name}`}>{t.schema}.{t.name}</option>)}
                </Select>
              </Field>
            )}
            <Problem error={loadTables.error ?? loadColumns.error} />
          </section>
        )}

        {columns && (
          <section className="space-y-4" aria-labelledby="step-map">
            <h3 id="step-map" className="text-sm font-semibold text-ink">3. Map columns</h3>
            <p className="text-sm text-muted">Only the columns you map are read. Rows that do not fit are rejected with a reason; nothing is guessed.</p>
            <div className="grid gap-4 md:grid-cols-2">
              <Field id="map-id" label="Record identifier" hint="Unique per row, e.g. the primary key. Kept as the event ID.">
                <Select id="map-id" value={recordId} onChange={(e) => { setRecordId(e.target.value); setPreview(null); }} className="w-full">
                  <option value="">Choose…</option>{columnOptions}
                </Select>
              </Field>
              <Field id="map-cursor" label="Read new rows in order of" hint="A column that only grows for new rows: an ID sequence or an 'inserted at' time.">
                <Select id="map-cursor" value={cursor} onChange={(e) => { setCursor(e.target.value); setPreview(null); }} className="w-full">
                  <option value="">Choose…</option>{columnOptions}
                </Select>
              </Field>
              <Field id="map-ts" label="Event time">
                <Select id="map-ts" value={ts.column} onChange={(e) => { setTs({ ...ts, column: e.target.value }); setPreview(null); }} className="w-full">
                  <option value="">Choose…</option>{columnOptions}
                </Select>
              </Field>
              <Field id="map-ts-format" label="Time format" hint="Database date/time columns are read directly.">
                <Select id="map-ts-format" value={ts.format} onChange={(e) => { setTs({ ...ts, format: e.target.value as TimestampFormat }); setPreview(null); }} className="w-full">
                  <option value="iso8601">ISO 8601 text (2026-11-13T09:00:05Z)</option>
                  <option value="epoch_seconds">Seconds since 1970</option>
                  <option value="epoch_millis">Milliseconds since 1970</option>
                </Select>
              </Field>
              <Field id="map-zone" label="Time zone for times without one (optional)" hint="IANA name, e.g. Europe/London. Leave empty to reject such times.">
                <Input id="map-zone" value={ts.zone} onChange={(e) => { setTs({ ...ts, zone: e.target.value.trim() }); setPreview(null); }} className="w-full" />
              </Field>
              <Field id="map-lookback" label="Re-check for late rows (look-back)" hint="Seconds for a time column, IDs for a number column. 0 = off.">
                <Input id="map-lookback" type="number" min={0} max={86400} value={lookback} onChange={(e) => setLookback(Number(e.target.value))} className="w-full" />
              </Field>
            </div>

            <div className="space-y-3">
              {FIELDS.map((f) => {
                const c = choices[f.key];
                return (
                  <fieldset key={f.key} className="rounded-md border border-border p-3">
                    <legend className="px-1 text-sm font-medium text-ink">{f.label}{f.required ? "" : " (optional)"}</legend>
                    <div className="grid gap-3 md:grid-cols-2">
                      <div>
                        <label className="sr-only" htmlFor={`map-${f.key}`}>Column for {f.label}</label>
                        <Select id={`map-${f.key}`} value={c.column} onChange={(e) => setChoice(f.key, { column: e.target.value })} className="w-full">
                          <option value="">{f.required ? "Choose…" : "Not mapped"}</option>
                          {columnOptions}
                          {f.required && <option value={CONSTANT}>Not in this table: use one fixed value</option>}
                        </Select>
                        <p className="mt-1 text-xs text-muted">{f.hint}</p>
                      </div>
                      {c.column === CONSTANT ? (
                        <div className="space-y-2">
                          <label className="sr-only" htmlFor={`const-${f.key}`}>Fixed value for {f.label}</label>
                          <Input id={`const-${f.key}`} value={c.constant} placeholder="Fixed value" onChange={(e) => setChoice(f.key, { constant: e.target.value.trim(), confirmed: false })} className="w-full" />
                          <label className="flex items-start gap-2 text-sm text-ink">
                            <input type="checkbox" checked={c.confirmed} onChange={(e) => setChoice(f.key, { confirmed: e.target.checked })} className="mt-1" />
                            <span>I confirm every event from this source gets <strong>{c.constant || "this value"}</strong> for {f.label.toLowerCase()}. This is shown wherever the data appears.</span>
                          </label>
                        </div>
                      ) : c.column && ENUM_FIELDS.includes(f.key) ? (
                        <div>
                          <label className="text-xs font-medium text-ink" htmlFor={`values-${f.key}`}>Translate values (one per line: source value = AgentSOC value)</label>
                          <textarea id={`values-${f.key}`} value={c.values} onChange={(e) => setChoice(f.key, { values: e.target.value })} rows={3}
                            placeholder={f.key === "outcome" ? "true = Success\nfalse = Fail" : "login = LogOn\nlogout = LogOff"}
                            className="mt-1 w-full rounded-md border border-border bg-surface px-2 py-1 font-mono text-xs text-ink" />
                        </div>
                      ) : null}
                    </div>
                  </fieldset>
                );
              })}
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <Button variant="primary" onClick={() => previewRun.mutate()} disabled={previewRun.isPending || !recordId || !cursor || !ts.column || unconfirmed.length > 0}>
                {previewRun.isPending ? "Reading sample…" : "Preview first 50 rows"}
              </Button>
              {unconfirmed.length > 0 && <span className="text-sm text-warn">Confirm each fixed value first.</span>}
            </div>
            <Problem error={previewRun.error} />
          </section>
        )}

        {preview && (
          <section className="space-y-4" aria-labelledby="step-preview">
            <h3 id="step-preview" className="text-sm font-semibold text-ink">4. Check the result</h3>
            <p className="text-sm text-ink">{preview.rows_read} rows read: <strong>{preview.accepted.length} accepted</strong>, <strong>{preview.rejected.length} rejected</strong>. Nothing has been stored.</p>
            <Warnings items={preview.disclosures} />
            {preview.accepted.length > 0 && (
              <Table>
                <thead><tr><Th>Event</Th><Th>Time (UTC)</Th><Th>User</Th><Th>From → to</Th><Th>Kind</Th><Th>Outcome</Th></tr></thead>
                <tbody>{preview.accepted.slice(0, 10).map((e) => (
                  <Tr key={e.event_id}><Td className="font-mono text-xs">{e.event_id}</Td><Td className="whitespace-nowrap">{formatDateTime(e.time)}</Td>
                    <Td>{e.src_user}</Td><Td>{e.src_host} → {e.dst_host}</Td><Td>{e.orientation}</Td><Td>{e.outcome}</Td></Tr>
                ))}</tbody>
              </Table>
            )}
            {preview.rejected.length > 0 && (
              <Table>
                <thead><tr><Th>Row</Th><Th>Reason</Th><Th>Field</Th><Th>Detail</Th></tr></thead>
                <tbody>{preview.rejected.slice(0, 10).map((r) => (
                  <Tr key={r.row}><Td>{r.row}</Td><Td>{r.reason}</Td><Td>{r.field ?? "—"}</Td><Td>{r.detail}</Td></Tr>
                ))}</tbody>
              </Table>
            )}
            <div className="grid gap-4 md:grid-cols-2">
              <Field id="ds-interval" label="Check for new rows every (seconds)" hint="At least 30. This is polling, not real-time.">
                <Input id="ds-interval" type="number" min={30} max={86400} value={interval} onChange={(e) => setIntervalSeconds(Number(e.target.value))} className="w-full" />
              </Field>
            </div>
            <Button variant="primary" onClick={() => save.mutate()} disabled={save.isPending || !slug(name)}>Save data source</Button>
            <p className="text-xs text-muted">Saved with scheduled sync off and AI investigation off. Turn them on below.</p>
            <Problem error={save.error} />
          </section>
        )}
      </CardBody>
    </Card>
  );
}

function AiControl({ source, onChange }: { source: AdminOrgSource; onChange: () => void }) {
  const [asking, setAsking] = useState(false);
  const [understood, setUnderstood] = useState(false);
  const update = useMutation({
    mutationFn: (enable: boolean) => api.updateOrgSource(source.key, { ai_enabled: enable, ai_risk_acknowledged: enable && understood }),
    onSuccess: () => { setAsking(false); setUnderstood(false); onChange(); },
  });
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm text-ink">AI investigation:</span>
        {source.ai_enabled ? <Badge tone="warn">Allowed</Badge> : <Badge tone="neutral">Off</Badge>}
        {source.ai_changed_by && <span className="text-xs text-muted">changed by {source.ai_changed_by}, {formatDateTime(source.ai_changed_at!)}</span>}
        {source.ai_enabled
          ? <Button size="sm" onClick={() => update.mutate(false)} disabled={update.isPending}>Turn off</Button>
          : <Button size="sm" onClick={() => setAsking(!asking)} aria-expanded={asking}>Allow…</Button>}
      </div>
      {asking && (
        <div className="space-y-2 rounded-md border border-warn/30 bg-warn-soft p-3">
          <p className="flex gap-2 text-sm text-ink"><ShieldAlert className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />{source.ai_warning}</p>
          <label className="flex items-start gap-2 text-sm text-ink">
            <input type="checkbox" checked={understood} onChange={(e) => setUnderstood(e.target.checked)} className="mt-1" />
            <span>I understand, and my organisation permits sending this data to that provider.</span>
          </label>
          <Button size="sm" variant="primary" disabled={!understood || update.isPending} onClick={() => update.mutate(true)}>Allow AI investigation</Button>
        </div>
      )}
      <Problem error={update.error} />
    </div>
  );
}

function SourceCard({ source }: { source: AdminOrgSource }) {
  const client = useQueryClient();
  const refresh = () => {
    void client.invalidateQueries({ queryKey: ["admin", "datasources"] });
    void client.invalidateQueries({ queryKey: ["sources"] });
    void client.invalidateQueries({ queryKey: ["datasets"] });
  };
  const sync = useMutation({ mutationFn: () => api.syncOrgSource(source.key), onSettled: refresh });
  const snapshot = useMutation({ mutationFn: () => api.snapshotOrgSource(source.key), onSettled: refresh });
  const schedule = useMutation({ mutationFn: (on: boolean) => api.updateOrgSource(source.key, { sync_enabled: on }), onSuccess: refresh });
  const remove = useMutation({ mutationFn: () => api.deleteOrgSource(source.key), onSuccess: refresh });
  const [newPassword, setNewPassword] = useState("");
  const password = useMutation({ mutationFn: () => api.setOrgSourcePassword(source.key, newPassword), onSuccess: () => { setNewPassword(""); refresh(); } });
  const [confirmDelete, setConfirmDelete] = useState(false);
  const run = source.last_run;
  return (
    <Card>
      <CardHeader title={<span className="flex flex-wrap items-center gap-2"><Database className="size-4 text-muted" aria-hidden />{source.name}
          {source.sync_enabled ? <Badge tone="ok">Scheduled sync on</Badge> : <Badge tone="neutral">Scheduled sync off</Badge>}</span>}
        description={`${source.connection.username}@${source.connection.host}:${source.connection.port}/${source.connection.database} · ${source.table.schema}.${source.table.name}`} />
      <CardBody className="space-y-4">
        <p className="text-sm text-muted">{source.mode}</p>
        <Warnings items={[...source.connection_warnings, ...source.disclosures]} />
        <dl className="grid gap-x-8 gap-y-1 text-sm md:grid-cols-2">
          <div className="flex justify-between gap-4"><dt className="text-muted">Stored events</dt><dd className="tabular">{source.stats.accepted.toLocaleString()}</dd></div>
          <div className="flex justify-between gap-4"><dt className="text-muted">Rejected rows</dt><dd className="tabular">{source.stats.rejected.toLocaleString()}</dd></div>
          <div className="flex justify-between gap-4"><dt className="text-muted">Rows changed at the source</dt><dd className="tabular">{source.stats.changed.toLocaleString()}</dd></div>
          <div className="flex justify-between gap-4"><dt className="text-muted">Newest event</dt><dd>{source.stats.last_event ? formatDateTime(source.stats.last_event) : "—"}</dd></div>
          <div className="flex justify-between gap-4"><dt className="text-muted">Last sync</dt><dd>{run ? `${run.status}, ${run.new} new, ${formatDateTime(run.finished_at ?? run.started_at)}` : "never"}</dd></div>
          <div className="flex justify-between gap-4"><dt className="text-muted">Snapshot in dashboard</dt><dd>{source.snapshot ? `${source.snapshot.event_count.toLocaleString()} events, ${source.snapshot.incident_count} incidents, ${formatDateTime(source.snapshot.created_at)}` : "none yet"}</dd></div>
        </dl>
        {Object.keys(source.stats.rejected_by_reason).length > 0 && (
          <p className="text-xs text-muted">Rejected by reason: {Object.entries(source.stats.rejected_by_reason).map(([r, n]) => `${r} ${n}`).join(" · ")}</p>
        )}
        {run?.error && <p role="alert" className="text-sm text-critical">Last sync failed: {run.error}</p>}
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="primary" onClick={() => sync.mutate()} disabled={sync.isPending}>{sync.isPending ? "Syncing…" : "Sync now"}</Button>
          <Button size="sm" onClick={() => snapshot.mutate()} disabled={snapshot.isPending || source.stats.accepted === 0}>{snapshot.isPending ? "Analysing…" : "Update dashboard snapshot"}</Button>
          <Button size="sm" onClick={() => schedule.mutate(!source.sync_enabled)} disabled={schedule.isPending}>{source.sync_enabled ? "Stop scheduled sync" : "Start scheduled sync"}</Button>
        </div>
        <Problem error={sync.error ?? snapshot.error ?? schedule.error} />
        <AiControl source={source} onChange={refresh} />
        <details className="text-sm">
          <summary className="cursor-pointer text-muted">More: password, delete, recent runs</summary>
          <div className="mt-3 space-y-4">
            <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => { e.preventDefault(); password.mutate(); }}>
              <Field id={`pw-${source.key}`} label="New database password">
                <Input id={`pw-${source.key}`} type="password" autoComplete="new-password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required className="w-64" />
              </Field>
              <Button size="sm" type="submit" disabled={password.isPending}>Replace password</Button>
              <Problem error={password.error} />
            </form>
            {source.runs.length > 0 && (
              <Table>
                <thead><tr><Th>Run</Th><Th>Trigger</Th><Th>Finished</Th><Th>Status</Th><Th>Read</Th><Th>New</Th><Th>Already stored</Th><Th>Rejected</Th></tr></thead>
                <tbody>{source.runs.map((r) => (
                  <Tr key={r.id}><Td>{r.id}</Td><Td>{r.trigger}</Td><Td className="whitespace-nowrap">{r.finished_at ? formatDateTime(r.finished_at) : "—"}</Td>
                    <Td>{r.status}</Td><Td className="tabular">{r.fetched}</Td><Td className="tabular">{r.new}</Td><Td className="tabular">{r.duplicates}</Td><Td className="tabular">{r.rejected}</Td></Tr>
                ))}</tbody>
              </Table>
            )}
            {!confirmDelete ? <Button size="sm" onClick={() => setConfirmDelete(true)}>Delete data source…</Button> : (
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm text-ink">Removes the connection and its password. Stored data stays on disk but is no longer shown.</span>
                <Button size="sm" variant="primary" onClick={() => remove.mutate()} disabled={remove.isPending}>Delete</Button>
                <Button size="sm" onClick={() => setConfirmDelete(false)}>Cancel</Button>
              </div>
            )}
            <Problem error={remove.error} />
          </div>
        </details>
      </CardBody>
    </Card>
  );
}

export function ConnectionsPage() {
  const { session } = useAuth();
  const client = useQueryClient();
  const isAdmin = session?.user.role === "admin";
  const sources = useQuery({ queryKey: ["admin", "datasources"], queryFn: api.adminOrgSources, enabled: isAdmin });
  const [adding, setAdding] = useState(false);
  if (!isAdmin) return <ErrorState error={new Error("Administrator access is required.")} />;
  return (
    <>
      <PageHeader title="Database connections" description="Connect an organisation's authentication data. Read-only, checked for new rows on a schedule, analysed in snapshots." />
      <div className="mb-6 space-y-4">
        {sources.isLoading ? <LoadingBlock label="Loading data sources…" />
          : sources.error ? <ErrorState error={sources.error} onRetry={() => void sources.refetch()} />
          : sources.data!.length === 0 ? <EmptyState title="No databases connected" icon={<Database className="size-5" aria-hidden />}>Add one below.</EmptyState>
          : sources.data!.map((s) => <SourceCard key={s.key} source={s} />)}
      </div>
      {adding
        ? <NewSourceWizard onDone={() => { setAdding(false); void client.invalidateQueries({ queryKey: ["admin", "datasources"] }); }} />
        : <Button variant="primary" onClick={() => setAdding(true)}>Connect a database</Button>}
    </>
  );
}
