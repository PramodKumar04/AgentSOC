// Typed client for the AgentSOC REST API (src/agentsoc/api). The UI holds no security
// logic: every number and record shown comes from these endpoints.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type Provenance = "synthetic" | "lanl" | "upload" | "organization";
export type InvestigationStatus = "none" | "completed" | "completed_limited" | "stale";

export interface Page<T> { items: T[]; total: number; page: number; page_size: number }
export interface SourceRef { key: string; label: string; provenance: Provenance; is_default: boolean }
export interface Health { status: "ok"; version: string; analysis: "available" | "limited"; sources: number }

export type AssessmentState = "available" | "not_assessed" | "stale" | "unavailable";
export interface AssessmentStatus { state: AssessmentState; detail: string }
export interface IncidentAssessments {
  structural: AssessmentStatus; risk: AssessmentStatus; truncated: boolean; truncation_reasons: string[];
}

export interface IncidentSummary {
  incident_id: string; source_key: string; principal_user: string; severity: Severity;
  rule_ids: string[]; finding_count: number; involved_hosts: string[];
  first_seen: string; last_seen: string; first_seen_label: string; last_seen_label: string;
  provenance: Provenance[]; evidence_count: number; investigation_status: InvestigationStatus;
  risk_score?: number | null; risk_band?: Severity | null;
  review_status?: ReviewStatus;
}

export interface EventView {
  event_id: string; timestamp: string; time_label: string; src_user: string;
  dst_user: string | null; src_host: string; dst_host: string; auth_type: string | null;
  logon_type: string | null; orientation: string; outcome: "Success" | "Fail";
  provenance: Provenance; raw_file: string; raw_line: number; cited_by: string[];
}

export interface FindingView {
  finding_id: string; rule_id: string; rule_title: string; severity: Severity;
  description: string; metrics: Record<string, boolean | number | string>;
  event_ids: string[]; first_seen_label: string; last_seen_label: string;
}

export interface IncidentDetail extends IncidentSummary {
  description: string; involved_users: string[]; findings: FindingView[];
  severity_rationale: string; shared_evidence: { event_id: string; rule_ids: string[] }[];
  benign_explanations: string[]; limitations: string[]; missing_information: string[];
  timeline: EventView[]; missing_evidence_ids: string[]; assessments?: IncidentAssessments;
}

export interface Overview {
  source: SourceRef;
  dataset: { label: string; provenance: Provenance; event_count: number };
  incidents_total: number; severity_counts: Record<Severity, number>;
  findings_total: number; investigations_completed: number;
  rule_activity: { rule_id: string; title: string; findings: number }[];
  activity: { label: string; count: number }[];
  recent_incidents: IncidentSummary[];
  risk_status?: AssessmentStatus; risk_counts?: Record<Severity, number> | null; risk_assessed?: number;
  review_counts?: Partial<Record<ReviewStatus, number>>;
}

// Human in the loop: the analyst's decision on an incident.
export type ReviewStatus = "open" | "accepted" | "dismissed" | "more_evidence";
export type ReviewDecision = "accepted" | "dismissed" | "more_evidence" | "reopened";
export type DismissReason = "expected_activity" | "false_positive" | "duplicate" | "authorised_test" | "other";
export type ContextWindow = 1 | 6 | 24 | 72;
export interface ReviewEntry {
  decision: ReviewDecision; reason: DismissReason | null; note: string | null; window_hours: number | null;
  analyst: string; created_at: string; current_version: boolean;
}
export interface ReviewState { status: ReviewStatus; latest: ReviewEntry | null; history: ReviewEntry[] }
export interface ReviewRequest { decision: ReviewDecision; reason?: DismissReason; note?: string; window_hours?: ContextWindow }
export interface ContextView {
  window_hours: number; window_start_label: string; window_end_label: string; account: string;
  account_events: number; account_failures: number; account_before: number; account_after: number;
  account_src_hosts: string[]; account_dst_hosts: string[]; account_first_seen_label: string | null;
  events: EventView[]; events_truncated: boolean;
  hosts: { host: string; events: number; failures: number; other_accounts: { label: string; count: number }[] }[];
  pairs: { src_host: string; dst_host: string; before: number; first_seen_label: string | null; after: number }[];
  related: { incident_id: string; principal_user: string; severity: Severity; first_seen_label: string;
             last_seen_label: string; relation: string; review_status: ReviewStatus }[];
  observations: string[]; limitations: string[];
}
// Specialised agents (identity, network/host, threat intelligence, endpoint) and correlation.
export type Stance = "suspicious" | "benign" | "context";
export interface AgentFinding {
  statement: string; stance: Stance; strength: "weak" | "moderate" | "strong";
  accounts: string[]; hosts: string[]; event_ids: string[];
  techniques: { id: string; name: string | null; url: string }[]; expanded: boolean;
}
export interface AgentReport {
  agent: string; title: string; purpose: string;
  status: "completed" | "no_findings" | "unavailable" | "failed";
  examined: string[]; findings: AgentFinding[]; gaps: string[]; duration_ms: number;
}
export interface AgentAnalysis {
  incident_id: string; source_key: string; mode: "standard" | "expanded"; window_hours: number | null;
  generated_at: string; duration_ms: number; agents: AgentReport[];
  correlation: {
    summary: string; corroborated: string[]; conflicts: string[];
    techniques: { id: string; name: string | null; url: string }[]; open_questions: string[];
    unavailable_agents: string[]; counts: Record<string, number>;
    entities: { kind: "account" | "host"; name: string; suspicious_agents: string[]; benign_agents: string[]; findings: number }[];
  };
  response_plan?: ResponsePlan | null;
}

/** How to stop the activity. Recommendations only: AgentSOC executes nothing. */
export interface ResponsePlan {
  posture: "contain_now" | "verify_first" | "monitor" | "closed";
  summary: string; notes: string[];
  steps: {
    phase: "contain" | "investigate" | "recover" | "prevent"; action: string; target: string | null; why: string;
    based_on: string[]; action_type: string | null; risk_engine_proposed: boolean; disruptive: boolean;
  }[];
}

export interface ReportView {
  generated_at: string; generated_by: string; source_label: string; dataset_label: string;
  dataset_sha256: string; detection_engine: string; incident: IncidentDetail; review: ReviewState;
  risk: RiskView | null; risk_unavailable: string | null;
  paths: { path_id: string; kind: string; verdict: string; hosts: string[]; accounts: string[]; reasons: string[] }[];
  paths_unavailable: string | null; investigation: InvestigationView | null; context: ContextView | null;
  agents?: AgentAnalysis | null;
  notices: string[];
}

export interface EvidenceRef {
  event_id: string; relevance: string | null; time_label: string | null;
  path: string | null; outcome: string | null;
}

export type Feasibility = "FEASIBLE" | "CONDITIONALLY_FEASIBLE" | "INFEASIBLE";
export interface PathValidation {
  hypothesis_id: string; verdict: Feasibility; checked_path: string[];
  missing_edges: { source: string; target: string }[]; conditions: string[];
  reasons: string[]; evidence_event_ids: string[];
}

export interface HypothesisView {
  hypothesis_id: string; kind: "MALICIOUS" | "BENIGN"; title: string; narrative: string;
  confidence: number; attack_techniques: { id: string; name: string | null; url: string }[];
  supporting: EvidenceRef[]; contradicting: EvidenceRef[]; missing_information: string[];
  proposed_path?: string[]; path_validation?: PathValidation | null;
}

export interface InvestigationView {
  investigation_id: string; incident_id: string; source_key: string;
  status: "completed" | "completed_limited"; created_at: string; cached: boolean;
  conclusion: {
    most_plausible_hypothesis_id: string; most_plausible_title: string; summary: string;
    confidence: number; uncertainty: string; alternative_hypothesis_ids: string[];
    next_steps: string[]; evidence_gaps: string[]; is_proof_of_compromise: false;
  };
  hypotheses: HypothesisView[];
  analyst_notes: string[];
  diagnostics: { engine: "llm" | "deterministic"; model: string | null; latency_ms: number };
  structural_evidence?: "used" | "unavailable";
}

export interface InvestigationSummary {
  investigation_id: string; incident_id: string; source_key: string; source_label: string;
  provenance: Provenance; principal_user: string | null; severity: Severity | null;
  conclusion: string; conclusion_kind: "MALICIOUS" | "BENIGN"; confidence: number;
  created_at: string; status: "completed" | "completed_limited" | "stale";
}

export interface AnalysisRunInfo extends AssessmentStatus {
  engine_version: string | null; config_sha256: string | null; output_sha256: string | null;
  generated_at: string | null; records: number | null; truncated_records?: number | null;
}

export interface DatasetInfo {
  key: string; label: string; provenance: Provenance; dataset_label: string;
  source_file: string; parser_version: string; input_sha256: string; events_sha256: string;
  lines_read: number; event_count: number; rejected_count: number;
  time_start_label: string | null; time_end_label: string | null; time_coverage_seconds: number;
  detection: { engine_version: string; generated_at: string; findings: number; incidents: number;
               config_sha256: string; baseline_seconds: number };
  status: "verified" | "error"; status_detail: string;
  structural?: AnalysisRunInfo | null; risk?: AnalysisRunInfo | null;
}

export interface RiskComponent { name: string; value: number; weight: number; explanation: string }
export interface ConfidenceAssessment {
  score: number; level: "LOW" | "MODERATE" | "HIGH"; components: RiskComponent[]; includes_investigation: boolean;
}
export interface ResponseAction {
  action_id: string; incident_id: string; action_type: string; target: string; rationale: string;
  requires_approval: boolean; status: "PROPOSED"; dry_run: true;
  score: { containment: number; business_impact: number; alpha: number; beta: number; composite: number } | null;
}
export interface IncidentRiskRecord {
  incident_id: string; incident_sha256: string; structural_sha256: string;
  risk: { incident_id: string; score: number; band: Severity; components: RiskComponent[] };
  base_score: number;
  adjustments: { name: string; kind: "FACTOR" | "CAP"; value: number; before: number; after: number; explanation: string }[];
  route: { event_ids: string[]; hosts: string[]; kind: "OBSERVED" | "INFERRED"; effective_hops: number;
           source_path_id: string; reduced_jump_route: boolean } | null;
  attributions: { event_id: string; component: string }[];
  confidence: ConfidenceAssessment;
  severity_comparison: { detection_severity: Severity; risk_band: Severity;
                         relation: "SAME" | "RISK_HIGHER" | "RISK_LOWER"; explanation: string };
  actions: ResponseAction[];
  withheld_actions: { action_type: string; reasons: string[] }[];
  limitations: string[]; is_proof_of_compromise: false;
}
export interface RiskView {
  detection_severity: Severity; record: IncidentRiskRecord;
  investigation_confidence: ConfidenceAssessment;
  model_generated_estimates: Record<string, number>;
  contributions?: Record<string, number>;
}

export type NodeRole = "PRINCIPAL" | "ADMIN" | "SENSITIVE" | "JUMP_HOST" | "CHOKE_POINT" | "ACCOUNT_SWITCH" | "AMBIGUOUS_SWITCH";
export type LinkKind = "MOVEMENT" | "ATTEMPT" | "LOCAL" | "ACCOUNT";
export interface GraphNode { node_id: string; kind: "host" | "user"; label: string; roles: NodeRole[]; event_count: number }
export interface GraphLink {
  link_id: string; source: string; target: string; kind: LinkKind; event_ids: string[]; accounts: string[];
  relations: ("ACTED_FROM" | "REACHED")[]; rule_ids: string[]; first_seen_label: string;
  last_seen_label: string; path_ids: string[];
}
export interface GraphEvent {
  event_id: string; duplicate_event_ids: string[]; timestamp: string; time_label: string; account: string;
  src_host: string; dst_host: string; kind: "MOVEMENT" | "ATTEMPT" | "LOCAL"; auth_type: string | null;
  logon_type: string | null; dataset: Provenance; raw_file: string; raw_line: number;
  rule_ids: string[]; path_ids: string[];
}
export interface GraphPath {
  path_id: string; kind: "OBSERVED" | "INFERRED"; verdict: Feasibility; event_ids: string[]; link_ids: string[];
  hosts: string[]; accounts: string[];
  switches: { host: string; from_event_id: string; to_event_id: string; gap_seconds: number;
              other_accounts_arriving: number; ambiguous: boolean }[];
  ambiguous: boolean; finding_ids: string[]; anchor_event_ids: string[]; context_event_ids: string[];
  revisited_hosts: string[]; conditions: string[]; reasons: string[]; is_proof_of_compromise: false;
}
export interface IncidentGraph {
  incident_id: string; incident_sha256: string; datasets: Provenance[]; nodes: GraphNode[]; links: GraphLink[];
  events: GraphEvent[]; paths: GraphPath[];
  finding_validations: { finding_id: string; rule_id: string; verdict: Feasibility; checked_path: string[];
                         missing_event_ids: string[]; missing_edges: { source: string; target: string }[];
                         conditions: string[]; reasons: string[]; extended_by: string[]; event_ids: string[] }[];
  disconnected: { event_id: string; reason: string; detail: string; nearest_event_id: string | null }[];
  choke_points: { target_event_id: string; target_host: string; entry_hosts: string[]; via_hosts: string[] }[];
  cyclic_host_groups: string[][];
  account_bridges: { account: string; host_groups: string[][] }[];
  missing_event_ids: string[];
  stats: { truncated: boolean; truncation_reasons: string[]; movement_edges: number; attempt_edges: number;
           local_edges: number; context_events: number; depth_reached: number; anchors: number };
  limitations: string[]; is_proof_of_compromise: false;
}

export interface ActivityLog {
  entries: { sequence: number; timestamp: string; actor: string; event_type: string;
             subject_id: string; details: Record<string, string | number | boolean | null> }[];
  total: number; chain_intact: boolean;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

type Query = Record<string, string | number | boolean | string[] | null | undefined>;

function toSearch(query?: Query): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) value.forEach((v) => params.append(key, v));
    else params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

// The CSRF token for the current session. Held in memory only: never in browser storage.
let csrfToken: string | null = null;
export function setCsrfToken(token: string | null) { csrfToken = token; }
export const UNAUTHORIZED_EVENT = "agentsoc:unauthorized";

type Method = "GET" | "POST" | "PATCH" | "DELETE";

async function request<T>(method: Method, path: string, query?: Query, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  let response: Response;
  try {
    response = await fetch(`/api${path}${toSearch(query)}`, {
      method, headers, credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "The AgentSOC service is unreachable.");
  }
  if (!response.ok) {
    let detail = `Request failed (${response.status}).`;
    try {
      const data = await response.json();
      if (typeof data?.detail === "string") detail = data.detail;
      else if (response.status === 422) detail = "The request parameters were not accepted.";
    } catch { /* non-JSON error body */ }
    // A session that ended mid-use sends the analyst back to sign-in.
    if (response.status === 401 && !path.startsWith("/auth/")) {
      window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    }
    throw new ApiError(response.status, detail);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export type Role = "admin" | "analyst";
export interface SessionInfo { user: { username: string; role: Role }; csrf_token: string }
export interface AdminUser {
  username: string; role: Role; disabled: boolean; locked: boolean;
  created_at: string; password_changed_at: string;
}

// Organisational databases. Passwords are sent, never received.
export type SslMode = "verify-full" | "verify-ca" | "require" | "prefer" | "disable";
export type Engine = "postgresql" | "mysql";
export interface PgConnection {
  engine?: Engine; host: string; port: number; database: string; username: string; sslmode: SslMode;
  connect_timeout_seconds?: number; statement_timeout_ms?: number;
}
export type MappedField = "src_user" | "dst_user" | "src_host" | "dst_host" | "auth_type" | "logon_type" | "orientation" | "outcome";
export interface FieldMapping { column?: string | null; constant?: string | null; values?: Record<string, string> }
export type TimestampFormat = "iso8601" | "epoch_seconds" | "epoch_millis";
export interface Mapping {
  record_id: string;
  timestamp: { column: string; format: TimestampFormat; naive_timezone?: string | null };
  fields: Partial<Record<MappedField, FieldMapping>>;
  confirmed_constants: MappedField[];
}
export interface TableName { schema: string; name: string }
export interface DbColumn { name: string; data_type: string; nullable: boolean }
export interface ConnectionReport { server_version: string; account: string; read_only_session: boolean; warnings: string[] }
export interface PreviewEvent {
  event_id: string; time: string; src_user: string; dst_user: string | null; src_host: string; dst_host: string;
  auth_type: string | null; logon_type: string | null; orientation: string; outcome: string;
}
export interface MappingPreview {
  rows_read: number; accepted: PreviewEvent[];
  rejected: { row: number; reason: string; field: string | null; detail: string }[]; disclosures: string[];
}
export interface SyncRun {
  id: number; trigger: "manual" | "scheduled"; started_at: string; finished_at: string | null;
  status: "running" | "completed" | "failed" | "interrupted"; fetched: number; new: number;
  duplicates: number; changed: number; rejected: number; more_available: boolean; error: string | null;
}
export interface SnapshotSummary { created_at: string; event_count: number; incident_count: number; first_event: string; last_event: string }
export interface OrgSource {
  key: string; dashboard_key: string; name: string; kind: string; mode: string;
  sync_enabled: boolean; sync_interval_seconds: number; ai_enabled: boolean; disclosures: string[];
  stats: { accepted: number; rejected: number; changed: number; rejected_by_reason: Record<string, number>;
           first_event: string | null; last_event: string | null };
  last_run: SyncRun | null; snapshot: SnapshotSummary | null;
}
export interface AdminOrgSource extends OrgSource {
  connection: PgConnection; table: TableName; cursor_column: string; lookback: number;
  batch_size: number; max_rows_per_sync: number; mapping: Mapping; has_password: boolean;
  ai_changed_by: string | null; ai_changed_at: string | null; ai_warning: string;
  created_by: string; created_at: string; runs: SyncRun[]; connection_warnings: string[];
}
export interface ConnectionRequest { connection: PgConnection; password?: string; key?: string }
export interface NewOrgSource {
  key: string; name: string; password: string;
  config: { connection: PgConnection; table: TableName; cursor_column: string; lookback: number;
            sync_interval_seconds: number; mapping: Mapping };
}
export interface OrgSourcePatch {
  name?: string; sync_enabled?: boolean; sync_interval_seconds?: number;
  ai_enabled?: boolean; ai_risk_acknowledged?: boolean;
}

export const api = {
  orgSources: () => request<OrgSource[]>("GET", "/datasources/organisation"),
  adminOrgSources: () => request<AdminOrgSource[]>("GET", "/admin/datasources"),
  testConnection: (body: ConnectionRequest) => request<ConnectionReport>("POST", "/admin/datasources/test", undefined, body),
  listTables: (body: ConnectionRequest) => request<TableName[]>("POST", "/admin/datasources/tables", undefined, body),
  listColumns: (body: ConnectionRequest & { table: TableName }) =>
    request<DbColumn[]>("POST", "/admin/datasources/columns", undefined, body),
  previewMapping: (body: ConnectionRequest & { table: TableName; cursor_column: string; mapping: Mapping }) =>
    request<MappingPreview>("POST", "/admin/datasources/preview", undefined, body),
  createOrgSource: (body: NewOrgSource) => request<AdminOrgSource>("POST", "/admin/datasources", undefined, body),
  updateOrgSource: (key: string, patch: OrgSourcePatch) =>
    request<AdminOrgSource>("PATCH", `/admin/datasources/${encodeURIComponent(key)}`, undefined, patch),
  setOrgSourcePassword: (key: string, password: string) =>
    request<void>("POST", `/admin/datasources/${encodeURIComponent(key)}/password`, undefined, { password }),
  syncOrgSource: (key: string) => request<SyncRun>("POST", `/admin/datasources/${encodeURIComponent(key)}/sync`),
  snapshotOrgSource: (key: string) =>
    request<SnapshotSummary>("POST", `/admin/datasources/${encodeURIComponent(key)}/snapshot`),
  deleteOrgSource: (key: string) => request<void>("DELETE", `/admin/datasources/${encodeURIComponent(key)}`),
  authStatus: () => request<{ setup_required: boolean }>("GET", "/auth/status"),
  session: () => request<SessionInfo>("GET", "/auth/session"),
  login: (username: string, password: string) =>
    request<SessionInfo>("POST", "/auth/login", undefined, { username, password }),
  logout: () => request<void>("POST", "/auth/logout"),
  changePassword: (current_password: string, new_password: string) =>
    request<SessionInfo>("POST", "/auth/password", undefined, { current_password, new_password }),
  users: () => request<AdminUser[]>("GET", "/admin/users"),
  createUser: (username: string, password: string, role: Role) =>
    request<AdminUser>("POST", "/admin/users", undefined, { username, password, role }),
  updateUser: (username: string, patch: { role?: Role; disabled?: boolean }) =>
    request<AdminUser>("PATCH", `/admin/users/${encodeURIComponent(username)}`, undefined, patch),
  resetPassword: (username: string, new_password: string) =>
    request<void>("POST", `/admin/users/${encodeURIComponent(username)}/password`, undefined, { new_password }),
  health: () => request<Health>("GET", "/health"),
  sources: () => request<SourceRef[]>("GET", "/sources"),
  overview: (source: string) => request<Overview>("GET", "/overview", { source }),
  incidents: (source: string, query: Query) =>
    request<Page<IncidentSummary>>("GET", "/incidents", { source, ...query }),
  incident: (source: string, id: string) =>
    request<IncidentDetail>("GET", `/incidents/${encodeURIComponent(id)}`, { source }),
  savedInvestigation: (source: string, id: string) =>
    request<InvestigationView>("GET", `/incidents/${encodeURIComponent(id)}/investigation`, { source }),
  review: (source: string, id: string) =>
    request<ReviewState>("GET", `/incidents/${encodeURIComponent(id)}/review`, { source }),
  submitReview: (source: string, id: string, body: ReviewRequest) =>
    request<ReviewState>("POST", `/incidents/${encodeURIComponent(id)}/review`, { source }, body),
  context: (source: string, id: string, window_hours: ContextWindow) =>
    request<ContextView>("GET", `/incidents/${encodeURIComponent(id)}/context`, { source, window_hours }),
  agents: (source: string, id: string, window_hours: ContextWindow | null) =>
    request<AgentAnalysis>("GET", `/incidents/${encodeURIComponent(id)}/agents`, { source, window_hours }),
  report: (source: string, id: string) =>
    request<ReportView>("GET", `/incidents/${encodeURIComponent(id)}/report`, { source }),
  reportMarkdown: async (source: string, id: string): Promise<Blob> => {
    const response = await fetch(`/api/incidents/${encodeURIComponent(id)}/report.md${toSearch({ source })}`,
                                 { credentials: "same-origin" });
    if (response.status === 401) window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    if (!response.ok) throw new ApiError(response.status, `Export failed (${response.status}).`);
    return response.blob();
  },
  investigate: (source: string, id: string, rerun: boolean) =>
    request<InvestigationView>("POST", `/incidents/${encodeURIComponent(id)}/investigate`,
      { source, rerun }),
  investigations: () => request<InvestigationSummary[]>("GET", "/investigations"),
  graph: (source: string, id: string) =>
    request<IncidentGraph>("GET", `/incidents/${encodeURIComponent(id)}/graph`, { source }),
  risk: (source: string, id: string) =>
    request<RiskView>("GET", `/incidents/${encodeURIComponent(id)}/risk`, { source }),
  investigation: (source: string, id: string) =>
    request<InvestigationView>("GET", `/investigations/${encodeURIComponent(id)}`, { source }),
  events: (source: string, query: Query) =>
    request<Page<EventView>>("GET", "/events", { source, ...query }),
  datasets: () => request<DatasetInfo[]>("GET", "/datasets"),
  activity: (limit = 100, filter?: { subject: string; source: string }) =>
    request<ActivityLog>("GET", "/activity", { limit, ...filter }),
};
