// Shaped like the API responses. Scores are deliberately not derivable from their inputs,
// so a test can tell a displayed server value from one recalculated in the browser.
import type {
  AnalysisRunInfo, GraphEvent, GraphLink, GraphPath, IncidentDetail, IncidentGraph, InvestigationView, RiskView,
} from "@/lib/api";
import { ALICE_DETAIL, investigation } from "./fixtures";

export const AVAILABLE = { state: "available", detail: "Hash-verified against this run." } as const;

export const DETAIL: IncidentDetail = {
  ...ALICE_DETAIL, risk_score: 37.5, risk_band: "MEDIUM",
  assessments: { structural: AVAILABLE, risk: AVAILABLE, truncated: false, truncation_reasons: [] },
};

function event(id: string, account: string, src: string, dst: string, kind: GraphEvent["kind"], path_ids: string[] = []): GraphEvent {
  return {
    event_id: id, duplicate_event_ids: [], timestamp: "1970-01-04T10:40:00Z", time_label: `Day 3 ${id}`, account,
    src_host: src, dst_host: dst, kind, auth_type: "Kerberos", logon_type: null, dataset: "synthetic",
    raw_file: "auth.txt", raw_line: Number(id.slice(1)), rule_ids: kind === "MOVEMENT" ? ["LATERAL_CHAIN"] : [], path_ids,
  };
}

function link(kind: GraphLink["kind"], source: string, target: string, event_ids: string[], accounts: string[], path_ids: string[] = []): GraphLink {
  return {
    link_id: `${kind}|${source}|${target}`, source, target, kind, event_ids, accounts, relations: [], rule_ids: [],
    first_seen_label: "Day 3 10:40:00", last_seen_label: "Day 3 10:50:00", path_ids,
  };
}

const A = "alice.fin@CORP";
const B = "bob.it@CORP";
const H = (n: string) => `host:${n}`;

export const OBSERVED: GraphPath = {
  path_id: "P-OBS", kind: "OBSERVED", verdict: "FEASIBLE", event_ids: ["E1", "E2"],
  link_ids: ["MOVEMENT|host:WS1|host:SRV1", "MOVEMENT|host:SRV1|host:DB1"], hosts: ["WS1", "SRV1", "DB1"], accounts: [A],
  switches: [], ambiguous: false, finding_ids: [], anchor_event_ids: ["E1", "E2"], context_event_ids: [], revisited_hosts: [],
  conditions: [], reasons: ["Each hop was observed for this account."], is_proof_of_compromise: false,
};

export const INFERRED: GraphPath = {
  ...OBSERVED, path_id: "P-INF", kind: "INFERRED", verdict: "CONDITIONALLY_FEASIBLE", event_ids: ["E1", "E3"],
  link_ids: ["MOVEMENT|host:WS1|host:SRV1", "MOVEMENT|host:SRV1|host:APP1"], hosts: ["WS1", "SRV1", "APP1"], accounts: [A, B],
  switches: [{ host: "SRV1", from_event_id: "E1", to_event_id: "E3", gap_seconds: 60, other_accounts_arriving: 1, ambiguous: false }],
  conditions: ["Assumes one party operated both accounts."], reasons: ["Hops were observed; the join is inferred."],
};

export const AMBIGUOUS: GraphPath = {
  ...INFERRED, path_id: "P-AMB", ambiguous: true,
  switches: [{ host: "SRV1", from_event_id: "E1", to_event_id: "E3", gap_seconds: 60, other_accounts_arriving: 4, ambiguous: true }],
};

export const GRAPH: IncidentGraph = {
  incident_id: "INC-00002", incident_sha256: "d".repeat(64), datasets: ["synthetic"],
  nodes: [
    { node_id: H("APP1"), kind: "host", label: "APP1", roles: [], event_count: 1 },
    { node_id: H("DB1"), kind: "host", label: "DB1", roles: ["SENSITIVE"], event_count: 1 },
    { node_id: H("SRV1"), kind: "host", label: "SRV1", roles: ["CHOKE_POINT", "ACCOUNT_SWITCH", "AMBIGUOUS_SWITCH"], event_count: 4 },
    { node_id: H("WS1"), kind: "host", label: "WS1", roles: [], event_count: 3 },
    { node_id: `user:${A}`, kind: "user", label: A, roles: ["PRINCIPAL"], event_count: 3 },
    { node_id: `user:${B}`, kind: "user", label: B, roles: [], event_count: 1 },
  ],
  links: [
    link("ACCOUNT", `user:${A}`, H("WS1"), ["E1", "E5"], [A]),
    link("ATTEMPT", H("WS1"), H("SRV1"), ["E4"], [B]),
    link("LOCAL", H("WS1"), H("WS1"), ["E5"], [A]),
    link("MOVEMENT", H("SRV1"), H("APP1"), ["E3"], [B], ["P-AMB", "P-INF"]),
    link("MOVEMENT", H("SRV1"), H("DB1"), ["E2"], [A], ["P-OBS"]),
    link("MOVEMENT", H("WS1"), H("SRV1"), ["E1"], [A], ["P-AMB", "P-INF", "P-OBS"]),
  ],
  events: [
    event("E1", A, "WS1", "SRV1", "MOVEMENT", ["P-OBS", "P-INF", "P-AMB"]), event("E2", A, "SRV1", "DB1", "MOVEMENT", ["P-OBS"]),
    event("E3", B, "SRV1", "APP1", "MOVEMENT", ["P-INF", "P-AMB"]), event("E4", B, "WS1", "SRV1", "ATTEMPT"), event("E5", A, "WS1", "WS1", "LOCAL"),
  ],
  paths: [OBSERVED, INFERRED, AMBIGUOUS],
  finding_validations: [{ finding_id: "F1", rule_id: "LATERAL_CHAIN", verdict: "FEASIBLE", checked_path: ["WS1", "SRV1", "DB1"],
                          missing_event_ids: [], missing_edges: [], conditions: [], reasons: ["Re-checked hop by hop."], extended_by: [], event_ids: ["E1", "E2"] }],
  disconnected: [{ event_id: "E4", reason: "FAILED_LINK_ONLY", detail: "Only a failed attempt would have joined it.", nearest_event_id: null }],
  choke_points: [{ target_event_id: "E2", target_host: "DB1", entry_hosts: ["WS1"], via_hosts: ["SRV1"] }],
  cyclic_host_groups: [], account_bridges: [], missing_event_ids: [],
  stats: { truncated: false, truncation_reasons: [], movement_edges: 3, attempt_edges: 1, local_edges: 1, context_events: 0, depth_reached: 1, anchors: 3 },
  limitations: ["Built from observed authentication logs only."], is_proof_of_compromise: false,
};

const component = (name: string, value: number, weight: number) => ({ name, value, weight, explanation: `Explains ${name}.` });

export const RISK: RiskView = {
  detection_severity: "CRITICAL",
  contributions: { movement_depth: 21.0, credential_pressure: 16.5 },
  model_generated_estimates: { H1: 0.68 },
  investigation_confidence: {
    score: 61.5, level: "MODERATE", includes_investigation: true,
    components: [component("evidence_found", 1, 0.3), component("investigation_quality", 0.5, 0.2)],
  },
  record: {
    incident_id: "INC-00002", incident_sha256: "e".repeat(64), structural_sha256: "f".repeat(64),
    risk: { incident_id: "INC-00002", score: 37.5, band: "MEDIUM",
            components: [component("movement_depth", 0.6, 0.35), component("credential_pressure", 0.8, 0.15)] },
    base_score: 41.7,
    adjustments: [{ name: "evidence_quality", kind: "FACTOR", value: 0.9, before: 41.7, after: 37.5, explanation: "Context was truncated." }],
    route: { event_ids: ["E1", "E2"], hosts: ["WS1", "SRV1", "DB1"], kind: "OBSERVED", effective_hops: 2, source_path_id: "P-OBS", reduced_jump_route: false },
    attributions: [{ event_id: "E1", component: "movement_depth" }],
    confidence: { score: 50, level: "MODERATE", includes_investigation: false, components: [component("evidence_found", 1, 0.3)] },
    severity_comparison: { detection_severity: "CRITICAL", risk_band: "MEDIUM", relation: "RISK_LOWER", explanation: "No sensitive host exposure was observed." },
    actions: [
      { action_id: "A-1", incident_id: "INC-00002", action_type: "ENABLE_MFA", target: A, rationale: "Failed authentication was recorded.",
        requires_approval: true, status: "PROPOSED", dry_run: true, score: { containment: 0.6, business_impact: 0.2, alpha: 0.7, beta: 0.3, composite: 0.36 } },
      { action_id: "A-2", incident_id: "INC-00002", action_type: "MONITOR_ONLY", target: A, rationale: "Keep watching this account.",
        requires_approval: false, status: "PROPOSED", dry_run: true, score: { containment: 0.1, business_impact: 0, alpha: 0.7, beta: 0.3, composite: 0.07 } },
    ],
    withheld_actions: [{ action_type: "ISOLATE_HOST", reasons: ["Risk is below High."] }],
    limitations: ["Weights are unvalidated defaults."], is_proof_of_compromise: false,
  },
};

const validated = investigation("completed");

export function withPath(hypothesis: Partial<InvestigationView["hypotheses"][number]>, extra: Partial<InvestigationView> = {}): InvestigationView {
  return { ...validated, cached: true, structural_evidence: "used", ...extra,
           hypotheses: [{ ...validated.hypotheses[0], ...hypothesis }, validated.hypotheses[1]] };
}

export const RUN: AnalysisRunInfo = {
  ...AVAILABLE, engine_version: "rsem/1.0", config_sha256: "1".repeat(64), output_sha256: "2".repeat(64),
  generated_at: "2026-11-09T06:00:00Z", records: 3, truncated_records: 0,
};
