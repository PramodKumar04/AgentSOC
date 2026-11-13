// Test fixtures shaped exactly like the API responses (src/agentsoc/api/models.py).
import type {
  DatasetInfo, EventView, IncidentDetail, IncidentSummary, InvestigationSummary,
  InvestigationView, Overview, SourceRef,
} from "@/lib/api";

export const SOURCES: SourceRef[] = [
  { key: "demo", label: "Synthetic demo scenario (4 days)", provenance: "synthetic", is_default: true },
  { key: "lanl-first_100k", label: "LANL 2015 (real, sampled): first_100k", provenance: "lanl", is_default: false },
];

export const EVENT: EventView = {
  event_id: "auth.txt-116", timestamp: "1970-01-04T10:55:00Z", time_label: "Day 3 10:55:00",
  src_user: "alice.fin@CORP", dst_user: "alice.fin@CORP", src_host: "SRV-APP-02", dst_host: "DB-FIN-01",
  auth_type: "Kerberos", logon_type: null, orientation: "LogOn", outcome: "Success",
  provenance: "synthetic", raw_file: "auth.txt", raw_line: 116, cited_by: ["LATERAL_CHAIN"],
};

export const ALICE: IncidentSummary = {
  incident_id: "INC-00002", source_key: "demo", principal_user: "alice.fin@CORP", severity: "CRITICAL",
  rule_ids: ["FAILURE_BURST", "LATERAL_CHAIN"], finding_count: 2, involved_hosts: ["DB-FIN-01", "SRV-APP-02"],
  first_seen: "1970-01-04T10:30:00Z", last_seen: "1970-01-04T10:55:00Z",
  first_seen_label: "Day 3 10:30:00", last_seen_label: "Day 3 10:55:00",
  provenance: ["synthetic"], evidence_count: 1, investigation_status: "none",
};

export const CAROL: IncidentSummary = {
  ...ALICE, incident_id: "INC-00001", principal_user: "carol.fin@CORP", severity: "MEDIUM",
  rule_ids: ["FAIL_THEN_SUCCESS"], finding_count: 1, involved_hosts: ["WS-FIN-02"],
};

export const ALICE_DETAIL: IncidentDetail = {
  ...ALICE,
  description: "alice.fin@CORP triggered 2 detection rule(s). Suspicious activity requiring investigation; not a confirmed compromise.",
  involved_users: ["alice.fin@CORP"],
  findings: [{
    finding_id: "FND-00007", rule_id: "LATERAL_CHAIN", rule_title: "Sequential host-to-host authentication chain",
    severity: "HIGH", description: "alice.fin@CORP authenticated along WS-FIN-07 -> SRV-APP-02 -> DB-FIN-01.",
    metrics: { hops: 2, path: "WS-FIN-07 > SRV-APP-02 > DB-FIN-01" }, event_ids: ["auth.txt-116"],
    first_seen_label: "Day 3 10:40:00", last_seen_label: "Day 3 10:55:00",
  }],
  severity_rationale: "Points over distinct rules: FAILURE_BURST=2 + LATERAL_CHAIN=3 = 5 -> HIGH.",
  shared_evidence: [], benign_explanations: ["Administrators routinely hop through jump hosts."],
  limitations: ["Indicates suspicious behaviour only; it does not confirm compromise."],
  missing_information: ["MFA status of the successful authentication."],
  timeline: [EVENT], missing_evidence_ids: [],
};

export const OVERVIEW: Overview = {
  source: SOURCES[0],
  dataset: { label: "SYNTHETIC 4-day enterprise scenario", provenance: "synthetic", event_count: 176 },
  incidents_total: 3, severity_counts: { CRITICAL: 1, HIGH: 0, MEDIUM: 1, LOW: 1 },
  findings_total: 15, investigations_completed: 0,
  rule_activity: [{ rule_id: "LATERAL_CHAIN", title: "Sequential host-to-host authentication chain", findings: 1 }],
  activity: [{ label: "Day 3 10:00", count: 1 }],
  recent_incidents: [ALICE, CAROL],
};

export function investigation(status: "completed" | "completed_limited"): InvestigationView {
  return {
    investigation_id: "INC-00002-aac7316fc0b11f44", incident_id: "INC-00002", source_key: "demo",
    status, created_at: "2026-10-30T15:10:26Z", cached: false,
    conclusion: {
      most_plausible_hypothesis_id: "H1", most_plausible_title: "Credential misuse leading to lateral movement",
      summary: "Failures then success from an unfamiliar host, then a chain to a sensitive database.",
      confidence: 0.68, uncertainty: "Logs cannot show who operated the account.",
      alternative_hypothesis_ids: ["H2"], next_steps: ["Check MFA logs for the successful logons."],
      evidence_gaps: ["Endpoint telemetry"], is_proof_of_compromise: false,
    },
    hypotheses: [
      { hypothesis_id: "H1", kind: "MALICIOUS", title: "Credential misuse leading to lateral movement",
        narrative: "Consistent with stolen credentials.", confidence: 0.68,
        attack_techniques: [{ id: "T1078", name: "Valid Accounts", url: "https://attack.mitre.org/techniques/T1078/" }],
        supporting: [{ event_id: "auth.txt-116", relevance: "Hop to the sensitive database", time_label: "Day 3 10:55:00",
                       path: "SRV-APP-02 → DB-FIN-01", outcome: "Success" }],
        contradicting: [], missing_information: ["MFA logs"] },
      { hypothesis_id: "H2", kind: "BENIGN", title: "Forgotten password and legitimate work",
        narrative: "User recovered after typos.", confidence: 0.3, attack_techniques: [],
        supporting: [], contradicting: [], missing_information: [] },
    ],
    analyst_notes: [],
    diagnostics: { engine: status === "completed" ? "llm" : "deterministic",
                   model: status === "completed" ? "openai/gpt-oss-120b" : null, latency_ms: 4200 },
  };
}

export const INVESTIGATIONS: InvestigationSummary[] = [{
  investigation_id: "INC-00002-aac7316fc0b11f44", incident_id: "INC-00002", source_key: "demo",
  source_label: "Synthetic demo scenario (4 days)", provenance: "synthetic", principal_user: "alice.fin@CORP",
  severity: "CRITICAL", conclusion: "Credential misuse leading to lateral movement", conclusion_kind: "MALICIOUS",
  confidence: 0.68, created_at: "2026-10-30T15:10:26Z", status: "completed",
}];

export const DATASETS: DatasetInfo[] = [{
  key: "demo", label: "Synthetic demo scenario (4 days)", provenance: "synthetic",
  dataset_label: "SYNTHETIC 4-day enterprise scenario", source_file: "auth_scenarios_synthetic.txt",
  parser_version: "lanl-auth/1.0", input_sha256: "a".repeat(64), events_sha256: "b".repeat(64),
  lines_read: 176, event_count: 176, rejected_count: 0, time_start_label: "Day 0 09:00:00",
  time_end_label: "Day 3 17:00:04", time_coverage_seconds: 288304,
  detection: { engine_version: "auth-detect/1.0", generated_at: "2026-10-30T15:00:00Z", findings: 15,
               incidents: 3, config_sha256: "c".repeat(64), baseline_seconds: 172800 },
  status: "verified", status_detail: "Manifest, event hash and detection output hashes verified.",
}];
