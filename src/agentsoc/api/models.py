"""API response models. Views over the existing contracts (`agentsoc.schemas`), shaped
for the web UI. They never carry API keys, provider error text or stack traces."""

from __future__ import annotations

from datetime import datetime
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel

from agentsoc.schemas import PathValidation
from agentsoc.schemas.rsem import ConfidenceAssessment, IncidentRiskRecord

T = TypeVar("T")
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
Provenance = Literal["synthetic", "lanl", "upload", "organization"]
InvestigationStatus = Literal["none", "completed", "completed_limited", "stale"]
AssessmentState = Literal["available", "not_assessed", "stale", "unavailable"]


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


class SourceRef(BaseModel):
    key: str
    label: str
    provenance: Provenance
    is_default: bool


class Health(BaseModel):
    status: Literal["ok"]
    version: str
    analysis: Literal["available", "limited"]
    sources: int


class AssessmentStatus(BaseModel):
    state: AssessmentState
    detail: str  # fixed text; never exception or file content


class IncidentAssessments(BaseModel):
    structural: AssessmentStatus
    risk: AssessmentStatus
    truncated: bool = False
    truncation_reasons: list[str] = []


class IncidentSummary(BaseModel):
    incident_id: str
    source_key: str
    principal_user: str
    severity: Severity
    rule_ids: list[str]
    finding_count: int
    involved_hosts: list[str]
    first_seen: datetime
    last_seen: datetime
    first_seen_label: str
    last_seen_label: str
    provenance: list[Provenance]
    evidence_count: int
    investigation_status: InvestigationStatus
    # From hash-checked, independently re-verified RSEM records. None = no record to show.
    risk_score: float | None = None
    risk_band: Severity | None = None


class EventView(BaseModel):
    event_id: str
    timestamp: datetime
    time_label: str
    src_user: str
    dst_user: str | None
    src_host: str
    dst_host: str
    auth_type: str | None
    logon_type: str | None
    orientation: str
    outcome: Literal["Success", "Fail"]
    provenance: Provenance
    raw_file: str
    raw_line: int
    cited_by: list[str] = []


class FindingView(BaseModel):
    finding_id: str
    rule_id: str
    rule_title: str
    severity: Severity
    description: str
    metrics: dict[str, bool | int | float | str]
    event_ids: list[str]
    first_seen_label: str
    last_seen_label: str


class SharedEvidence(BaseModel):
    event_id: str
    rule_ids: list[str]


class IncidentDetail(IncidentSummary):
    description: str
    involved_users: list[str]
    findings: list[FindingView]
    severity_rationale: str
    shared_evidence: list[SharedEvidence]
    benign_explanations: list[str]
    limitations: list[str]
    missing_information: list[str]
    timeline: list[EventView]
    missing_evidence_ids: list[str]
    assessments: IncidentAssessments


class CountItem(BaseModel):
    label: str
    count: int


class RuleActivity(BaseModel):
    rule_id: str
    title: str
    findings: int


class DatasetBrief(BaseModel):
    label: str
    provenance: Provenance
    event_count: int


class Overview(BaseModel):
    source: SourceRef
    dataset: DatasetBrief
    incidents_total: int
    severity_counts: dict[Severity, int]
    findings_total: int
    investigations_completed: int
    rule_activity: list[RuleActivity]
    activity: list[CountItem]  # incidents by first-seen hour
    recent_incidents: list[IncidentSummary]
    risk_status: AssessmentStatus
    risk_counts: dict[Severity, int] | None = None  # None when no verified records exist
    risk_assessed: int = 0


class AttackTechnique(BaseModel):
    id: str
    name: str | None
    url: str


class EvidenceRef(BaseModel):
    event_id: str
    relevance: str | None
    time_label: str | None
    path: str | None
    outcome: str | None


class HypothesisView(BaseModel):
    hypothesis_id: str
    kind: Literal["MALICIOUS", "BENIGN"]
    title: str
    narrative: str
    confidence: float
    attack_techniques: list[AttackTechnique]
    supporting: list[EvidenceRef]
    contradicting: list[EvidenceRef]
    missing_information: list[str]
    proposed_path: list[str] = []
    path_validation: PathValidation | None = None  # None only when no path was proposed


class ConclusionView(BaseModel):
    most_plausible_hypothesis_id: str
    most_plausible_title: str
    summary: str
    confidence: float
    uncertainty: str
    alternative_hypothesis_ids: list[str]
    next_steps: list[str]
    evidence_gaps: list[str]
    is_proof_of_compromise: Literal[False]


class Diagnostics(BaseModel):
    """Technical attribution, shown collapsed. Provider error details stay in server logs."""

    engine: Literal["llm", "deterministic"]
    model: str | None
    latency_ms: float


class InvestigationView(BaseModel):
    investigation_id: str
    incident_id: str
    source_key: str
    status: Literal["completed", "completed_limited"]
    created_at: datetime
    cached: bool
    conclusion: ConclusionView
    hypotheses: list[HypothesisView]
    analyst_notes: list[str]
    diagnostics: Diagnostics
    structural_evidence: Literal["used", "unavailable"] = "unavailable"


class RiskView(BaseModel):
    """Risk, investigation confidence and detection severity are separate quantities."""

    detection_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    record: IncidentRiskRecord
    investigation_confidence: ConfidenceAssessment
    # What the model said about its own hypotheses. Not used in any score.
    model_generated_estimates: dict[str, float] = {}
    # Points each component adds to the base score, so the UI need not calculate them.
    contributions: dict[str, float] = {}


class InvestigationSummary(BaseModel):
    investigation_id: str
    incident_id: str
    source_key: str
    source_label: str
    provenance: Provenance
    principal_user: str | None
    severity: Severity | None
    conclusion: str
    conclusion_kind: Literal["MALICIOUS", "BENIGN"]
    confidence: float
    created_at: datetime
    status: Literal["completed", "completed_limited", "stale"]


class DetectionRunInfo(BaseModel):
    engine_version: str
    generated_at: datetime
    findings: int
    incidents: int
    config_sha256: str
    baseline_seconds: int


class AnalysisRunInfo(BaseModel):
    state: AssessmentState
    detail: str
    engine_version: str | None = None
    config_sha256: str | None = None
    output_sha256: str | None = None
    generated_at: datetime | None = None
    records: int | None = None
    truncated_records: int | None = None


class DatasetInfo(BaseModel):
    key: str
    label: str
    provenance: Provenance
    dataset_label: str
    source_file: str
    parser_version: str
    input_sha256: str
    events_sha256: str
    lines_read: int
    event_count: int
    rejected_count: int
    time_start_label: str | None
    time_end_label: str | None
    time_coverage_seconds: int
    detection: DetectionRunInfo
    status: Literal["verified", "error"]
    status_detail: str
    structural: AnalysisRunInfo | None = None
    risk: AnalysisRunInfo | None = None


class ActivityEntry(BaseModel):
    sequence: int
    timestamp: datetime
    actor: str
    event_type: str
    subject_id: str
    details: dict[str, str | int | float | bool | None]


class ActivityLog(BaseModel):
    entries: list[ActivityEntry]
    total: int
    chain_intact: bool
