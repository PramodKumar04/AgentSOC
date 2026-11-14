"""Service layer for the API: verified data access, investigation orchestration and the
hash-chained activity log. Thread-safe (FastAPI runs sync endpoints in a thread pool)."""

from __future__ import annotations

import json
import threading
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from agentsoc import __version__
from agentsoc.agents.orchestrator import prompt_payload
from agentsoc.api import models as m
from agentsoc.api.review_service import ReviewMixin
from agentsoc.app_data import (
    LoadedSource,
    Source,
    data_root,
    discover_sources,
    format_hour,
    format_time,
    load_evidence,
    load_source,
    time_formatter,
)
from agentsoc.audit import AuditLog
from agentsoc.config import get_settings
from agentsoc.detection.catalog import CATALOG, RuleId
from agentsoc.detection.config import DetectionConfig
from agentsoc.exceptions import AgentSOCError, DatasetIntegrityError
from agentsoc.graph.config import StructuralConfig
from agentsoc.graph.proposed import StructuralEvidence
from agentsoc.graph.store import STRUCTURAL_DIR, load_assessments, load_structural_summary
from agentsoc.graph.store import SUMMARY_FILE as STRUCTURAL_SUMMARY
from agentsoc.graph.view import build_incident_graph
from agentsoc.investigator.agent import InvestigatorAgent, build_provider, incident_sha256
from agentsoc.investigator.llm.base import LLMProvider
from agentsoc.investigator.store import (
    INVESTIGATIONS_DIR,
    investigation_id,
    load_investigation,
    save_investigation,
)
from agentsoc.logging_setup import get_logger
from agentsoc.orgsource.registry import DataSourceRegistry
from agentsoc.risk.confidence import assess_confidence
from agentsoc.risk.config import RiskConfig
from agentsoc.risk.store import RISK_DIR, load_risk_records, load_risk_summary
from agentsoc.risk.store import SUMMARY_FILE as RISK_SUMMARY
from agentsoc.risk.verify import RiskVerificationError, verify_record
from agentsoc.schemas import (
    AuditRecord,
    AuthEvent,
    DatasetSource,
    Incident,
    InvestigationResult,
    verify_chain,
)
from agentsoc.schemas.graph import StructuralAssessment
from agentsoc.schemas.graph_view import IncidentGraph
from agentsoc.schemas.rsem import IncidentRiskRecord
from agentsoc.store.datasets import EVENTS_FILE, REPORT_JSON
from agentsoc.store.detections import load_detection_summary

logger = get_logger(__name__)

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def time_formatter_default(ts: datetime) -> str:
    return format_time(ts)
MAX_BROWSABLE_EVENTS = 200_000
# Agent warnings that describe the provider path, not the evidence. Logged server-side only.
DIAGNOSTIC_PREFIXES = ("LLM not used", "LLM provider failed", "LLM output failed validation",
                       "Accepted after")
ATTACK_NAMES = {
    "T1078": "Valid Accounts", "T1078.002": "Valid Accounts: Domain Accounts",
    "T1078.003": "Valid Accounts: Local Accounts", "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing", "T1110.003": "Brute Force: Password Spraying",
    "T1110.004": "Brute Force: Credential Stuffing", "T1021": "Remote Services",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1021.006": "Remote Services: Windows Remote Management",
    "T1550": "Use Alternate Authentication Material",
    "T1550.002": "Use Alternate Authentication Material: Pass the Hash",
    "T1550.003": "Use Alternate Authentication Material: Pass the Ticket",
    "T1558": "Steal or Forge Kerberos Tickets", "T1003": "OS Credential Dumping",
    "T1087": "Account Discovery",
}


_AVAILABLE = m.AssessmentStatus(state="available", detail="Hash-verified against this run.")


def _status(state: m.AssessmentState, name: str) -> m.AssessmentStatus:
    details = {
        "not_assessed": f"No {name} assessment has been run for this data source.",
        "stale": f"The stored {name} assessment belongs to an earlier run and is not shown.",
        "unavailable": f"The stored {name} assessment failed verification and is not shown.",
    }
    return m.AssessmentStatus(state=state, detail=details[state])


def _structural_problem(detection_dir: Path) -> m.AssessmentStatus:
    """Why stored structural output could not be used. Called only after loading failed."""
    name = "structural"
    if not (detection_dir / STRUCTURAL_DIR / STRUCTURAL_SUMMARY).is_file():
        return _status("not_assessed", name)
    try:
        summary = load_structural_summary(detection_dir)
        current = load_detection_summary(detection_dir).incidents_sha256
    except DatasetIntegrityError:
        return _status("unavailable", name)
    stale = current != summary.detection_incidents_sha256
    return _status("stale" if stale else "unavailable", name)


def _risk_problem(detection_dir: Path) -> m.AssessmentStatus:
    """Why stored risk records could not be used. Called only after loading failed."""
    name = "risk"
    if not (detection_dir / RISK_DIR / RISK_SUMMARY).is_file():
        return _status("not_assessed", name)
    try:
        summary = load_risk_summary(detection_dir)
        detection = load_detection_summary(detection_dir).incidents_sha256
        structural = load_structural_summary(detection_dir).assessments_sha256
    except DatasetIntegrityError:
        return _status("unavailable", name)
    stale = (detection != summary.detection_incidents_sha256
             or structural != summary.structural_assessments_sha256)
    return _status("stale" if stale else "unavailable", name)


class NotFoundError(AgentSOCError):
    pass


class BadRequestError(AgentSOCError):
    pass


class InvestigationFailedError(AgentSOCError):
    pass


def _severity_rank(i: Incident) -> tuple:
    return (SEVERITY_ORDER.index(i.severity.value), i.first_seen, i.incident_id)


class Service(ReviewMixin):
    def __init__(
        self,
        root: Path | None = None,
        provider_factory: Callable[[], tuple[LLMProvider | None, str | None]] | None = None,
        app_db: Path | None = None,
    ) -> None:
        self.root = Path(root) if root else data_root()
        # An explicit data root is an isolated instance (tests, tools): keep its accounts there.
        self.app_db = Path(app_db) if app_db else (
            self.root / "agentsoc.db" if root else get_settings().db_path)
        self.provider_factory = provider_factory or (lambda: build_provider(get_settings()))
        self._lock = threading.RLock()
        self._sources: list[Source] | None = None
        self._loaded: dict[str, LoadedSource] = {}
        self._evidence: dict[str, dict[str, AuthEvent]] = {}
        self._all_events: dict[str, list[AuthEvent]] = {}
        self._structural: dict[str, tuple[dict[str, StructuralAssessment], StructuralConfig]] = {}
        self._inv_locks: dict[str, threading.Lock] = {}
        self._risk: dict[str, tuple[dict[str, IncidentRiskRecord], RiskConfig]] = {}
        self._structural_status: dict[str, m.AssessmentStatus] = {}
        self._risk_status: dict[str, m.AssessmentStatus] = {}
        self._activity_lock = threading.Lock()
        self.activity_path = self.root / "activity_log.jsonl"
        self.audit = AuditLog(self.activity_path)
        self._datasources: DataSourceRegistry | None = None

    # ------------------------------------------------------------------ sources & data
    def sources(self) -> list[Source]:
        with self._lock:
            if self._sources is None:
                self._sources = discover_sources(self.root)
            return self._sources

    @property
    def datasources(self) -> DataSourceRegistry:
        if self._datasources is None:
            self._datasources = DataSourceRegistry(self.app_db)
        return self._datasources

    def refresh_sources(self) -> None:
        """Re-discover sources (a new snapshot) and drop cached data that no longer matches."""
        fresh = discover_sources(self.root)
        with self._lock:
            current = {s.key: s for s in fresh}
            old = {s.key: s for s in self._sources or []}
            for key, source in old.items():
                if current.get(key) != source:
                    for cache in (self._loaded, self._evidence, self._all_events,
                                  self._structural, self._risk, self._structural_status,
                                  self._risk_status):
                        cache.pop(key, None)
            self._sources = fresh

    def ai_allowed(self, source: Source) -> bool:
        """Organisational data goes to an external model only if an administrator allowed it."""
        if source.provenance is not DatasetSource.ORGANIZATION:
            return True
        return self.datasources.ai_allowed(source.key)

    def source_refs(self) -> list[m.SourceRef]:
        return [m.SourceRef(key=s.key, label=s.label, provenance=s.provenance.value,
                            is_default=k == 0) for k, s in enumerate(self.sources())]

    def source(self, key: str | None) -> Source:
        sources = self.sources()
        if key is None:
            return sources[0]
        for s in sources:
            if s.key == key:
                return s
        raise NotFoundError(f"unknown data source '{key}'")

    def loaded(self, key: str | None) -> LoadedSource:
        source = self.source(key)
        with self._lock:
            if source.key not in self._loaded:
                self._loaded[source.key] = load_source(source)  # hash-verified
                self._log("dataset.verified", source.key, {
                    "provenance": source.provenance.value,
                    "incidents": len(self._loaded[source.key].incidents)})
            return self._loaded[source.key]

    def evidence(self, key: str | None) -> dict[str, AuthEvent]:
        data = self.loaded(key)
        with self._lock:
            if data.source.key not in self._evidence:
                ids = {e for i in data.incidents for e in i.event_ids}
                ids |= {i for a in self._structural_for(data)[0].values() for e in a.edges
                        for i in (e.event_id, *e.duplicate_event_ids)}
                self._evidence[data.source.key] = load_evidence(data.source.dataset_dir, ids)
            return self._evidence[data.source.key]

    def _structural_for(
        self, data: LoadedSource
    ) -> tuple[dict[str, StructuralAssessment], StructuralConfig]:
        """Verified assessments for this source; empty if none were built or they are stale."""
        with self._lock:
            if data.source.key not in self._structural:
                self._structural_status[data.source.key] = _AVAILABLE
                try:
                    items = load_assessments(data.source.detection_dir)
                    config = load_structural_summary(data.source.detection_dir).structural_config
                except DatasetIntegrityError:
                    logger.info("no usable structural assessment", extra={"context": {
                        "source": data.source.key}})
                    items, config = [], StructuralConfig()
                    self._structural_status[data.source.key] = _structural_problem(
                        data.source.detection_dir)
                self._structural[data.source.key] = (
                    {a.incident_id: a for a in items}, config)
            return self._structural[data.source.key]

    def _risk_for(self, data: LoadedSource) -> tuple[dict[str, IncidentRiskRecord], RiskConfig]:
        """Records whose hashes match and whose scores reproduce; anything else is not served."""
        with self._lock:
            if data.source.key not in self._risk:
                self._risk_status[data.source.key] = _AVAILABLE
                records: dict[str, IncidentRiskRecord] = {}
                config = RiskConfig()
                assessments = self._structural_for(data)[0]
                incidents = {i.incident_id: i for i in data.incidents}
                detection_config = DetectionConfig.model_validate(data.summary["config"])
                try:
                    config = load_risk_summary(data.source.detection_dir).risk_config
                    for record in load_risk_records(data.source.detection_dir):
                        verify_record(record, incidents[record.incident_id],
                                      assessments[record.incident_id], detection_config, config)
                        records[record.incident_id] = record
                except (DatasetIntegrityError, RiskVerificationError, KeyError) as exc:
                    records = {}
                    status = _risk_problem(data.source.detection_dir)
                    self._risk_status[data.source.key] = status
                    if status.state != "not_assessed":
                        logger.warning("risk records not served", extra={"context": {
                            "source": data.source.key, "reason": type(exc).__name__}})
                self._risk[data.source.key] = (records, config)
            return self._risk[data.source.key]

    def incident_risk(self, key: str | None, incident_id: str) -> m.RiskView:
        data, inc = self.incident(key, incident_id)
        records, config = self._risk_for(data)
        record = records.get(inc.incident_id)
        if record is None:
            raise NotFoundError(f"no risk assessment for incident '{incident_id}'")
        assessment = self._structural_for(data)[0][inc.incident_id]
        investigation = load_investigation(data.source.detection_dir, inc)
        confidence = assess_confidence(
            inc, assessment, DetectionConfig.model_validate(data.summary["config"]),
            {u for p in data.summary["partitions"].values()
             for u in p["users_without_baseline"]},
            config, investigation)
        return m.RiskView(
            detection_severity=inc.severity.value, record=record,
            investigation_confidence=confidence,
            model_generated_estimates=(
                {h.hypothesis_id: h.confidence for h in investigation.hypotheses}
                if investigation else {}),
            contributions={c.name: round(100 * c.contribution, 2)
                           for c in record.risk.components},
        )

    def incident_structure(self, key: str | None, incident_id: str) -> StructuralAssessment:
        data, inc = self.incident(key, incident_id)
        assessment = self._structural_for(data)[0].get(inc.incident_id)
        if assessment is None or assessment.incident_sha256 != incident_sha256(inc):
            raise NotFoundError(f"no structural assessment for incident '{incident_id}'")
        return assessment

    def incident_graph(self, key: str | None, incident_id: str) -> IncidentGraph:
        data, inc = self.incident(key, incident_id)
        assessment = self.incident_structure(key, incident_id)
        return build_incident_graph(
            assessment, detection_config=DetectionConfig.model_validate(data.summary["config"]),
            principal_user=inc.principal_user, time_label=time_formatter(data.source),
        )

    def _incident_assessments(self, data: LoadedSource, inc: Incident) -> m.IncidentAssessments:
        assessments = self._structural_for(data)[0]
        records = self._risk_for(data)[0]
        structural = self._structural_status[data.source.key]
        risk = self._risk_status[data.source.key]
        assessment = assessments.get(inc.incident_id)
        if structural.state == "available":
            if assessment is None:
                structural = m.AssessmentStatus(
                    state="not_assessed",
                    detail="No structural assessment exists for this incident.")
            elif assessment.incident_sha256 != incident_sha256(inc):
                structural = m.AssessmentStatus(
                    state="stale", detail="The structural assessment is for an earlier version "
                    "of this incident and is not shown.")
        if risk.state == "available" and inc.incident_id not in records:
            risk = m.AssessmentStatus(
                state="not_assessed", detail="No risk record exists for this incident.")
        usable = assessment is not None and structural.state == "available"
        return m.IncidentAssessments(
            structural=structural, risk=risk,
            truncated=usable and assessment.stats.truncated,
            truncation_reasons=assessment.stats.truncation_reasons if usable else [],
        )

    def _structural_evidence(self, data: LoadedSource, inc: Incident) -> StructuralEvidence | None:
        assessments, config = self._structural_for(data)
        assessment = assessments.get(inc.incident_id)
        if assessment is None:
            return None
        return StructuralEvidence(
            assessment=assessment, events=self.evidence(data.source.key),
            detection_config=DetectionConfig.model_validate(data.summary["config"]), config=config,
        )

    def incident(self, key: str | None, incident_id: str) -> tuple[LoadedSource, Incident]:
        data = self.loaded(key)
        for i in data.incidents:
            if i.incident_id == incident_id:
                return data, i
        raise NotFoundError(f"incident '{incident_id}' not found in source '{data.source.key}'")

    # ------------------------------------------------------------------ views
    def _cited_by(self, data: LoadedSource) -> dict[str, list[str]]:
        out: dict[str, set[str]] = {}
        for f in data.findings:
            for e in f.event_ids:
                out.setdefault(e, set()).add(f.rule_id)
        return {k: sorted(v) for k, v in out.items()}

    @staticmethod
    def event_view(e: AuthEvent, cited_by: list[str] | None = None,
                   fmt: Callable[[datetime], str] | None = None) -> m.EventView:
        return m.EventView(
            event_id=e.event_id, timestamp=e.timestamp,
            time_label=(fmt or time_formatter_default)(e.timestamp),
            src_user=e.src_user, dst_user=e.dst_user, src_host=e.src_host, dst_host=e.dst_host,
            auth_type=e.auth_type, logon_type=e.logon_type, orientation=e.orientation.value,
            outcome=e.outcome.value, provenance=e.dataset.value, raw_file=e.raw_ref.file,
            raw_line=e.raw_ref.line, cited_by=cited_by or [],
        )

    def _investigation_status(self, data: LoadedSource, inc: Incident) -> str:
        result = load_investigation(data.source.detection_dir, inc)
        if result is None:
            return "none"
        return "completed" if result.source.value == "llm" else "completed_limited"

    def incident_summary(self, data: LoadedSource, inc: Incident, status: str | None = None,
                         reviews: dict[str, str] | None = None) -> m.IncidentSummary:
        record = self._risk_for(data)[0].get(inc.incident_id)
        review = (reviews.get(inc.incident_id, "open") if reviews is not None
                  else self._review_state(data, inc).status)
        fmt = time_formatter(data.source)
        return m.IncidentSummary(
            incident_id=inc.incident_id, source_key=data.source.key,
            principal_user=inc.principal_user, severity=inc.severity.value,
            rule_ids=inc.rule_ids, finding_count=len(inc.findings),
            involved_hosts=inc.involved_hosts, first_seen=inc.first_seen,
            last_seen=inc.last_seen, first_seen_label=fmt(inc.first_seen),
            last_seen_label=fmt(inc.last_seen),
            provenance=[d.value for d in inc.datasets], evidence_count=len(inc.event_ids),
            investigation_status=status or self._investigation_status(data, inc),
            risk_score=record.risk.score if record else None,
            risk_band=record.risk.band.value if record else None,
            review_status=review,
        )

    def overview(self, key: str | None) -> m.Overview:
        data = self.loaded(key)
        incidents = sorted(data.incidents, key=_severity_rank)
        counts = Counter(i.severity.value for i in incidents)
        hours = Counter(format_hour(i.first_seen, data.source.time_display) for i in incidents)
        recent = sorted(incidents, key=lambda i: (i.last_seen, i.incident_id), reverse=True)[:6]
        ref = next(r for r in self.source_refs() if r.key == data.source.key)
        records = self._risk_for(data)[0]
        current = {i.incident_id for i in incidents}
        bands = Counter(r.risk.band.value for k, r in records.items() if k in current)
        reviews = self.review_statuses(data)
        return m.Overview(
            source=ref,
            dataset=m.DatasetBrief(label=data.manifest.dataset_label,
                                   provenance=data.manifest.dataset.value,
                                   event_count=data.manifest.event_count),
            incidents_total=len(incidents),
            severity_counts={s: counts.get(s, 0) for s in SEVERITY_ORDER},
            findings_total=data.summary["findings_total"],
            investigations_completed=sum(
                1 for i in incidents if self._investigation_status(data, i) != "none"),
            rule_activity=[m.RuleActivity(rule_id=r, title=CATALOG[RuleId(r)].title,
                                          findings=n)
                           for r, n in data.summary["findings_by_rule"].items()],
            activity=[m.CountItem(label=k, count=v) for k, v in sorted(hours.items())],
            recent_incidents=[self.incident_summary(data, i, reviews=reviews) for i in recent],
            risk_status=self._risk_status[data.source.key],
            risk_counts={s: bands.get(s, 0) for s in SEVERITY_ORDER} if bands else None,
            risk_assessed=sum(bands.values()),
            review_counts=dict(Counter(reviews.values())),
        )

    def list_incidents(self, key: str | None, *, q: str | None, severity: list[str],
                       provenance: list[str], rule: str | None, sort: str, order: str,
                       page: int, page_size: int,
                       review: list[str] | None = None) -> m.Page[m.IncidentSummary]:
        data = self.loaded(key)
        items = data.incidents
        reviews = self.review_statuses(data)
        if review:
            items = [i for i in items if reviews[i.incident_id] in review]
        if q:
            needle = q.lower()
            items = [i for i in items if needle in i.incident_id.lower()
                     or needle in i.principal_user.lower()
                     or any(needle in h.lower() for h in i.involved_hosts)]
        if severity:
            items = [i for i in items if i.severity.value in severity]
        if provenance:
            items = [i for i in items if {d.value for d in i.datasets} & set(provenance)]
        if rule:
            items = [i for i in items if rule in i.rule_ids]
        keys = {
            "severity": _severity_rank,
            "incident_id": lambda i: i.incident_id,
            "user": lambda i: (i.principal_user, i.incident_id),
            "first_seen": lambda i: (i.first_seen, i.incident_id),
            "last_seen": lambda i: (i.last_seen, i.incident_id),
            "findings": lambda i: (len(i.findings), i.incident_id),
        }
        if sort not in keys:
            raise BadRequestError(f"cannot sort by '{sort}'")
        items = sorted(items, key=keys[sort], reverse=order == "desc")
        start = (page - 1) * page_size
        return m.Page(items=[self.incident_summary(data, i, reviews=reviews)
                             for i in items[start:start + page_size]],
                      total=len(items), page=page, page_size=page_size)

    def incident_detail(self, key: str | None, incident_id: str) -> m.IncidentDetail:
        data, inc = self.incident(key, incident_id)
        evidence = self.evidence(key)
        cited = self._cited_by(data)
        fmt = time_formatter(data.source)
        rules_per_event: dict[str, set[str]] = {}
        for f in inc.findings:
            for e in f.event_ids:
                rules_per_event.setdefault(e, set()).add(f.rule_id)
        timeline = [self.event_view(evidence[e], cited.get(e), fmt) for e in inc.event_ids
                    if e in evidence]
        description = (
            f"{inc.principal_user} triggered {len(inc.rule_ids)} detection rule(s) involving "
            f"{len(inc.involved_hosts)} host(s) between {fmt(inc.first_seen)} and "
            f"{fmt(inc.last_seen)}. Suspicious activity requiring investigation; "
            "not a confirmed compromise.")
        return m.IncidentDetail(
            **self.incident_summary(data, inc).model_dump(),
            description=description,
            involved_users=inc.involved_users,
            findings=[m.FindingView(
                finding_id=f.finding_id, rule_id=f.rule_id,
                rule_title=CATALOG[RuleId(f.rule_id)].title, severity=f.severity.value,
                description=f.description, metrics=f.metrics, event_ids=f.event_ids,
                first_seen_label=fmt(f.first_seen),
                last_seen_label=fmt(f.last_seen)) for f in inc.findings],
            severity_rationale=inc.severity_rationale,
            shared_evidence=[m.SharedEvidence(event_id=e, rule_ids=sorted(r))
                             for e, r in rules_per_event.items() if len(r) > 1],
            benign_explanations=inc.benign_explanations,
            limitations=inc.limitations,
            missing_information=inc.missing_information,
            timeline=timeline,
            missing_evidence_ids=[e for e in inc.event_ids if e not in evidence],
            assessments=self._incident_assessments(data, inc),
        )

    def incident_evidence(self, key: str | None, incident_id: str) -> list[m.EventView]:
        return self.incident_detail(key, incident_id).timeline

    def list_events(self, key: str | None, *, scope: str, q: str | None, user: str | None,
                    host: str | None, outcome: str | None, page: int,
                    page_size: int) -> m.Page[m.EventView]:
        data = self.loaded(key)
        cited = self._cited_by(data)
        if scope == "evidence":
            pool = sorted(self.evidence(key).values(), key=lambda e: (e.timestamp, e.event_id))
        else:
            if data.manifest.event_count > MAX_BROWSABLE_EVENTS:
                raise BadRequestError(
                    f"dataset has {data.manifest.event_count:,} events; browsing all events is "
                    f"limited to {MAX_BROWSABLE_EVENTS:,}. Use the evidence scope.")
            pool = self._load_all_events(data)
        if q:
            pool = [e for e in pool if q.lower() in e.event_id.lower()]
        if user:
            u = user.lower()
            pool = [e for e in pool if u in e.src_user.lower() or u in (e.dst_user or "").lower()]
        if host:
            h = host.lower()
            pool = [e for e in pool if h in e.src_host.lower() or h in e.dst_host.lower()]
        if outcome:
            pool = [e for e in pool if e.outcome.value == outcome]
        start = (page - 1) * page_size
        fmt = time_formatter(data.source)
        return m.Page(items=[self.event_view(e, cited.get(e.event_id), fmt)
                             for e in pool[start:start + page_size]],
                      total=len(pool), page=page, page_size=page_size)

    def _load_all_events(self, data: LoadedSource) -> list[AuthEvent]:
        with self._lock:
            if data.source.key not in self._all_events:
                ids = set()
                with (data.source.dataset_dir / EVENTS_FILE).open("rb") as handle:
                    for raw in handle:
                        ids.add(json.loads(raw)["event_id"])
                events = load_evidence(data.source.dataset_dir, ids)  # hash-verified
                self._all_events[data.source.key] = sorted(
                    events.values(), key=lambda e: (e.timestamp, e.event_id))
            return self._all_events[data.source.key]

    # ------------------------------------------------------------------ investigations
    def _view(self, data: LoadedSource, inc: Incident, result: InvestigationResult,
              cached: bool) -> m.InvestigationView:
        evidence = self.evidence(data.source.key)
        fmt = time_formatter(data.source)

        def ref(eid: str, notes: dict[str, str]) -> m.EvidenceRef:
            e = evidence.get(eid)
            return m.EvidenceRef(event_id=eid, relevance=notes.get(eid),
                                 time_label=fmt(e.timestamp) if e else None,
                                 path=f"{e.src_host} → {e.dst_host}" if e else None,
                                 outcome=e.outcome.value if e else None)

        hyps = {h.hypothesis_id: h for h in result.hypotheses}
        validations = {v.hypothesis_id: v for v in result.path_validations}
        c = result.conclusion
        return m.InvestigationView(
            investigation_id=investigation_id(inc), incident_id=inc.incident_id,
            source_key=data.source.key,
            status="completed" if result.source.value == "llm" else "completed_limited",
            created_at=result.created_at, cached=cached,
            conclusion=m.ConclusionView(
                most_plausible_hypothesis_id=c.most_plausible_hypothesis_id,
                most_plausible_title=hyps[c.most_plausible_hypothesis_id].title,
                summary=c.summary, confidence=c.confidence, uncertainty=c.uncertainty,
                alternative_hypothesis_ids=c.alternative_hypothesis_ids,
                next_steps=c.next_steps, evidence_gaps=c.evidence_gaps,
                is_proof_of_compromise=False),
            hypotheses=[m.HypothesisView(
                hypothesis_id=h.hypothesis_id, kind=h.kind.value, title=h.title,
                narrative=h.narrative, confidence=h.confidence,
                attack_techniques=[m.AttackTechnique(
                    id=t, name=ATTACK_NAMES.get(t),
                    url=f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/")
                    for t in h.attack_techniques],
                supporting=[ref(e, {n.event_id: n.relevance for n in h.evidence_notes})
                            for e in h.supporting_event_ids],
                contradicting=[ref(e, {n.event_id: n.relevance for n in h.evidence_notes})
                               for e in h.contradicting_event_ids],
                missing_information=h.missing_information, proposed_path=h.proposed_path,
                path_validation=validations.get(h.hypothesis_id)) for h in result.hypotheses],
            analyst_notes=[w for w in result.warnings if not w.startswith(DIAGNOSTIC_PREFIXES)],
            diagnostics=m.Diagnostics(
                engine="llm" if result.source.value == "llm" else "deterministic",
                model=result.model, latency_ms=result.latency_ms),
            structural_evidence="used" if result.structural_sha256 else "unavailable",
        )

    def saved_investigation(self, key: str | None, incident_id: str) -> m.InvestigationView:
        data, inc = self.incident(key, incident_id)
        result = load_investigation(data.source.detection_dir, inc)
        if result is None:
            raise NotFoundError(f"no investigation saved for incident '{incident_id}'")
        return self._view(data, inc, result, cached=True)

    def investigate(self, key: str | None, incident_id: str, *,
                    rerun: bool) -> m.InvestigationView:
        data, inc = self.incident(key, incident_id)
        lock_key = f"{data.source.key}|{incident_sha256(inc)}"
        with self._lock:
            lock = self._inv_locks.setdefault(lock_key, threading.Lock())
        with lock:  # a second click waits, then receives the result of the first
            if not rerun:
                saved = load_investigation(data.source.detection_dir, inc)
                if saved is not None:
                    return self._view(data, inc, saved, cached=True)
            evidence = self.evidence(data.source.key)
            events = [evidence[e] for e in inc.event_ids if e in evidence]
            is_admin = inc.principal_user in data.admin_users
            structural = self._structural_evidence(data, inc)
            try:
                if self.ai_allowed(data.source):
                    provider, reason = self.provider_factory()
                else:
                    provider, reason = None, ("AI investigation is disabled for this "
                                              "organisational source")
                result = InvestigatorAgent(provider, disabled_reason=reason).investigate(
                    inc, events, is_admin=is_admin, structural=structural,
                    agent_findings=self._agent_findings_for_prompt(data, inc))
            except Exception:  # the agent never raises for LLM issues; this is a bug guard
                logger.exception("investigation failed; retrying with deterministic analysis")
                try:
                    result = InvestigatorAgent(None, disabled_reason="internal error").investigate(
                        inc, events, is_admin=is_admin, structural=structural)
                except Exception:
                    logger.exception("deterministic investigation failed")
                    self._log("investigation.failed", inc.incident_id,
                              {"source": data.source.key})
                    raise InvestigationFailedError("investigation could not be completed") from None
            for w in result.warnings:
                if w.startswith(DIAGNOSTIC_PREFIXES):
                    logger.warning("investigation diagnostic", extra={"context": {
                        "incident": inc.incident_id, "source": data.source.key, "detail": w}})
            save_investigation(data.source.detection_dir, inc, result)
            status = "completed" if result.source.value == "llm" else "completed_limited"
            self._log(f"investigation.{status}", inc.incident_id, {
                "source": data.source.key, "engine": result.source.value,
                "latency_ms": result.latency_ms, "rerun": rerun})
            return self._view(data, inc, result, cached=False)

    def _agent_findings_for_prompt(self, data: LoadedSource, inc: Incident) -> dict | None:
        """The specialised agents' correlated findings, for the reasoning layer. An agent
        problem never blocks an investigation: it runs without them."""
        try:
            return prompt_payload(self.agent_analysis(data, inc))
        except Exception:
            logger.exception("agent analysis failed; investigating without it")
            return None

    def list_investigations(self) -> list[m.InvestigationSummary]:
        out = []
        for source in self.sources():
            directory = source.detection_dir / INVESTIGATIONS_DIR
            if not directory.is_dir():
                continue
            data = self.loaded(source.key)
            by_id = {investigation_id(i): i for i in data.incidents}
            for path in sorted(directory.glob("*.json")):
                try:
                    result = InvestigationResult.model_validate_json(
                        path.read_text(encoding="utf-8"))
                except ValueError:
                    continue
                inc = by_id.get(path.stem)
                best = next(h for h in result.hypotheses
                            if h.hypothesis_id == result.conclusion.most_plausible_hypothesis_id)
                status = ("stale" if inc is None or incident_sha256(inc) != result.incident_sha256
                          else "completed" if result.source.value == "llm"
                          else "completed_limited")
                out.append(m.InvestigationSummary(
                    investigation_id=path.stem, incident_id=result.incident_id,
                    source_key=source.key, source_label=source.label,
                    provenance=source.provenance.value,
                    principal_user=inc.principal_user if inc else None,
                    severity=inc.severity.value if inc else None,
                    conclusion=best.title, conclusion_kind=best.kind.value,
                    confidence=result.conclusion.confidence, created_at=result.created_at,
                    status=status))
        return sorted(out, key=lambda s: s.created_at, reverse=True)

    def investigation_by_id(self, key: str | None, inv_id: str) -> m.InvestigationView:
        data = self.loaded(key)
        for inc in data.incidents:
            if investigation_id(inc) == inv_id:
                return self.saved_investigation(data.source.key, inc.incident_id)
        raise NotFoundError(f"investigation '{inv_id}' not found for the current incident data")

    # ------------------------------------------------------------------ datasets & activity
    def datasets(self) -> list[m.DatasetInfo]:
        out = []
        for source in self.sources():
            try:
                data = self.loaded(source.key)
                quality = json.loads((source.dataset_dir / REPORT_JSON).read_text("utf-8"))
                start = (datetime.fromisoformat(quality["time_start"])
                         if quality["time_start"] else None)
                end = datetime.fromisoformat(quality["time_end"]) if quality["time_end"] else None
                s = data.summary
                out.append(m.DatasetInfo(
                    key=source.key, label=source.label, provenance=source.provenance.value,
                    dataset_label=data.manifest.dataset_label,
                    source_file=data.manifest.source_file,
                    parser_version=data.manifest.parser_version,
                    input_sha256=data.manifest.input_sha256,
                    events_sha256=data.manifest.events_sha256,
                    lines_read=quality["lines_read"], event_count=data.manifest.event_count,
                    rejected_count=data.manifest.rejected_count,
                    time_start_label=time_formatter(source)(start) if start else None,
                    time_end_label=time_formatter(source)(end) if end else None,
                    time_coverage_seconds=int((end - start).total_seconds()) if start else 0,
                    detection=m.DetectionRunInfo(
                        engine_version=s["engine_version"], generated_at=s["generated_at"],
                        findings=s["findings_total"], incidents=s["incidents_total"],
                        config_sha256=s["config_sha256"],
                        baseline_seconds=s["config"]["baseline_seconds"]),
                    status="verified",
                    status_detail="Manifest, event hash and detection output hashes verified.",
                    structural=self._structural_run(data), risk=self._risk_run(data)))
            except (AgentSOCError, OSError, KeyError, ValueError) as exc:
                logger.warning("dataset verification failed", extra={"context": {
                    "source": source.key, "error": type(exc).__name__}})
                out.append(m.DatasetInfo(
                    key=source.key, label=source.label, provenance=source.provenance.value,
                    dataset_label="", source_file="", parser_version="", input_sha256="",
                    events_sha256="", lines_read=0, event_count=0, rejected_count=0,
                    time_start_label=None, time_end_label=None, time_coverage_seconds=0,
                    detection=m.DetectionRunInfo(engine_version="", generated_at=datetime.now(UTC),
                                                 findings=0, incidents=0, config_sha256="",
                                                 baseline_seconds=0),
                    status="error", status_detail="Verification failed; see server logs."))
        return out

    def _structural_run(self, data: LoadedSource) -> m.AnalysisRunInfo:
        self._structural_for(data)
        status = self._structural_status[data.source.key]
        if status.state != "available":
            return m.AnalysisRunInfo(**status.model_dump())
        s = load_structural_summary(data.source.detection_dir)
        return m.AnalysisRunInfo(
            **status.model_dump(), engine_version=s.engine_version,
            config_sha256=s.structural_config_sha256, output_sha256=s.assessments_sha256,
            generated_at=s.generated_at, records=s.incidents_assessed,
            truncated_records=s.truncated_incidents)

    def _risk_run(self, data: LoadedSource) -> m.AnalysisRunInfo:
        self._risk_for(data)
        status = self._risk_status[data.source.key]
        if status.state != "available":
            return m.AnalysisRunInfo(**status.model_dump())
        s = load_risk_summary(data.source.detection_dir)
        return m.AnalysisRunInfo(
            **status.model_dump(), engine_version=s.engine_version,
            config_sha256=s.risk_config_sha256, output_sha256=s.records_sha256,
            generated_at=s.generated_at, records=s.incidents_scored)

    def _log(self, event_type: str, subject: str, details: dict) -> None:
        """Append to the hash-chained activity log as the current actor. Best effort: a
        logging failure never fails the analyst's request (it goes to the server log)."""
        self.audit.append(event_type, subject, details)

    def _read_activity(self) -> list[AuditRecord]:
        return self.audit.read()

    def activity(self, limit: int, *, subject: str | None = None,
                 source: str | None = None) -> m.ActivityLog:
        with self._activity_lock:
            everything = self._read_activity()
        # Incident IDs repeat between sources, so an incident's trail needs both filters.
        records = [r for r in everything
                   if (subject is None or r.subject_id == subject)
                   and (source is None or r.details.get("source") == source)]
        return m.ActivityLog(
            entries=[m.ActivityEntry(**r.model_dump(include={
                "sequence", "timestamp", "actor", "event_type", "subject_id", "details"}))
                for r in reversed(records[-limit:])],
            total=len(records), chain_intact=verify_chain(everything) is None)

    def health(self) -> m.Health:
        provider, _ = self.provider_factory()
        return m.Health(status="ok", version=__version__,
                        analysis="available" if provider is not None else "limited",
                        sources=len(self.sources()))
