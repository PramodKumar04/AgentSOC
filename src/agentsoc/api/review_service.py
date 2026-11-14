"""Analyst review (human in the loop), wider context and the full incident report.

Mixed into `Service`. Decisions are recorded, audited and shown; they never trigger an
action. The context and the report only read the verified data.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from agentsoc.agents.base import InvestigationTask
from agentsoc.agents.orchestrator import AgentAnalysis, orchestrate
from agentsoc.agents.response import ResponsePlan, plan_response
from agentsoc.agents.threat_intel import TECHNIQUES
from agentsoc.api import models as m
from agentsoc.app_data import LoadedSource, time_formatter
from agentsoc.audit import AuditEventType
from agentsoc.detection.config import DetectionConfig
from agentsoc.investigator.agent import incident_sha256
from agentsoc.review.context import build_context
from agentsoc.review.store import (
    CONTEXT_WINDOWS,
    Decision,
    ReviewEntry,
    ReviewStatus,
    ReviewStore,
    status_of,
)
from agentsoc.schemas import Incident

AUDIT_FOR = {
    Decision.ACCEPTED: AuditEventType.INCIDENT_ACCEPTED,
    Decision.DISMISSED: AuditEventType.INCIDENT_DISMISSED,
    Decision.MORE_EVIDENCE: AuditEventType.INCIDENT_EVIDENCE_REQUESTED,
    Decision.REOPENED: AuditEventType.INCIDENT_REOPENED,
}
DEFAULT_WINDOW = 24


class ReviewRequestError(ValueError):
    pass


class ReviewMixin:
    _reviews: ReviewStore | None = None

    @property
    def reviews(self) -> ReviewStore:
        if self._reviews is None:
            self._reviews = ReviewStore(self.app_db)
        return self._reviews

    # -- status --------------------------------------------------------------------------------
    def review_statuses(self, data: LoadedSource) -> dict[str, str]:
        latest = self.reviews.latest_by_incident(data.source.key)
        return {i.incident_id: status_of(latest.get(i.incident_id), incident_sha256(i)).value
                for i in data.incidents}

    def review_counts(self, data: LoadedSource) -> dict[str, int]:
        counts = Counter(self.review_statuses(data).values())
        return {s.value: counts.get(s.value, 0) for s in ReviewStatus}

    @staticmethod
    def _entry_view(entry: ReviewEntry, sha: str) -> m.ReviewEntryView:
        return m.ReviewEntryView(decision=entry.decision.value, reason=entry.reason,
                                 note=entry.note, window_hours=entry.window_hours,
                                 analyst=entry.analyst,
                                 created_at=datetime.fromisoformat(entry.created_at),
                                 current_version=entry.incident_sha256 == sha)

    def _review_state(self, data: LoadedSource, inc: Incident) -> m.ReviewState:
        sha = incident_sha256(inc)
        history = self.reviews.history(data.source.key, inc.incident_id)
        latest = history[-1] if history else None
        return m.ReviewState(
            status=status_of(latest, sha).value,
            latest=self._entry_view(latest, sha) if latest else None,
            history=[self._entry_view(e, sha) for e in reversed(history)])

    def incident_review(self, key: str | None, incident_id: str) -> m.ReviewState:
        data, inc = self.incident(key, incident_id)
        return self._review_state(data, inc)

    def submit_review(self, key: str | None, incident_id: str, request: m.ReviewRequest, *,
                      analyst: str) -> m.ReviewState:
        data, inc = self.incident(key, incident_id)
        decision = Decision(request.decision)
        note = (request.note or "").strip() or None
        reason = request.reason
        window = request.window_hours
        if decision is Decision.DISMISSED:
            if reason is None:
                raise ReviewRequestError("Choose why the incident is being dismissed.")
            if reason == "other" and not note:
                raise ReviewRequestError("Explain the reason in the note.")
        elif reason is not None:
            raise ReviewRequestError("A reason is only recorded when dismissing.")
        if decision is Decision.MORE_EVIDENCE:
            window = window or DEFAULT_WINDOW
        elif window is not None:
            raise ReviewRequestError("A time window is only used when requesting evidence.")
        entry = self.reviews.add(
            source_key=data.source.key, incident_id=inc.incident_id,
            incident_sha256=incident_sha256(inc), decision=decision, reason=reason, note=note,
            window_hours=window, analyst=analyst)
        details: dict[str, object] = {"source": data.source.key, "review": entry.id}
        if reason:
            details["reason"] = reason
        if window:
            details["window_hours"] = window
        if note:
            details["note_chars"] = len(note)  # the note itself stays in the review record
        self.audit.append(AUDIT_FOR[decision], inc.incident_id, details, actor=analyst)
        return self._review_state(data, inc)

    # -- more evidence -------------------------------------------------------------------------
    def incident_context(self, key: str | None, incident_id: str,
                         window_hours: int = DEFAULT_WINDOW) -> m.ContextView:
        if window_hours not in CONTEXT_WINDOWS:
            raise ReviewRequestError(f"window must be one of {CONTEXT_WINDOWS} hours")
        data, inc = self.incident(key, incident_id)
        fmt = time_formatter(data.source)
        events = self._load_all_events(data)
        context = build_context(inc, events, data.incidents, window_hours, fmt)
        statuses = self.review_statuses(data)
        cited = self._cited_by(data)
        return m.ContextView(
            window_hours=context.window_hours, window_start_label=fmt(context.window_start),
            window_end_label=fmt(context.window_end), account=context.account,
            account_events=context.account_events, account_failures=context.account_failures,
            account_before=context.account_before, account_after=context.account_after,
            account_src_hosts=context.account_src_hosts,
            account_dst_hosts=context.account_dst_hosts,
            account_first_seen_label=fmt(context.account_first_seen)
            if context.account_first_seen else None,
            events=[self.event_view(e, cited.get(e.event_id), fmt) for e in context.events],
            events_truncated=context.events_truncated,
            hosts=[m.HostActivityView(host=h.host, events=h.events, failures=h.failures,
                                      other_accounts=[m.CountItem(label=u, count=n)
                                                      for u, n in h.other_accounts])
                   for h in context.hosts],
            pairs=[m.PairHistoryView(src_host=p.src_host, dst_host=p.dst_host, before=p.before,
                                     first_seen_label=fmt(p.first_seen) if p.first_seen
                                     else None, after=p.after) for p in context.pairs],
            related=[m.RelatedIncidentView(
                incident_id=r.incident_id, principal_user=r.principal_user,
                severity=r.severity, first_seen_label=fmt(r.first_seen),
                last_seen_label=fmt(r.last_seen), relation=r.relation,
                review_status=statuses.get(r.incident_id, "open")) for r in context.related],
            observations=context.observations, limitations=context.limitations)

    # -- specialised agents ------------------------------------------------------------------
    def agent_analysis(self, data: LoadedSource, inc: Incident,
                       window_hours: int | None = None) -> AgentAnalysis:
        """Run the orchestrator: identity, network/host, threat-intel and endpoint agents in
        parallel, then the correlation agent. `window_hours` is the analyst's request for
        more evidence; None is the standard run."""
        return orchestrate(self.agent_task(data, inc, window_hours))

    def agent_task(self, data: LoadedSource, inc: Incident,
                   window_hours: int | None = None) -> InvestigationTask:
        if window_hours is not None and window_hours not in CONTEXT_WINDOWS:
            raise ReviewRequestError(f"window must be one of {CONTEXT_WINDOWS} hours")
        structural = self._structural_for(data)[0].get(inc.incident_id)
        if structural is not None and structural.incident_sha256 != incident_sha256(inc):
            structural = None
        task = InvestigationTask(
            incident=inc, events=self._load_all_events(data), incidents=data.incidents,
            detection=DetectionConfig.model_validate(data.summary["config"]),
            structural=structural, label=time_formatter(data.source),
            relative_time=data.source.time_display == "relative", window_hours=window_hours)
        return task

    @staticmethod
    def _technique(t: str) -> m.AttackTechnique:
        url = "https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/"
        return m.AttackTechnique(id=t, name=TECHNIQUES.get(t, (None,))[0], url=url)

    def _analysis_view(self, data: LoadedSource, a: AgentAnalysis) -> m.AgentAnalysisView:
        c = a.correlation
        return m.AgentAnalysisView(
            incident_id=a.incident_id, source_key=data.source.key,
            mode="expanded" if a.window_hours else "standard", window_hours=a.window_hours,
            generated_at=a.generated_at, duration_ms=a.duration_ms,
            agents=[m.AgentReportView(
                agent=r.agent, title=r.title, purpose=r.purpose, status=r.status.value,
                examined=r.examined, gaps=r.gaps, duration_ms=r.duration_ms,
                findings=[m.AgentFindingView(
                    statement=f.statement, stance=f.stance.value, strength=f.strength.value,
                    accounts=list(f.accounts), hosts=list(f.hosts),
                    event_ids=list(f.event_ids),
                    techniques=[self._technique(t) for t in f.techniques], expanded=f.expanded)
                    for f in r.findings]) for r in a.reports],
            correlation=m.CorrelationView(
                summary=c.summary, corroborated=c.corroborated, conflicts=c.conflicts,
                techniques=[self._technique(t) for t in c.techniques],
                open_questions=c.open_questions, unavailable_agents=c.unavailable_agents,
                counts=c.counts,
                entities=[m.CorrelatedEntityView(kind=e.kind, name=e.name,
                                                 suspicious_agents=e.suspicious_agents,
                                                 benign_agents=e.benign_agents,
                                                 findings=e.findings) for e in c.entities]))

    def incident_agents(self, key: str | None, incident_id: str,
                        window_hours: int | None = None) -> m.AgentAnalysisView:
        data, inc = self.incident(key, incident_id)
        return self._agents_with_plan(data, inc, window_hours)

    def _agents_with_plan(self, data: LoadedSource, inc: Incident,
                          window_hours: int | None) -> m.AgentAnalysisView:
        task = self.agent_task(data, inc, window_hours)
        analysis = orchestrate(task)
        view = self._analysis_view(data, analysis)
        view.response_plan = self._plan_view(self.response_plan(data, inc, task, analysis))
        return view

    def response_plan(self, data: LoadedSource, inc: Incident, task: InvestigationTask,
                      analysis: AgentAnalysis) -> ResponsePlan:
        """How to stop the activity: recommendations from the agents' evidence. Never executed."""
        proposed: list = []
        try:
            record = self._risk_for(data)[0].get(inc.incident_id)
            if record is not None:
                proposed = [(a.action_type, a.target) for a in record.actions]
        except Exception:  # the plan does not depend on the risk engine being available
            proposed = []
        dismissed = self._review_state(data, inc).status == ReviewStatus.DISMISSED.value
        return plan_response(task, analysis.reports, analysis.correlation,
                             proposed=proposed, dismissed=dismissed)

    @staticmethod
    def _plan_view(plan: ResponsePlan) -> m.ResponsePlanView:
        return m.ResponsePlanView(
            posture=plan.posture.value, summary=plan.summary, notes=plan.notes,
            steps=[m.ResponseStepView(
                phase=s.phase.value, action=s.action, target=s.target, why=s.why,
                based_on=list(s.based_on),
                action_type=s.action_type.value if s.action_type else None,
                risk_engine_proposed=s.risk_engine_proposed, disruptive=s.disruptive)
                for s in plan.steps])

    # -- report --------------------------------------------------------------------------------
    def incident_report(self, key: str | None, incident_id: str, *,
                        generated_by: str) -> m.ReportView:
        from agentsoc.api.service import NotFoundError

        data, inc = self.incident(key, incident_id)
        detail = self.incident_detail(data.source.key, inc.incident_id)
        review = self._review_state(data, inc)
        notices = [
            "Detection severity and risk are triage aids. Nothing in this report proves a "
            "compromise.",
            "Proposed response actions are dry-run proposals. AgentSOC has not executed any "
            "of them.",
        ]
        try:
            risk, risk_unavailable = self.incident_risk(data.source.key, inc.incident_id), None
        except NotFoundError:
            risk, risk_unavailable = None, "No verified risk assessment for this incident."
        try:
            structure = self.incident_structure(data.source.key, inc.incident_id)
            paths = [m.PathBrief(path_id=p.path_id, kind=p.kind.value, verdict=p.verdict.value,
                                 hosts=p.hosts, accounts=p.accounts, reasons=p.reasons)
                     for p in structure.paths]
            paths_unavailable = None
        except NotFoundError:
            paths, paths_unavailable = [], "No verified structural assessment for this incident."
        try:
            investigation = self.saved_investigation(data.source.key, inc.incident_id)
        except NotFoundError:
            investigation = None
            notices.append("No investigation has been run for this incident.")
        context = None
        requested = [e for e in review.history
                     if e.decision == "more_evidence" and e.current_version]
        window = (requested[0].window_hours or DEFAULT_WINDOW) if requested else None
        if window is not None:
            context = self.incident_context(data.source.key, inc.incident_id, window)
        agents = self._agents_with_plan(data, inc, window)
        if inc.datasets and data.source.provenance.value == "synthetic":
            notices.insert(0, "SYNTHETIC DATA: generated for demonstration; not real activity.")
        return m.ReportView(
            generated_at=datetime.now(UTC), generated_by=generated_by,
            source_label=data.source.label, dataset_label=data.manifest.dataset_label,
            dataset_sha256=data.manifest.events_sha256,
            detection_engine=str(data.summary.get("engine_version", "")),
            incident=detail, review=review, risk=risk, risk_unavailable=risk_unavailable,
            paths=paths, paths_unavailable=paths_unavailable, investigation=investigation,
            context=context, agents=agents, notices=notices)

    def report_exported(self, key: str | None, incident_id: str, *, analyst: str) -> None:
        data, inc = self.incident(key, incident_id)
        self.audit.append(AuditEventType.INCIDENT_REPORT_EXPORTED, inc.incident_id,
                          {"source": data.source.key, "format": "markdown"}, actor=analyst)
