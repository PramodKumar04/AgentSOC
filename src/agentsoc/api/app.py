"""FastAPI application.

    uvicorn agentsoc.api.app:app --port 8000

Endpoints are synchronous `def`s: FastAPI runs them in a worker thread pool, so a
slow LLM investigation does not block other requests.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi import Path as PathParam
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from agentsoc import __version__
from agentsoc.api import models as m
from agentsoc.api.datasources import datasource_router
from agentsoc.api.review_service import ReviewRequestError
from agentsoc.api.service import (
    BadRequestError,
    InvestigationFailedError,
    NotFoundError,
    Service,
)
from agentsoc.auth.api import CurrentUser, auth_router, current_user, require_csrf
from agentsoc.auth.service import AuthService
from agentsoc.config import PROJECT_ROOT, get_settings
from agentsoc.credentials import open_credential_store
from agentsoc.exceptions import AgentSOCError
from agentsoc.logging_setup import configure_logging, get_logger
from agentsoc.orgsource.manager import DataSourceManager, SyncScheduler
from agentsoc.review.report import render_markdown
from agentsoc.schemas.graph import StructuralAssessment
from agentsoc.schemas.graph_view import IncidentGraph

logger = get_logger(__name__)
FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"

IncidentId = Annotated[str, PathParam(pattern=r"^[A-Za-z0-9_.\-]{1,64}$")]
SourceKey = Annotated[str | None, Query(max_length=128, pattern=r"^[A-Za-z0-9_.:\-]+$")]
PageNo = Annotated[int, Query(ge=1, le=100_000)]
PageSize = Annotated[int, Query(ge=1, le=200)]
SearchText = Annotated[str | None, Query(max_length=128)]


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"),
}


def create_app(service: Service | None = None, *, serve_frontend: bool = True,
               auth: AuthService | None = None, datasources: DataSourceManager | None = None,
               start_scheduler: bool = False) -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level, settings.secret_values())
    svc = service or Service()
    manager = datasources or DataSourceManager(
        svc.datasources, open_credential_store(svc.app_db, settings.credential_key, svc.audit),
        svc.audit, svc.root, on_snapshot=svc.refresh_sources)
    scheduler = SyncScheduler(manager) if start_scheduler else None

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if scheduler is not None:
            scheduler.start()
        try:
            yield
        finally:
            if scheduler is not None:
                scheduler.stop()

    app = FastAPI(title="AgentSOC API", version=__version__, lifespan=lifespan,
                  description="AI-assisted SOC incident investigation (research prototype).")
    app.state.auth = auth or AuthService(svc.app_db, svc.audit, settings)
    app.state.datasources = manager
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
        allow_credentials=True,
    )

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # Everything except health and sign-in needs a session.
    protected = APIRouter(dependencies=[Depends(current_user)])

    @app.exception_handler(NotFoundError)
    def _not_found(_: Request, exc: NotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(BadRequestError)
    def _bad_request(_: Request, exc: BadRequestError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(ReviewRequestError)
    def _review_refused(_: Request, exc: ReviewRequestError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(InvestigationFailedError)
    def _inv_failed(_: Request, exc: InvestigationFailedError) -> JSONResponse:
        return JSONResponse(status_code=503, content={
            "detail": "The investigation could not be completed. Please try again later."})

    @app.exception_handler(AgentSOCError)
    def _integrity(_: Request, exc: AgentSOCError) -> JSONResponse:
        logger.error("data error", extra={"context": {"type": type(exc).__name__}})
        return JSONResponse(status_code=500, content={
            "detail": "Data could not be loaded or failed integrity verification."})

    @app.exception_handler(Exception)
    def _unexpected(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error")
        return JSONResponse(status_code=500, content={"detail": "Internal server error."})

    @app.get("/api/health", response_model=m.Health)
    def health() -> m.Health:
        return svc.health()

    @protected.get("/api/sources", response_model=list[m.SourceRef])
    def sources() -> list[m.SourceRef]:
        return svc.source_refs()

    @protected.get("/api/overview", response_model=m.Overview)
    def overview(source: SourceKey = None) -> m.Overview:
        return svc.overview(source)

    @protected.get("/api/incidents", response_model=m.Page[m.IncidentSummary])
    def incidents(
        source: SourceKey = None, q: SearchText = None,
        severity: Annotated[list[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]],
                            Query()] = [],  # noqa: B006 — FastAPI query lists
        provenance: Annotated[list[m.Provenance], Query()] = [],  # noqa: B006
        rule: Annotated[str | None, Query(max_length=64)] = None,
        sort: Literal["severity", "incident_id", "user", "first_seen", "last_seen",
                      "findings"] = "severity",
        order: Literal["asc", "desc"] = "asc",
        page: PageNo = 1, page_size: PageSize = 25,
        review: Annotated[list[m.ReviewStatus], Query()] = [],  # noqa: B006
    ) -> m.Page[m.IncidentSummary]:
        return svc.list_incidents(source, q=q, severity=list(severity),
                                  provenance=list(provenance), rule=rule, sort=sort,
                                  order=order, page=page, page_size=page_size,
                                  review=list(review))

    # Human in the loop: the analyst decides; AgentSOC records, gathers context, reports.
    @protected.get("/api/incidents/{incident_id}/review", response_model=m.ReviewState)
    def incident_review(incident_id: IncidentId, source: SourceKey = None) -> m.ReviewState:
        return svc.incident_review(source, incident_id)

    @protected.post("/api/incidents/{incident_id}/review", response_model=m.ReviewState,
                    dependencies=[Depends(require_csrf)])
    def submit_review(incident_id: IncidentId, body: m.ReviewRequest, user: CurrentUser,
                      source: SourceKey = None) -> m.ReviewState:
        return svc.submit_review(source, incident_id, body, analyst=user.username)

    @protected.get("/api/incidents/{incident_id}/context", response_model=m.ContextView)
    def incident_context(incident_id: IncidentId, source: SourceKey = None,
                         window_hours: Annotated[int, Query(ge=1, le=72)] = 24,
                         ) -> m.ContextView:
        return svc.incident_context(source, incident_id, window_hours)

    @protected.get("/api/incidents/{incident_id}/agents", response_model=m.AgentAnalysisView)
    def incident_agents(incident_id: IncidentId, source: SourceKey = None,
                        window_hours: Annotated[int | None, Query(ge=1, le=72)] = None,
                        ) -> m.AgentAnalysisView:
        """Orchestrated specialised agents. `window_hours`: the analyst asked for more."""
        return svc.incident_agents(source, incident_id, window_hours)

    @protected.get("/api/incidents/{incident_id}/report", response_model=m.ReportView)
    def incident_report(incident_id: IncidentId, user: CurrentUser,
                        source: SourceKey = None) -> m.ReportView:
        return svc.incident_report(source, incident_id, generated_by=user.username)

    @protected.get("/api/incidents/{incident_id}/report.md")
    def incident_report_markdown(incident_id: IncidentId, user: CurrentUser,
                                 source: SourceKey = None) -> Response:
        report = svc.incident_report(source, incident_id, generated_by=user.username)
        svc.report_exported(source, incident_id, analyst=user.username)
        name = f"agentsoc-{report.incident.source_key}-{report.incident.incident_id}.md"
        return Response(render_markdown(report), media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @protected.get("/api/incidents/{incident_id}", response_model=m.IncidentDetail)
    def incident(incident_id: IncidentId, source: SourceKey = None) -> m.IncidentDetail:
        return svc.incident_detail(source, incident_id)

    @protected.get("/api/incidents/{incident_id}/structure", response_model=StructuralAssessment)
    def incident_structure(incident_id: IncidentId,
                           source: SourceKey = None) -> StructuralAssessment:
        return svc.incident_structure(source, incident_id)

    @protected.get("/api/incidents/{incident_id}/graph", response_model=IncidentGraph)
    def incident_graph(incident_id: IncidentId, source: SourceKey = None) -> IncidentGraph:
        return svc.incident_graph(source, incident_id)

    @protected.get("/api/incidents/{incident_id}/risk", response_model=m.RiskView)
    def incident_risk(incident_id: IncidentId, source: SourceKey = None) -> m.RiskView:
        return svc.incident_risk(source, incident_id)

    @protected.get("/api/incidents/{incident_id}/evidence", response_model=list[m.EventView])
    def incident_evidence(incident_id: IncidentId,
                          source: SourceKey = None) -> list[m.EventView]:
        return svc.incident_evidence(source, incident_id)

    @protected.get("/api/incidents/{incident_id}/investigation", response_model=m.InvestigationView)
    def incident_investigation(incident_id: IncidentId,
                               source: SourceKey = None) -> m.InvestigationView:
        return svc.saved_investigation(source, incident_id)

    @protected.post("/api/incidents/{incident_id}/investigate", response_model=m.InvestigationView,
                    dependencies=[Depends(require_csrf)])
    def investigate(incident_id: IncidentId, source: SourceKey = None,
                    rerun: bool = False) -> m.InvestigationView:
        return svc.investigate(source, incident_id, rerun=rerun)

    @protected.get("/api/investigations", response_model=list[m.InvestigationSummary])
    def investigations() -> list[m.InvestigationSummary]:
        return svc.list_investigations()

    @protected.get("/api/investigations/{investigation_id}", response_model=m.InvestigationView)
    def investigation(
        investigation_id: Annotated[str, PathParam(pattern=r"^[A-Za-z0-9_.\-]{1,96}$")],
        source: SourceKey = None,
    ) -> m.InvestigationView:
        return svc.investigation_by_id(source, investigation_id)

    @protected.get("/api/events", response_model=m.Page[m.EventView])
    def events(
        source: SourceKey = None, scope: Literal["evidence", "all"] = "evidence",
        q: SearchText = None, user: SearchText = None, host: SearchText = None,
        outcome: Literal["Success", "Fail"] | None = None,
        page: PageNo = 1, page_size: PageSize = 50,
    ) -> m.Page[m.EventView]:
        return svc.list_events(source, scope=scope, q=q, user=user, host=host,
                               outcome=outcome, page=page, page_size=page_size)

    @protected.get("/api/datasets", response_model=list[m.DatasetInfo])
    def datasets() -> list[m.DatasetInfo]:
        return svc.datasets()

    @protected.get("/api/activity", response_model=m.ActivityLog)
    def activity(
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        subject: Annotated[str | None, Query(max_length=128,
                                             pattern=r"^[A-Za-z0-9_.:\-]+$")] = None,
        source: SourceKey = None,
    ) -> m.ActivityLog:
        return svc.activity(limit, subject=subject, source=source)

    app.include_router(auth_router(settings.cookie_secure, settings.session_max_hours * 3600))
    app.include_router(protected)
    app.include_router(datasource_router())

    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PATCH", "DELETE"],
                 include_in_schema=False)
    def unknown_api(path: str) -> None:
        raise HTTPException(status_code=404, detail="Unknown API endpoint.")

    if serve_frontend and (FRONTEND_DIST / "index.html").is_file():
        # Single-process option: serve the built React app (SPA fallback to index.html).
        app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str) -> FileResponse:
            candidate = (FRONTEND_DIST / path).resolve()
            if path and candidate.is_file() and Path(FRONTEND_DIST) in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(FRONTEND_DIST / "index.html")

    return app


app = create_app(start_scheduler=get_settings().sync_scheduler)
