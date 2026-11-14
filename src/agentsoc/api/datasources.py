"""Organisational data sources over HTTP.

`/api/admin/datasources*` is for administrators only (and needs the CSRF header for every
change). `/api/datasources/organisation` lets every signed-in user see what is connected and
how fresh it is, without connection details. Passwords are accepted, never returned.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field, SecretStr, StringConstraints, model_validator

from agentsoc.auth.api import AdminUser, current_user, require_admin, require_csrf
from agentsoc.connectors.base import ConnectorError, TableRef
from agentsoc.connectors.settings import ConnectionSettings, with_engine
from agentsoc.credentials import CredentialError, CredentialStoreUnavailableError
from agentsoc.ingest.mapping import ColumnName, MappingSpec
from agentsoc.orgsource.manager import DataSourceManager, SourceStatus
from agentsoc.orgsource.registry import DataSourceConfig, DataSourceError, SourceKey, TableName
from agentsoc.orgsource.snapshot import SnapshotError
from agentsoc.orgsource.staging import RunRecord, SyncBusyError

Password = Annotated[SecretStr, Field(max_length=256)]
DisplayName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1,
                                                max_length=80)]
AI_WARNING = ("Investigating an incident from this source with AI sends the incident's "
              "evidence (user names, host names, times and outcomes from your database) to the "
              "external language-model provider configured on this server.")


class ConnectionBody(BaseModel):
    connection: ConnectionSettings
    password: Password | None = None
    key: SourceKey | None = None  # use the stored password of this source

    @model_validator(mode="before")
    @classmethod
    def _engine_default(cls, data: object) -> object:
        # Requests from before MySQL support carry no engine: they mean PostgreSQL.
        if isinstance(data, dict) and isinstance(data.get("connection"), dict):
            data = {**data, "connection": with_engine(data["connection"])}
        return data


class TableBody(ConnectionBody):
    table: TableName


class PreviewBody(TableBody):
    cursor_column: ColumnName
    mapping: MappingSpec


class CreateBody(BaseModel):
    key: SourceKey
    name: DisplayName
    config: DataSourceConfig
    password: Password


class PatchBody(BaseModel):
    name: DisplayName | None = None
    sync_enabled: bool | None = None
    sync_interval_seconds: int | None = Field(default=None, ge=30, le=86_400)
    ai_enabled: bool | None = None
    # Enabling AI requires the administrator to have seen and accepted AI_WARNING.
    ai_risk_acknowledged: bool = False


class PasswordBody(BaseModel):
    password: Password


class ReportView(BaseModel):
    server_version: str
    account: str
    read_only_session: bool
    warnings: list[str]


class TableView(BaseModel):
    schema_name: str = Field(serialization_alias="schema")
    name: str


class ColumnView(BaseModel):
    name: str
    data_type: str
    nullable: bool


class PreviewEvent(BaseModel):
    event_id: str
    time: str
    src_user: str
    dst_user: str | None
    src_host: str
    dst_host: str
    auth_type: str | None
    logon_type: str | None
    orientation: str
    outcome: str


class PreviewReject(BaseModel):
    row: int
    reason: str
    field: str | None
    detail: str


class PreviewView(BaseModel):
    rows_read: int
    accepted: list[PreviewEvent]
    rejected: list[PreviewReject]
    disclosures: list[str]


class RunView(BaseModel):
    id: int
    trigger: str
    started_at: str
    finished_at: str | None
    status: str
    fetched: int
    new: int
    duplicates: int
    changed: int
    rejected: int
    more_available: bool
    error: str | None


class SnapshotView(BaseModel):
    created_at: str
    event_count: int
    incident_count: int
    first_event: str
    last_event: str


class StatsView(BaseModel):
    accepted: int
    rejected: int
    changed: int
    rejected_by_reason: dict[str, int]
    first_event: str | None
    last_event: str | None


class OrgSourceView(BaseModel):
    """What any signed-in user may see."""

    key: str
    dashboard_key: str
    name: str
    kind: str
    mode: str
    sync_enabled: bool
    sync_interval_seconds: int
    ai_enabled: bool
    disclosures: list[str]
    stats: StatsView
    last_run: RunView | None
    snapshot: SnapshotView | None


class AdminSourceView(OrgSourceView):
    connection: ConnectionSettings
    table: TableView
    cursor_column: str
    lookback: int
    batch_size: int
    max_rows_per_sync: int
    mapping: MappingSpec
    has_password: bool
    ai_changed_by: str | None
    ai_changed_at: str | None
    ai_warning: str
    created_by: str
    created_at: str
    runs: list[RunView]
    connection_warnings: list[str]


def _run(run: RunRecord) -> RunView:
    return RunView(id=run.id, trigger=run.trigger, started_at=run.started_at,
                   finished_at=run.finished_at, status=run.status, fetched=run.fetched,
                   new=run.new, duplicates=run.duplicates, changed=run.changed,
                   rejected=run.rejected, more_available=run.more_available, error=run.error)


def _public(status: SourceStatus) -> dict:
    s, st, cfg = status.source, status.stats, status.source.config
    snap = status.snapshot
    return {
        "key": s.key, "dashboard_key": s.dashboard_key, "name": s.name, "kind": cfg.kind,
        "mode": (f"Polling every {cfg.sync_interval_seconds} s, then a new snapshot at most "
                 f"every {cfg.snapshot.min_interval_seconds} s. Not real-time."),
        "sync_enabled": s.sync_enabled, "sync_interval_seconds": cfg.sync_interval_seconds,
        "ai_enabled": s.ai_enabled, "disclosures": cfg.mapping.disclosures(),
        "stats": StatsView(accepted=st.accepted, rejected=st.rejected, changed=st.changed,
                           rejected_by_reason=st.rejected_by_reason,
                           first_event=st.first_event.isoformat() if st.first_event else None,
                           last_event=st.last_event.isoformat() if st.last_event else None),
        "last_run": _run(status.runs[0]) if status.runs else None,
        "snapshot": SnapshotView(**{k: snap[k] for k in SnapshotView.model_fields})
        if snap else None,
    }


def _admin(status: SourceStatus) -> AdminSourceView:
    s, cfg = status.source, status.source.config
    return AdminSourceView(
        **_public(status), connection=cfg.connection,
        table=TableView(schema_name=cfg.table.schema_name, name=cfg.table.name),
        cursor_column=cfg.cursor_column, lookback=cfg.lookback, batch_size=cfg.batch_size,
        max_rows_per_sync=cfg.max_rows_per_sync, mapping=cfg.mapping,
        has_password=status.has_password, ai_changed_by=s.ai_changed_by,
        ai_changed_at=s.ai_changed_at, ai_warning=AI_WARNING, created_by=s.created_by,
        created_at=s.created_at, runs=[_run(r) for r in status.runs],
        connection_warnings=cfg.connection.warnings())


def _manager(request: Request) -> DataSourceManager:
    return request.app.state.datasources


async def _call(fn, *args, **kwargs):
    """Run blocking database work off the event loop; turn known failures into HTTP errors."""
    try:
        return await run_in_threadpool(fn, *args, **kwargs)
    except CredentialStoreUnavailableError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    except SyncBusyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    except (ConnectorError, SnapshotError) as exc:
        raise HTTPException(status_code=502 if isinstance(exc, ConnectorError) else 409,
                            detail=str(exc)) from None
    except DataSourceError as exc:
        code = 404 if str(exc).startswith("unknown data source") else 400
        raise HTTPException(status_code=code, detail=str(exc)) from None
    except CredentialError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


def datasource_router() -> APIRouter:
    admin = APIRouter(prefix="/api/admin/datasources",
                      dependencies=[Depends(require_admin), Depends(require_csrf)])
    public = APIRouter(prefix="/api/datasources", dependencies=[Depends(current_user)])

    @public.get("/organisation", response_model=list[OrgSourceView])
    async def organisation(request: Request) -> list[OrgSourceView]:
        mgr = _manager(request)
        sources = await _call(mgr.registry.list)
        statuses = [await _call(mgr.status, s.key) for s in sources]
        return [OrgSourceView(**_public(st)) for st in statuses]

    @admin.get("", response_model=list[AdminSourceView])
    async def list_sources(request: Request) -> list[AdminSourceView]:
        mgr = _manager(request)
        sources = await _call(mgr.registry.list)
        return [_admin(await _call(mgr.status, s.key)) for s in sources]

    @admin.get("/{key}", response_model=AdminSourceView)
    async def get_source(key: SourceKey, request: Request) -> AdminSourceView:
        return _admin(await _call(_manager(request).status, key))

    @admin.post("/test", response_model=ReportView)
    async def test(body: ConnectionBody, request: Request) -> ReportView:
        report = await _call(_manager(request).test, body.connection, body.password, body.key)
        return ReportView(server_version=report.server_version, account=report.account,
                          read_only_session=report.read_only_session, warnings=report.warnings)

    @admin.post("/tables", response_model=list[TableView])
    async def tables(body: ConnectionBody, request: Request) -> list[TableView]:
        found = await _call(_manager(request).tables, body.connection, body.password, body.key)
        return [TableView(schema_name=t.schema, name=t.name) for t in found]

    @admin.post("/columns", response_model=list[ColumnView])
    async def columns(body: TableBody, request: Request) -> list[ColumnView]:
        table = TableRef(body.table.schema_name, body.table.name)
        found = await _call(_manager(request).columns, body.connection, body.password,
                            body.key, table)
        return [ColumnView(name=c.name, data_type=c.data_type, nullable=c.nullable)
                for c in found]

    @admin.post("/preview", response_model=PreviewView)
    async def preview(body: PreviewBody, request: Request) -> PreviewView:
        table = TableRef(body.table.schema_name, body.table.name)
        result = await _call(_manager(request).preview, body.connection, body.password,
                             body.key, table, body.cursor_column, body.mapping)
        return PreviewView(
            rows_read=result.rows_read,
            accepted=[PreviewEvent(
                event_id=e.event_id, time=e.timestamp.isoformat(), src_user=e.src_user,
                dst_user=e.dst_user, src_host=e.src_host, dst_host=e.dst_host,
                auth_type=e.auth_type, logon_type=e.logon_type,
                orientation=e.orientation.value, outcome=e.outcome.value)
                for e in result.events],
            rejected=[PreviewReject(row=r.line, reason=r.reason.value, field=r.field,
                                    detail=r.detail) for r in result.rejected],
            disclosures=result.disclosures)

    @admin.post("", response_model=AdminSourceView, status_code=201)
    async def create(body: CreateBody, request: Request, user: AdminUser) -> AdminSourceView:
        mgr = _manager(request)
        await _call(mgr.create, body.key, body.name, body.config, body.password,
                    actor=user.username)
        return _admin(await _call(mgr.status, body.key))

    @admin.patch("/{key}", response_model=AdminSourceView)
    async def update(key: SourceKey, body: PatchBody, request: Request,
                     user: AdminUser) -> AdminSourceView:
        if body.ai_enabled and not body.ai_risk_acknowledged:
            raise HTTPException(status_code=400, detail="Confirm that you have read the "
                                "warning before enabling AI investigation.")
        mgr = _manager(request)
        await _call(mgr.update, key, name=body.name, sync_enabled=body.sync_enabled,
                    sync_interval_seconds=body.sync_interval_seconds,
                    ai_enabled=body.ai_enabled, actor=user.username)
        return _admin(await _call(mgr.status, key))

    @admin.post("/{key}/password", status_code=204)
    async def set_password(key: SourceKey, body: PasswordBody, request: Request,
                           user: AdminUser) -> None:
        await _call(_manager(request).set_password, key, body.password, actor=user.username)

    @admin.post("/{key}/sync", response_model=RunView)
    async def sync_now(key: SourceKey, request: Request) -> RunView:
        return _run(await _call(_manager(request).sync, key, trigger="manual"))

    @admin.post("/{key}/snapshot", response_model=SnapshotView)
    async def snapshot_now(key: SourceKey, request: Request) -> SnapshotView:
        info = await _call(_manager(request).snapshot, key)
        return SnapshotView(created_at=info.created_at, event_count=info.event_count,
                            incident_count=info.incident_count, first_event=info.first_event,
                            last_event=info.last_event)

    @admin.delete("/{key}", status_code=204)
    async def delete(key: SourceKey, request: Request, user: AdminUser) -> None:
        await _call(_manager(request).delete, key, actor=user.username)

    router = APIRouter()
    router.include_router(public)
    router.include_router(admin)
    return router
