"""Organisational source: sync, recovery, snapshots, dashboard, API and AI permission.

The database here is SIMULATED (an in-memory table with the same read semantics the
PostgreSQL connector implements). These tests verify AgentSOC's own logic; they are not a
verification of PostgreSQL itself (see tests/integration/test_postgres_real.py).
"""

import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from agentsoc.api.service import Service
from agentsoc.app_data import DEMO_INPUT, discover_sources
from agentsoc.audit import AuditLog
from agentsoc.auth.service import Role
from agentsoc.connectors.base import ConnectorError, Position
from agentsoc.credentials import EncryptedCredentialStore, UnavailableCredentialStore
from agentsoc.detection.config import load_detection_config
from agentsoc.detection.engine import run_detection
from agentsoc.orgsource.manager import DataSourceManager, SyncScheduler
from agentsoc.orgsource.registry import DataSourceConfig, DataSourceRegistry
from agentsoc.orgsource.snapshot import DETECTION_CONFIG, read_current, source_dir
from agentsoc.orgsource.staging import StagingStore, SyncBusyError
from agentsoc.orgsource.sync import sync_once
from agentsoc.schemas import DatasetSource
from agentsoc.store.datasets import load_events
from tests.support import signed_in_client

DB_PASSWORD = "Org-db-Passw0rd-xyz"
START = datetime(2026, 11, 1, tzinfo=UTC)
COLUMNS = ("id", "ingested_at", "event_time", "account", "target_account", "client", "server",
           "auth_package", "logon_kind", "action", "result")


def demo_rows():
    """The synthetic demo scenario as rows of an organisation-style table (SYNTHETIC)."""
    rows = []
    for line_no, line in enumerate(DEMO_INPUT.read_text(encoding="utf-8").splitlines(), 1):
        t, su, du, sh, dh, at, lt, o, out = line.split(",")
        when = START + timedelta(seconds=int(t))
        rows.append({"id": line_no, "ingested_at": when + timedelta(seconds=2),
                     "event_time": when.isoformat(), "account": su,
                     "target_account": None if du == "?" else du, "client": sh, "server": dh,
                     "auth_package": None if at == "?" else at,
                     "logon_kind": None if lt == "?" else lt, "action": o,
                     "result": {"Success": "1", "Fail": "0"}[out]})
    return rows


class FakeTable:
    """Rows ordered by (cursor, key) with the connector's after/since semantics."""

    def __init__(self, rows):
        self.rows, self.fail_on_call, self.calls, self.passwords = list(rows), None, 0, []

    def __call__(self, settings, password):  # connector factory
        self.passwords.append(password.get_secret_value())
        return self

    def test(self):
        from agentsoc.connectors.base import ConnectionReport
        return ConnectionReport("16.4", "reader", True, [])

    def list_tables(self):
        from agentsoc.connectors.base import TableRef
        return [TableRef("public", "auth_events")]

    def list_columns(self, table):
        from agentsoc.connectors.base import Column
        return [Column(c, "text", True) for c in COLUMNS]

    def fetch(self, table, columns, *, cursor_column, key_column, after, since, limit):
        self.calls += 1
        if self.fail_on_call == self.calls:
            raise ConnectorError("The query took longer than the statement timeout.",
                                 code="57014")
        assert set(columns) <= set(COLUMNS)
        data = sorted((r for r in self.rows if r[cursor_column] is not None),
                      key=lambda r: (r[cursor_column], r[key_column]))
        if after is not None:
            data = [r for r in data if (r[cursor_column], r[key_column]) > (after.cursor,
                                                                             after.key)]
        elif since is not None:
            data = [r for r in data if r[cursor_column] >= since]
        wanted = list(dict.fromkeys([*columns, cursor_column, key_column]))
        return [{c: r.get(c) for c in wanted} for r in data[:limit]]


def config(**overrides):
    base = {
        "connection": {"host": "db.example.test", "database": "security",
                       "username": "agentsoc_reader", "sslmode": "verify-full"},
        "table": {"schema": "public", "name": "auth_events"},
        "cursor_column": "ingested_at", "batch_size": 50,
        "mapping": {
            "record_id": "id", "timestamp": {"column": "event_time"},
            "fields": {
                "src_user": {"column": "account"}, "dst_user": {"column": "target_account"},
                "src_host": {"column": "client"}, "dst_host": {"column": "server"},
                "auth_type": {"column": "auth_package"}, "logon_type": {"column": "logon_kind"},
                "orientation": {"column": "action"},
                "outcome": {"column": "result", "values": {"1": "Success", "0": "Fail"}}}},
    }
    base.update(overrides)
    return DataSourceConfig.model_validate(base)


@pytest.fixture
def env(tmp_path, monkeypatch):
    root = tmp_path / "root"
    service = Service(root=root, provider_factory=lambda: (None, "off"))
    audit = AuditLog(root / "activity_log.jsonl")
    creds = EncryptedCredentialStore(service.app_db, SecretStr(Fernet.generate_key().decode()),
                                     audit)
    table = FakeTable(demo_rows())
    manager = DataSourceManager(service.datasources, creds, service.audit, root,
                                connector_factory=table, on_snapshot=service.refresh_sources)
    return service, manager, table, root


def create(manager, key="hr-auth", **overrides):
    return manager.create(key, "HR authentication log", config(**overrides),
                          SecretStr(DB_PASSWORD), actor="admin1")


class TestSync:
    def test_reads_everything_in_bounded_batches_then_only_new_rows(self, env):
        _, manager, table, _ = env
        create(manager)
        run = manager.sync("hr-auth")
        total = len(table.rows)
        assert (run.status, run.fetched, run.new, run.rejected) == ("completed", total, total, 0)
        assert run.batches == -(-total // 50) and table.passwords[-1] == DB_PASSWORD
        assert manager.sync("hr-auth").fetched == 0
        last = table.rows[-1]
        table.rows.append({**last, "id": 999_999, "ingested_at": last["ingested_at"]
                           + timedelta(seconds=5)})
        again = manager.sync("hr-auth")
        assert (again.fetched, again.new) == (1, 1)
        assert manager.store("hr-auth").stats().accepted == total + 1

    def test_ingestion_is_idempotent(self, env):
        _, manager, table, _ = env
        create(manager)
        manager.sync("hr-auth")
        store = manager.store("hr-auth")
        store.reset()
        run = manager.sync("hr-auth")
        assert (run.new, run.duplicates) == (0, len(table.rows))
        assert store.stats().accepted == len(table.rows)

    def test_a_changed_row_is_counted_and_the_first_version_kept(self, env):
        _, manager, table, _ = env
        create(manager)
        manager.sync("hr-auth")
        original = table.rows[10]
        table.rows[10] = {**original, "result": "0" if original["result"] == "1" else "1"}
        manager.store("hr-auth").reset()
        assert manager.sync("hr-auth").changed == 1
        events = {e.event_id: e for e in manager.store("hr-auth").window(10_000, 500_000)}
        expected = "Success" if original["result"] == "1" else "Fail"
        assert events[f"hr-auth.{original['id']}"].outcome.value == expected

    def test_late_rows_are_caught_only_with_a_lookback(self, env):
        _, manager, table, _ = env
        create(manager, key="no-lookback")
        create(manager, key="with-lookback", lookback=600)
        for key in ("no-lookback", "with-lookback"):
            manager.sync(key)
        newest = max(r["ingested_at"] for r in table.rows)
        late = {**table.rows[0], "id": 888_888, "ingested_at": newest - timedelta(seconds=60)}
        table.rows.append(late)
        assert manager.sync("no-lookback").new == 0  # documented limitation
        late_run = manager.sync("with-lookback")
        assert late_run.new == 1 and late_run.duplicates > 0

    def test_a_failed_sync_resumes_from_the_last_stored_batch(self, env):
        _, manager, table, _ = env
        create(manager)
        table.fail_on_call = 3
        failed = manager.sync("hr-auth")
        assert failed.status == "failed" and failed.new == 100
        assert "statement timeout" in failed.error
        store = manager.store("hr-auth")
        ordered = sorted(table.rows, key=lambda r: (r["ingested_at"], r["id"]))
        assert store.checkpoint() == Position(ordered[99]["ingested_at"], ordered[99]["id"])
        table.fail_on_call = None
        resumed = manager.sync("hr-auth")
        assert resumed.status == "completed" and resumed.duplicates == 0
        assert store.stats().accepted == len(table.rows)

    def test_crash_after_capture_before_commit_loses_nothing(self, env, monkeypatch):
        _, manager, table, root = env
        create(manager)
        store_cls = StagingStore
        original = store_cls.apply_batch
        calls = {"n": 0}

        def crash_on_second(self, *args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("disk went away")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(store_cls, "apply_batch", crash_on_second)
        assert manager.sync("hr-auth").status == "failed"
        monkeypatch.setattr(store_cls, "apply_batch", original)
        assert manager.sync("hr-auth").status == "completed"
        store = manager.store("hr-auth")
        assert store.stats().accepted == len(table.rows)
        # Every stored event points at a capture line holding its own original record.
        for event in store.window(10_000, 500_000)[:50]:
            path = source_dir(root, "hr-auth") / event.raw_ref.file
            line = path.read_text(encoding="utf-8").splitlines()[event.raw_ref.line - 1]
            assert json.loads(line)["record_id"] == event.event_id.split(".", 1)[1]

    def test_rejected_rows_are_kept_with_reasons(self, env):
        _, manager, table, _ = env
        table.rows[5]["action"] = "Unlock"
        table.rows[6]["event_time"] = "2026-11-01T00:00:00"  # no zone
        table.rows[7]["id"] = "bad/id"
        create(manager)
        run = manager.sync("hr-auth")
        stats = manager.store("hr-auth").stats()
        assert run.rejected == stats.rejected == 3
        assert stats.rejected_by_reason == {"INVALID_FIELD": 1, "INVALID_ORIENTATION": 1,
                                            "INVALID_TIMESTAMP": 1}

    def test_one_sync_at_a_time(self, env):
        _, manager, _, _ = env
        create(manager)
        store = manager.store("hr-auth")
        with store.exclusive(), pytest.raises(SyncBusyError):
            manager.sync("hr-auth")

    def test_rows_per_sync_are_bounded(self, env):
        _, manager, _, _ = env
        create(manager, max_rows_per_sync=120)
        run = manager.sync("hr-auth")
        assert run.fetched == 120 and run.more_available

    def test_a_lookback_larger_than_one_sync_is_reported(self, env):
        _, manager, _, _ = env
        create(manager, max_rows_per_sync=10, lookback=86_400)
        manager.sync("hr-auth")
        stuck = manager.sync("hr-auth")
        assert stuck.status == "failed" and "look-back window" in stuck.error

    def test_interrupted_runs_are_marked(self, env):
        _, manager, _, _ = env
        create(manager)
        store = manager.store("hr-auth")
        store.start_run("manual")  # never finished: a crashed process
        manager.sync("hr-auth")
        assert [r.status for r in store.runs()][-1] == "interrupted"


class TestSnapshots:
    def test_snapshot_runs_the_unchanged_engines_and_appears_as_a_source(self, env):
        service, manager, table, root = env
        create(manager)
        manager.sync("hr-auth")
        info = manager.snapshot("hr-auth")
        events = load_events(info.dataset_dir)
        assert len(events) == len(table.rows) == info.event_count
        assert all(e.dataset is DatasetSource.ORGANIZATION for e in events)
        expected = run_detection(events, load_detection_config(DETECTION_CONFIG))
        assert info.incident_count == len(expected.incidents) > 0
        source = next(s for s in discover_sources(root) if s.key == "org-hr-auth")
        assert source.provenance is DatasetSource.ORGANIZATION
        assert source.time_display == "absolute"
        assert (info.detection_dir / "structural").is_dir()
        assert (info.detection_dir / "risk").is_dir()
        assert "org-hr-auth" in [s.key for s in service.sources()]

    def test_snapshots_are_immutable_and_current_moves(self, env):
        _, manager, table, root = env
        create(manager)
        manager.sync("hr-auth")
        first = manager.snapshot("hr-auth")
        before = (first.dataset_dir / "events.jsonl").read_bytes()
        table.rows.append({**table.rows[-1], "id": 777_777,
                           "ingested_at": table.rows[-1]["ingested_at"] + timedelta(seconds=1)})
        manager.sync("hr-auth")
        second = manager.snapshot("hr-auth")
        assert second.dataset_dir != first.dataset_dir
        assert (first.dataset_dir / "events.jsonl").read_bytes() == before
        assert read_current(source_dir(root, "hr-auth"))["snapshot"] == second.stamp

    def test_window_bounds_the_snapshot(self, env):
        _, manager, _, _ = env
        create(manager, snapshot={"window_hours": 24, "max_events": 100})
        manager.sync("hr-auth")
        events = load_events(manager.snapshot("hr-auth").dataset_dir)
        newest = max(r["event_time"] for r in env[2].rows)
        assert len(events) < len(env[2].rows)
        assert all(e.timestamp >= datetime.fromisoformat(newest) - timedelta(hours=24)
                   for e in events)
        manager.registry.delete("hr-auth")
        create(manager, snapshot={"window_hours": 2160, "max_events": 100}, key="capped")
        manager.sync("capped")
        capped = load_events(manager.snapshot("capped").dataset_dir)
        assert len(capped) == 100 < len(env[2].rows)
        newest_ids = sorted(env[2].rows, key=lambda r: (r["event_time"], r["id"]))[-100:]
        assert {e.event_id for e in capped} == {f"capped.{r['id']}" for r in newest_ids}
        assert events == sorted(events, key=lambda e: (e.timestamp, e.raw_ref.file,
                                                       e.raw_ref.line))

    def test_deleting_withdraws_the_source_and_its_password(self, env):
        service, manager, _, _root = env
        create(manager)
        manager.sync("hr-auth")
        manager.snapshot("hr-auth")
        manager.delete("hr-auth", actor="admin1")
        assert "org-hr-auth" not in [s.key for s in service.sources()]
        assert manager.credentials.list() == []

    def test_scheduler_syncs_due_sources_and_snapshots_new_data(self, env):
        _, manager, table, root = env
        create(manager)
        now = {"t": datetime.now(UTC)}
        scheduler = SyncScheduler(manager, clock=lambda: now["t"])
        scheduler.tick()
        assert manager.store("hr-auth").runs() == []  # sync not enabled
        manager.update("hr-auth", sync_enabled=True, actor="admin1")
        scheduler.tick()
        first = read_current(source_dir(root, "hr-auth"))
        assert first is not None and len(manager.store("hr-auth").runs()) == 1
        scheduler.tick()  # not due yet
        assert len(manager.store("hr-auth").runs()) == 1
        table.rows.append({**table.rows[-1], "id": 666_666,
                           "ingested_at": table.rows[-1]["ingested_at"] + timedelta(seconds=1)})
        now["t"] += timedelta(seconds=61)
        scheduler.tick()  # synced, but the snapshot interval (300 s) has not passed
        assert read_current(source_dir(root, "hr-auth"))["snapshot"] == first["snapshot"]
        now["t"] += timedelta(seconds=300)
        scheduler.tick()
        assert read_current(source_dir(root, "hr-auth"))["snapshot"] != first["snapshot"]


def admin_client(service, manager, role=Role.ADMIN):
    return signed_in_client(service, role=role, username="admin1", datasources=manager)


def body(key="hr-auth"):
    return {"key": key, "name": "HR authentication log", "password": DB_PASSWORD,
            "config": json.loads(config().model_dump_json(by_alias=True))}


class TestApi:
    def test_only_administrators_manage_sources(self, env):
        service, manager, _, _ = env
        analyst = admin_client(service, manager, role=Role.ANALYST)
        assert analyst.get("/api/admin/datasources").status_code == 403
        assert analyst.post("/api/admin/datasources", json=body()).status_code == 403
        assert analyst.get("/api/datasources/organisation").status_code == 200

    def test_changes_need_the_csrf_header(self, env):
        service, manager, _, _ = env
        client = admin_client(service, manager)
        r = client.post("/api/admin/datasources", json=body(),
                        headers={"X-CSRF-Token": "wrong"})
        assert r.status_code == 403

    def test_password_is_never_returned_logged_or_audited(self, env, caplog):
        service, manager, _, root = env
        client = admin_client(service, manager)
        created = client.post("/api/admin/datasources", json=body())
        assert created.status_code == 201, created.text
        responses = [created, client.get("/api/admin/datasources"),
                     client.get("/api/datasources/organisation"),
                     client.post("/api/admin/datasources/hr-auth/sync"),
                     client.post("/api/admin/datasources/test",
                                 json={"connection": body()["config"]["connection"],
                                       "key": "hr-auth"})]
        for r in responses:
            assert r.status_code == 200 or r.status_code == 201, r.text
            assert DB_PASSWORD not in r.text
        assert DB_PASSWORD not in (root / "activity_log.jsonl").read_text(encoding="utf-8")
        assert DB_PASSWORD not in caplog.text
        assert DB_PASSWORD.encode() not in (root / "agentsoc.db").read_bytes()
        assert created.json()["has_password"] is True

    def test_analysts_see_status_but_no_connection_details(self, env):
        service, manager, _, _ = env
        admin_client(service, manager).post("/api/admin/datasources", json=body())
        view = admin_client(service, manager, Role.ANALYST).get(
            "/api/datasources/organisation").json()[0]
        assert "connection" not in view and "db.example.test" not in json.dumps(view)
        assert "Not real-time" in view["mode"]

    def test_without_a_key_sources_cannot_be_created(self, env):
        service, _, table, root = env
        manager = DataSourceManager(service.datasources,
                                    UnavailableCredentialStore("set AGENTSOC_CREDENTIAL_KEY"),
                                    service.audit, root, connector_factory=table)
        r = admin_client(service, manager).post("/api/admin/datasources", json=body())
        assert r.status_code == 409 and "AGENTSOC_CREDENTIAL_KEY" in r.json()["detail"]
        assert DataSourceRegistry(service.app_db).list() == []

    def test_connector_errors_are_reported_safely(self, env):
        service, manager, table, _ = env
        client = admin_client(service, manager)
        client.post("/api/admin/datasources", json=body())
        table.fail_on_call = 1
        r = client.post("/api/admin/datasources/preview", json={
            "connection": body()["config"]["connection"], "key": "hr-auth",
            "table": {"schema": "public", "name": "auth_events"},
            "cursor_column": "ingested_at", "mapping": body()["config"]["mapping"]})
        assert r.status_code == 502 and "statement timeout" in r.json()["detail"]

    def test_preview_maps_without_storing(self, env):
        service, manager, table, root = env
        table.rows[0]["action"] = "Unlock"
        r = admin_client(service, manager).post("/api/admin/datasources/preview", json={
            "connection": body()["config"]["connection"], "password": DB_PASSWORD,
            "table": {"schema": "public", "name": "auth_events"},
            "cursor_column": "ingested_at", "mapping": body()["config"]["mapping"]})
        data = r.json()
        assert r.status_code == 200 and data["rows_read"] == 50
        assert data["rejected"][0]["reason"] == "INVALID_ORIENTATION"
        assert not (root / "org").exists()

    def test_unconfirmed_constants_are_refused(self, env):
        service, manager, _, _ = env
        b = body()
        b["config"]["mapping"]["fields"]["orientation"] = {"constant": "LogOn"}
        r = admin_client(service, manager).post("/api/admin/datasources", json=b)
        assert r.status_code == 422 and "constants must be confirmed" in r.text


class TestAiPermission:
    def setup_source(self, env):
        service, manager, _, _ = env
        client = admin_client(service, manager)
        client.post("/api/admin/datasources", json=body())
        client.post("/api/admin/datasources/hr-auth/sync")
        assert client.post("/api/admin/datasources/hr-auth/snapshot").status_code == 200
        return client

    def test_ai_is_off_by_default_and_needs_an_acknowledged_admin_change(self, env):
        service, manager, _, root = env
        client = self.setup_source(env)
        view = client.get("/api/admin/datasources/hr-auth").json()
        assert view["ai_enabled"] is False and "external language-model" in view["ai_warning"]
        refused = client.patch("/api/admin/datasources/hr-auth", json={"ai_enabled": True})
        assert refused.status_code == 400
        analyst = admin_client(service, manager, Role.ANALYST)
        assert analyst.patch("/api/admin/datasources/hr-auth",
                             json={"ai_enabled": True,
                                   "ai_risk_acknowledged": True}).status_code == 403
        ok = client.patch("/api/admin/datasources/hr-auth",
                          json={"ai_enabled": True, "ai_risk_acknowledged": True})
        assert ok.json()["ai_enabled"] is True and ok.json()["ai_changed_by"] == "admin1"
        log = (root / "activity_log.jsonl").read_text(encoding="utf-8")
        assert '"event_type":"datasource.ai_permission_changed"' in log

    def test_investigation_never_reaches_the_provider_while_ai_is_off(self, env, tmp_path):
        service, manager, _, _root = env
        self.setup_source(env)
        calls = []

        def provider():
            calls.append(1)
            return None, "test provider unavailable"

        service.provider_factory = provider
        client = admin_client(service, manager)
        incident = client.get("/api/incidents?source=org-hr-auth").json()["items"][0]
        r = client.post(f"/api/incidents/{incident['incident_id']}/investigate"
                        "?source=org-hr-auth")
        assert r.status_code == 200 and calls == []
        assert r.json()["status"] == "completed_limited"
        assert r.json()["diagnostics"]["engine"] == "deterministic"
        client.patch("/api/admin/datasources/hr-auth",
                     json={"ai_enabled": True, "ai_risk_acknowledged": True})
        client.post(f"/api/incidents/{incident['incident_id']}/investigate"
                    "?source=org-hr-auth&rerun=true")
        assert calls == [1]

    def test_built_in_sources_are_unaffected(self, env):
        service, manager, _, _ = env
        calls = []
        service.provider_factory = lambda: (calls.append(1), (None, "off"))[1]
        admin_client(service, manager).post("/api/incidents/INC-00001/investigate")
        assert calls == [1]


def test_sync_once_records_no_secret_in_the_capture(env):
    _, manager, table, root = env
    create(manager)
    source = manager.registry.get("hr-auth")
    sync_once(source, table, StagingStore(source_dir(root, "hr-auth")))
    for path in (source_dir(root, "hr-auth") / "capture").iterdir():
        assert DB_PASSWORD not in path.read_text(encoding="utf-8")
