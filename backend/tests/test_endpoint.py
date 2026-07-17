"""Testes do endpoint GET /cyber/tenants (tenant -> organizations), health check e compatibilidade."""
from fastapi.testclient import TestClient
from starlette.routing import Mount

from app import cyber_registry, cyber_tokens, db
from app.cyber_registry import CyberOrganization, CyberTenant
from app.cyber_tokens import TokenStatus
from app.main import app
from tests.fakes import FakePool, FakeRedis


def _org(oid, name=None, order=1):
    return CyberOrganization(oid, name or oid.upper(), order, True, True)


def _tenant(tid, orgs=()):
    return CyberTenant(tid, tid.upper(), "https://api.xdr.trendmicro.com", True, True, True, list(orgs))


def _resolver(configured):
    def r(tid):
        ok = configured.get(tid, False)
        return TokenStatus(tid, ok, "VAR", "tok" if ok else None)
    return r


def _patch(monkeypatch, tenants, configured):
    async def fake_fetch(pool):
        return tenants
    monkeypatch.setattr(cyber_registry, "fetch_cyber_registry", fake_fetch)
    monkeypatch.setattr(cyber_tokens, "resolve_token", _resolver(configured))


# ---------------- GET /cyber/tenants ----------------

def test_endpoint_complete(monkeypatch):
    _patch(monkeypatch, [_tenant("prodesp-sp", [_org("org-prodesp", "Prodesp")])], {"prodesp-sp": True})
    db.set_pool(FakePool())
    body = TestClient(app).get("/cyber/tenants").json()
    assert body["status"] == "ok" and "updatedAt" in body
    t = body["tenants"][0]
    assert t["tenantId"] == "prodesp-sp" and t["credentialsConfigured"] is True and t["status"] == "ok"
    assert t["organizations"][0]["organizationId"] == "org-prodesp"


def test_endpoint_tenant_with_multiple_orgs(monkeypatch):
    _patch(monkeypatch, [_tenant("sggd", [_org("org-sggd", "SGGD", 1), _org("org-pge", "PGE", 2)])], {"sggd": True})
    db.set_pool(FakePool())
    orgs = TestClient(app).get("/cyber/tenants").json()["tenants"][0]["organizations"]
    assert [o["organizationId"] for o in orgs] == ["org-sggd", "org-pge"]


def test_endpoint_db_empty(monkeypatch):
    _patch(monkeypatch, [], {})
    db.set_pool(FakePool())
    body = TestClient(app).get("/cyber/tenants").json()
    assert body["status"] == "ok" and body["tenants"] == []


def test_endpoint_db_unavailable():
    db.set_pool(None)
    body = TestClient(app).get("/cyber/tenants").json()
    assert body["status"] == "unavailable" and body["tenants"] == []


def test_endpoint_db_error(monkeypatch):
    async def boom(pool):
        raise RuntimeError("db kaput")
    monkeypatch.setattr(cyber_registry, "fetch_cyber_registry", boom)
    db.set_pool(FakePool())
    body = TestClient(app).get("/cyber/tenants").json()
    assert body["status"] == "unavailable" and body["tenants"] == []


def test_endpoint_tenant_without_token(monkeypatch):
    _patch(monkeypatch, [_tenant("iamspe-sp", [_org("org-iamspe")])], {})  # sem token
    db.set_pool(FakePool())
    t = TestClient(app).get("/cyber/tenants").json()["tenants"][0]
    assert t["credentialsConfigured"] is False and t["status"] == "configuration_error"
    assert len(t["organizations"]) == 1  # orgaos continuam listados


def test_endpoint_one_tenant_failure_isolated(monkeypatch):
    _patch(monkeypatch, [_tenant("a-sp", [_org("org-a")]), _tenant("b-sp", [_org("org-b")])], {"b-sp": True})
    db.set_pool(FakePool())
    by = {t["tenantId"]: t for t in TestClient(app).get("/cyber/tenants").json()["tenants"]}
    assert by["a-sp"]["status"] == "configuration_error" and by["b-sp"]["status"] == "ok"


def test_endpoint_no_sensitive_info(monkeypatch):
    _patch(monkeypatch, [_tenant("sggd", [_org("org-sggd"), _org("org-pge", order=2)])], {"sggd": True})
    db.set_pool(FakePool())
    raw = TestClient(app).get("/cyber/tenants").text.lower()
    for bad in ["token", "dsn", "password", "authorization", "v1_api", "senha"]:
        assert bad not in raw


# ---------------- health check (aditivo) ----------------

def test_healthz_adds_postgres_state(monkeypatch):
    monkeypatch.setattr("app.main.get_redis", lambda: FakeRedis(ping_ok=True))

    async def anoop():
        return None
    monkeypatch.setattr(db, "init_pool", anoop)
    db.set_pool(FakePool())
    with TestClient(app) as c:
        body = c.get("/healthz").json()
    assert body["status"] == "ok" and body["redis"] is True and body["postgres"] == "ok"


def test_healthz_pg_failure_isolated_from_redis(monkeypatch):
    monkeypatch.setattr("app.main.get_redis", lambda: FakeRedis(ping_ok=True))

    async def anoop():
        return None
    monkeypatch.setattr(db, "init_pool", anoop)
    db.set_pool(None)  # PG indisponivel
    with TestClient(app) as c:
        body = c.get("/healthz").json()
    assert body["status"] == "ok" and body["redis"] is True and body["postgres"] == "unavailable"


# ---------------- compatibilidade ----------------

def test_existing_routes_still_registered():
    paths = {getattr(r, "path", None) for r in app.routes}
    assert {"/healthz", "/api/{tenant}/overview", "/ws/{tenant}", "/cyber/tenants"} <= paths


def test_cyber_route_registered_before_static_mount():
    idx_cyber = next(i for i, r in enumerate(app.routes)
                     if getattr(r, "path", None) == "/cyber/tenants")
    mount_idx = next((i for i, r in enumerate(app.routes) if isinstance(r, Mount)), None)
    assert mount_idx is None or idx_cyber < mount_idx
