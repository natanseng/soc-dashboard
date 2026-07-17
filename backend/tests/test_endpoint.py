"""Testes do endpoint GET /cyber/tenants, health check e compatibilidade."""
from fastapi.testclient import TestClient
from starlette.routing import Mount

from app import cyber_registry, cyber_tokens, db
from app.cyber_registry import CyberOrganization, CyberTenant
from app.cyber_tokens import TokenStatus
from app.main import app
from tests.fakes import FakePool, FakeRedis


def _tenant(tid):
    return CyberTenant(tid, tid.upper(), "https://api.xdr.trendmicro.com", True, True, True)


def _resolver(configured):
    def r(tid):
        ok = configured.get(tid, False)
        return TokenStatus(tid, ok, "VAR", "tok" if ok else None)
    return r


def _patch_registry(monkeypatch, orgs, configured):
    async def fake_fetch(pool):
        return orgs
    monkeypatch.setattr(cyber_registry, "fetch_cyber_registry", fake_fetch)
    monkeypatch.setattr(cyber_tokens, "resolve_token", _resolver(configured))


# ---------------- GET /cyber/tenants ----------------

def test_endpoint_complete(monkeypatch):
    orgs = [CyberOrganization("org-a", "Org A", 1, [_tenant("a-sp")])]
    _patch_registry(monkeypatch, orgs, {"a-sp": True})
    db.set_pool(FakePool())
    body = TestClient(app).get("/cyber/tenants").json()
    assert body["status"] == "ok"
    t = body["organizations"][0]["tenants"][0]
    assert t["credentialsConfigured"] is True and t["status"] == "ok"
    assert "updatedAt" in body


def test_endpoint_db_empty(monkeypatch):
    _patch_registry(monkeypatch, [], {})
    db.set_pool(FakePool())
    body = TestClient(app).get("/cyber/tenants").json()
    assert body["status"] == "ok" and body["organizations"] == []


def test_endpoint_db_unavailable():
    db.set_pool(None)
    body = TestClient(app).get("/cyber/tenants").json()
    assert body["status"] == "unavailable" and body["organizations"] == []


def test_endpoint_db_error(monkeypatch):
    async def boom(pool):
        raise RuntimeError("db kaput")
    monkeypatch.setattr(cyber_registry, "fetch_cyber_registry", boom)
    db.set_pool(FakePool())
    body = TestClient(app).get("/cyber/tenants").json()
    assert body["status"] == "unavailable" and body["organizations"] == []


def test_endpoint_partial_without_token(monkeypatch):
    orgs = [CyberOrganization("org-a", "A", 1, [_tenant("a-sp"), _tenant("b-sp")])]
    _patch_registry(monkeypatch, orgs, {"a-sp": True})  # b-sp sem token
    db.set_pool(FakePool())
    org = TestClient(app).get("/cyber/tenants").json()["organizations"][0]
    assert org["status"] == "degraded"
    by = {t["tenantId"]: t for t in org["tenants"]}
    assert by["a-sp"]["credentialsConfigured"] is True
    assert by["b-sp"]["credentialsConfigured"] is False
    assert by["b-sp"]["status"] == "configuration_error"


def test_endpoint_multiple_orgs(monkeypatch):
    orgs = [
        CyberOrganization("o1", "A", 1, [_tenant("a-sp")]),
        CyberOrganization("o2", "B", 2, [_tenant("b-sp")]),
    ]
    _patch_registry(monkeypatch, orgs, {"a-sp": True, "b-sp": True})
    db.set_pool(FakePool())
    body = TestClient(app).get("/cyber/tenants").json()
    assert [o["organizationId"] for o in body["organizations"]] == ["o1", "o2"]


def test_endpoint_no_sensitive_info(monkeypatch):
    orgs = [CyberOrganization("org-a", "A", 1, [_tenant("a-sp")])]
    _patch_registry(monkeypatch, orgs, {"a-sp": True})
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
    assert body["status"] == "ok" and body["redis"] is True
    assert body["postgres"] == "ok"


def test_healthz_pg_failure_isolated_from_redis(monkeypatch):
    monkeypatch.setattr("app.main.get_redis", lambda: FakeRedis(ping_ok=True))

    async def anoop():
        return None
    monkeypatch.setattr(db, "init_pool", anoop)
    db.set_pool(None)  # PG indisponivel
    with TestClient(app) as c:
        body = c.get("/healthz").json()
    assert body["status"] == "ok" and body["redis"] is True   # redis reportado normalmente
    assert body["postgres"] == "unavailable"


# ---------------- compatibilidade ----------------

def test_existing_routes_still_registered():
    paths = {getattr(r, "path", None) for r in app.routes}
    assert "/healthz" in paths
    assert "/api/{tenant}/overview" in paths
    assert "/ws/{tenant}" in paths
    assert "/cyber/tenants" in paths


def test_cyber_route_registered_before_static_mount():
    idx_cyber = next(i for i, r in enumerate(app.routes)
                     if getattr(r, "path", None) == "/cyber/tenants")
    mount_idx = next((i for i, r in enumerate(app.routes) if isinstance(r, Mount)), None)
    assert mount_idx is None or idx_cyber < mount_idx
