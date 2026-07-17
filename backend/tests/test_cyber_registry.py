"""Testes do cadastro dinamico (app/cyber_registry.py).

- build_payload: unitario e puro (sem I/O).
- fetch_cyber_registry: integracao contra banco temporario com o schema real
  (filtros/ordenacao vivem no SQL, entao precisam de um banco de verdade).
"""
import json
from pathlib import Path

from app.cyber_registry import (
    CyberOrganization,
    CyberTenant,
    _REGISTRY_SQL,
    build_payload,
    fetch_cyber_registry,
)
from app.cyber_tokens import TokenStatus
from tests.conftest import insert_fixture

APP = Path(__file__).resolve().parents[1] / "app"


def _tenant(tid, name=None):
    return CyberTenant(tid, name or tid.upper(), "https://api.xdr.trendmicro.com", True, True, True)


def _resolver(configured):
    def r(tenant_id):
        ok = configured.get(tenant_id, False)
        return TokenStatus(tenant_id, ok, "VAR", "tok" if ok else None)
    return r


# ---------------- build_payload (unit) ----------------

def test_payload_complete():
    orgs = [CyberOrganization("org-a", "Org A", 1, [_tenant("a-sp", "Alpha")])]
    p = build_payload(orgs, _resolver({"a-sp": True}), updated_at="2026-01-01T00:00:00Z")
    assert p["status"] == "ok"
    o = p["organizations"][0]
    assert (o["organizationId"], o["organizationName"], o["displayOrder"], o["status"]) == (
        "org-a", "Org A", 1, "ok")
    t = o["tenants"][0]
    assert t["tenantId"] == "a-sp" and t["tenantName"] == "Alpha"
    assert t["cyberEnabled"] is True and t["credentialsConfigured"] is True and t["status"] == "ok"
    assert t["sources"] == {"oat": True, "workbench": True, "suspiciousObjects": True}
    assert "updatedAt" in p


def test_payload_empty():
    p = build_payload([], _resolver({}), updated_at="t")
    assert p["status"] == "ok" and p["organizations"] == []


def test_payload_one_tenant_without_token_is_partial():
    orgs = [CyberOrganization("o", "O", 1, [_tenant("a-sp"), _tenant("b-sp")])]
    p = build_payload(orgs, _resolver({"a-sp": True}), updated_at="t")  # b-sp sem token
    org = p["organizations"][0]
    assert org["status"] == "degraded"
    by = {t["tenantId"]: t for t in org["tenants"]}
    assert by["a-sp"]["credentialsConfigured"] is True and by["a-sp"]["status"] == "ok"
    assert by["b-sp"]["credentialsConfigured"] is False and by["b-sp"]["status"] == "configuration_error"


def test_payload_multiple_orgs_preserve_input_order():
    orgs = [
        CyberOrganization("o1", "A", 1, [_tenant("a-sp")]),
        CyberOrganization("o2", "B", 2, [_tenant("b-sp")]),
    ]
    p = build_payload(orgs, _resolver({"a-sp": True, "b-sp": True}), updated_at="t")
    assert [o["organizationId"] for o in p["organizations"]] == ["o1", "o2"]


def test_payload_has_no_sensitive_info():
    orgs = [CyberOrganization("o", "O", 1, [_tenant("a-sp")])]
    p = build_payload(orgs, _resolver({"a-sp": True}), updated_at="t")
    blob = json.dumps(p).lower()
    for bad in ["token", "dsn", "password", "authorization", "v1_api", "senha"]:
        assert bad not in blob


def test_registry_sql_is_select_only():
    s = _REGISTRY_SQL.strip().upper()
    assert s.startswith("SELECT")
    for w in ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE"]:
        assert w not in s


def test_no_hardcoded_org_names_in_registry_source():
    src = (APP / "cyber_registry.py").read_text(encoding="utf-8").lower()
    for name in ["prodesp", "detran", "iamspe", "sggd"]:
        assert name not in src


def test_registry_and_db_modules_do_not_touch_redis():
    # nao devem IMPORTAR/usar redis (mencao a "Redis" em docstring e permitida)
    for mod in ("cyber_registry.py", "db.py"):
        src = (APP / mod).read_text(encoding="utf-8")
        assert "import redis" not in src
        assert "aioredis" not in src
        assert "get_redis" not in src


# ---------------- fetch_cyber_registry (integracao) ----------------

async def test_registry_all_enabled(reg_pool):
    await insert_fixture(
        reg_pool,
        orgs=[("org-a", "A", 1, True, True), ("org-b", "B", 2, True, True)],
        tenants=[("a-sp", "A Tenant"), ("b-sp", "B Tenant")],
        cfgs=[("a-sp", "org-a", True, True, True, True), ("b-sp", "org-b", True, True, True, True)],
    )
    regs = await fetch_cyber_registry(reg_pool)
    assert [o.organization_id for o in regs] == ["org-a", "org-b"]


async def test_registry_org_disabled_hidden(reg_pool):
    await insert_fixture(reg_pool, [("org-a", "A", 1, False, True)], [("a-sp", "A")],
                         [("a-sp", "org-a", True, True, True, True)])
    assert await fetch_cyber_registry(reg_pool) == []


async def test_registry_org_cyber_disabled_hidden(reg_pool):
    await insert_fixture(reg_pool, [("org-a", "A", 1, True, False)], [("a-sp", "A")],
                         [("a-sp", "org-a", True, True, True, True)])
    assert await fetch_cyber_registry(reg_pool) == []


async def test_registry_config_cyber_disabled_hidden(reg_pool):
    await insert_fixture(reg_pool, [("org-a", "A", 1, True, True)], [("a-sp", "A")],
                         [("a-sp", "org-a", False, True, True, True)])
    assert await fetch_cyber_registry(reg_pool) == []


async def test_registry_tenant_without_config_hidden(reg_pool):
    await insert_fixture(
        reg_pool, [("org-a", "A", 1, True, True)],
        [("a-sp", "A"), ("orphan-sp", "Orphan")],
        [("a-sp", "org-a", True, True, True, True)],
    )
    ids = [t.tenant_id for o in await fetch_cyber_registry(reg_pool) for t in o.tenants]
    assert "a-sp" in ids and "orphan-sp" not in ids


async def test_registry_multiple_tenants_per_org_ordered(reg_pool):
    await insert_fixture(
        reg_pool, [("org-a", "A", 1, True, True)],
        [("a1-sp", "Zeta"), ("a2-sp", "Alpha")],
        [("a1-sp", "org-a", True, True, True, True), ("a2-sp", "org-a", True, True, True, True)],
    )
    regs = await fetch_cyber_registry(reg_pool)
    assert len(regs) == 1 and len(regs[0].tenants) == 2
    assert [t.tenant_name for t in regs[0].tenants] == ["Alpha", "Zeta"]  # por display_name


async def test_registry_order_by_display_order(reg_pool):
    await insert_fixture(
        reg_pool, [("org-b", "B", 2, True, True), ("org-a", "A", 1, True, True)],
        [("b-sp", "B"), ("a-sp", "A")],
        [("b-sp", "org-b", True, True, True, True), ("a-sp", "org-a", True, True, True, True)],
    )
    regs = await fetch_cyber_registry(reg_pool)
    assert [o.organization_id for o in regs] == ["org-a", "org-b"]


async def test_registry_order_by_name_tiebreak(reg_pool):
    # mesmo display_order -> desempate por organization.name (Alpha antes de Zeta)
    await insert_fixture(
        reg_pool, [("org-z", "Zeta", 1, True, True), ("org-a", "Alpha", 1, True, True)],
        [("z-sp", "Z"), ("a-sp", "A")],
        [("z-sp", "org-z", True, True, True, True), ("a-sp", "org-a", True, True, True, True)],
    )
    regs = await fetch_cyber_registry(reg_pool)
    assert [o.organization_name for o in regs] == ["Alpha", "Zeta"]


async def test_registry_new_org_appears_without_code_change(reg_pool):
    await insert_fixture(
        reg_pool, [("org-xyz-novo", "Secretaria Nova", 7, True, True)],
        [("xyz-sp", "XYZ")], [("xyz-sp", "org-xyz-novo", True, True, True, True)],
    )
    regs = await fetch_cyber_registry(reg_pool)
    assert any(o.organization_id == "org-xyz-novo" for o in regs)


async def test_registry_sources_flags_reflected(reg_pool):
    await insert_fixture(
        reg_pool, [("org-a", "A", 1, True, True)], [("a-sp", "A")],
        [("a-sp", "org-a", True, True, False, True)],  # workbench desabilitado
    )
    regs = await fetch_cyber_registry(reg_pool)
    t = regs[0].tenants[0]
    assert t.oat_enabled is True and t.workbench_enabled is False and t.suspicious_objects_enabled is True
