"""Testes do cadastro dinamico (app/cyber_registry.py) — modelo TENANT -> N ORGANIZATIONS.

- build_payload: unitario e puro (sem I/O).
- fetch_cyber_registry: integracao contra banco temporario (migrations 001+002 reais).
"""
import json
from pathlib import Path

from app.cyber_registry import (
    CyberOrganization,
    CyberTenant,
    _ORGS_SQL,
    _TENANTS_SQL,
    build_payload,
    fetch_cyber_registry,
)
from app.cyber_tokens import TokenStatus
from tests.conftest import insert_fixture

APP = Path(__file__).resolve().parents[1] / "app"


def _org(oid, name=None, order=1, cyber=True, attr=True):
    return CyberOrganization(oid, name or oid.upper(), order, cyber, attr)


def _tenant(tid, orgs=(), name=None):
    return CyberTenant(tid, name or tid.upper(), "https://api.xdr.trendmicro.com",
                       True, True, True, list(orgs))


def _resolver(configured):
    def r(tenant_id):
        ok = configured.get(tenant_id, False)
        return TokenStatus(tenant_id, ok, "VAR", "tok" if ok else None)
    return r


# ---------------- build_payload (unit) ----------------

def test_payload_tenant_with_one_org():
    tenants = [_tenant("prodesp-sp", [_org("org-prodesp", "Prodesp", 1)], name="Prodesp")]
    p = build_payload(tenants, _resolver({"prodesp-sp": True}), updated_at="2026-01-01T00:00:00Z")
    assert p["status"] == "ok" and "updatedAt" in p
    t = p["tenants"][0]
    assert (t["tenantId"], t["tenantName"], t["status"], t["credentialsConfigured"]) == (
        "prodesp-sp", "Prodesp", "ok", True)
    assert t["sources"] == {"oat": True, "workbench": True, "suspiciousObjects": True}
    assert len(t["organizations"]) == 1
    o = t["organizations"][0]
    assert (o["organizationId"], o["organizationName"], o["displayOrder"], o["cyberEnabled"],
            o["attributionEnabled"]) == ("org-prodesp", "Prodesp", 1, True, True)


def test_payload_tenant_with_multiple_orgs():
    tenants = [_tenant("sggd", [
        _org("org-sggd", "SGGD", 1), _org("org-pge", "PGE", 2), _org("org-cge", "CGE", 3)])]
    p = build_payload(tenants, _resolver({"sggd": True}), updated_at="t")
    orgs = p["tenants"][0]["organizations"]
    assert [o["organizationId"] for o in orgs] == ["org-sggd", "org-pge", "org-cge"]


def test_payload_empty():
    p = build_payload([], _resolver({}), updated_at="t")
    assert p["status"] == "ok" and p["tenants"] == []


def test_payload_tenant_without_token_is_unavailable_but_keeps_orgs():
    tenants = [_tenant("iamspe-sp", [_org("org-iamspe", "Iamspe", 1)])]
    p = build_payload(tenants, _resolver({}), updated_at="t")  # sem token
    t = p["tenants"][0]
    assert t["credentialsConfigured"] is False and t["status"] == "configuration_error"
    assert len(t["organizations"]) == 1  # orgaos continuam listados


def test_payload_one_tenant_failure_does_not_drop_others():
    tenants = [_tenant("a-sp", [_org("org-a")]), _tenant("b-sp", [_org("org-b")])]
    p = build_payload(tenants, _resolver({"b-sp": True}), updated_at="t")  # a-sp sem token
    by = {t["tenantId"]: t for t in p["tenants"]}
    assert by["a-sp"]["status"] == "configuration_error"
    assert by["b-sp"]["status"] == "ok"


def test_payload_tenant_without_orgs():
    tenants = [_tenant("x-sp", [])]
    p = build_payload(tenants, _resolver({"x-sp": True}), updated_at="t")
    assert p["tenants"][0]["organizations"] == []


def test_payload_has_no_sensitive_info():
    tenants = [_tenant("sggd", [_org("org-sggd"), _org("org-pge", order=2)])]
    p = build_payload(tenants, _resolver({"sggd": True}), updated_at="t")
    blob = json.dumps(p).lower()
    for bad in ["token", "dsn", "password", "authorization", "v1_api", "senha", "secret"]:
        assert bad not in blob


def test_registry_sql_is_select_only():
    for sql in (_TENANTS_SQL, _ORGS_SQL):
        s = sql.strip().upper()
        assert s.startswith("SELECT")
        for w in ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE"]:
            assert w not in s


def test_no_hardcoded_org_names_in_registry_source():
    src = (APP / "cyber_registry.py").read_text(encoding="utf-8").lower()
    for name in ["prodesp", "detran", "iamspe", "sggd", "pge", "cge", "spprev", "sgri"]:
        assert name not in src


# ---------------- fetch_cyber_registry (integracao 001+002) ----------------

async def test_registry_all_enabled(reg_pool):
    await insert_fixture(
        reg_pool,
        tenants=[("a-sp", "A Tenant"), ("b-sp", "B Tenant")],
        orgs=[("org-a", "a-sp", "A", 1, True, True), ("org-b", "b-sp", "B", 1, True, True)],
        cfgs=[("a-sp", "org-a", True, True, True, True), ("b-sp", "org-b", True, True, True, True)],
    )
    regs = await fetch_cyber_registry(reg_pool)
    assert [t.tenant_id for t in regs] == ["a-sp", "b-sp"]
    assert [o.organization_id for o in regs[0].organizations] == ["org-a"]


async def test_registry_tenant_with_multiple_orgs(reg_pool):
    # REGRA FUNDAMENTAL: um tenant contem varios orgaos
    await insert_fixture(
        reg_pool,
        tenants=[("sggd", "SGGD")],
        orgs=[("org-sggd", "sggd", "SGGD", 1, True, True),
              ("org-pge", "sggd", "PGE", 2, True, True),
              ("org-cge", "sggd", "CGE", 3, True, True)],
        cfgs=[("sggd", "org-sggd", True, True, True, True)],
    )
    regs = await fetch_cyber_registry(reg_pool)
    assert len(regs) == 1 and regs[0].tenant_id == "sggd"
    assert [o.organization_id for o in regs[0].organizations] == ["org-sggd", "org-pge", "org-cge"]


async def test_registry_org_disabled_hidden(reg_pool):
    await insert_fixture(
        reg_pool, [("a-sp", "A")],
        [("org-a", "a-sp", "A", 1, False, True), ("org-a2", "a-sp", "A2", 2, True, True)],
        [("a-sp", "org-a2", True, True, True, True)],
    )
    regs = await fetch_cyber_registry(reg_pool)
    assert [o.organization_id for o in regs[0].organizations] == ["org-a2"]


async def test_registry_org_cyber_disabled_hidden(reg_pool):
    await insert_fixture(
        reg_pool, [("a-sp", "A")],
        [("org-a", "a-sp", "A", 1, True, False), ("org-a2", "a-sp", "A2", 2, True, True)],
        [("a-sp", "org-a2", True, True, True, True)],
    )
    regs = await fetch_cyber_registry(reg_pool)
    assert [o.organization_id for o in regs[0].organizations] == ["org-a2"]


async def test_registry_tenant_cyber_disabled_hidden(reg_pool):
    await insert_fixture(
        reg_pool, [("a-sp", "A")], [("org-a", "a-sp", "A", 1, True, True)],
        [("a-sp", "org-a", False, True, True, True)],  # cyber_enabled=false
    )
    assert await fetch_cyber_registry(reg_pool) == []


async def test_registry_tenant_config_disabled_hidden(reg_pool):
    await insert_fixture(
        reg_pool, [("a-sp", "A")], [("org-a", "a-sp", "A", 1, True, True)],
        [("a-sp", "org-a", True, True, True, True)],
    )
    async with reg_pool.acquire() as c:
        await c.execute("UPDATE cyber_tenant_config SET enabled=false WHERE tenant_id='a-sp'")
    assert await fetch_cyber_registry(reg_pool) == []


async def test_registry_tenant_without_enabled_orgs_appears_empty(reg_pool):
    await insert_fixture(
        reg_pool, [("a-sp", "A")], [("org-a", "a-sp", "A", 1, False, True)],  # org desabilitado
        [("a-sp", "org-a", True, True, True, True)],
    )
    regs = await fetch_cyber_registry(reg_pool)
    assert len(regs) == 1 and regs[0].organizations == []


async def test_registry_orgs_ordered_by_display_order(reg_pool):
    await insert_fixture(
        reg_pool, [("sggd", "SGGD")],
        [("org-z", "sggd", "Zeta", 3, True, True), ("org-a", "sggd", "Alpha", 1, True, True),
         ("org-m", "sggd", "Mid", 2, True, True)],
        [("sggd", "org-a", True, True, True, True)],
    )
    regs = await fetch_cyber_registry(reg_pool)
    assert [o.organization_id for o in regs[0].organizations] == ["org-a", "org-m", "org-z"]


async def test_registry_new_org_appears_without_code_change(reg_pool):
    await insert_fixture(
        reg_pool, [("sggd", "SGGD")],
        [("org-sggd", "sggd", "SGGD", 1, True, True)],
        [("sggd", "org-sggd", True, True, True, True)],
    )
    # novo orgao inserido depois, sem alterar codigo
    async with reg_pool.acquire() as c:
        await c.execute("INSERT INTO organization (organization_id, tenant_id, name, display_order, enabled, cyber_enabled) "
                        "VALUES ('org-novo-xyz', 'sggd', 'Secretaria Nova', 9, true, true)")
    regs = await fetch_cyber_registry(reg_pool)
    ids = [o.organization_id for o in regs[0].organizations]
    assert "org-novo-xyz" in ids


async def test_registry_org_from_other_tenant_not_mixed(reg_pool):
    await insert_fixture(
        reg_pool, [("a-sp", "A"), ("b-sp", "B")],
        [("org-a", "a-sp", "A", 1, True, True), ("org-b", "b-sp", "B", 1, True, True)],
        [("a-sp", "org-a", True, True, True, True), ("b-sp", "org-b", True, True, True, True)],
    )
    regs = await fetch_cyber_registry(reg_pool)
    by = {t.tenant_id: t for t in regs}
    assert [o.organization_id for o in by["a-sp"].organizations] == ["org-a"]
    assert [o.organization_id for o in by["b-sp"].organizations] == ["org-b"]


async def test_registry_sources_flags_reflected(reg_pool):
    await insert_fixture(
        reg_pool, [("a-sp", "A")], [("org-a", "a-sp", "A", 1, True, True)],
        [("a-sp", "org-a", True, True, False, True)],  # workbench desabilitado
    )
    t = (await fetch_cyber_registry(reg_pool))[0]
    assert t.oat_enabled is True and t.workbench_enabled is False and t.suspicious_objects_enabled is True
