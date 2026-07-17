"""Testes do motor de atribuicao (app/cyber_attribution.py) — §2, §10 e reatribuicao."""
import hashlib
import json

from app.cyber_attribution import (
    _mapping_candidates,
    extract_identifiers,
    reattribute_unassigned,
    resolve_organization,
)
from tests.conftest import insert_fixture


def _h(v):
    return hashlib.sha256(v.encode()).digest()


# ---------------- unit (puro) ----------------

def test_extract_preserves_instance_identifiers():
    detail = {"managementScopeInstanceId": "sep-01", "instanceId": "i1", "groupId": "g1",
              "customAssetTags": {"Environment": "prod", "Service": "pge"}, "irrelevante": "x"}
    ids = extract_identifiers(detail, source="detections", product_code="xes")
    assert ids["managementScopeInstanceId"] == "sep-01"
    assert ids["instanceId"] == "i1" and ids["groupId"] == "g1"
    assert ids["customAssetTags"] == {"Environment": "prod", "Service": "pge"}
    assert ids["source"] == "detections" and ids["productCode"] == "xes"
    assert "irrelevante" not in ids


def test_single_org_attributes():
    r = resolve_organization("single_org", ["org-x"], {}, lambda mt, vh: [])
    assert (r.status, r.organization_id, r.method, r.confidence) == ("attributed", "org-x", "single_org", "high")


def test_single_org_multiple_orgs_stays_unassigned():
    r = resolve_organization("single_org", ["a", "b"], {}, lambda mt, vh: [])
    assert r.status == "unassigned" and r.organization_id is None


def test_instance_mode_no_mapping_is_pending():
    r = resolve_organization("instance", [], {"managementScopeInstanceId": "sep-01"}, lambda mt, vh: [])
    assert r.status == "unassigned" and r.method == "instance_mapping_pending" and r.organization_id is None


def test_mapping_mode_no_mapping_unknown():
    r = resolve_organization("mapping", [], {"instanceId": "i1"}, lambda mt, vh: [])
    assert r.status == "unassigned" and r.method == "unknown"


def test_instance_with_mapping_attributes():
    ids = {"managementScopeInstanceId": "sep-pge"}
    target = _h("sep-pge")

    def lookup(mt, vh):
        return [("org-pge", "high")] if (mt == "management_scope_instance" and vh == target) else []

    r = resolve_organization("instance", [], ids, lookup)
    assert r.status == "attributed" and r.organization_id == "org-pge"
    assert r.method == "management_scope_instance" and r.confidence == "high"


def test_ambiguous_multiple_orgs():
    ids = {"managementScopeInstanceId": "x", "instanceId": "y"}

    def lookup(mt, vh):
        if mt == "management_scope_instance":
            return [("org-a", "high")]
        if mt == "product_instance_id":
            return [("org-b", "high")]
        return []

    r = resolve_organization("instance", [], ids, lookup)
    assert r.status == "ambiguous" and r.organization_id is None
    assert "org-a" in r.evidence and "org-b" in r.evidence


def test_none_mode_unassigned():
    r = resolve_organization("none", ["org-x"], {"instanceId": "i"}, lambda mt, vh: [])
    assert r.status == "unassigned"


def test_tag_candidates_generated():
    cands = _mapping_candidates({"customAssetTags": {"org": "pge"}})
    types = {mt for mt, _ in cands}
    assert "organization_tag" in types and "custom_tag" in types


# ---------------- integracao: reatribuicao idempotente (temp DB 001+002+003) ----------------

async def test_reattribute_idempotent(reg_pool):
    await insert_fixture(
        reg_pool,
        tenants=[("sggd", "SGGD")],
        orgs=[("org-sggd", "sggd", "SGGD", 1, True, True), ("org-pge", "sggd", "PGE", 2, True, True)],
        cfgs=[("sggd", "org-sggd", True, True, True, True)],
    )
    async with reg_pool.acquire() as c:
        await c.execute("UPDATE cyber_tenant_config SET attribution_mode='instance' WHERE tenant_id='sggd'")
        await c.execute(
            "INSERT INTO cyber_organization_mapping "
            "(tenant_id,organization_id,mapping_type,mapping_value_normalized,mapping_value_hash,confidence) "
            "VALUES ('sggd','org-pge','management_scope_instance','sep-pge',$1,'high')", _h("sep-pge"))
        await c.execute(
            "INSERT INTO cyber_indicator (tenant_id,indicator_type,value_hash,value_normalized,value_raw,first_seen_at,last_seen_at) "
            "VALUES ('sggd','ip',$1,'8.8.8.8','8.8.8.8',now(),now())", hashlib.sha256(b"ip|8.8.8.8").digest())
        ind = await c.fetchval("SELECT indicator_pk FROM cyber_indicator WHERE tenant_id='sggd' AND value_normalized='8.8.8.8'")
        await c.execute(
            "INSERT INTO cyber_oat_observation "
            "(tenant_id,indicator_pk,source,source_event_id,source_field,indicator_role,event_time,severity,"
            " organization_attribution_status,organization_attribution_method,attribution_identifiers) "
            "VALUES ('sggd',$1,'detections','ev1','peerIp','attacker',now(),'high','unassigned','instance_mapping_pending',$2::jsonb)",
            ind, json.dumps({"managementScopeInstanceId": "sep-pge"}))

    r1 = await reattribute_unassigned(reg_pool, "sggd")
    assert r1["reattributed"] == 1 and r1["still_unassigned"] == 0

    async with reg_pool.acquire() as c:
        row = await c.fetchrow(
            "SELECT organization_id, organization_attribution_status, organization_attribution_method "
            "FROM cyber_oat_observation WHERE tenant_id='sggd'")
    assert row["organization_id"] == "org-pge"
    assert row["organization_attribution_status"] == "attributed"
    assert row["organization_attribution_method"] == "management_scope_instance"

    r2 = await reattribute_unassigned(reg_pool, "sggd")   # idempotente
    assert r2["reattributed"] == 0 and r2["scanned"] == 0


async def test_reattribute_no_mapping_keeps_unassigned(reg_pool):
    await insert_fixture(
        reg_pool, tenants=[("sggd", "SGGD")],
        orgs=[("org-sggd", "sggd", "SGGD", 1, True, True)],
        cfgs=[("sggd", "org-sggd", True, True, True, True)])
    async with reg_pool.acquire() as c:
        await c.execute("UPDATE cyber_tenant_config SET attribution_mode='instance' WHERE tenant_id='sggd'")
        await c.execute(
            "INSERT INTO cyber_indicator (tenant_id,indicator_type,value_hash,value_normalized,value_raw,first_seen_at,last_seen_at) "
            "VALUES ('sggd','ip',$1,'1.1.1.1','1.1.1.1',now(),now())", hashlib.sha256(b"ip|1.1.1.1").digest())
        ind = await c.fetchval("SELECT indicator_pk FROM cyber_indicator WHERE tenant_id='sggd'")
        await c.execute(
            "INSERT INTO cyber_oat_observation "
            "(tenant_id,indicator_pk,source,source_event_id,source_field,indicator_role,event_time,severity,"
            " organization_attribution_status,organization_attribution_method,attribution_identifiers) "
            "VALUES ('sggd',$1,'detections','ev2','peerIp','attacker',now(),'high','unassigned','instance_mapping_pending',$2::jsonb)",
            ind, json.dumps({"managementScopeInstanceId": "sep-desconhecida"}))
    r = await reattribute_unassigned(reg_pool, "sggd")
    assert r["reattributed"] == 0 and r["still_unassigned"] == 1
