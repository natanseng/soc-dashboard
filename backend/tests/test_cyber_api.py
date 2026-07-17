"""Testes das APIs Cyber (app/cyber_api.py) — §16/§17."""
import json

from app import cyber_api
from collectors.cyber_oat import _persist_obs, build_observations
from tests.conftest import insert_fixture


def _ho(f, t, v):
    return {"field": f, "type": t, "value": v}


def _det(uuid, act=None, ind="8.8.8.8"):
    d = {"source": "detections", "productCode": "pdi"}
    if act is not None:
        d["act"] = act
    return {"uuid": uuid, "detectedDateTime": "2026-07-17T10:00:00Z", "ingestedDateTime": "2026-07-17T10:00:00Z",
            "detail": d, "filters": [{"highlightedObjects": [_ho("src", "ip", ind)]}]}


async def _seed(pool):
    await insert_fixture(pool, tenants=[("prodesp-sp", "Prodesp"), ("sggd", "SGGD")],
                         orgs=[("org-prodesp", "prodesp-sp", "Prodesp", 1, True, True),
                               ("org-sggd", "sggd", "SGGD", 1, True, True),
                               ("org-pge", "sggd", "PGE", 2, True, True)],
                         cfgs=[("prodesp-sp", "org-prodesp", True, True, True, True),
                               ("sggd", "org-sggd", True, True, True, True)])
    async with pool.acquire() as c:
        await c.execute("UPDATE cyber_tenant_config SET attribution_mode='instance' WHERE tenant_id='sggd'")
        async with c.transaction():
            o1, _ = build_observations(_det("p1", act=["Reset"], ind="8.8.8.8"), "high", ("single_org", ["org-prodesp"], {}, set()))
            await _persist_obs(c, "prodesp-sp", o1[0])
            o2, _ = build_observations(_det("p2", act=["not blocked"], ind="1.1.1.1"), "critical", ("single_org", ["org-prodesp"], {}, set()))
            await _persist_obs(c, "prodesp-sp", o2[0])
            o3, _ = build_observations(_det("s1", act=["Reset"], ind="9.9.9.9"), "high", ("instance", ["org-sggd", "org-pge"], {}, set()))
            await _persist_obs(c, "sggd", o3[0])


async def test_summary(reg_pool):
    await _seed(reg_pool)
    s = (await cyber_api.summary(reg_pool))["summary"]
    assert s["observations"] == 3 and s["attributed"] == 2 and s["unassigned"] == 1
    assert s["blocked_confirmed"] == 2 and s["high"] == 2 and s["critical"] == 1


async def test_by_organization_all_enabled_orgs_appear(reg_pool):
    await _seed(reg_pool)
    r = await cyber_api.by_organization(reg_pool)
    byid = {o["organizationId"]: o for o in r["organizations"]}
    assert byid["org-prodesp"]["observations"] == 2 and byid["org-prodesp"]["blockedConfirmed"] == 1
    assert byid["org-sggd"]["observations"] == 0 and byid["org-pge"]["observations"] == 0   # sggd unassigned
    assert "org-pge" in byid   # orgao dinamico aparece mesmo sem observacoes


async def test_by_tenant_unassigned(reg_pool):
    await _seed(reg_pool)
    bt = {t["tenantId"]: t for t in (await cyber_api.by_tenant(reg_pool))["tenants"]}
    assert bt["sggd"]["unassigned"]["observations"] == 1
    assert bt["prodesp-sp"]["organizations"][0]["observations"] == 2


async def test_coverage(reg_pool):
    await _seed(reg_pool)
    r = await cyber_api.coverage(reg_pool)
    assert r["global"]["attributed"] == 2 and r["global"]["total"] == 3
    cov = {x["tenantId"]: x for x in r["byTenant"]}
    assert cov["prodesp-sp"]["coveragePct"] == 100.0 and cov["sggd"]["coveragePct"] == 0.0


async def test_map_layer_blocked(reg_pool):
    await _seed(reg_pool)
    r = await cyber_api.map_points(reg_pool, layer="blocked_confirmed")
    assert r["totals"]["observations"] == 2   # 2 prevented (Reset)


async def test_events_no_secrets(reg_pool):
    await _seed(reg_pool)
    r = await cyber_api.events(reg_pool)
    assert len(r["events"]) == 3
    blob = json.dumps(r).lower()
    for bad in ("token", "dsn", "password", "authorization"):
        assert bad not in blob


async def test_validate_org_in_tenant(reg_pool):
    await _seed(reg_pool)
    assert await cyber_api.validate_org_in_tenant(reg_pool, "prodesp-sp", "org-prodesp") is True
    assert await cyber_api.validate_org_in_tenant(reg_pool, "prodesp-sp", "org-pge") is False  # org-pge e do sggd
    assert await cyber_api.validate_org_in_tenant(reg_pool, None, None) is True
