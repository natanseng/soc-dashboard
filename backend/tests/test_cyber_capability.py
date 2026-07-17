"""Testes da capacidade de enforcement (collectors/cyber_capability.py) — §14."""
from collectors.cyber_capability import _capability, compute_capability
from collectors.cyber_oat import _persist_obs, build_observations
from tests.conftest import insert_fixture


def test_capability_thresholds():
    assert _capability(10, 0) == "none"
    assert _capability(10, 9) == "full"
    assert _capability(10, 10) == "full"
    assert _capability(10, 5) == "partial"


def _ho(f, t, v):
    return {"field": f, "type": t, "value": v}


def _det(uuid, act=None, ind="8.8.8.8"):
    d = {"source": "detections", "productCode": "pdi"}
    if act is not None:
        d["act"] = act
    return {"uuid": uuid, "detectedDateTime": "2026-07-17T10:00:00Z", "ingestedDateTime": "2026-07-17T10:00:00Z",
            "detail": d, "filters": [{"highlightedObjects": [_ho("src", "ip", ind)]}]}


async def _prep(pool):
    await insert_fixture(pool, tenants=[("prodesp-sp", "Prodesp")],
                         orgs=[("org-prodesp", "prodesp-sp", "Prodesp", 1, True, True)],
                         cfgs=[("prodesp-sp", "org-prodesp", True, True, True, True)])


async def test_capability_full(reg_pool):
    await _prep(reg_pool)
    ctx = ("single_org", ["org-prodesp"], {}, set())
    async with reg_pool.acquire() as c:
        async with c.transaction():
            for i, ip in enumerate(["8.8.8.8", "1.1.1.1", "9.9.9.9"]):
                obs, _ = build_observations(_det(f"u{i}", act=["Reset"], ind=ip), "high", ctx)
                await _persist_obs(c, "prodesp-sp", obs[0])
    r = await compute_capability(reg_pool)
    g = {(x["source"], x["product_code"]): x for x in r["groups"]}
    assert g[("detections", "pdi")]["capability"] == "full"
    async with reg_pool.acquire() as c:
        cap = await c.fetchrow("SELECT capability, status, evidence_field FROM cyber_enforcement_capability "
                               "WHERE tenant_id='prodesp-sp' AND source='detections' AND product_code='pdi'")
    assert cap["capability"] == "full" and cap["status"] == "current" and cap["evidence_field"] == "detail.act"


async def test_capability_none_when_no_act(reg_pool):
    await _prep(reg_pool)
    ctx = ("single_org", ["org-prodesp"], {}, set())
    async with reg_pool.acquire() as c:
        async with c.transaction():
            obs, _ = build_observations(_det("u1", act=None, ind="8.8.8.8"), "high", ctx)  # detections sem act -> unknown
            await _persist_obs(c, "prodesp-sp", obs[0])
    r = await compute_capability(reg_pool)
    g = {(x["source"], x["product_code"]): x for x in r["groups"]}
    assert g[("detections", "pdi")]["capability"] == "none"
