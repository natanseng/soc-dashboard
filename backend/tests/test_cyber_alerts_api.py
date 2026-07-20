"""Testes das APIs da tela Alertas (agregacao MTTD/MTTR, severidade, status, nao atribuidos)."""
from app import cyber_alerts_api as api
from tests.conftest import insert_fixture

_INS = (
    "INSERT INTO cyber_workbench_alert (tenant_id, alert_id, severity, status, model_type, created_at, "
    "updated_at_v1, detect_seconds, resolve_seconds, organization_id, organization_attribution_status) "
    "VALUES ($1,$2,$3,$4,$5, now(), now(), $6, $7, $8, $9)"
)


async def _seed(pool):
    await insert_fixture(
        pool,
        tenants=[("prodesp-sp", "Prodesp"), ("sggd", "SGGD")],
        orgs=[("org-prodesp", "prodesp-sp", "Prodesp", 1, True, True),
              ("org-sggd", "sggd", "SGGD", 1, True, True)],
        cfgs=[("prodesp-sp", "org-prodesp", True, True, True, True),
              ("sggd", "org-sggd", True, True, True, True)])
    async with pool.acquire() as c:
        # prodesp: 2 Open (high/medium) + 1 Closed (high), atribuidos
        await c.execute(_INS, "prodesp-sp", "WB-A1", "high", "Open", "preset", 60.0, None, "org-prodesp", "attributed")
        await c.execute(_INS, "prodesp-sp", "WB-A2", "medium", "Open", "preset", 120.0, None, "org-prodesp", "attributed")
        await c.execute(_INS, "prodesp-sp", "WB-A3", "high", "Closed", "custom", 30.0, 3600.0, "org-prodesp", "attributed")
        # sggd: 1 Open nao atribuido (sem mapeamento de instancia)
        await c.execute(_INS, "sggd", "WB-B1", "medium", "Open", "custom", None, None, None, "unassigned")


async def test_summary(reg_pool):
    await _seed(reg_pool)
    s = await api.summary(reg_pool)
    assert s["status"] == "ok"
    assert s["severity30d"] == {"high": 2, "medium": 2}
    assert s["active"] == 3 and s["byStatus"].get("Open") == 3 and s["byStatus"].get("Closed") == 1
    assert s["total30d"] == 4
    assert round(s["mtt"]["mttdSeconds"]) == 70 and s["mtt"]["mttdSampleSize"] == 3   # (60+120+30)/3
    assert s["mtt"]["mttrSeconds"] == 3600 and s["mtt"]["mttrSampleSize"] == 1
    # segmentado: preset (A1,A2) e custom (A3)
    assert round(s["mttBySegment"]["preset"]["mttdSeconds"]) == 90
    assert s["mttBySegment"]["custom"]["mttdSeconds"] == 30


async def test_by_tenant(reg_pool):
    await _seed(reg_pool)
    d = await api.by_tenant(reg_pool)
    by = {t["tenantId"]: t for t in d["tenants"]}
    p = by["prodesp-sp"]
    assert p["open"] == 2 and p["active"] == 2 and p["total30d"] == 3
    assert round(p["mtt"]["mttdSeconds"]) == 70 and p["mtt"]["mttrSeconds"] == 3600
    s = by["sggd"]
    assert s["open"] == 1 and s["active"] == 1 and s["mtt"]["mttdSeconds"] is None   # A4 sem MTTD


async def test_by_organization_and_unassigned(reg_pool):
    await _seed(reg_pool)
    d = await api.by_organization(reg_pool)
    orgs = {o["organizationId"]: o for o in d["organizations"]}
    assert orgs["org-prodesp"]["total"] == 3 and orgs["org-prodesp"]["active"] == 2
    assert orgs["org-sggd"]["total"] == 0                    # nada atribuido ao suborgao sggd
    un = {u["tenantId"]: u for u in d["unassigned"]}
    assert un["sggd"]["total"] == 1 and un["sggd"]["active"] == 1   # nao atribuido identificado


async def test_history_and_events(reg_pool):
    await _seed(reg_pool)
    h = await api.history(reg_pool, days=30)
    assert sum(h["consolidated"].values()) == 4
    e = await api.events(reg_pool, tenant_id="prodesp-sp")
    assert e["count"] == 3 and all(ev["tenantId"] == "prodesp-sp" for ev in e["events"])
    eu = await api.events(reg_pool, unassigned=True)
    assert eu["count"] == 1 and eu["events"][0]["alertId"] == "WB-B1"
