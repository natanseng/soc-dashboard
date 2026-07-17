"""Testes do coletor Workbench (collectors/cyber_workbench.py)."""
from collectors.cyber_oat import _persist_obs, build_observations
from collectors.cyber_workbench import _link_and_count, _persist_wb, build_wb_indicators
from tests.conftest import insert_fixture


def _ctx(mode="single_org", orgs=("org-a",), mappings=None):
    return (mode, list(orgs), mappings or {}, None)


def _ind(t, value, field="src", prov=None):
    return {"type": t, "field": field, "value": value, "provenance": prov or ["Alert"]}


def _alert(aid="WB-1", created="2026-07-17T10:00:00Z", indicators=None, severity="high",
           model="M", provider="SAE", entities=None):
    return {"id": aid, "createdDateTime": created, "severity": severity, "model": model,
            "alertProvider": provider, "indicators": indicators or [],
            "impactScope": {"entities": entities or []}}


def test_wb_extract_external_public_only():
    a = _alert(indicators=[_ind("ip", "8.8.8.8"), _ind("ip", "10.0.0.1"),
                           _ind("domain", "bad.example.com"), _ind("url", "http://evil.com/x"),
                           _ind("command_line", "whoami"), _ind("text", "xx")])
    rows, disc = build_wb_indicators(a, _ctx())
    vals = {r["value_normalized"] for r in rows}
    assert vals == {"8.8.8.8", "bad.example.com", "http://evil.com/x"}
    assert disc["non_public"] == 1   # 10.0.0.1


def test_wb_attribution_single_org():
    rows, _ = build_wb_indicators(_alert(indicators=[_ind("ip", "8.8.8.8")]), _ctx("single_org", ["org-a"]))
    assert rows[0]["organization_id"] == "org-a" and rows[0]["attr_status"] == "attributed"
    assert rows[0]["attr_method"] == "single_org"


def test_wb_attribution_instance_pending():
    rows, _ = build_wb_indicators(_alert(indicators=[_ind("ip", "8.8.8.8")]), _ctx("instance", ["org-sggd", "org-pge"]))
    assert rows[0]["organization_id"] is None and rows[0]["attr_method"] == "instance_mapping_pending"


def test_wb_missing_key_fields():
    rows, disc = build_wb_indicators({"indicators": [_ind("ip", "8.8.8.8")]}, _ctx())
    assert rows == [] and disc["missing_key_fields"] == 1


async def test_wb_persist_link_unlinked_idempotent(reg_pool):
    await insert_fixture(reg_pool, tenants=[("prodesp-sp", "Prodesp")],
                         orgs=[("org-prodesp", "prodesp-sp", "Prodesp", 1, True, True)],
                         cfgs=[("prodesp-sp", "org-prodesp", True, True, True, True)])
    oat_det = {"uuid": "u1", "detectedDateTime": "2026-07-17T10:00:00Z",
               "ingestedDateTime": "2026-07-17T10:00:00Z",
               "detail": {"source": "detections", "productCode": "pdi", "act": ["Reset"]},
               "filters": [{"highlightedObjects": [{"field": "src", "type": "ip", "value": "8.8.8.8"}]}]}
    oat_obs, _ = build_observations(oat_det, "high", ("single_org", ["org-prodesp"], {}, set()))
    wb_rows, _ = build_wb_indicators(
        _alert(aid="WB-1", indicators=[_ind("ip", "8.8.8.8"), _ind("domain", "only-wb.example.com")]),
        ("single_org", ["org-prodesp"], {}, None))

    async with reg_pool.acquire() as c:
        async with c.transaction():
            await _persist_obs(c, "prodesp-sp", oat_obs[0])
            for w in wb_rows:
                await _persist_wb(c, "prodesp-sp", w)
            new_links, linked, unlinked = await _link_and_count(c, "prodesp-sp")
    assert new_links == 1 and linked == 1 and unlinked == 1   # 8.8.8.8 linka; only-wb fica unlinked

    async with reg_pool.acquire() as c:      # idempotencia
        async with c.transaction():
            for w in wb_rows:
                await _persist_wb(c, "prodesp-sp", w)
            nl2, l2, u2 = await _link_and_count(c, "prodesp-sp")
    assert nl2 == 0 and l2 == 1 and u2 == 1

    async with reg_pool.acquire() as c:
        wb_cnt = await c.fetchval("SELECT count(*) FROM cyber_workbench_indicator WHERE tenant_id='prodesp-sp'")
        oat_cnt = await c.fetchval("SELECT count(*) FROM cyber_oat_observation WHERE tenant_id='prodesp-sp'")
    assert wb_cnt == 2 and oat_cnt == 1      # Workbench NAO inflou observacoes OAT
