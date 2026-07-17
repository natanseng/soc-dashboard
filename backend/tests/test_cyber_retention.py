"""Testes da retencao (collectors/cyber_retention.py) — §15."""
from datetime import datetime, timedelta, timezone

from app.cyber_normalize import value_hash
from collectors.cyber_retention import run_retention
from tests.conftest import insert_fixture


async def _prep(pool):
    await insert_fixture(pool, tenants=[("prodesp-sp", "Prodesp")],
                         orgs=[("org-prodesp", "prodesp-sp", "Prodesp", 1, True, True)],
                         cfgs=[("prodesp-sp", "org-prodesp", True, True, True, True)])


async def test_retention_deletes_old_keeps_recent(reg_pool):
    await _prep(reg_pool)
    old = datetime.now(timezone.utc) - timedelta(hours=40)
    new = datetime.now(timezone.utc) - timedelta(hours=1)
    async with reg_pool.acquire() as c:
        await c.execute("INSERT INTO cyber_indicator (tenant_id,indicator_type,value_hash,value_normalized,value_raw,first_seen_at,last_seen_at) "
                        "VALUES ('prodesp-sp','ip',$1,'8.8.8.8','8.8.8.8',now(),now())", value_hash("ip", "8.8.8.8"))
        ind = await c.fetchval("SELECT indicator_pk FROM cyber_indicator WHERE value_normalized='8.8.8.8'")
        for ev, t in (("old", old), ("new", new)):
            await c.execute("INSERT INTO cyber_oat_observation (tenant_id,indicator_pk,source,source_event_id,source_field,indicator_role,event_time,severity) "
                            "VALUES ('prodesp-sp',$1,'detections',$2,'src','attacker',$3,'high')", ind, ev, t)
        await c.execute("INSERT INTO cyber_discard_sample (tenant_id,reason,sampled_at) VALUES ('prodesp-sp','severity',$1)", old)

    dry = await run_retention(reg_pool, dry_run=True)
    assert dry["targets"]["cyber_oat_observation"]["would_delete"] == 1
    assert dry["targets"]["cyber_discard_sample"]["would_delete"] == 1

    res = await run_retention(reg_pool, batch=100)
    assert res["targets"]["cyber_oat_observation"]["deleted"] == 1
    assert res["targets"]["cyber_discard_sample"]["deleted"] == 1
    async with reg_pool.acquire() as c:
        remaining = await c.fetchval("SELECT count(*) FROM cyber_oat_observation")
        ev = await c.fetchval("SELECT source_event_id FROM cyber_oat_observation")
        ind_kept = await c.fetchval("SELECT count(*) FROM cyber_indicator")
    assert remaining == 1 and ev == "new" and ind_kept == 1   # indicador canonico NAO removido

    res2 = await run_retention(reg_pool, batch=100)            # idempotente
    assert res2["targets"]["cyber_oat_observation"]["deleted"] == 0


async def test_retention_batching(reg_pool):
    await _prep(reg_pool)
    old = datetime.now(timezone.utc) - timedelta(hours=40)
    async with reg_pool.acquire() as c:
        for _ in range(12):
            await c.execute("INSERT INTO cyber_discard_sample (tenant_id,reason,sampled_at) VALUES ('prodesp-sp','severity',$1)", old)
    res = await run_retention(reg_pool, batch=5)   # 12 em lotes de 5
    assert res["targets"]["cyber_discard_sample"]["deleted"] == 12
    async with reg_pool.acquire() as c:
        assert await c.fetchval("SELECT count(*) FROM cyber_discard_sample") == 0
