"""Testes do coletor de Suspicious Objects (collectors/cyber_suspicious_objects.py)."""
from app.cyber_normalize import value_hash
from collectors.cyber_suspicious_objects import classify, persist_sync
from tests.conftest import insert_fixture


def _so(t, val, action="block", risk="high", exc=False, lm=None, exp=None, desc=None):
    d = {"type": t, "scanAction": action, "riskLevel": risk, "inExceptionList": exc,
         "lastModifiedDateTime": lm, "expiredDateTime": exp, "description": desc}
    d[t] = val
    return d


# ---------------- classify (unit) ----------------

def test_classify_filters_types_and_normalizes():
    items = [_so("ip", " 8.8.8.8 "), _so("domain", "Evil.COM."), _so("url", "HTTP://x.com/A"),
             _so("fileSha256", "abc"), _so("senderMailAddress", "a@b.com"), _so("ip", "nao-ip")]
    rows, stats = classify(items)
    assert stats["ip"] == 1 and stats["domain"] == 1 and stats["url"] == 1
    assert stats["skipped_type"] == 2 and stats["invalid_value"] == 1
    vals = {r[1] for r in rows}
    assert {"8.8.8.8", "evil.com", "http://x.com/A"} <= vals


def test_classify_dedup_within_batch():
    rows, _ = classify([_so("ip", "8.8.8.8"), _so("ip", "8.8.8.8")])
    assert len(rows) == 1


def test_classify_counts_actions():
    _, stats = classify([_so("ip", "8.8.8.8", action="block"), _so("domain", "e.com", action="log")])
    assert stats["block"] == 1 and stats["log"] == 1


# ---------------- persist_sync (integracao temp DB) ----------------

async def _prep(pool):
    await insert_fixture(pool, tenants=[("prodesp-sp", "Prodesp")],
                         orgs=[("org-prodesp", "prodesp-sp", "Prodesp", 1, True, True)],
                         cfgs=[("prodesp-sp", "org-prodesp", True, True, True, True)])


async def test_so_sync_added_then_idempotent(reg_pool):
    await _prep(reg_pool)
    rows, _ = classify([_so("ip", "8.8.8.8"), _so("domain", "evil.com")])
    m1 = await persist_sync(reg_pool, "prodesp-sp", rows, 1)
    assert m1["added"] == 2 and m1["removed"] == 0 and m1["active_total"] == 2 and m1["collisions"] == 0
    async with reg_pool.acquire() as c:
        n = await c.fetchval("SELECT count(*) FROM cyber_suspicious_object so JOIN cyber_indicator i "
                             "ON i.indicator_pk=so.indicator_pk WHERE i.tenant_id='prodesp-sp'")
        hist_added = await c.fetchval("SELECT count(*) FROM cyber_suspicious_object_history "
                                      "WHERE tenant_id='prodesp-sp' AND change_type='added'")
    assert n == 2 and hist_added == 2
    m2 = await persist_sync(reg_pool, "prodesp-sp", rows, 1)   # idempotente
    assert m2["added"] == 0 and m2["modified"] == 0 and m2["removed"] == 0 and m2["active_total"] == 2


async def test_so_sync_modified_and_removed(reg_pool):
    await _prep(reg_pool)
    rows, _ = classify([_so("ip", "8.8.8.8", action="block"), _so("domain", "evil.com")])
    await persist_sync(reg_pool, "prodesp-sp", rows, 1)
    rows2, _ = classify([_so("ip", "8.8.8.8", action="log")])   # ip muda; domain some
    m = await persist_sync(reg_pool, "prodesp-sp", rows2, 1)
    assert m["modified"] == 1 and m["removed"] == 1 and m["active_total"] == 1
    async with reg_pool.acquire() as c:
        hmod = await c.fetchval("SELECT count(*) FROM cyber_suspicious_object_history "
                                "WHERE tenant_id='prodesp-sp' AND change_type='modified'")
        hrem = await c.fetchval("SELECT count(*) FROM cyber_suspicious_object_history "
                                "WHERE tenant_id='prodesp-sp' AND change_type='removed'")
        inactive = await c.fetchval("SELECT count(*) FROM cyber_suspicious_object so "
                                    "JOIN cyber_indicator i ON i.indicator_pk=so.indicator_pk "
                                    "WHERE i.tenant_id='prodesp-sp' AND NOT so.is_active")
        # o ip 8.8.8.8 permanece ativo com scan_action atualizado
        act = await c.fetchval("SELECT scan_action FROM cyber_suspicious_object so "
                               "JOIN cyber_indicator i ON i.indicator_pk=so.indicator_pk "
                               "WHERE i.tenant_id='prodesp-sp' AND i.value_normalized='8.8.8.8'")
    assert hmod == 1 and hrem == 1 and inactive == 1 and act == "log"


async def test_so_truncated_skips_removal(reg_pool):
    await _prep(reg_pool)
    await persist_sync(reg_pool, "prodesp-sp", classify([_so("ip", "8.8.8.8"), _so("domain", "evil.com")])[0], 1)
    # fetch truncado (complete=False): NAO remove o domain ausente do lote parcial
    m = await persist_sync(reg_pool, "prodesp-sp", classify([_so("ip", "8.8.8.8")])[0], 1, complete=False)
    assert m["removed"] == 0 and m["active_total"] == 2
    async with reg_pool.acquire() as c:
        st = await c.fetchval("SELECT status FROM cyber_collection_state WHERE tenant_id='prodesp-sp' AND collector='suspicious_object'")
    assert st == "partial"


async def test_so_reactivation_history(reg_pool):
    await _prep(reg_pool)
    await persist_sync(reg_pool, "prodesp-sp", classify([_so("ip", "8.8.8.8"), _so("domain", "evil.com")])[0], 1)
    await persist_sync(reg_pool, "prodesp-sp", classify([_so("ip", "8.8.8.8")])[0], 1)   # remove domain
    async with reg_pool.acquire() as c:
        inact = await c.fetchval("SELECT NOT so.is_active FROM cyber_suspicious_object so JOIN cyber_indicator i "
                                 "ON i.indicator_pk=so.indicator_pk WHERE i.value_normalized='evil.com'")
    assert inact is True
    m = await persist_sync(reg_pool, "prodesp-sp", classify([_so("ip", "8.8.8.8"), _so("domain", "evil.com")])[0], 1)
    assert m["added"] == 1   # reativacao contabilizada como 'added'
    async with reg_pool.acquire() as c:
        active = await c.fetchval("SELECT so.is_active FROM cyber_suspicious_object so JOIN cyber_indicator i "
                                  "ON i.indicator_pk=so.indicator_pk WHERE i.value_normalized='evil.com'")
        open_removed = await c.fetchval("SELECT count(*) FROM cyber_suspicious_object_history h JOIN cyber_indicator i "
                                        "ON i.indicator_pk=h.indicator_pk WHERE i.value_normalized='evil.com' "
                                        "AND h.change_type='removed' AND h.valid_to IS NULL")
        open_added = await c.fetchval("SELECT count(*) FROM cyber_suspicious_object_history h JOIN cyber_indicator i "
                                      "ON i.indicator_pk=h.indicator_pk WHERE i.value_normalized='evil.com' "
                                      "AND h.change_type='added' AND h.valid_to IS NULL")
    assert active is True and open_removed == 0 and open_added == 1


async def test_so_sync_collision_counted(reg_pool):
    await _prep(reg_pool)
    async with reg_pool.acquire() as c:
        await c.execute("INSERT INTO cyber_indicator (tenant_id,indicator_type,value_hash,value_normalized,"
                        "value_raw,first_seen_at,last_seen_at) VALUES ('prodesp-sp','ip',$1,'1.1.1.1','1.1.1.1',now(),now())",
                        value_hash("ip", "1.1.1.1"))
    # linha forjada: MESMO hash de ip|1.1.1.1 mas value_normalized divergente -> colisao (nao sobrescreve)
    forged = ("ip", "9.9.9.9", value_hash("ip", "1.1.1.1"), "9.9.9.9", "block", "high", False, None, None, None)
    m = await persist_sync(reg_pool, "prodesp-sp", [forged], 1)
    assert m["collisions"] == 1
    async with reg_pool.acquire() as c:
        preserved = await c.fetchval("SELECT value_normalized FROM cyber_indicator "
                                     "WHERE tenant_id='prodesp-sp' AND value_hash=$1", value_hash("ip", "1.1.1.1"))
    assert preserved == "1.1.1.1"   # valor original nao foi sobrescrito
