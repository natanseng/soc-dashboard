"""Testes do GeoIP Cyber (collectors/cyber_geo.py)."""
from app.cyber_normalize import value_hash
from collectors.cyber_geo import GeoResolver, run_geo
from tests.conftest import insert_fixture

_GEO = {"country": "US", "city": "X", "lat": 37.0, "lon": -97.0}


async def test_resolve_ip_direct():
    r = GeoResolver(ip_lookup=lambda ip: _GEO)
    g = await r.resolve("ip", "8.8.8.8")
    assert g["geo_status"] == "ok" and g["geo_resolution_method"] == "direct_ip"
    assert g["resolved_ip"] == "8.8.8.8" and g["country"] == "US" and g["latitude"] == 37.0


async def test_resolve_ip_nogeo():
    r = GeoResolver(ip_lookup=lambda ip: None)
    g = await r.resolve("ip", "8.8.8.8")
    assert g["geo_status"] == "nogeo" and g["resolved_ip"] == "8.8.8.8" and g["latitude"] is None


async def test_resolve_domain_via_dns():
    async def dns(host):
        return "1.2.3.4" if host == "evil.com" else None
    r = GeoResolver(ip_lookup=lambda ip: {"country": "BR", "city": "SP", "lat": -23.5, "lon": -46.6}, dns_resolver=dns)
    g = await r.resolve("domain", "evil.com")
    assert g["geo_status"] == "ok" and g["geo_resolution_method"] == "dns"
    assert g["resolved_ip"] == "1.2.3.4" and g["country"] == "BR"


async def test_resolve_domain_unresolved():
    async def dns(host):
        return None
    g = await GeoResolver(dns_resolver=dns).resolve("domain", "nx.example.com")
    assert g["geo_status"] == "unresolved" and g["geo_resolution_method"] == "dns" and g["resolved_ip"] is None


async def test_resolve_url_uses_host():
    async def dns(host):
        return "9.9.9.9" if host == "evil.com" else None
    r = GeoResolver(ip_lookup=lambda ip: _GEO, dns_resolver=dns)
    g = await r.resolve("url", "http://evil.com/a")
    assert g["geo_status"] == "ok" and g["resolved_ip"] == "9.9.9.9"


async def test_resolve_domain_resolves_private_is_private():
    async def dns(host):
        return "10.0.0.5"
    g = await GeoResolver(dns_resolver=dns).resolve("domain", "internal.example.com")
    assert g["geo_status"] == "private" and g["geo_resolution_method"] == "none" and g["resolved_ip"] is None


async def test_dns_cache_used():
    calls = {"n": 0}

    async def dns(host):
        calls["n"] += 1
        return "1.2.3.4"
    r = GeoResolver(ip_lookup=lambda ip: _GEO, dns_resolver=dns)
    await r.resolve("domain", "x.com")
    await r.resolve("domain", "x.com")
    assert calls["n"] == 1


async def test_run_geo_only_referenced_and_idempotent(reg_pool):
    await insert_fixture(reg_pool, tenants=[("prodesp-sp", "Prodesp")],
                         orgs=[("org-prodesp", "prodesp-sp", "Prodesp", 1, True, True)],
                         cfgs=[("prodesp-sp", "org-prodesp", True, True, True, True)])
    async with reg_pool.acquire() as c:
        await c.execute("INSERT INTO cyber_indicator (tenant_id,indicator_type,value_hash,value_normalized,value_raw,first_seen_at,last_seen_at) "
                        "VALUES ('prodesp-sp','ip',$1,'8.8.8.8','8.8.8.8',now(),now())", value_hash("ip", "8.8.8.8"))
        ind = await c.fetchval("SELECT indicator_pk FROM cyber_indicator WHERE value_normalized='8.8.8.8'")
        await c.execute("INSERT INTO cyber_oat_observation (tenant_id,indicator_pk,source,source_event_id,source_field,indicator_role,event_time,severity) "
                        "VALUES ('prodesp-sp',$1,'detections','u1','src','attacker',now(),'high')", ind)
        # indicador SO-only (nao referenciado por OAT/WB) -> NAO deve ser enriquecido
        await c.execute("INSERT INTO cyber_indicator (tenant_id,indicator_type,value_hash,value_normalized,value_raw,first_seen_at,last_seen_at) "
                        "VALUES ('prodesp-sp','ip',$1,'1.1.1.1','1.1.1.1',now(),now())", value_hash("ip", "1.1.1.1"))
    res = await run_geo(reg_pool, resolver=GeoResolver(ip_lookup=lambda ip: _GEO))
    assert res["candidates"] == 1 and res["ok"] == 1
    async with reg_pool.acquire() as c:
        g1 = await c.fetchrow("SELECT geo_status, country, latitude, resolved_ip FROM cyber_indicator WHERE value_normalized='8.8.8.8'")
        g2 = await c.fetchval("SELECT geo_status FROM cyber_indicator WHERE value_normalized='1.1.1.1'")
    assert g1["geo_status"] == "ok" and g1["country"] == "US" and str(g1["resolved_ip"]) == "8.8.8.8"
    assert g2 is None    # SO-only nao enriquecido
    res2 = await run_geo(reg_pool, resolver=GeoResolver(ip_lookup=lambda ip: _GEO))
    assert res2["candidates"] == 0   # ja resolvido, nao expirado
