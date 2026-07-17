"""GeoIP dos indicadores externos Cyber (§13).

So enriquece indicadores JA ACEITOS (type ip/domain/url referenciados por observacao OAT ou
indicador Workbench) — nao o blocklist SO inteiro. IP: geo direto (GeoLite2). Dominio/URL:
resolve hostname -> IP publico -> geo (method='dns'), com cache DNS + limite de concorrencia.
Registra geo_resolved_at/geo_expires_at (permite re-resolucao). NUNCA descarta indicador sem geo
(marca geo_status). Reusa app/geo.lookup_ip (nao altera o coletor da Fase 1).
"""
from __future__ import annotations

import asyncio
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional

from app import geo as geo_mod
from app.cyber_normalize import is_public_ip, url_host

_CANDIDATES_SQL = """
SELECT i.indicator_pk, i.indicator_type, i.value_normalized
FROM cyber_indicator i
WHERE i.indicator_type IN ('ip','domain','url')
  AND (i.geo_status IS NULL OR (i.geo_expires_at IS NOT NULL AND i.geo_expires_at < now()))
  AND (EXISTS (SELECT 1 FROM cyber_oat_observation o WHERE o.indicator_pk = i.indicator_pk)
       OR EXISTS (SELECT 1 FROM cyber_workbench_indicator w WHERE w.indicator_pk = i.indicator_pk))
ORDER BY i.indicator_pk
LIMIT $1
"""

_UPDATE_SQL = """
UPDATE cyber_indicator SET geo_status=$2, geo_resolution_method=$3, country=$4, country_iso2=$5,
  city=$6, latitude=$7, longitude=$8, resolved_ip=$9, geo_resolved_at=now(), geo_expires_at=$10, updated_at=now()
WHERE indicator_pk=$1
"""

_EMPTY = {"country": None, "country_iso2": None, "city": None, "latitude": None,
          "longitude": None, "resolved_ip": None}


class GeoResolver:
    def __init__(self, *, ip_lookup=None, dns_resolver=None, concurrency: int = 8, dns_cache_ttl: int = 3600):
        self._ip_lookup = ip_lookup or geo_mod.lookup_ip
        self._dns = dns_resolver or self._default_dns
        self._sem = asyncio.Semaphore(concurrency)
        self._cache: dict = {}
        self._dns_cache_ttl = dns_cache_ttl

    async def _default_dns(self, host: str) -> Optional[str]:
        try:
            infos = await asyncio.get_event_loop().getaddrinfo(host, None)
        except (OSError, UnicodeError):
            return None
        for info in infos:
            ip = info[4][0]
            if is_public_ip(ip):
                return ip
        return None

    async def _resolve_host(self, host: str) -> Optional[str]:
        now = time.monotonic()
        cached = self._cache.get(host)
        if cached and (now - cached[1] < self._dns_cache_ttl):
            return cached[0]
        async with self._sem:
            ip = await self._dns(host)
        self._cache[host] = (ip, now)
        return ip

    async def resolve(self, indicator_type: str, value_normalized: str) -> dict:
        if indicator_type == "ip":
            method, ip = "direct_ip", value_normalized
        else:
            host = value_normalized if indicator_type == "domain" else url_host(value_normalized)
            method = "dns"
            ip = await self._resolve_host(host) if host else None
        if ip is None:
            return {"geo_status": "unresolved", "geo_resolution_method": ("dns" if method == "dns" else "none"), **_EMPTY}
        if not is_public_ip(ip):
            return {"geo_status": "private", "geo_resolution_method": "none", **_EMPTY}
        g = self._ip_lookup(ip)
        if not g:
            return {"geo_status": "nogeo", "geo_resolution_method": method, **{**_EMPTY, "resolved_ip": ip}}
        return {"geo_status": "ok", "geo_resolution_method": method, "country": g.get("country"),
                "country_iso2": g.get("country"), "city": g.get("city"),
                "latitude": g.get("lat"), "longitude": g.get("lon"), "resolved_ip": ip}


async def run_geo(pool, *, limit: int = 2000, concurrency: int = 8, dns_ttl_hours: float = 6,
                  ip_ttl_days: float = 30, dry_run: bool = False, resolver: Optional[GeoResolver] = None) -> dict:
    resolver = resolver or GeoResolver(concurrency=concurrency)
    async with pool.acquire() as conn:
        rows = await conn.fetch(_CANDIDATES_SQL, limit)
    results = await asyncio.gather(*[resolver.resolve(r["indicator_type"], r["value_normalized"]) for r in rows])
    stats = Counter({"candidates": len(rows)})
    for g in results:
        stats[g["geo_status"]] += 1
    if dry_run:
        return dict(stats, mode="dry_run")

    dns_ttl = timedelta(hours=dns_ttl_hours)
    ip_ttl = timedelta(days=ip_ttl_days)
    updated = 0
    async with pool.acquire() as conn:
        async with conn.transaction():
            for r, g in zip(rows, results):
                now = datetime.now(timezone.utc)
                exp = now + (ip_ttl if (g["geo_resolution_method"] == "direct_ip" and g["geo_status"] in ("ok", "nogeo")) else dns_ttl)
                await conn.execute(_UPDATE_SQL, r["indicator_pk"], g["geo_status"], g["geo_resolution_method"],
                                   g["country"], g["country_iso2"], g["city"], g["latitude"], g["longitude"],
                                   g["resolved_ip"], exp)
                updated += 1
    return dict(stats, mode="sync", updated=updated)
