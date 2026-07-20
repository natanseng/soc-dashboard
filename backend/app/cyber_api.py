"""Consultas read-only das APIs Cyber (§16/§17). Sem segredos. Le os dados ja coletados.

Camadas do mapa/enforcement:
  blocked_confirmed = enforcement_status='prevented_confirmed'
  policy_matched    = block_policy_matched AND enforcement_status<>'prevented_confirmed'
  observed          = restante
Rankings por orgao usam SOMENTE observacoes atribuidas (organization_id IS NOT NULL).
Nao atribuidos (unassigned/ambiguous) permanecem no total do tenant e em metricas tecnicas.
"""
from __future__ import annotations

from typing import Optional

# --- filtros de observacao (parametrizado) ---


def _obs_filters(tenant_id=None, organization_id=None, severity=None, enforcement_status=None,
                 attribution_status=None, hours: Optional[int] = None, start_param: int = 1):
    clauses, params = [], []
    i = start_param
    if tenant_id:
        clauses.append(f"tenant_id = ${i}"); params.append(tenant_id); i += 1
    if organization_id:
        clauses.append(f"organization_id = ${i}"); params.append(organization_id); i += 1
    if severity:
        clauses.append(f"severity = ${i}"); params.append(severity); i += 1
    if enforcement_status:
        clauses.append(f"enforcement_status = ${i}"); params.append(enforcement_status); i += 1
    if attribution_status:
        clauses.append(f"organization_attribution_status = ${i}"); params.append(attribution_status); i += 1
    if hours:
        clauses.append(f"event_time >= now() - (${i} || ' hours')::interval"); params.append(str(hours)); i += 1
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params, i


_ENF_CASE = (
    "count(*) FILTER (WHERE enforcement_status='prevented_confirmed') AS blocked_confirmed, "
    "count(*) FILTER (WHERE block_policy_matched AND enforcement_status<>'prevented_confirmed') AS policy_matched, "
    "count(*) FILTER (WHERE enforcement_status='observed') AS observed, "
    "count(*) FILTER (WHERE enforcement_status='observed_not_prevented') AS observed_not_prevented, "
    "count(*) FILTER (WHERE enforcement_status='allowed_confirmed') AS allowed, "
    "count(*) FILTER (WHERE enforcement_status='unknown') AS unknown_enf"
)


async def summary(pool, **f) -> dict:
    where, params, _ = _obs_filters(**f)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"SELECT count(*) AS observations, count(DISTINCT indicator_pk) AS external_distinct, "
            f"count(*) FILTER (WHERE organization_attribution_status='attributed') AS attributed, "
            f"count(*) FILTER (WHERE organization_attribution_status='unassigned') AS unassigned, "
            f"count(*) FILTER (WHERE organization_attribution_status='ambiguous') AS ambiguous, "
            f"count(*) FILTER (WHERE severity='high') AS high, "
            f"count(*) FILTER (WHERE severity='critical') AS critical, {_ENF_CASE} "
            f"FROM cyber_oat_observation{where}", *params)
        wb = await conn.fetchval("SELECT count(*) FROM cyber_workbench_indicator")
        so = await conn.fetchval("SELECT count(*) FROM cyber_suspicious_object WHERE is_active")
    d = dict(row)
    d["workbench_indicators"] = int(wb)
    d["suspicious_objects_active"] = int(so)
    return {"status": "ok", "summary": {k: int(v) if isinstance(v, int) else v for k, v in d.items()}}


async def by_tenant(pool) -> dict:
    async with pool.acquire() as conn:
        org_rows = await conn.fetch(
            "SELECT tenant_id, organization_id, count(*) AS observations, "
            "count(DISTINCT indicator_pk) AS external_distinct FROM cyber_oat_observation "
            "WHERE organization_id IS NOT NULL GROUP BY tenant_id, organization_id")
        unassigned = await conn.fetch(
            "SELECT tenant_id, "
            "count(*) FILTER (WHERE organization_attribution_status='unassigned') AS observations, "
            "count(*) FILTER (WHERE organization_attribution_status='ambiguous') AS ambiguous, "
            "count(DISTINCT indicator_pk) FILTER (WHERE organization_attribution_status IN ('unassigned','ambiguous')) AS external_distinct "
            "FROM cyber_oat_observation GROUP BY tenant_id")
        reg = await conn.fetch(
            "SELECT t.tenant_id, t.display_name AS tenant_name, o.organization_id, o.name AS organization_name, o.display_order "
            "FROM cyber_tenant_config c JOIN tenant t ON t.tenant_id=c.tenant_id "
            "LEFT JOIN organization o ON o.tenant_id=t.tenant_id AND o.enabled AND o.cyber_enabled "
            "WHERE c.cyber_enabled AND c.enabled ORDER BY t.display_name, o.display_order")
    org_counts = {(r["tenant_id"], r["organization_id"]): r for r in org_rows}
    unassigned_by = {r["tenant_id"]: r for r in unassigned}
    tenants: dict = {}
    for r in reg:
        t = tenants.setdefault(r["tenant_id"], {"tenantId": r["tenant_id"], "tenantName": r["tenant_name"],
                                                "status": "ok", "organizations": [],
                                                "unassigned": {"observations": 0, "ambiguous": 0, "externalDistinct": 0}})
        if r["organization_id"]:
            oc = org_counts.get((r["tenant_id"], r["organization_id"]))
            t["organizations"].append({
                "organizationId": r["organization_id"], "organizationName": r["organization_name"],
                "displayOrder": r["display_order"],
                "observations": int(oc["observations"]) if oc else 0,
                "externalDistinct": int(oc["external_distinct"]) if oc else 0, "status": "ok"})
    for tid, u in unassigned_by.items():
        if tid in tenants:
            tenants[tid]["unassigned"] = {"observations": int(u["observations"]), "ambiguous": int(u["ambiguous"]),
                                          "externalDistinct": int(u["external_distinct"])}
    return {"status": "ok", "tenants": list(tenants.values())}


async def by_organization(pool, **f) -> dict:
    where, params, _ = _obs_filters(**f)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT o.tenant_id, t.display_name AS tenant_name, o.organization_id, o.name AS organization_name, "
            f"o.display_order, count(obs.observation_id) AS observations, "
            f"count(DISTINCT obs.indicator_pk) AS external_distinct, "
            f"count(*) FILTER (WHERE obs.enforcement_status='prevented_confirmed') AS blocked_confirmed, "
            f"count(*) FILTER (WHERE obs.block_policy_matched AND obs.enforcement_status<>'prevented_confirmed') AS policy_matched, "
            f"count(*) FILTER (WHERE obs.enforcement_status='observed') AS observed, "
            f"count(*) FILTER (WHERE obs.enforcement_status='observed_not_prevented') AS observed_not_prevented, "
            f"count(*) FILTER (WHERE obs.enforcement_status='allowed_confirmed') AS allowed, "
            f"count(*) FILTER (WHERE obs.enforcement_status='unknown') AS unknown_enf, "
            f"max(obs.event_time) AS last_event "
            f"FROM organization o JOIN tenant t ON t.tenant_id=o.tenant_id "
            f"LEFT JOIN cyber_oat_observation obs ON obs.tenant_id=o.tenant_id AND obs.organization_id=o.organization_id "
            f"WHERE o.enabled AND o.cyber_enabled "
            f"GROUP BY o.tenant_id, t.display_name, o.organization_id, o.name, o.display_order "
            f"ORDER BY o.tenant_id, o.display_order, o.name")
        wb_rows = await conn.fetch(
            "SELECT tenant_id, organization_id, count(*) AS wb FROM cyber_workbench_indicator "
            "WHERE organization_id IS NOT NULL GROUP BY tenant_id, organization_id")
        cap_rows = await conn.fetch(
            "SELECT tenant_id, capability, status FROM cyber_enforcement_capability")
        totals = await conn.fetch(
            "SELECT tenant_id, count(*) AS total FROM cyber_oat_observation WHERE organization_id IS NOT NULL GROUP BY tenant_id")
    wb_by = {(r["tenant_id"], r["organization_id"]): int(r["wb"]) for r in wb_rows}
    total_by = {r["tenant_id"]: int(r["total"]) for r in totals}
    rank = {"none": 0, "partial": 1, "full": 2}
    cap_by: dict = {}
    for r in cap_rows:
        cur = cap_by.get(r["tenant_id"])
        val = r["capability"] if r["status"] != "stale" else "none"
        if cur is None or rank.get(val, 0) > rank.get(cur, 0):
            cap_by[r["tenant_id"]] = val
    out = []
    for r in rows:
        tot = total_by.get(r["tenant_id"], 0)
        obs = int(r["observations"])
        out.append({
            "tenantId": r["tenant_id"], "tenantName": r["tenant_name"],
            "organizationId": r["organization_id"], "organizationName": r["organization_name"],
            "externalDistinct": int(r["external_distinct"]), "observations": obs,
            "blockedConfirmed": int(r["blocked_confirmed"]), "policyMatched": int(r["policy_matched"]),
            "observedOnly": int(r["observed"]), "observedNotPrevented": int(r["observed_not_prevented"]),
            "allowed": int(r["allowed"]), "unknown": int(r["unknown_enf"]),
            "workbenches": wb_by.get((r["tenant_id"], r["organization_id"]), 0),
            "capability": cap_by.get(r["tenant_id"], "unavailable"),
            "lastCollection": r["last_event"].isoformat() if r["last_event"] else None,
            "participationPct": round(100.0 * obs / tot, 1) if tot else 0.0,
            "status": "ok",
        })
    return {"status": "ok", "title": "Indicadores externos High/Critical por órgão", "organizations": out}


async def coverage(pool) -> dict:
    async with pool.acquire() as conn:
        g = await conn.fetchrow(
            "SELECT count(*) AS total, count(*) FILTER (WHERE organization_attribution_status='attributed') AS attributed "
            "FROM cyber_oat_observation")
        by_t = await conn.fetch(
            "SELECT tenant_id, count(*) AS total, count(*) FILTER (WHERE organization_attribution_status='attributed') AS attributed "
            "FROM cyber_oat_observation GROUP BY tenant_id")
        by_s = await conn.fetch(
            "SELECT source, count(*) AS total, count(*) FILTER (WHERE organization_attribution_status='attributed') AS attributed "
            "FROM cyber_oat_observation GROUP BY source")

    def pct(a, t):
        return round(100.0 * a / t, 1) if t else 0.0
    return {"status": "ok",
            "global": {"attributed": int(g["attributed"]), "total": int(g["total"]), "coveragePct": pct(g["attributed"], g["total"])},
            "byTenant": [{"tenantId": r["tenant_id"], "attributed": int(r["attributed"]), "total": int(r["total"]),
                          "coveragePct": pct(r["attributed"], r["total"])} for r in by_t],
            "bySource": [{"source": r["source"], "attributed": int(r["attributed"]), "total": int(r["total"]),
                          "coveragePct": pct(r["attributed"], r["total"])} for r in by_s]}


async def waf_blocks(pool) -> dict:
    """Bloqueios WAF: workbenches (30d) de coletores WAF + Top 10 hosts atacados (campo requests, encurtado)."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT count(*) FILTER (WHERE created_at >= now() - interval '30 days') AS total_30d, "
            "count(*) FILTER (WHERE status IN ('Open','In Progress')) AS active "
            "FROM cyber_workbench_alert WHERE waf_collector IS NOT NULL")
        tops = await conn.fetch(
            "SELECT waf_url_host, count(*) n FROM cyber_workbench_alert "
            "WHERE waf_collector IS NOT NULL AND waf_url_host IS NOT NULL "
            "AND created_at >= now() - interval '30 days' "
            "GROUP BY waf_url_host ORDER BY n DESC, waf_url_host LIMIT 10")
    return {"status": "ok", "total30d": int(row["total_30d"]), "active": int(row["active"]),
            "topUrls": [{"host": r["waf_url_host"], "count": int(r["n"])} for r in tops]}


async def map_points(pool, layer=None, **f) -> dict:
    where, params, i = _obs_filters(**f)
    layer_sql = ""
    if layer == "blocked_confirmed":
        layer_sql = " AND obs.enforcement_status='prevented_confirmed'"
    elif layer == "policy_matched":
        layer_sql = " AND obs.block_policy_matched AND obs.enforcement_status<>'prevented_confirmed'"
    elif layer == "observed":
        layer_sql = " AND obs.enforcement_status<>'prevented_confirmed' AND NOT obs.block_policy_matched"
    w = (where + layer_sql) if where else (" WHERE TRUE" + layer_sql)
    async with pool.acquire() as conn:
        totals = await conn.fetchrow(
            f"SELECT count(*) AS observations, count(DISTINCT obs.indicator_pk) AS distinct_indicators "
            f"FROM cyber_oat_observation obs{w}", *params)
        clusters = await conn.fetch(
            f"SELECT i.country, count(DISTINCT obs.indicator_pk) AS distinct_indicators, count(*) AS observations, "
            f"avg(i.latitude)::float AS lat, avg(i.longitude)::float AS lon "
            f"FROM cyber_oat_observation obs JOIN cyber_indicator i ON i.indicator_pk=obs.indicator_pk "
            f"{w} AND i.geo_status='ok' AND i.latitude IS NOT NULL "
            f"GROUP BY i.country ORDER BY observations DESC", *params)
    return {"status": "ok", "title": "Distribuição geográfica de indicadores externos High/Critical",
            "layer": layer or "all",
            "totals": {"observations": int(totals["observations"]), "distinctIndicators": int(totals["distinct_indicators"]),
                       "clusters": len(clusters)},
            "clusters": [{"country": r["country"], "distinctIndicators": int(r["distinct_indicators"]),
                          "observations": int(r["observations"]), "lat": r["lat"], "lon": r["lon"]} for r in clusters]}


async def events(pool, limit: int = 100, **f) -> dict:
    where, params, i = _obs_filters(**f)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT obs.tenant_id, obs.organization_id, i.indicator_type, i.value_normalized, obs.indicator_role, "
            f"obs.severity, obs.enforcement_status, obs.block_policy_matched, obs.organization_attribution_status, "
            f"obs.event_time, i.country, i.city "
            f"FROM cyber_oat_observation obs JOIN cyber_indicator i ON i.indicator_pk=obs.indicator_pk"
            f"{where} ORDER BY obs.event_time DESC LIMIT ${i}", *params, limit)
    return {"status": "ok", "events": [{
        "tenantId": r["tenant_id"], "organizationId": r["organization_id"], "indicatorType": r["indicator_type"],
        "indicator": r["value_normalized"], "role": r["indicator_role"], "severity": r["severity"],
        "enforcementStatus": r["enforcement_status"], "blockPolicyMatched": r["block_policy_matched"],
        "attributionStatus": r["organization_attribution_status"],
        "eventTime": r["event_time"].isoformat() if r["event_time"] else None,
        "country": r["country"], "city": r["city"]} for r in rows]}


async def status(pool) -> dict:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT tenant_id, collector, source, severity_scope, status, saturated, watermark_event_time, "
            "last_success_at, received, inserted, ext_accepted, attr_attributed, attr_unassigned, attr_ambiguous "
            "FROM cyber_collection_state ORDER BY tenant_id, collector, severity_scope")
    return {"status": "ok", "collectors": [{
        "tenantId": r["tenant_id"], "collector": r["collector"], "source": r["source"],
        "severityScope": r["severity_scope"], "status": r["status"], "saturated": r["saturated"],
        "watermark": r["watermark_event_time"].isoformat() if r["watermark_event_time"] else None,
        "lastSuccess": r["last_success_at"].isoformat() if r["last_success_at"] else None,
        "received": r["received"], "inserted": r["inserted"], "extAccepted": r["ext_accepted"],
        "attributed": r["attr_attributed"], "unassigned": r["attr_unassigned"], "ambiguous": r["attr_ambiguous"]}
        for r in rows]}


async def validate_org_in_tenant(pool, tenant_id, organization_id) -> bool:
    if not (tenant_id and organization_id):
        return True
    async with pool.acquire() as conn:
        return bool(await conn.fetchval(
            "SELECT 1 FROM organization WHERE tenant_id=$1 AND organization_id=$2", tenant_id, organization_id))
