"""APIs read-only da tela "Alertas" (workbenches consolidados) sobre cyber_workbench_alert.

Sem segredos, sem dados simulados. MTTD/MTTR ja vem por-alerta (detect_seconds/resolve_seconds,
regras vision-one-soc-dashboard); aqui apenas AGREGA (media aritmetica) global, por tenant,
por suborgao e segmentado por modelType (preset/custom). "Atual" = status Open/In Progress
(nao-Closed); historico/30d = created_at nos ultimos 30 dias. Nunca conta Closed como ativo.
"""
from __future__ import annotations

ACTIVE = "status IN ('Open','In Progress')"
WIN30 = "created_at >= now() - interval '30 days'"

# medias de MTTD/MTTR + tamanho de amostra (segundos; humanizacao no frontend)
_MTT = (
    "avg(detect_seconds)  AS mttd_sec,  count(detect_seconds)  AS mttd_n, "
    "avg(resolve_seconds) AS mttr_sec,  count(resolve_seconds) AS mttr_n"
)


def _mtt(row) -> dict:
    return {
        "mttdSeconds": float(row["mttd_sec"]) if row["mttd_sec"] is not None else None,
        "mttdSampleSize": int(row["mttd_n"]),
        "mttrSeconds": float(row["mttr_sec"]) if row["mttr_sec"] is not None else None,
        "mttrSampleSize": int(row["mttr_n"]),
    }


async def _enabled_tenants(conn):
    return await conn.fetch(
        "SELECT t.tenant_id, t.display_name FROM cyber_tenant_config c JOIN tenant t ON t.tenant_id=c.tenant_id "
        "WHERE c.cyber_enabled AND c.enabled ORDER BY t.display_name")


async def summary(pool) -> dict:
    """Consolidado de TODAS as consoles: severidade (dinamica), status, total 30d/ativo, MTTD/MTTR global+segmentado."""
    async with pool.acquire() as conn:
        sev30 = await conn.fetch(f"SELECT severity, count(*) n FROM cyber_workbench_alert WHERE {WIN30} GROUP BY severity")
        sevact = await conn.fetch(f"SELECT severity, count(*) n FROM cyber_workbench_alert WHERE {ACTIVE} GROUP BY severity")
        stat = await conn.fetch("SELECT status, count(*) n FROM cyber_workbench_alert GROUP BY status")
        tot = await conn.fetchrow(
            f"SELECT count(*) FILTER (WHERE {WIN30}) AS total_30d, "
            f"count(*) FILTER (WHERE {ACTIVE}) AS active, count(*) AS total_all FROM cyber_workbench_alert")
        mtt = await conn.fetchrow(f"SELECT {_MTT} FROM cyber_workbench_alert WHERE {WIN30}")
        seg = await conn.fetch(
            f"SELECT model_type, {_MTT} FROM cyber_workbench_alert WHERE {WIN30} GROUP BY model_type")
    def _sev(rows):
        return {(r["severity"] or "unknown"): int(r["n"]) for r in rows}
    return {"status": "ok",
            "severity30d": _sev(sev30), "severityActive": _sev(sevact),
            "byStatus": {(r["status"] or "unknown"): int(r["n"]) for r in stat},
            "total30d": int(tot["total_30d"]), "active": int(tot["active"]), "totalStored": int(tot["total_all"]),
            "mtt": _mtt(mtt),
            "mttBySegment": {(r["model_type"] or "unknown"): _mtt(r) for r in seg}}


async def by_tenant(pool) -> dict:
    """Por console/tenant: severidade atual, abertos, em andamento, ativos, total 30d, MTTD/MTTR, ultima atualizacao."""
    async with pool.acquire() as conn:
        regs = await _enabled_tenants(conn)
        agg = await conn.fetch(
            f"SELECT tenant_id, "
            f"count(*) FILTER (WHERE status='Open') AS open, "
            f"count(*) FILTER (WHERE status='In Progress') AS in_progress, "
            f"count(*) FILTER (WHERE {ACTIVE}) AS active, "
            f"count(*) FILTER (WHERE {WIN30}) AS total_30d, "
            f"max(last_collected_at) AS last_update, "
            f"avg(detect_seconds) FILTER (WHERE {WIN30}) AS mttd_sec, count(detect_seconds) FILTER (WHERE {WIN30}) AS mttd_n, "
            f"avg(resolve_seconds) FILTER (WHERE {WIN30}) AS mttr_sec, count(resolve_seconds) FILTER (WHERE {WIN30}) AS mttr_n "
            f"FROM cyber_workbench_alert GROUP BY tenant_id")
        sev = await conn.fetch(
            f"SELECT tenant_id, severity, count(*) n FROM cyber_workbench_alert WHERE {ACTIVE} GROUP BY tenant_id, severity")
    by = {r["tenant_id"]: r for r in agg}
    sev_by: dict = {}
    for r in sev:
        sev_by.setdefault(r["tenant_id"], {})[r["severity"] or "unknown"] = int(r["n"])
    out = []
    for t in regs:
        tid = t["tenant_id"]; a = by.get(tid)
        out.append({
            "tenantId": tid, "tenantName": t["display_name"],
            "severityActive": sev_by.get(tid, {}),
            "open": int(a["open"]) if a else 0, "inProgress": int(a["in_progress"]) if a else 0,
            "active": int(a["active"]) if a else 0, "total30d": int(a["total_30d"]) if a else 0,
            "mtt": _mtt(a) if a else {"mttdSeconds": None, "mttdSampleSize": 0, "mttrSeconds": None, "mttrSampleSize": 0},
            "lastUpdate": a["last_update"].isoformat() if (a and a["last_update"]) else None,
            "status": "ok"})
    return {"status": "ok", "tenants": out}


async def by_organization(pool, tenant_id=None) -> dict:
    """Por suborgao (Cyber Risk Subindex via instancia): severidade, status, MTTD/MTTR + nao atribuidos por tenant."""
    where = " WHERE o.tenant_id=$1" if tenant_id else ""
    params = [tenant_id] if tenant_id else []
    async with pool.acquire() as conn:
        orgs = await conn.fetch(
            f"SELECT o.tenant_id, t.display_name AS tenant_name, o.organization_id, o.name AS org_name, o.display_order, "
            f"count(a.alert_id) AS total, "
            f"count(*) FILTER (WHERE a.status IN ('Open','In Progress')) AS active, "
            f"count(*) FILTER (WHERE a.created_at >= now() - interval '30 days') AS total_30d, "
            f"avg(a.detect_seconds) FILTER (WHERE a.created_at >= now() - interval '30 days') AS mttd_sec, "
            f"count(a.detect_seconds) FILTER (WHERE a.created_at >= now() - interval '30 days') AS mttd_n, "
            f"avg(a.resolve_seconds) FILTER (WHERE a.created_at >= now() - interval '30 days') AS mttr_sec, "
            f"count(a.resolve_seconds) FILTER (WHERE a.created_at >= now() - interval '30 days') AS mttr_n "
            f"FROM organization o JOIN tenant t ON t.tenant_id=o.tenant_id "
            f"LEFT JOIN cyber_workbench_alert a ON a.tenant_id=o.tenant_id AND a.organization_id=o.organization_id "
            f"{where}{' AND' if where else ' WHERE'} o.enabled AND o.cyber_enabled "
            f"GROUP BY o.tenant_id, t.display_name, o.organization_id, o.name, o.display_order "
            f"ORDER BY o.tenant_id, o.display_order, o.name", *params)
        sev = await conn.fetch(
            f"SELECT tenant_id, organization_id, severity, count(*) n FROM cyber_workbench_alert "
            f"WHERE organization_id IS NOT NULL AND created_at >= now() - interval '30 days'"
            f"{' AND tenant_id=$1' if tenant_id else ''} "
            f"GROUP BY tenant_id, organization_id, severity", *params)
        unassigned = await conn.fetch(
            f"SELECT a.tenant_id, count(*) AS total, "
            f"count(*) FILTER (WHERE a.created_at >= now() - interval '30 days') AS total_30d, "
            f"count(*) FILTER (WHERE a.status IN ('Open','In Progress')) AS active "
            f"FROM cyber_workbench_alert a JOIN cyber_tenant_config c ON c.tenant_id=a.tenant_id "
            f"WHERE a.organization_attribution_status <> 'attributed' AND c.cyber_enabled AND c.enabled"
            f"{' AND a.tenant_id=$1' if tenant_id else ''} GROUP BY a.tenant_id", *params)
    sev_by: dict = {}
    for r in sev:
        sev_by.setdefault((r["tenant_id"], r["organization_id"]), {})[r["severity"] or "unknown"] = int(r["n"])
    out = []
    for r in orgs:
        out.append({
            "tenantId": r["tenant_id"], "tenantName": r["tenant_name"],
            "organizationId": r["organization_id"], "organizationName": r["org_name"],
            "total": int(r["total"]), "active": int(r["active"]), "total30d": int(r["total_30d"]),
            "severity": sev_by.get((r["tenant_id"], r["organization_id"]), {}),
            "mtt": _mtt(r), "status": "ok"})
    return {"status": "ok", "organizations": out,
            "unassigned": [{"tenantId": r["tenant_id"], "total": int(r["total"]),
                            "total30d": int(r["total_30d"]), "active": int(r["active"])}
                           for r in unassigned]}


async def by_subindex(pool, tenant_id) -> dict:
    """Metricas de workbench por subindice (coluna subindex, correlacao via coletor). Janela 30d."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT subindex, "
            f"count(*) FILTER (WHERE status='Open') AS open, "
            f"count(*) FILTER (WHERE status='In Progress') AS in_progress, "
            f"count(*) FILTER (WHERE {ACTIVE}) AS active, "
            f"count(*) FILTER (WHERE {WIN30}) AS total_30d, "
            f"avg(detect_seconds) FILTER (WHERE {WIN30}) AS mttd_sec, count(detect_seconds) FILTER (WHERE {WIN30}) AS mttd_n, "
            f"avg(resolve_seconds) FILTER (WHERE {WIN30}) AS mttr_sec, count(resolve_seconds) FILTER (WHERE {WIN30}) AS mttr_n "
            f"FROM cyber_workbench_alert WHERE tenant_id=$1 AND subindex IS NOT NULL GROUP BY subindex", tenant_id)
        sev = await conn.fetch(
            f"SELECT subindex, severity, count(*) n FROM cyber_workbench_alert "
            f"WHERE tenant_id=$1 AND subindex IS NOT NULL AND {ACTIVE} GROUP BY subindex, severity", tenant_id)
    sev_by: dict = {}
    for r in sev:
        sev_by.setdefault(r["subindex"], {})[r["severity"] or "unknown"] = int(r["n"])
    return {"status": "ok", "tenantId": tenant_id,
            "subindexes": {r["subindex"]: {
                "open": int(r["open"]), "inProgress": int(r["in_progress"]), "active": int(r["active"]),
                "total30d": int(r["total_30d"]), "severityActive": sev_by.get(r["subindex"], {}),
                "mtt": _mtt(r)} for r in rows}}


async def history(pool, days: int = 30) -> dict:
    """Serie temporal por dia (created_at) por tenant + consolidado, ultimos N dias."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT tenant_id, (created_at AT TIME ZONE 'UTC')::date AS d, count(*) n "
            "FROM cyber_workbench_alert WHERE created_at >= now() - make_interval(days => $1) "
            "GROUP BY tenant_id, d ORDER BY d", int(days))
    series: dict = {}
    total: dict = {}
    for r in rows:
        d = r["d"].isoformat(); n = int(r["n"])
        series.setdefault(r["tenant_id"], {})[d] = n
        total[d] = total.get(d, 0) + n
    return {"status": "ok", "days": days, "byTenant": series, "consolidated": total}


async def events(pool, tenant_id=None, organization_id=None, severity=None, status=None,
                 model_type=None, unassigned=False, limit: int = 100) -> dict:
    """Lista de workbenches (quais compoem cada subindice/tenant). Filtros opcionais."""
    clauses, params, i = [], [], 1
    for col, val in (("tenant_id", tenant_id), ("organization_id", organization_id),
                     ("severity", severity), ("status", status), ("model_type", model_type)):
        if val:
            clauses.append(f"{col}=${i}"); params.append(val); i += 1
    if unassigned:
        clauses.append("organization_attribution_status <> 'attributed'")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(min(int(limit), 500))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT tenant_id, alert_id, severity, status, investigation_status, model, model_type, "
            f"organization_id, organization_attribution_status, created_at, updated_at_v1, "
            f"detect_seconds, resolve_seconds, workbench_link FROM cyber_workbench_alert"
            f"{where} ORDER BY created_at DESC LIMIT ${i}", *params)
    return {"status": "ok", "count": len(rows), "events": [{
        "tenantId": r["tenant_id"], "alertId": r["alert_id"], "severity": r["severity"], "status": r["status"],
        "investigationStatus": r["investigation_status"], "model": r["model"], "modelType": r["model_type"],
        "organizationId": r["organization_id"], "attributionStatus": r["organization_attribution_status"],
        "createdAt": r["created_at"].isoformat() if r["created_at"] else None,
        "updatedAt": r["updated_at_v1"].isoformat() if r["updated_at_v1"] else None,
        "detectSeconds": r["detect_seconds"], "resolveSeconds": r["resolve_seconds"],
        "workbenchLink": r["workbench_link"]} for r in rows]}
