"""Coletor de INVENTARIO de workbenches (tela "Alertas"). Por tenant.

Distinto de cyber_workbench.py (que so extrai indicadores externos). Aqui grava 1 linha por
(tenant, alert_id) em cyber_workbench_alert com severidade/status/modelo/timestamps + MTTD/MTTR.

MTTD/MTTR seguem EXATAMENTE as regras do projeto vision-one-soc-dashboard:
  MTTD = createdDateTime - matchedDateTime (OAT). preset -> 1o OAT (min); custom -> ultimo OAT (max).
         delta negativo -> None; sem OAT -> None (fallback firstInvestigated NAO existe na API).
  MTTR = updatedDateTime - createdDateTime, SOMENTE status 'Closed'. delta negativo -> None.
Atribuicao a suborgao por instancia (managementScopeInstanceId) via cyber_attribution (reuso).
Dedup por (tenant, alert_id) + upsert dos campos mutaveis. Watermark por updatedDateTime (captura
alertas novos E os que mudaram de status). So avanca em coleta COMPLETA (nao perde alertas).
"""
from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.cyber_attribution import load_mappings, resolve_organization
from .cyber_http import CyberClient

WB_PATH = "/v3.0/workbench/alerts"
RESOLVED_STATUSES = ("Closed",)   # resolvedStatuses do projeto anterior


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _matched_times(alert: dict) -> list:
    """Todos os matchedDateTime (OAT). Schema real V3: matchedRules[].matchedFilters[].matchedDateTime
    e matchedRules[].matchedFilters[].matchedEvents[].matchedDateTime (events ANINHADO em filters)."""
    out = []
    for rule in (alert.get("matchedRules") or []):
        for mf in (rule.get("matchedFilters") or []):
            t = _parse_dt(mf.get("matchedDateTime"))
            if t:
                out.append(t)
            for me in (mf.get("matchedEvents") or []):     # matchedEvents aninhado em matchedFilters
                te = _parse_dt(me.get("matchedDateTime"))
                if te:
                    out.append(te)
    return out


def _detect_seconds(created, model_type, m_first, m_last):
    """MTTD efetivo. custom -> ultimo OAT (max); preset/demais -> 1o OAT (min). <0 -> None; sem OAT -> None."""
    anchor = m_last if model_type == "custom" else m_first
    if not created or not anchor:
        return None
    d = (created - anchor).total_seconds()
    return d if d >= 0 else None


def _resolve_seconds(status, created, updated):
    """MTTR = updated - created SOMENTE p/ status resolvido (Closed). <0 -> None."""
    if status not in RESOLVED_STATUSES or not created or not updated:
        return None
    d = (updated - created).total_seconds()
    return d if d >= 0 else None


def _identifiers(alert: dict) -> dict:
    """managementScopeInstanceId/GroupId do impactScope.entities (so o necessario p/ atribuicao)."""
    ids = {}
    for e in ((alert.get("impactScope") or {}).get("entities") or []):
        for k in ("managementScopeInstanceId", "managementScopeGroupId"):
            v = e.get(k)
            if v:
                ids.setdefault(k, str(v))
    return ids


def _collector_ids(alert: dict) -> list:
    """collectorId(s) de origem do OAT (indicators[].field='collectorId')."""
    out = []
    for ind in (alert.get("indicators") or []):
        if ind.get("field") == "collectorId":
            v = ind.get("value")
            if isinstance(v, str) and v and v not in out:
                out.append(v)
    return out


def _resolve_subindex(alert, collector_map, default_subindex):
    """Subindice do workbench via COLETOR de origem do OAT. Sem coletor mapeado -> default do
    tenant (deteccoes nativas). Retorna (subindex, method: collector|default|none)."""
    subs = []
    for cid in _collector_ids(alert):
        s = collector_map.get(cid)
        if s and s not in subs:
            subs.append(s)
    if subs:
        return subs[0], "collector"     # coletores atuais -> mesmo subindice; 1o match
    if default_subindex:
        return default_subindex, "default"
    return None, "none"


_URL_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)


def _shorten_host(req):
    """URL do campo requests -> host encurtado (sem scheme/www/porta/path). Ex.: www.piloto.e-crvsp.sp.gov.br/x -> piloto.e-crvsp.sp.gov.br."""
    if not isinstance(req, str) or not req:
        return None
    s = _URL_SCHEME.sub("", req.strip())
    s = s.split("/", 1)[0].split("?", 1)[0]     # host[:porta] antes do path/query
    s = s.split("@")[-1]                          # remove userinfo
    s = re.sub(r":\d+$", "", s)                    # remove :porta
    s = re.sub(r"^www\.", "", s, flags=re.I)
    return s.lower() or None


def _resolve_waf(alert, waf_collectors):
    """Se algum collectorId do workbench for WAF: (collector_id, host_atacado_mais_frequente do campo requests)."""
    waf = next((c for c in _collector_ids(alert) if c in waf_collectors), None)
    if not waf:
        return None, None
    hosts = {}
    for ind in (alert.get("indicators") or []):
        if ind.get("field") == "requests":
            hh = _shorten_host(ind.get("value"))
            if hh:
                hosts[hh] = hosts.get(hh, 0) + 1
    return waf, (max(hosts, key=hosts.get) if hosts else None)


def build_alert_row(alert: dict, ctx) -> Optional[dict]:
    """Puro: alerta cru -> linha de cyber_workbench_alert (ou None se sem id/created)."""
    mode, enabled_orgs, mappings, collector_map, default_subindex, waf_collectors = ctx
    alert_id = alert.get("id")
    created = _parse_dt(alert.get("createdDateTime"))
    if not alert_id or not created:
        return None
    updated = _parse_dt(alert.get("updatedDateTime"))
    model_type = alert.get("modelType")
    times = _matched_times(alert)
    m_first = min(times) if times else None
    m_last = max(times) if times else None
    status = alert.get("status")

    ids = _identifiers(alert)

    def lookup(mt, vh):
        return [(o, c) for (o, c, _m) in mappings.get((mt, vh), [])]

    attr = resolve_organization(mode, enabled_orgs, ids, lookup)
    subindex, subindex_method = _resolve_subindex(alert, collector_map, default_subindex)
    waf_collector, waf_url_host = _resolve_waf(alert, waf_collectors)
    return {
        "alert_id": alert_id,
        "subindex": subindex, "subindex_method": subindex_method,
        "waf_collector": waf_collector, "waf_url_host": waf_url_host,
        "severity": alert.get("severity"),
        "status": status,
        "investigation_status": alert.get("investigationStatus"),
        "investigation_result": alert.get("investigationResult"),
        "model": alert.get("model"),
        "model_id": alert.get("modelId"),
        "model_type": model_type,
        "alert_provider": alert.get("alertProvider"),
        "score": alert.get("score") if isinstance(alert.get("score"), int) else None,
        "created_at": created,
        "updated_at_v1": updated,
        "matched_first": m_first,
        "matched_last": m_last,
        "oat_count": len(times),
        "detect_seconds": _detect_seconds(created, model_type, m_first, m_last),
        "resolve_seconds": _resolve_seconds(status, created, updated),
        "organization_id": attr.organization_id,
        "attr_status": attr.status,
        "attr_method": attr.method,
        "attr_confidence": attr.confidence,
        "attr_evidence": attr.evidence,
        "attribution_identifiers": json.dumps(ids, ensure_ascii=False, default=str),
        "workbench_link": alert.get("workbenchLink"),
    }


async def _load_context(conn, tenant_id):
    mrow = await conn.fetchrow(
        "SELECT attribution_mode, default_subindex FROM cyber_tenant_config WHERE tenant_id=$1", tenant_id)
    mode = mrow["attribution_mode"] if mrow else "mapping"
    default_subindex = mrow["default_subindex"] if mrow else None
    orows = await conn.fetch(
        "SELECT organization_id FROM organization WHERE tenant_id=$1 AND enabled AND cyber_enabled", tenant_id)
    mappings = await load_mappings(conn, tenant_id)
    crows = await conn.fetch(
        "SELECT collector_id, subindex FROM cyber_subindex_collector WHERE tenant_id=$1", tenant_id)
    collector_map = {r["collector_id"]: r["subindex"] for r in crows}
    wrows = await conn.fetch("SELECT collector_id FROM cyber_waf_collector WHERE tenant_id=$1", tenant_id)
    waf_collectors = {r["collector_id"] for r in wrows}
    return mode, [r["organization_id"] for r in orows], mappings, collector_map, default_subindex, waf_collectors


_UPSERT = (
    "INSERT INTO cyber_workbench_alert ("
    " tenant_id, alert_id, severity, status, investigation_status, investigation_result,"
    " model, model_id, model_type, alert_provider, score, created_at, updated_at_v1,"
    " matched_first, matched_last, oat_count, detect_seconds, resolve_seconds,"
    " organization_id, organization_attribution_status, organization_attribution_method,"
    " organization_attribution_confidence, organization_attribution_evidence, attribution_identifiers,"
    " workbench_link, subindex, subindex_method, waf_collector, waf_url_host, first_collected_at, last_collected_at)"
    " VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24::jsonb,$25,$26,$27,$28,$29,now(),now())"
    " ON CONFLICT (tenant_id, alert_id) DO UPDATE SET"
    " severity=EXCLUDED.severity, status=EXCLUDED.status, investigation_status=EXCLUDED.investigation_status,"
    " investigation_result=EXCLUDED.investigation_result, model=EXCLUDED.model, model_id=EXCLUDED.model_id,"
    " model_type=EXCLUDED.model_type, alert_provider=EXCLUDED.alert_provider, score=EXCLUDED.score,"
    " updated_at_v1=EXCLUDED.updated_at_v1, matched_first=EXCLUDED.matched_first, matched_last=EXCLUDED.matched_last,"
    " oat_count=EXCLUDED.oat_count, detect_seconds=EXCLUDED.detect_seconds, resolve_seconds=EXCLUDED.resolve_seconds,"
    " organization_id=EXCLUDED.organization_id, organization_attribution_status=EXCLUDED.organization_attribution_status,"
    " organization_attribution_method=EXCLUDED.organization_attribution_method,"
    " organization_attribution_confidence=EXCLUDED.organization_attribution_confidence,"
    " organization_attribution_evidence=EXCLUDED.organization_attribution_evidence,"
    " attribution_identifiers=EXCLUDED.attribution_identifiers, workbench_link=EXCLUDED.workbench_link,"
    " subindex=EXCLUDED.subindex, subindex_method=EXCLUDED.subindex_method,"
    " waf_collector=EXCLUDED.waf_collector, waf_url_host=EXCLUDED.waf_url_host,"
    " last_collected_at=now()"
    " RETURNING (xmax = 0) AS inserted"   # xmax=0 => linha nova (INSERT); senao foi UPDATE
)


async def _persist(conn, tenant_id, r) -> str:
    inserted = await conn.fetchval(
        _UPSERT, tenant_id, r["alert_id"], r["severity"], r["status"], r["investigation_status"],
        r["investigation_result"], r["model"], r["model_id"], r["model_type"], r["alert_provider"],
        r["score"], r["created_at"], r["updated_at_v1"], r["matched_first"], r["matched_last"],
        r["oat_count"], r["detect_seconds"], r["resolve_seconds"], r["organization_id"],
        r["attr_status"], r["attr_method"], r["attr_confidence"], r["attr_evidence"],
        r["attribution_identifiers"], r["workbench_link"], r["subindex"], r["subindex_method"],
        r["waf_collector"], r["waf_url_host"])
    return "inserted" if inserted else "updated"


async def run_wb_alerts(pool, tenant_id: str, token: str, *, base: Optional[str] = None, dry_run: bool = False,
                        backfill_days: int = 35, overlap_minutes: int = 30, item_cap: int = 40000) -> dict:
    """Coleta/atualiza o inventario de workbenches do tenant (janela por updatedDateTime)."""
    now = datetime.now(timezone.utc)
    async with pool.acquire() as conn:
        ctx = await _load_context(conn, tenant_id)
        wm = await conn.fetchval(
            "SELECT watermark_event_time FROM cyber_collection_state "
            "WHERE tenant_id=$1 AND collector='workbench_alert' AND source='all' AND severity_scope='all'", tenant_id)
    start = (wm - timedelta(minutes=overlap_minutes)) if wm else (now - timedelta(days=backfill_days))

    client = CyberClient(token, base)
    try:
        pr = await client.paginate(
            WB_PATH,
            params={"startDateTime": _iso(start), "endDateTime": _iso(now),
                    "dateTimeTarget": "updatedDateTime", "orderBy": "updatedDateTime asc", "top": 100},
            item_cap=item_cap, timeout=120)
    finally:
        await client.aclose()

    rows, disc = [], Counter()
    max_updated = None
    for alert in pr.items:
        r = build_alert_row(alert, ctx)
        if r is None:
            disc["missing_key_fields"] += 1
            continue
        rows.append(r)
        if r["updated_at_v1"] and (max_updated is None or r["updated_at_v1"] > max_updated):
            max_updated = r["updated_at_v1"]

    complete = (pr.stop_reason == "complete")
    stats = {"tenant_id": tenant_id, "mode": "dry_run" if dry_run else "sync", "attribution_mode": ctx[0],
             "alerts": len(pr.items), "pages": pr.pages, "stop_reason": pr.stop_reason, "complete": complete,
             "rows": len(rows), "inserted": 0, "updated": 0,
             "attributed": sum(1 for r in rows if r["attr_status"] == "attributed"),
             "unassigned": sum(1 for r in rows if r["attr_status"] in ("unassigned", "unavailable")),
             "ambiguous": sum(1 for r in rows if r["attr_status"] == "ambiguous"),
             "with_mttd": sum(1 for r in rows if r["detect_seconds"] is not None),
             "closed": sum(1 for r in rows if r["status"] == "Closed"),
             "with_mttr": sum(1 for r in rows if r["resolve_seconds"] is not None),
             "sev": dict(Counter(r["severity"] for r in rows)),
             "status_counts": dict(Counter(r["status"] for r in rows)),
             "disc": dict(disc)}
    if dry_run:
        return stats

    async with pool.acquire() as conn:
        async with conn.transaction():
            for r in rows:
                stats[await _persist(conn, tenant_id, r)] += 1
            # watermark = maior updatedDateTime processado. orderBy updatedDateTime ASC => mesmo truncado
            # o intervalo [start, max_updated] foi coberto contiguamente; avancar e seguro (overlap cobre a
            # borda) e evita stall de backfill em volume alto. GREATEST no UPSERT garante monotonicidade.
            new_wm = max_updated if max_updated else wm
            status = "ok" if complete else "partial"
            await conn.execute(
                "INSERT INTO cyber_collection_state (tenant_id, collector, source, severity_scope, "
                "watermark_event_time, window_start, window_end, last_attempt_at, last_success_at, pages, "
                "received, inserted, duplicates, status, updated_at) "
                "VALUES ($1,'workbench_alert','all','all',$2,$3,$4,now(),now(),$5,$6,$7,$8,$9,now()) "
                "ON CONFLICT (tenant_id, collector, source, severity_scope) DO UPDATE SET "
                "watermark_event_time=GREATEST(cyber_collection_state.watermark_event_time, EXCLUDED.watermark_event_time), "
                "window_start=EXCLUDED.window_start, window_end=EXCLUDED.window_end, last_attempt_at=now(), "
                "last_success_at=now(), pages=EXCLUDED.pages, received=EXCLUDED.received, inserted=EXCLUDED.inserted, "
                "duplicates=EXCLUDED.duplicates, status=EXCLUDED.status, updated_at=now()",
                tenant_id, new_wm, start, now, pr.pages, len(pr.items), stats["inserted"], stats["updated"], status)
    return stats
