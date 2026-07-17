"""Coletor Workbench (§12) — GET /v3.0/workbench/alerts. Por tenant.

Workbench e CONTEXTO e ASSOCIACAO: registra indicadores externos publicos dos alertas em
cyber_workbench_indicator (idempotente por tenant+alert+indicator) e associa a observacoes OAT
existentes (M:N same_value) em cyber_workbench_oat_link. NAO cria observacao OAT e NAO infla os
totais de observacoes. Indicadores WB sem vinculo permanecem 'workbench_unlinked'.
Atribuicao por instancia via motor cyber_attribution (SGGD->instance_mapping_pending).
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.cyber_attribution import extract_identifiers, load_mappings, resolve_organization
from app.cyber_normalize import is_public_indicator, normalize_indicator, normalize_ip
from .cyber_http import CyberClient
from .cyber_oat_select import ATTACKER_FIELDS

WB_PATH = "/v3.0/workbench/alerts"
WB_NET_TYPES = {"ip", "domain", "url", "host"}


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _wb_identifiers(alert: dict) -> dict:
    """Identificadores de instancia para atribuicao (do impactScope.entities). Somente o necessario."""
    ids = {}
    for e in ((alert.get("impactScope") or {}).get("entities") or []):
        for k in ("managementScopeInstanceId", "managementScopeGroupId"):
            v = e.get(k)
            if v:
                ids.setdefault(k, str(v))
    return ids


def build_wb_indicators(alert: dict, ctx):
    """Puro: extrai indicadores externos publicos de um alerta + atribuicao. Retorna (rows, disc)."""
    mode, enabled_orgs, mappings, _so = ctx
    alert_id = alert.get("id")
    created = _parse_dt(alert.get("createdDateTime"))
    if not alert_id or not created:
        return [], Counter({"missing_key_fields": 1})
    ids = _wb_identifiers(alert)

    def lookup(mt, vh):
        return [(o, c) for (o, c, _m) in mappings.get((mt, vh), [])]

    attr = resolve_organization(mode, enabled_orgs, ids, lookup)
    ids_json = json.dumps(ids, ensure_ascii=False, default=str)
    severity = alert.get("severity")
    model = alert.get("model")
    provider = alert.get("alertProvider")

    disc = Counter()
    out = {}
    for ind in (alert.get("indicators") or []):
        t = str(ind.get("type") or "").lower()
        if t not in WB_NET_TYPES:
            continue
        raw = ind.get("value")
        if not isinstance(raw, str) or not raw:
            continue
        itype = "url" if t == "url" else ("ip" if (t == "ip" or normalize_ip(raw)) else "domain")
        norm = normalize_indicator(itype, raw)
        if norm is None:
            disc["type"] += 1
            continue
        vn, vh = norm
        if not is_public_indicator(itype, vn):
            disc["non_public"] += 1
            continue
        role = ATTACKER_FIELDS.get(str(ind.get("field", "")).lower(), "indicator")
        prov = ind.get("provenance")
        if isinstance(prov, str):
            prov = [prov]
        out[(itype, vn)] = {
            "indicator_type": itype, "value_normalized": vn, "value_raw": raw, "value_hash": vh,
            "alert_id": alert_id, "indicator_role": role, "alert_severity": severity, "model": model,
            "provider": provider, "provenance": prov, "alert_created_at": created,
            "organization_id": attr.organization_id, "attr_status": attr.status,
            "attr_method": attr.method, "attr_confidence": attr.confidence, "attr_evidence": attr.evidence,
            "attribution_identifiers": ids_json,
        }
    return list(out.values()), disc


async def _load_context(conn, tenant_id):
    mrow = await conn.fetchrow("SELECT attribution_mode FROM cyber_tenant_config WHERE tenant_id=$1", tenant_id)
    mode = mrow["attribution_mode"] if mrow else "mapping"
    orows = await conn.fetch("SELECT organization_id FROM organization WHERE tenant_id=$1 AND enabled AND cyber_enabled", tenant_id)
    mappings = await load_mappings(conn, tenant_id)
    return mode, [r["organization_id"] for r in orows], mappings, None


async def _persist_wb(conn, tenant_id, w) -> str:
    pk = await conn.fetchval(
        "INSERT INTO cyber_indicator (tenant_id,indicator_type,value_hash,value_normalized,value_raw,first_seen_at,last_seen_at) "
        "VALUES ($1,$2,$3,$4,$5,now(),now()) ON CONFLICT (tenant_id,indicator_type,value_hash) "
        "DO UPDATE SET last_seen_at=now(), value_raw=EXCLUDED.value_raw, updated_at=now() "
        "WHERE cyber_indicator.value_normalized=EXCLUDED.value_normalized RETURNING indicator_pk",
        tenant_id, w["indicator_type"], w["value_hash"], w["value_normalized"], w["value_raw"])
    if pk is None:
        return "collision"
    tag = await conn.execute(
        "INSERT INTO cyber_workbench_indicator (tenant_id, indicator_pk, alert_id, indicator_role, "
        "alert_severity, model, provider, provenance, alert_created_at, organization_id, "
        "organization_attribution_status, organization_attribution_method, organization_attribution_confidence, "
        "organization_attribution_evidence, attribution_identifiers) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb) "
        "ON CONFLICT (tenant_id, alert_id, indicator_pk) DO NOTHING",
        tenant_id, pk, w["alert_id"], w["indicator_role"], w["alert_severity"], w["model"], w["provider"],
        w["provenance"], w["alert_created_at"], w["organization_id"], w["attr_status"], w["attr_method"],
        w["attr_confidence"], w["attr_evidence"], w["attribution_identifiers"])
    return "inserted" if tag.endswith(" 1") else "duplicate"


async def _link_and_count(conn, tenant_id) -> tuple[int, int, int]:
    """Associa WB<->OAT por mesmo indicador (same_value); retorna (novos_links, wb_linked, wb_unlinked)."""
    tag = await conn.execute(
        "INSERT INTO cyber_workbench_oat_link (tenant_id, workbench_indicator_pk, oat_observation_id, link_method, link_confidence) "
        "SELECT w.tenant_id, w.workbench_indicator_pk, o.observation_id, 'same_value', 'medium' "
        "FROM cyber_workbench_indicator w JOIN cyber_oat_observation o "
        "ON o.tenant_id=w.tenant_id AND o.indicator_pk=w.indicator_pk "
        "WHERE w.tenant_id=$1 ON CONFLICT (workbench_indicator_pk, oat_observation_id) DO NOTHING", tenant_id)
    new_links = int(tag.split()[-1]) if tag.startswith("INSERT") else 0
    linked = await conn.fetchval(
        "SELECT count(DISTINCT w.workbench_indicator_pk) FROM cyber_workbench_indicator w "
        "JOIN cyber_workbench_oat_link l ON l.workbench_indicator_pk=w.workbench_indicator_pk WHERE w.tenant_id=$1", tenant_id)
    total = await conn.fetchval("SELECT count(*) FROM cyber_workbench_indicator WHERE tenant_id=$1", tenant_id)
    return new_links, int(linked), int(total) - int(linked)


async def run_wb(pool, tenant_id: str, token: str, *, base: Optional[str] = None, dry_run: bool = False,
                 window_hours: int = 24, overlap_minutes: int = 15, item_cap: int = 20000) -> dict:
    now = datetime.now(timezone.utc)
    async with pool.acquire() as conn:
        ctx = await _load_context(conn, tenant_id)
        wm = await conn.fetchval(
            "SELECT watermark_event_time FROM cyber_collection_state "
            "WHERE tenant_id=$1 AND collector='workbench' AND source='all' AND severity_scope='all'", tenant_id)
    start = (wm - timedelta(minutes=overlap_minutes)) if wm else (now - timedelta(hours=window_hours))

    client = CyberClient(token, base)
    try:
        pr = await client.paginate(WB_PATH, params={"startDateTime": _iso(start), "endDateTime": _iso(now), "top": 100},
                                   item_cap=item_cap, timeout=120)
    finally:
        await client.aclose()

    disc = Counter()
    rows = []
    for alert in pr.items:
        r, d = build_wb_indicators(alert, ctx)
        disc.update(d)
        rows.extend(r)

    stats = {"tenant_id": tenant_id, "mode": "dry_run" if dry_run else "sync", "attribution_mode": ctx[0],
             "alerts": len(pr.items), "pages": pr.pages, "stop_reason": pr.stop_reason,
             "wb_indicators": len(rows), "attributed": sum(1 for r in rows if r["attr_status"] == "attributed"),
             "unassigned": sum(1 for r in rows if r["attr_status"] in ("unassigned", "unavailable")),
             "ambiguous": sum(1 for r in rows if r["attr_status"] == "ambiguous"),
             "inserted": 0, "duplicate": 0, "collision": 0, "disc": dict(disc)}
    if dry_run:
        return stats

    async with pool.acquire() as conn:
        async with conn.transaction():
            for w in rows:
                stats[await _persist_wb(conn, tenant_id, w)] += 1
            new_links, linked, unlinked = await _link_and_count(conn, tenant_id)
            complete = (pr.stop_reason == "complete")
            status = "ok" if complete else "partial"
            # watermark so avanca em coleta COMPLETA; truncada preserva o anterior (nao perde alertas)
            new_wm = now if complete else wm
            await conn.execute(
                "INSERT INTO cyber_collection_state (tenant_id, collector, source, severity_scope, "
                "watermark_event_time, window_start, window_end, last_attempt_at, last_success_at, pages, "
                "received, inserted, duplicates, status, updated_at) "
                "VALUES ($1,'workbench','all','all',$2,$3,$4,now(),now(),$5,$6,$7,$8,$9,now()) "
                "ON CONFLICT (tenant_id, collector, source, severity_scope) DO UPDATE SET "
                "watermark_event_time=GREATEST(cyber_collection_state.watermark_event_time, EXCLUDED.watermark_event_time), "
                "window_start=EXCLUDED.window_start, "
                "window_end=EXCLUDED.window_end, last_attempt_at=now(), last_success_at=now(), pages=EXCLUDED.pages, "
                "received=EXCLUDED.received, inserted=EXCLUDED.inserted, duplicates=EXCLUDED.duplicates, "
                "status=EXCLUDED.status, updated_at=now()",
                tenant_id, new_wm, start, now, pr.pages, len(pr.items), stats["inserted"], stats["duplicate"], status)
    stats.update({"new_links": new_links, "wb_linked": linked, "wb_unlinked": unlinked})
    return stats
