"""Coletor OAT (§7-§11). Por tenant, High/Critical, janelas adaptativas; seleciona indicadores
externos publicos (§8), classifica enforcement (§9), atribui a orgao por instancia (§10, motor
cyber_attribution), calcula block_policy_matched por cross-ref SO (dimensao independente; SO nunca
vira prevented_confirmed), persiste idempotente preservando identificadores (§11). Dry-run e sync.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.cyber_attribution import extract_identifiers, load_mappings, resolve_organization
from .cyber_http import CyberClient
from .cyber_oat_select import classify_enforcement, extract_external_indicators
from .cyber_oat_window import collect_adaptive

OAT_PATH = "/v3.0/oat/detections"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _detection_time(det: dict):
    # campo autoritativo do OAT: detectedDateTime (top-level)
    dt = _parse_dt(det.get("detectedDateTime") or det.get("detectionTime"))
    if dt:
        return dt
    # fallback: detail.eventTime (epoch ms)
    ev = (det.get("detail") or {}).get("eventTime")
    if ev:
        try:
            return datetime.fromtimestamp(int(ev) / 1000, tz=timezone.utc)
        except (ValueError, TypeError, OverflowError):
            return None
    return None


def _uuid(det: dict):
    return det.get("uuid") or det.get("uuidId") or det.get("id")


def build_observations(detection, severity, ctx) -> tuple[list, Counter]:
    """Puro: transforma uma deteccao em observacoes externas + contadores de descarte."""
    mode, enabled_orgs, mappings, so_block = ctx
    inds, disc = extract_external_indicators(detection)
    if not inds:
        return [], disc
    status, action_field, action_value = classify_enforcement(detection)
    detail = detection.get("detail") or {}
    source = detail.get("source") or detection.get("source")
    product = detail.get("productCode")
    identifiers = extract_identifiers(detail, source=source, product_code=product)

    def lookup(mt, vh):
        return [(o, c) for (o, c, _m) in mappings.get((mt, vh), [])]

    attr = resolve_organization(mode, enabled_orgs, identifiers, lookup)
    uuid = _uuid(detection)
    ev = _detection_time(detection)
    ingest = _parse_dt(detection.get("ingestedDateTime"))
    if not uuid or not ev:
        disc["missing_key_fields"] += 1
        return [], disc

    ids_json = json.dumps(identifiers, ensure_ascii=False, default=str)
    obs = []
    for ind in inds:
        bpm = (ind.indicator_type, ind.value_normalized) in so_block
        obs.append({
            "indicator_type": ind.indicator_type, "value_normalized": ind.value_normalized,
            "value_raw": ind.value_raw, "value_hash": ind.value_hash,
            "source": source, "product_code": product, "source_event_id": uuid,
            "source_field": ind.source_field, "indicator_role": ind.indicator_role,
            "event_time": ev, "ingest_time": ingest, "severity": severity,
            "enforcement_status": status, "action_field": action_field, "action_value_raw": action_value,
            "block_policy_matched": bpm, "policy_match_basis": "current_state" if bpm else "unavailable",
            "organization_id": attr.organization_id, "attr_status": attr.status,
            "attr_method": attr.method, "attr_confidence": attr.confidence, "attr_evidence": attr.evidence,
            "attribution_identifiers": ids_json,
        })
    return obs, disc


async def _load_context(conn, tenant_id):
    mrow = await conn.fetchrow("SELECT attribution_mode FROM cyber_tenant_config WHERE tenant_id=$1", tenant_id)
    mode = mrow["attribution_mode"] if mrow else "mapping"
    orows = await conn.fetch("SELECT organization_id FROM organization WHERE tenant_id=$1 AND enabled AND cyber_enabled", tenant_id)
    enabled_orgs = [r["organization_id"] for r in orows]
    mappings = await load_mappings(conn, tenant_id)
    srows = await conn.fetch(
        "SELECT i.indicator_type, i.value_normalized FROM cyber_suspicious_object so "
        "JOIN cyber_indicator i ON i.indicator_pk=so.indicator_pk "
        "WHERE i.tenant_id=$1 AND so.is_active AND lower(coalesce(so.scan_action,'')) IN ('block','deny','quarantine')",
        tenant_id)
    so_block = {(r["indicator_type"], r["value_normalized"]) for r in srows}
    return mode, enabled_orgs, mappings, so_block


async def _persist_obs(conn, tenant_id, o) -> str:
    """Upsert indicador (defesa de colisao) + insert observacao idempotente. Retorna
    'inserted' | 'duplicate' | 'collision'."""
    pk = await conn.fetchval(
        "INSERT INTO cyber_indicator (tenant_id,indicator_type,value_hash,value_normalized,value_raw,first_seen_at,last_seen_at) "
        "VALUES ($1,$2,$3,$4,$5,now(),now()) ON CONFLICT (tenant_id,indicator_type,value_hash) "
        "DO UPDATE SET last_seen_at=now(), value_raw=EXCLUDED.value_raw, updated_at=now() "
        "WHERE cyber_indicator.value_normalized=EXCLUDED.value_normalized RETURNING indicator_pk",
        tenant_id, o["indicator_type"], o["value_hash"], o["value_normalized"], o["value_raw"])
    if pk is None:
        return "collision"
    tag = await conn.execute(
        "INSERT INTO cyber_oat_observation (tenant_id, indicator_pk, source, product_code, source_event_id, "
        "source_field, indicator_role, value_raw_observed, event_time, ingest_time, severity, enforcement_status, "
        "action_field, action_value_raw, block_policy_matched, policy_match_basis, organization_id, "
        "organization_attribution_status, organization_attribution_method, organization_attribution_confidence, "
        "organization_attribution_evidence, attribution_identifiers) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22::jsonb) "
        "ON CONFLICT (tenant_id, source, source_event_id, indicator_pk, source_field, indicator_role) DO NOTHING",
        tenant_id, pk, o["source"], o["product_code"], o["source_event_id"], o["source_field"], o["indicator_role"],
        o["value_raw"], o["event_time"], o["ingest_time"], o["severity"], o["enforcement_status"],
        o["action_field"], o["action_value_raw"], o["block_policy_matched"], o["policy_match_basis"],
        o["organization_id"], o["attr_status"], o["attr_method"], o["attr_confidence"], o["attr_evidence"],
        o["attribution_identifiers"])
    return "inserted" if tag.endswith(" 1") else "duplicate"


async def run_oat(pool, tenant_id: str, token: str, *, base: Optional[str] = None, dry_run: bool = False,
                  window_hours: int = 24, overlap_minutes: int = 15,
                  severities=("high", "critical"), page_budget: int = 2000,
                  min_window_minutes: int = 5, fetch_page_cap: int = 800,
                  fetch_item_cap: int = 200000) -> dict:
    now = datetime.now(timezone.utc)
    out = {"tenant_id": tenant_id, "mode": "dry_run" if dry_run else "sync", "by_severity": {}}
    client = CyberClient(token, base)

    # contexto de atribuicao (read-only tambem no dry-run)
    async with pool.acquire() as conn:
        ctx = await _load_context(conn, tenant_id)
    out["attribution_mode"] = ctx[0]
    out["enabled_orgs"] = len(ctx[1])

    try:
        for sev in severities:
            async with pool.acquire() as conn:
                wm = await conn.fetchval(
                    "SELECT watermark_event_time FROM cyber_collection_state "
                    "WHERE tenant_id=$1 AND collector='oat' AND source='all' AND severity_scope=$2", tenant_id, sev)
            start = (wm - timedelta(minutes=overlap_minutes)) if wm else (now - timedelta(hours=window_hours))
            end = now

            async def count_fn(ws, we, _sev=sev):
                d = await client.get_json(OAT_PATH, params={"detectedStartDateTime": _iso(ws),
                    "detectedEndDateTime": _iso(we), "top": 1},
                    extra_headers={"TMV1-Filter": f"riskLevel eq '{_sev}'"}, timeout=90)
                return d.get("totalCount")

            async def fetch_fn(ws, we, _sev=sev):
                pr = await client.paginate(OAT_PATH, params={"detectedStartDateTime": _iso(ws),
                    "detectedEndDateTime": _iso(we), "top": 200},
                    extra_headers={"TMV1-Filter": f"riskLevel eq '{_sev}'"},
                    item_cap=fetch_item_cap, page_cap=fetch_page_cap, timeout=120)
                return pr.items, pr.pages, (pr.stop_reason == "complete")

            win = await collect_adaptive(count_fn, fetch_fn, start, end,
                                         min_window=timedelta(minutes=min_window_minutes), page_budget=page_budget)

            sev_stats = {"detections": len(win.items), "pages": win.pages, "windows": win.windows_done,
                         "complete": win.complete, "saturated_irreducible": len(win.saturated_irreducible),
                         "stop_reason": win.stop_reason, "ext_accepted": 0,
                         "attributed": 0, "unassigned": 0, "ambiguous": 0,
                         "prevented": 0, "allowed": 0, "observed_not_prevented": 0, "observed": 0,
                         "unknown_enf": 0, "block_policy_matched": 0, "inserted": 0, "duplicate": 0,
                         "collision": 0, "disc": {}}
            disc_total = Counter()
            enf_key = {"prevented_confirmed": "prevented", "allowed_confirmed": "allowed",
                       "observed_not_prevented": "observed_not_prevented", "observed": "observed",
                       "unknown": "unknown_enf"}

            all_obs = []
            for det in win.items:
                obs, disc = build_observations(det, sev, ctx)
                disc_total.update(disc)
                for o in obs:
                    sev_stats["ext_accepted"] += 1
                    sev_stats[enf_key.get(o["enforcement_status"], "unknown_enf")] += 1
                    if o["block_policy_matched"]:
                        sev_stats["block_policy_matched"] += 1
                    sev_stats[{"attributed": "attributed", "unassigned": "unassigned",
                               "ambiguous": "ambiguous", "unavailable": "unassigned"}.get(o["attr_status"], "unassigned")] += 1
                all_obs.append(obs)

            if not dry_run:
                async with pool.acquire() as conn:
                    async with conn.transaction():
                        for obs in all_obs:
                            for o in obs:
                                res = await _persist_obs(conn, tenant_id, o)
                                sev_stats[res] += 1
                        # watermark = fim do ultimo intervalo contiguo completo; status conforme completude
                        status = "ok" if win.complete else "partial"
                        await conn.execute(
                            "INSERT INTO cyber_collection_state (tenant_id, collector, source, severity_scope, "
                            "watermark_event_time, window_start, window_end, last_attempt_at, last_success_at, pages, "
                            "received, inserted, duplicates, saturated, status, ext_accepted, attr_attributed, "
                            "attr_unassigned, attr_ambiguous, updated_at) "
                            "VALUES ($1,'oat','all',$2,$3,$4,$5,now(),now(),$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,now()) "
                            "ON CONFLICT (tenant_id, collector, source, severity_scope) DO UPDATE SET "
                            "watermark_event_time=GREATEST(cyber_collection_state.watermark_event_time, EXCLUDED.watermark_event_time), "
                            "window_start=EXCLUDED.window_start, "
                            "window_end=EXCLUDED.window_end, last_attempt_at=now(), last_success_at=now(), "
                            "pages=EXCLUDED.pages, received=EXCLUDED.received, inserted=EXCLUDED.inserted, "
                            "duplicates=EXCLUDED.duplicates, saturated=EXCLUDED.saturated, status=EXCLUDED.status, "
                            "ext_accepted=EXCLUDED.ext_accepted, attr_attributed=EXCLUDED.attr_attributed, "
                            "attr_unassigned=EXCLUDED.attr_unassigned, attr_ambiguous=EXCLUDED.attr_ambiguous, updated_at=now()",
                            tenant_id, sev, win.watermark, start, end, win.pages, len(win.items),
                            sev_stats["inserted"], sev_stats["duplicate"], bool(win.saturated_irreducible), status,
                            sev_stats["ext_accepted"], sev_stats["attributed"], sev_stats["unassigned"], sev_stats["ambiguous"])

            sev_stats["disc"] = dict(disc_total)
            out["by_severity"][sev] = sev_stats
    finally:
        await client.aclose()
    return out
