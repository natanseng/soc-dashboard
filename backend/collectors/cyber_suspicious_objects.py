"""Coletor de Suspicious Objects (§5) — GET /v3.0/threatintel/suspiciousObjects.

Por tenant (tenant-scoped): organization_id NUNCA e atribuido aqui (regra 1) — o SO e estado
de POLITICA, nao observacao; nunca gera prevented_confirmed (regra 7). Tipos: ip/domain/url.
Paginacao completa (sem cap de 2.000), loop-guard, 429/Retry-After/backoff+jitter (via CyberClient).
Persiste em cyber_indicator (upsert com defesa de colisao), cyber_suspicious_object (estado atual),
cyber_suspicious_object_history (temporal: added/modified/removed) e cyber_collection_state.
Suporta dry-run (sem escrita), full sync e reexecucao idempotente.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app.cyber_normalize import normalize_indicator
from .cyber_http import CyberClient

SO_PATH = "/v3.0/threatintel/suspiciousObjects"
NET_TYPES = ("ip", "domain", "url")


def _parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def classify(items):
    """Extrai/normaliza SOs de rede (ip/domain/url). Retorna (rows, stats).
    rows: tuplas p/ staging. stats: contadores (inclui descartes, sem descarte silencioso)."""
    rows = []
    stats = {"fetched": len(items), "ip": 0, "domain": 0, "url": 0,
             "skipped_type": 0, "invalid_value": 0, "block": 0, "log": 0, "other_action": 0}
    seen = set()
    for it in items:
        t = it.get("type")
        if t not in NET_TYPES:
            stats["skipped_type"] += 1
            continue
        raw = it.get(t)
        norm = normalize_indicator(t, raw)
        if norm is None:
            stats["invalid_value"] += 1
            continue
        value_normalized, value_hash = norm
        key = (t, value_normalized)
        if key in seen:            # dedup dentro do lote
            continue
        seen.add(key)
        stats[t] += 1
        action = (it.get("scanAction") or "").lower()
        stats["block" if action == "block" else "log" if action == "log" else "other_action"] += 1
        rows.append((
            t, value_normalized, value_hash, str(raw),
            it.get("scanAction"), it.get("riskLevel"), bool(it.get("inExceptionList")),
            _parse_dt(it.get("lastModifiedDateTime")), _parse_dt(it.get("expiredDateTime")),
            (it.get("description") or None),
        ))
    return rows, stats


async def fetch(client: CyberClient, *, item_cap: int = 500_000, timeout: float = 90.0):
    return await client.paginate(SO_PATH, params={"top": 200}, item_cap=item_cap, timeout=timeout)


async def run_sync(pool, tenant_id: str, token: str, *, base: Optional[str] = None,
                   dry_run: bool = False) -> dict:
    """Executa a sincronizacao de SO para um tenant. dry_run=True nao escreve nada."""
    started = datetime.now(timezone.utc)
    client = CyberClient(token, base)
    try:
        page = await fetch(client)
    finally:
        await client.aclose()
    rows, stats = classify(page.items)
    stats.update({"pages": page.pages, "stop_reason": page.stop_reason, "truncated": page.truncated,
                  "relevant": len(rows), "dry_run": dry_run})

    if dry_run:
        stats["mode"] = "dry_run"
        return stats

    metrics = await persist_sync(pool, tenant_id, rows, page.pages, started=started)
    stats.update(metrics)
    return stats


async def persist_sync(pool, tenant_id: str, rows, pages: int, *, started=None) -> dict:
    """Persiste (staging set-based) o lote de SOs de rede. Idempotente. Retorna metricas."""
    started = started or datetime.now(timezone.utc)
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "CREATE TEMP TABLE so_stage (indicator_type text, value_normalized text, "
                "value_hash bytea, value_raw text, scan_action text, risk_level text, "
                "in_exception_list boolean, api_last_modified_at timestamptz, expired_at timestamptz, "
                "notes text) ON COMMIT DROP")
            if rows:
                await conn.copy_records_to_table("so_stage", records=rows, columns=[
                    "indicator_type", "value_normalized", "value_hash", "value_raw", "scan_action",
                    "risk_level", "in_exception_list", "api_last_modified_at", "expired_at", "notes"])

            # colisao: mesmo (tenant,type,hash) ja existe com value_normalized diferente
            collisions = await conn.fetchval(
                "SELECT count(*) FROM so_stage s JOIN cyber_indicator i "
                "ON i.tenant_id=$1 AND i.indicator_type=s.indicator_type AND i.value_hash=s.value_hash "
                "WHERE i.value_normalized <> s.value_normalized", tenant_id)

            # upsert de indicadores (defesa de colisao: so atualiza se value_normalized casa)
            await conn.execute(
                "INSERT INTO cyber_indicator (tenant_id, indicator_type, value_hash, value_normalized, "
                "value_raw, first_seen_at, last_seen_at) "
                "SELECT $1, indicator_type, value_hash, value_normalized, value_raw, now(), now() FROM so_stage "
                "ON CONFLICT (tenant_id, indicator_type, value_hash) DO UPDATE "
                "SET last_seen_at=now(), value_raw=EXCLUDED.value_raw, updated_at=now() "
                "WHERE cyber_indicator.value_normalized = EXCLUDED.value_normalized", tenant_id)

            # diffs para historico (antes do upsert do estado atual)
            added = await conn.fetchval(
                "SELECT count(*) FROM so_stage s JOIN cyber_indicator i "
                "ON i.tenant_id=$1 AND i.indicator_type=s.indicator_type AND i.value_normalized=s.value_normalized "
                "LEFT JOIN cyber_suspicious_object so ON so.indicator_pk=i.indicator_pk "
                "WHERE so.indicator_pk IS NULL", tenant_id)
            modified = await conn.fetchval(
                "SELECT count(*) FROM so_stage s JOIN cyber_indicator i "
                "ON i.tenant_id=$1 AND i.indicator_type=s.indicator_type AND i.value_normalized=s.value_normalized "
                "JOIN cyber_suspicious_object so ON so.indicator_pk=i.indicator_pk "
                "WHERE so.is_active AND (so.scan_action IS DISTINCT FROM s.scan_action "
                "  OR so.risk_level IS DISTINCT FROM s.risk_level "
                "  OR so.in_exception_list IS DISTINCT FROM s.in_exception_list)", tenant_id)

            # fecha intervalo aberto do historico p/ modificados e removidos
            await conn.execute(
                "UPDATE cyber_suspicious_object_history h SET valid_to=now() "
                "FROM cyber_suspicious_object so JOIN cyber_indicator i ON i.indicator_pk=so.indicator_pk "
                "LEFT JOIN so_stage s ON s.indicator_type=i.indicator_type AND s.value_normalized=i.value_normalized "
                "WHERE i.tenant_id=$1 AND so.is_active AND h.indicator_pk=so.indicator_pk AND h.valid_to IS NULL "
                "AND (s.value_normalized IS NULL OR so.scan_action IS DISTINCT FROM s.scan_action "
                "  OR so.risk_level IS DISTINCT FROM s.risk_level "
                "  OR so.in_exception_list IS DISTINCT FROM s.in_exception_list)", tenant_id)

            # historico: 'added' (novos)
            await conn.execute(
                "INSERT INTO cyber_suspicious_object_history (indicator_pk, tenant_id, valid_from, "
                "scan_action, risk_level, in_exception_list, change_type, policy_match_basis) "
                "SELECT i.indicator_pk, $1, now(), s.scan_action, s.risk_level, s.in_exception_list, 'added', 'current_state' "
                "FROM so_stage s JOIN cyber_indicator i "
                "ON i.tenant_id=$1 AND i.indicator_type=s.indicator_type AND i.value_normalized=s.value_normalized "
                "LEFT JOIN cyber_suspicious_object so ON so.indicator_pk=i.indicator_pk "
                "WHERE so.indicator_pk IS NULL", tenant_id)
            # historico: 'modified'
            await conn.execute(
                "INSERT INTO cyber_suspicious_object_history (indicator_pk, tenant_id, valid_from, "
                "scan_action, risk_level, in_exception_list, change_type, policy_match_basis) "
                "SELECT i.indicator_pk, $1, now(), s.scan_action, s.risk_level, s.in_exception_list, 'modified', 'current_state' "
                "FROM so_stage s JOIN cyber_indicator i "
                "ON i.tenant_id=$1 AND i.indicator_type=s.indicator_type AND i.value_normalized=s.value_normalized "
                "JOIN cyber_suspicious_object so ON so.indicator_pk=i.indicator_pk "
                "WHERE so.is_active AND (so.scan_action IS DISTINCT FROM s.scan_action "
                "  OR so.risk_level IS DISTINCT FROM s.risk_level "
                "  OR so.in_exception_list IS DISTINCT FROM s.in_exception_list)", tenant_id)

            # upsert do estado atual
            await conn.execute(
                "INSERT INTO cyber_suspicious_object (indicator_pk, tenant_id, scan_action, risk_level, "
                "in_exception_list, notes, api_last_modified_at, expired_at, first_seen_at, last_seen_at, is_active) "
                "SELECT i.indicator_pk, $1, s.scan_action, s.risk_level, s.in_exception_list, s.notes, "
                "s.api_last_modified_at, s.expired_at, now(), now(), true "
                "FROM so_stage s JOIN cyber_indicator i "
                "ON i.tenant_id=$1 AND i.indicator_type=s.indicator_type AND i.value_normalized=s.value_normalized "
                "ON CONFLICT (indicator_pk) DO UPDATE SET scan_action=EXCLUDED.scan_action, "
                "risk_level=EXCLUDED.risk_level, in_exception_list=EXCLUDED.in_exception_list, "
                "notes=EXCLUDED.notes, api_last_modified_at=EXCLUDED.api_last_modified_at, "
                "expired_at=EXCLUDED.expired_at, last_seen_at=now(), is_active=true, updated_at=now()", tenant_id)

            # removidos: SO ativo cujo indicador nao esta mais no lote
            removed = await conn.fetchval(
                "SELECT count(*) FROM cyber_suspicious_object so JOIN cyber_indicator i ON i.indicator_pk=so.indicator_pk "
                "LEFT JOIN so_stage s ON s.indicator_type=i.indicator_type AND s.value_normalized=i.value_normalized "
                "WHERE i.tenant_id=$1 AND so.is_active AND s.value_normalized IS NULL", tenant_id)
            await conn.execute(
                "INSERT INTO cyber_suspicious_object_history (indicator_pk, tenant_id, valid_from, "
                "scan_action, risk_level, in_exception_list, change_type, policy_match_basis) "
                "SELECT so.indicator_pk, $1, now(), so.scan_action, so.risk_level, so.in_exception_list, 'removed', 'current_state' "
                "FROM cyber_suspicious_object so JOIN cyber_indicator i ON i.indicator_pk=so.indicator_pk "
                "LEFT JOIN so_stage s ON s.indicator_type=i.indicator_type AND s.value_normalized=i.value_normalized "
                "WHERE i.tenant_id=$1 AND so.is_active AND s.value_normalized IS NULL", tenant_id)
            await conn.execute(
                "UPDATE cyber_suspicious_object so SET is_active=false, updated_at=now() "
                "FROM cyber_indicator i LEFT JOIN so_stage s "
                "ON s.indicator_type=i.indicator_type AND s.value_normalized=i.value_normalized "
                "WHERE so.indicator_pk=i.indicator_pk AND i.tenant_id=$1 AND so.is_active AND s.value_normalized IS NULL", tenant_id)

            active_total = await conn.fetchval(
                "SELECT count(*) FROM cyber_suspicious_object so JOIN cyber_indicator i ON i.indicator_pk=so.indicator_pk "
                "WHERE i.tenant_id=$1 AND so.is_active", tenant_id)

            dur_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
            await conn.execute(
                "INSERT INTO cyber_collection_state (tenant_id, collector, source, severity_scope, "
                "last_attempt_at, last_success_at, pages, received, inserted, updated, duplicates, "
                "duration_ms, status, updated_at) "
                "VALUES ($1,'suspicious_object','all','all', now(), now(), $2,$3,$4,$5,$6,$7,'ok', now()) "
                "ON CONFLICT (tenant_id, collector, source, severity_scope) DO UPDATE SET "
                "last_attempt_at=now(), last_success_at=now(), pages=EXCLUDED.pages, received=EXCLUDED.received, "
                "inserted=EXCLUDED.inserted, updated=EXCLUDED.updated, duplicates=EXCLUDED.duplicates, "
                "duration_ms=EXCLUDED.duration_ms, status='ok', updated_at=now()",
                tenant_id, pages, len(rows), int(added), int(modified), int(collisions), dur_ms)

    return {"mode": "sync", "added": int(added), "modified": int(modified),
            "removed": int(removed), "collisions": int(collisions),
            "active_total": int(active_total)}
