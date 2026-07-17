"""Capacidade de enforcement (§14). Calcula por (tenant, source, product_code) a partir das
observacoes OAT: none/partial/full conforme a cobertura de acao (act) reconhecida. Registra
status/reason/evidence_field/last_seen_at/expires_at. Capacidade obsoleta (expirada) vira 'stale'
e NAO deve ser tratada como atual. Primariamente do tenant/fonte/produto (orgaos refletem depois).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

_AGG_SQL = """
SELECT tenant_id, source, coalesce(product_code,'all') AS product_code,
       count(*) AS total,
       count(*) FILTER (WHERE action_field IS NOT NULL AND enforcement_status <> 'unknown') AS with_action,
       max(action_field) AS evidence_field,
       max(event_time)   AS last_seen
FROM cyber_oat_observation
GROUP BY tenant_id, source, coalesce(product_code,'all')
"""


def _capability(total: int, with_action: int) -> str:
    if with_action == 0:
        return "none"
    if with_action * 10 >= total * 9:   # >= 90%
        return "full"
    return "partial"


async def compute_capability(pool, *, ttl_hours: float = 48, dry_run: bool = False) -> dict:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=ttl_hours)
    async with pool.acquire() as conn:
        rows = await conn.fetch(_AGG_SQL)
        groups = []
        for r in rows:
            cap = _capability(r["total"], r["with_action"])
            cov = round(100.0 * r["with_action"] / r["total"]) if r["total"] else 0
            groups.append({
                "tenant_id": r["tenant_id"], "source": r["source"], "product_code": r["product_code"],
                "capability": cap, "coverage_pct": cov, "total": r["total"], "with_action": r["with_action"],
                "evidence_field": r["evidence_field"], "last_seen": r["last_seen"],
                "reason": f"coverage={cov}% ({r['with_action']}/{r['total']})",
            })
        if dry_run:
            return {"mode": "dry_run", "groups": groups}

        async with conn.transaction():
            for g in groups:
                await conn.execute(
                    "INSERT INTO cyber_enforcement_capability (tenant_id, source, product_code, capability, "
                    "status, reason, evidence_field, samples_seen, last_seen_at, expires_at, computed_at) "
                    "VALUES ($1,$2,$3,$4,'current',$5,$6,$7,$8,$9, now()) "
                    "ON CONFLICT (tenant_id, source, product_code) DO UPDATE SET "
                    "capability=EXCLUDED.capability, status='current', reason=EXCLUDED.reason, "
                    "evidence_field=EXCLUDED.evidence_field, samples_seen=EXCLUDED.samples_seen, "
                    "last_seen_at=EXCLUDED.last_seen_at, expires_at=EXCLUDED.expires_at, computed_at=now()",
                    g["tenant_id"], g["source"], g["product_code"], g["capability"], g["reason"],
                    g["evidence_field"], g["total"], g["last_seen"], expires)
            # capacidade expirada -> stale (nao tratar como atual)
            stale = await conn.fetchval(
                "WITH u AS (UPDATE cyber_enforcement_capability SET status='stale' "
                "WHERE expires_at IS NOT NULL AND expires_at < now() AND status <> 'stale' RETURNING 1) "
                "SELECT count(*) FROM u")
    return {"mode": "sync", "groups": groups, "computed": len(groups), "marked_stale": int(stale)}
