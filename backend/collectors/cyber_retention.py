"""Retencao (§15). Remove em LOTES (sem lock prolongado, idempotente) dados temporais:
  - cyber_oat_observation: 30h (por event_time) -> links WB<->OAT caem por CASCADE;
  - cyber_workbench_indicator: 30h (por alert_created_at) -> links caem por CASCADE;
  - cyber_discard_sample: 30h (por sampled_at).
NAO remove: cadastro (organization/tenant/config), cyber_organization_mapping, cyber_suspicious_object
(estado atual da politica), cyber_suspicious_object_history (historico), cyber_indicator (registro
canonico). Metricas: removidos e duracao por alvo; falhas registradas por alvo.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

# alvo -> (tabela, coluna de tempo, coluna de PK p/ delete em lote)
_TARGETS = {
    "cyber_oat_observation": ("event_time", "observation_id"),
    "cyber_workbench_indicator": ("alert_created_at", "workbench_indicator_pk"),
    "cyber_discard_sample": ("sampled_at", "id"),
}


async def _count_old(conn, table, tcol, cutoff) -> int:
    return int(await conn.fetchval(f"SELECT count(*) FROM {table} WHERE {tcol} < $1", cutoff))


async def _delete_batched(conn, table, tcol, pk, cutoff, batch) -> int:
    total = 0
    while True:
        tag = await conn.execute(
            f"DELETE FROM {table} WHERE {pk} IN "
            f"(SELECT {pk} FROM {table} WHERE {tcol} < $1 ORDER BY {pk} LIMIT $2)", cutoff, batch)
        n = int(tag.split()[-1]) if tag.startswith("DELETE") else 0
        total += n
        if n < batch:
            break
    return total


async def run_retention(pool, *, oat_hours: float = 30, wb_hours: float = 30, discard_hours: float = 30,
                        wba_days: int = 35, batch: int = 5000, dry_run: bool = False) -> dict:
    now = datetime.now(timezone.utc)
    cutoffs = {
        "cyber_oat_observation": now - timedelta(hours=oat_hours),
        "cyber_workbench_indicator": now - timedelta(hours=wb_hours),
        "cyber_discard_sample": now - timedelta(hours=discard_hours),
    }
    out = {"mode": "dry_run" if dry_run else "sync", "targets": {}}
    for table, (tcol, pk) in _TARGETS.items():
        cutoff = cutoffs[table]
        started = datetime.now(timezone.utc)
        try:
            async with pool.acquire() as conn:
                if dry_run:
                    n = await _count_old(conn, table, tcol, cutoff)
                    out["targets"][table] = {"would_delete": n, "cutoff": cutoff.isoformat()}
                else:
                    # lotes em transacoes curtas (sem lock prolongado): cada lote autocommit
                    n = await _delete_batched(conn, table, tcol, pk, cutoff, batch)
                    dur_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
                    out["targets"][table] = {"deleted": n, "duration_ms": dur_ms, "cutoff": cutoff.isoformat(),
                                             "status": "ok"}
        except Exception as exc:  # noqa: BLE001 — falha por alvo nao derruba os demais
            out["targets"][table] = {"status": "error", "error": type(exc).__name__}

    # cyber_workbench_alert: retencao de 35 dias por created_at (inventario da tela Alertas;
    # PK composta (tenant,alert_id) -> delete direto por cutoff, volume por ciclo e pequeno).
    cutoff_wba = now - timedelta(days=wba_days)
    try:
        async with pool.acquire() as conn:
            if dry_run:
                n = int(await conn.fetchval("SELECT count(*) FROM cyber_workbench_alert WHERE created_at < $1", cutoff_wba))
                out["targets"]["cyber_workbench_alert"] = {"would_delete": n, "cutoff": cutoff_wba.isoformat()}
            else:
                tag = await conn.execute("DELETE FROM cyber_workbench_alert WHERE created_at < $1", cutoff_wba)
                n = int(tag.split()[-1]) if tag.startswith("DELETE") else 0
                out["targets"]["cyber_workbench_alert"] = {"deleted": n, "cutoff": cutoff_wba.isoformat(), "status": "ok"}
    except Exception as exc:  # noqa: BLE001
        out["targets"]["cyber_workbench_alert"] = {"status": "error", "error": type(exc).__name__}
    return out
