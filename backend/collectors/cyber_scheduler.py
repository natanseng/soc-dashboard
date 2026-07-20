"""Scheduler recorrente dos coletores Cyber (§22). Processo SEPARADO do coletor da Fase 1.

Locks por (collector, tenant[, severity_scope]): se ja houver ciclo ativo -> skipped_running.
Tenants vem do cadastro dinamico (sem hardcode); tenant sem token e pulado (unavailable).
Periodicidade: OAT 60s, Workbench 300s, Suspicious Objects 900s, GeoIP 300s, capacidade 600s,
retencao 1800s. Nao reinicia nem interfere no coletor antigo. Rodar: python -m collectors.cyber_scheduler
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import asyncpg
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.config import settings
from app.cyber_tokens import resolve_token
from .cyber_capability import compute_capability
from .cyber_geo import run_geo
from .cyber_oat import run_oat
from .cyber_retention import run_retention
from .cyber_suspicious_objects import run_sync as so_sync
from .cyber_workbench import run_wb
from .cyber_workbench_alerts import run_wb_alerts

log = logging.getLogger("cyber.scheduler")
_running: set = set()


async def enabled_tenants(pool):
    """(tenant_id, token) dos tenants habilitados COM token. Sem hardcode; token nunca logado."""
    rows = await pool.fetch(
        "SELECT t.tenant_id FROM cyber_tenant_config c JOIN tenant t ON t.tenant_id=c.tenant_id "
        "WHERE c.cyber_enabled AND c.enabled ORDER BY t.tenant_id")
    out = []
    for r in rows:
        ts = resolve_token(r["tenant_id"])
        if ts.configured:
            out.append((r["tenant_id"], ts.token))
        else:
            log.warning("tenant %s sem credencial; ignorado neste ciclo", r["tenant_id"])
    return out


async def guarded(key, coro_factory):
    """Executa se nao houver ciclo ativo com a mesma chave; senao registra skipped_running."""
    if key in _running:
        log.info("skipped_running key=%s", key)
        return
    _running.add(key)
    try:
        await coro_factory()
    except Exception as exc:  # noqa: BLE001 — falha de um job nao derruba os demais
        log.warning("job %s falhou: %s", key, type(exc).__name__)
    finally:
        _running.discard(key)


def _make_jobs(pool):
    async def job_oat():
        for tid, tok in await enabled_tenants(pool):
            await guarded(("oat", tid), lambda tid=tid, tok=tok: run_oat(pool, tid, tok))

    async def job_wb():
        for tid, tok in await enabled_tenants(pool):
            await guarded(("wb", tid), lambda tid=tid, tok=tok: run_wb(pool, tid, tok))

    async def job_wba():   # inventario de workbenches (tela Alertas)
        for tid, tok in await enabled_tenants(pool):
            await guarded(("wba", tid), lambda tid=tid, tok=tok: run_wb_alerts(pool, tid, tok))

    async def job_so():
        for tid, tok in await enabled_tenants(pool):
            await guarded(("so", tid), lambda tid=tid, tok=tok: so_sync(pool, tid, tok))

    async def job_geo():
        await guarded(("geo",), lambda: run_geo(pool))

    async def job_capability():
        await guarded(("capability",), lambda: compute_capability(pool))

    async def job_retention():
        await guarded(("retention",), lambda: run_retention(pool))

    return {"oat": job_oat, "wb": job_wb, "wba": job_wba, "so": job_so, "geo": job_geo,
            "capability": job_capability, "retention": job_retention}


def build_scheduler(pool, *, run_now: bool = False) -> AsyncIOScheduler:
    jobs = _make_jobs(pool)
    sch = AsyncIOScheduler(timezone="UTC")
    nrt = datetime.now(timezone.utc) if run_now else None
    specs = [("oat", 60), ("wb", 300), ("wba", 600), ("so", 900), ("geo", 300), ("capability", 600), ("retention", 1800)]
    for jid, secs in specs:
        kw = {"id": jid, "max_instances": 1, "coalesce": True}
        if nrt is not None:
            kw["next_run_time"] = nrt
        sch.add_job(jobs[jid], "interval", seconds=secs, **kw)
    return sch


async def _main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if not settings.db_dsn:
        log.error("DB_DSN nao configurado; scheduler nao inicia.")
        return
    pool = await asyncpg.create_pool(dsn=settings.db_dsn, min_size=1, max_size=6, command_timeout=180)
    sch = build_scheduler(pool, run_now=True)
    sch.start()
    log.info("cyber scheduler iniciado (OAT 60s / WB 300s / SO 900s / GeoIP 300s / cap 600s / ret 1800s)")
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        sch.shutdown(wait=False)
        await pool.close()


if __name__ == "__main__":
    asyncio.run(_main())
