#!/usr/bin/env python3
"""Diagnóstico MTTA / MTTR — alertas Workbench FECHADOS (tenant atual).

Somente leitura: não altera nada, não grava em Redis. Reusa o cliente e o token
já configurados no backend. Objetivo: confirmar empiricamente se os alertas
Closed da Prodesp carregam `firstInvestigatedDateTime` (necessário p/ MTTA) e
medir os tempos reais antes de levar pro dashboard.

Rodar (no venv do backend):
    cd ~/projetos/soc-dashboard/backend && source .venv/bin/activate
    python diag_mttr.py
"""
import asyncio
import statistics
from datetime import datetime, timezone, timedelta

from app.config import settings
from app.vision_one import VisionOneClient

DAYS = 30  # janela de análise


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _fmt(secs):
    if secs is None:
        return "—"
    if secs < 3600:
        return f"{secs/60:.0f} min"
    if secs < 48 * 3600:
        return f"{secs/3600:.1f} h"
    return f"{secs/86400:.1f} dias"


def _stats(label, arr):
    if not arr:
        print(f"{label}: SEM amostra")
        return
    print(f"{label}:")
    print(f"   média   = {_fmt(statistics.mean(arr))}")
    print(f"   mediana = {_fmt(statistics.median(arr))}")
    print(f"   p90     = {_fmt(sorted(arr)[int(len(arr)*0.9)-1])}")
    print(f"   min/max = {_fmt(min(arr))} / {_fmt(max(arr))}")


async def main():
    v1 = VisionOneClient(settings.v1_api_token, settings.v1_api_base)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=DAYS)
    base = {
        "startDateTime": _iso(start),
        "endDateTime": _iso(end),
        "dateTimeTarget": "createdDateTime",
        "orderBy": "createdDateTime desc",
    }
    try:
        items = await v1.get_paginated(
            "/v3.0/workbench/alerts",
            params={**base, "top": 100},
            extra_headers={"TMV1-Filter": "status eq 'Closed'"},
            limit=3000,
        )
    finally:
        await v1.aclose()

    n = len(items)
    mtta, mttr, handle = [], [], []
    by_result = {}
    sample = []
    for a in items:
        c = a.get("createdDateTime")
        u = a.get("updatedDateTime")
        f = a.get("firstInvestigatedDateTime")
        res = a.get("investigationResult") or a.get("investigationStatus") or "?"
        by_result[res] = by_result.get(res, 0) + 1
        if f and c:
            ta = (_parse(f) - _parse(c)).total_seconds()
            if ta >= 0:
                mtta.append(ta)
            if u:
                th = (_parse(u) - _parse(f)).total_seconds()
                if th >= 0:
                    handle.append(th)
        if u and c:
            tr = (_parse(u) - _parse(c)).total_seconds()
            if tr >= 0:
                mttr.append(tr)
        if len(sample) < 8:
            sample.append((
                str(a.get("model") or a.get("modelName") or "?")[:38],
                c, f or "—(sem In Progress)", u, res,
            ))

    print(f"\n=== Workbench CLOSED — últimos {DAYS} dias (tenant={settings.tenant}) ===")
    print(f"Total Closed retornados......: {n}")
    pct = (100 * len(mtta) // n) if n else 0
    print(f"Com firstInvestigatedDateTime: {len(mtta)}  ({pct}%)  <- decide se MTTA é viável")
    print(f"Com updatedDateTime..........: {len(mttr)}")
    print(f"\nPor investigationResult: {by_result}")
    print()
    _stats("MTTA  (created -> In Progress)", mtta)
    print()
    _stats("MTTR* (created -> updated/fechamento, APROX)", mttr)
    print()
    _stats("Handle (In Progress -> updated, APROX)", handle)
    print("\n=== Amostra: model | created | firstInvestigated | updated | result ===")
    for s in sample:
        print("  " + "  |  ".join(str(x) for x in s))
    print("\n* MTTR aproximado: a API não tem closedDateTime; usa updatedDateTime (mutável).")


if __name__ == "__main__":
    asyncio.run(main())
