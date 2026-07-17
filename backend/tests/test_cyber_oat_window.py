"""Testes do motor de janela adaptativa (§7.3)."""
from datetime import datetime, timedelta, timezone

from collectors.cyber_oat_window import collect_adaptive

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
H = timedelta(hours=1)


async def test_no_saturation_single_window():
    async def cf(ws, we):
        return 10

    async def ff(ws, we):
        return ([f"item-{ws.isoformat()}"], 1)

    r = await collect_adaptive(cf, ff, T0, T0 + 24 * H)
    assert r.complete and r.watermark == T0 + 24 * H and r.windows_done == 1
    assert not r.saturated_irreducible and r.stop_reason == "complete"


async def test_saturation_reducible_bisects_to_completion():
    async def cf(ws, we):
        return 100001 if (we - ws) > timedelta(hours=6) else 10

    async def ff(ws, we):
        return ([1], 1)

    r = await collect_adaptive(cf, ff, T0, T0 + 24 * H, min_window=timedelta(minutes=5))
    assert r.complete and r.watermark == T0 + 24 * H
    assert r.windows_done == 4 and not r.saturated_irreducible   # 24h -> 4 janelas de 6h


async def test_saturation_irreducible_stops_no_watermark_advance():
    async def cf(ws, we):
        return 100001

    async def ff(ws, we):
        return ([1], 1)

    r = await collect_adaptive(cf, ff, T0, T0 + 24 * H, min_window=H, max_depth=20)
    assert not r.complete and r.saturated_irreducible and r.stop_reason == "saturated_irreducible"
    assert r.watermark == T0   # nada completou -> nao avanca (stop-on-gap)


async def test_partial_completion_stops_on_gap_watermark_at_boundary():
    mid = T0 + 12 * H

    async def cf(ws, we):
        return 100001 if we > mid else 10       # satura qualquer janela que passe do meio

    async def ff(ws, we):
        return ([1], 1)

    r = await collect_adaptive(cf, ff, T0, T0 + 24 * H, min_window=H)
    assert not r.complete
    assert r.watermark == mid                    # metade antiga completou; para na lacuna
    assert r.saturated_irreducible and r.stop_reason == "saturated_irreducible"


async def test_page_budget_stops():
    async def cf(ws, we):
        return 100001 if (we - ws) > H else 10   # forca varias janelas pequenas

    async def ff(ws, we):
        return ([1], 100)                        # cada janela consome 100 paginas

    r = await collect_adaptive(cf, ff, T0, T0 + 24 * H, min_window=timedelta(minutes=1),
                               page_budget=150)
    assert r.stop_reason == "page_budget" and not r.complete
