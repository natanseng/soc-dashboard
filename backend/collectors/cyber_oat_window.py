"""Janela adaptativa do OAT (§7.3). Puro: recebe count_fn/fetch_fn assincronos.

Bisseccao em saturacao (totalCount>=SATURATION), processamento OLDEST-FIRST, STOP-ON-GAP
(para no primeiro intervalo que nao completa e NAO avanca o watermark alem dele), MINIMUM_WINDOW,
MAX_DEPTH, orcamentos de paginas/janelas. watermark = fim do ultimo intervalo CONTIGUO completo.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

SATURATION = 100001


@dataclass
class WindowResult:
    items: list = field(default_factory=list)
    watermark: Optional[datetime] = None      # fim do ultimo intervalo contiguo completo
    complete: bool = False
    saturated_irreducible: List[Tuple[datetime, datetime]] = field(default_factory=list)
    pages: int = 0
    windows_done: int = 0
    stop_reason: str = "complete"


async def collect_adaptive(count_fn, fetch_fn, start: datetime, end: datetime, *,
                           saturation: int = SATURATION, min_window: timedelta = timedelta(minutes=5),
                           max_depth: int = 12, page_budget: int = 2000,
                           max_windows: int = 5000) -> WindowResult:
    r = WindowResult(watermark=start)

    async def process(ws: datetime, we: datetime, depth: int) -> bool:
        if r.windows_done >= max_windows:
            r.stop_reason = "window_budget"; return False
        if r.pages >= page_budget:
            r.stop_reason = "page_budget"; return False
        cnt = await count_fn(ws, we)
        if cnt is None:
            r.stop_reason = "count_error"; return False
        if cnt >= saturation:
            span = we - ws
            if span <= min_window or depth >= max_depth:
                r.saturated_irreducible.append((ws, we))
                r.stop_reason = "saturated_irreducible"
                return False
            mid = ws + span / 2
            if not await process(ws, mid, depth + 1):     # metade mais antiga primeiro
                return False
            return await process(mid, we, depth + 1)
        # nao saturado -> pagina a janela (fetch_fn retorna (items, pages, complete))
        items, pages, complete = await fetch_fn(ws, we)
        r.items.extend(items)
        r.pages += pages
        r.windows_done += 1
        if not complete:
            # janela nao paginou por completo (orcamento/limite) -> incompleta: NAO avanca watermark
            r.stop_reason = "fetch_truncated"
            return False
        r.watermark = we                                  # intervalo contiguo completo
        return True

    ok = await process(start, end, 0)
    if ok:
        r.complete = True
        r.stop_reason = "complete"
        r.watermark = end
    return r
