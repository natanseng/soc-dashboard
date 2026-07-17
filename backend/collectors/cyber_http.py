"""Cliente HTTP robusto para os coletores Cyber (isolado do cliente/coletor da Fase 1).

Recursos: auth Bearer, timeout, retry com backoff exponencial + JITTER, Retry-After em 429,
retry em 5xx/timeout/erros de rede, paginacao por nextLink com LOOP-GUARD (detecta nextLink
repetido) e orcamentos de paginas/itens. NAO altera o cliente da Fase 1 (app/vision_one.py).
"""
from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from typing import Optional

import httpx

from app.config import settings


@dataclass
class PageResult:
    items: list = field(default_factory=list)
    pages: int = 0
    total_count: Optional[int] = None
    truncated: bool = False
    stop_reason: str = "complete"   # complete | loop_detected | page_budget | item_budget | error


class CyberClient:
    def __init__(self, token: str, base: Optional[str] = None, timeout: float = 60.0):
        self._client = httpx.AsyncClient(
            base_url=base or settings.v1_api_base,
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json;charset=utf-8"},
            timeout=timeout,
        )

    async def aclose(self):
        await self._client.aclose()

    async def get_json(self, path, params=None, extra_headers=None, *, max_retries: int = 5,
                       timeout=None, base_backoff: float = 1.0, max_backoff: float = 30.0) -> dict:
        headers = dict(extra_headers or {})
        attempt = 0
        while True:
            try:
                kw = {} if timeout is None else {"timeout": timeout}
                r = await self._client.get(path, params=params, headers=headers, **kw)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                attempt += 1
                if attempt > max_retries:
                    raise
                await asyncio.sleep(self._delay(attempt, base_backoff, max_backoff))
                continue
            if r.status_code == 429 or 500 <= r.status_code < 600:
                attempt += 1
                if attempt > max_retries:
                    r.raise_for_status()
                ra = r.headers.get("Retry-After")
                wait = float(ra) if (ra and ra.isdigit()) else self._delay(attempt, base_backoff, max_backoff)
                await asyncio.sleep(wait)
                continue
            r.raise_for_status()   # 4xx (exceto 429) -> erro imediato
            return r.json()

    @staticmethod
    def _delay(attempt: int, base: float, cap: float) -> float:
        return min(cap, base * (2 ** (attempt - 1))) + random.uniform(0, base)

    async def paginate(self, path, params=None, extra_headers=None, *, item_cap: int = 1_000_000,
                       page_cap: int = 10_000, timeout=None) -> PageResult:
        """Segue nextLink ate esgotar, com loop-guard (nextLink repetido) e orcamentos."""
        res = PageResult()
        url, p, seen = path, params, set()
        while url:
            if res.pages >= page_cap:
                res.truncated = True; res.stop_reason = "page_budget"; break
            data = await self.get_json(url, params=p, extra_headers=extra_headers, timeout=timeout)
            res.pages += 1
            if res.total_count is None and isinstance(data.get("totalCount"), int):
                res.total_count = data["totalCount"]
            res.items.extend(data.get("items", []) or [])
            if len(res.items) >= item_cap:
                res.items = res.items[:item_cap]; res.truncated = True; res.stop_reason = "item_budget"; break
            nxt = data.get("nextLink")
            if not nxt:
                break
            nxt = nxt.replace(str(self._client.base_url), "")
            if nxt in seen:                       # loop-guard: nextLink repetido
                res.truncated = True; res.stop_reason = "loop_detected"; break
            seen.add(nxt)
            url, p = nxt, None
        return res
