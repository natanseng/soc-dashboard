"""Cliente HTTP do Trend Vision One v3.0: auth Bearer, paginação nextLink, backoff em 429."""
import asyncio
import httpx

from .config import settings


class VisionOneClient:
    def __init__(self, api_key: str, base: str | None = None):
        self._base = base or settings.v1_api_base
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json;charset=utf-8",
        }
        self._client = httpx.AsyncClient(base_url=self._base, headers=self._headers, timeout=60)

    async def get_json(self, path: str, params=None, extra_headers=None, max_retries: int = 5, timeout=None):
        """GET com tratamento de rate limit (429) e backoff exponencial."""
        headers = dict(extra_headers or {})
        attempt = 0
        while True:
            _kw = {} if timeout is None else {"timeout": timeout}
            r = await self._client.get(path, params=params, headers=headers, **_kw)
            if r.status_code == 429:
                attempt += 1
                if attempt > max_retries:
                    r.raise_for_status()
                wait = int(r.headers.get("Retry-After", 2 ** attempt))
                await asyncio.sleep(wait)
                continue
            r.raise_for_status()
            return r.json()

    async def get_paginated(self, path: str, params=None, extra_headers=None, limit: int = 10_000, timeout=None):
        """Segue nextLink até esgotar ou atingir 'limit' itens."""
        items, url, p = [], path, params
        while url and len(items) < limit:
            data = await self.get_json(url, params=p, extra_headers=extra_headers, timeout=timeout)
            items.extend(data.get("items", []))
            url = data.get("nextLink")  # URL absoluta -> não reenviar params
            p = None
            if url:
                url = url.replace(str(self._client.base_url), "")
        return items[:limit]

    async def aclose(self):
        await self._client.aclose()
