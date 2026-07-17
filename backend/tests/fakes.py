"""Dublês (fakes) sem I/O real, reutilizados pelos testes unitarios."""
from __future__ import annotations

import asyncio


class FakeConn:
    def __init__(self, *, rows=None, raise_on=None):
        self._rows = rows or []
        self._raise_on = raise_on  # 'execute' | 'fetch' | None

    async def execute(self, query, *args):
        if self._raise_on == "execute":
            raise RuntimeError("boom-execute")
        return "OK"

    async def fetch(self, query, *args):
        if self._raise_on == "fetch":
            raise RuntimeError("boom-fetch")
        return self._rows


class _Acquire:
    def __init__(self, conn):
        self._conn = conn

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, *exc):
        return False


class FakePool:
    """Mimetiza asyncpg.Pool: criado de forma sincrona e AWAITABLE (o await inicializa).

    init_error/init_delay simulam falha/lentidao durante a inicializacao para testar a
    limpeza (terminate) no init_pool.
    """
    def __init__(self, *, rows=None, raise_on=None, init_error=None, init_delay=0.0):
        self.conn = FakeConn(rows=rows, raise_on=raise_on)
        self.closed = False
        self.terminated = False
        self._init_error = init_error
        self._init_delay = init_delay

    async def _ainit(self):
        if self._init_delay:
            await asyncio.sleep(self._init_delay)
        if self._init_error is not None:
            raise self._init_error
        return self

    def __await__(self):
        return self._ainit().__await__()

    def acquire(self):
        return _Acquire(self.conn)

    async def close(self):
        self.closed = True

    def terminate(self):
        self.terminated = True


class FakeRedis:
    def __init__(self, ping_ok=True):
        self._ping_ok = ping_ok
        self.closed = False

    async def ping(self):
        if self._ping_ok:
            return True
        raise RuntimeError("redis down")

    async def aclose(self):
        self.closed = True
