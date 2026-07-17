"""Testes da camada de conexao PostgreSQL (app/db.py).

Os fakes mimetizam o asyncpg real: create_pool() e SINCRONO e retorna um Pool AWAITABLE
(o await inicializa). Assim o caminho de producao (vincular antes de aguardar + terminate
na falha) e realmente exercitado.
"""
import asyncio
import logging
import subprocess
import sys
from pathlib import Path

import asyncpg
import pytest

from app import db
from app.config import settings
from tests.fakes import FakePool

BACKEND = Path(__file__).resolve().parents[1]


def _factory(pool):
    def create_pool(**kwargs):  # sincrono, como o asyncpg real
        return pool
    return create_pool


async def test_pool_created_and_closed(monkeypatch):
    fake = FakePool()
    monkeypatch.setattr(asyncpg, "create_pool", _factory(fake))
    pool = await db.init_pool(dsn="postgresql://u:p@h:5432/db")
    assert pool is fake and db.get_pool() is fake
    await db.close_pool()
    assert fake.closed is True and db.get_pool() is None


async def test_init_is_idempotent(monkeypatch):
    fake = FakePool()
    calls = {"n": 0}

    def create_pool(**kwargs):
        calls["n"] += 1
        return fake

    monkeypatch.setattr(asyncpg, "create_pool", create_pool)
    await db.init_pool(dsn="postgresql://u:p@h/db")
    await db.init_pool(dsn="postgresql://u:p@h/db")
    assert calls["n"] == 1


async def test_forwards_explicit_params_to_create_pool(monkeypatch):
    fake = FakePool()
    captured = {}

    def create_pool(**kwargs):
        captured.update(kwargs)
        return fake

    monkeypatch.setattr(asyncpg, "create_pool", create_pool)
    await db.init_pool(
        dsn="postgresql://u:p@h/db",
        min_size=2, max_size=7, acquire_timeout=3.0, command_timeout=4.0, connect_timeout=5.0,
    )
    assert captured["min_size"] == 2 and captured["max_size"] == 7
    assert captured["timeout"] == 3.0 and captured["command_timeout"] == 4.0


async def test_defaults_come_from_settings(monkeypatch):
    fake = FakePool()
    captured = {}

    def create_pool(**kwargs):
        captured.update(kwargs)
        return fake

    monkeypatch.setattr(asyncpg, "create_pool", create_pool)
    await db.init_pool(dsn="postgresql://u:p@h/db")
    assert captured["min_size"] == settings.db_pool_min
    assert captured["max_size"] == settings.db_pool_max
    assert captured["timeout"] == settings.db_pool_acquire_timeout
    assert captured["command_timeout"] == settings.db_command_timeout


async def test_missing_dsn_returns_none():
    assert await db.init_pool(dsn="") is None
    assert db.get_pool() is None


async def test_create_pool_raises_sync_is_safe(monkeypatch):
    def create_pool(**kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(asyncpg, "create_pool", create_pool)
    assert await db.init_pool(dsn="postgresql://u:p@h/db") is None
    assert db.get_pool() is None


async def test_error_during_init_terminates_pool(monkeypatch):
    fake = FakePool(init_error=OSError("mid-init failure"))
    monkeypatch.setattr(asyncpg, "create_pool", _factory(fake))
    pool = await db.init_pool(dsn="postgresql://u:p@h/db")
    assert pool is None and db.get_pool() is None
    assert fake.terminated is True  # conexoes parciais foram limpas (sem vazamento)


async def test_connect_timeout_bounded_and_terminates(monkeypatch):
    fake = FakePool(init_delay=1.0)
    monkeypatch.setattr(asyncpg, "create_pool", _factory(fake))
    pool = await db.init_pool(dsn="postgresql://u:p@h/db", connect_timeout=0.05)
    assert pool is None and db.get_pool() is None
    assert fake.terminated is True  # pool parcialmente inicializado foi limpo no timeout


async def test_no_credentials_in_logs(monkeypatch, caplog):
    def create_pool(**kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(asyncpg, "create_pool", create_pool)
    secret = "postgresql://socdash:SUPER_SECRET_PW@localhost:5432/socdash"
    with caplog.at_level(logging.DEBUG):
        await db.init_pool(dsn=secret)
    assert "SUPER_SECRET_PW" not in caplog.text
    assert secret not in caplog.text


async def test_check_health_unavailable_when_no_pool():
    db.set_pool(None)
    assert await db.check_health() == "unavailable"


async def test_check_health_ok():
    db.set_pool(FakePool())
    assert await db.check_health() == "ok"


async def test_check_health_error_when_query_fails():
    db.set_pool(FakePool(raise_on="execute"))
    assert await db.check_health() == "error"


def test_no_pool_creation_at_import():
    """Em um processo LIMPO, importar app.db nao pode chamar create_pool nem criar pool."""
    code = (
        "import asyncpg\n"
        "calls={'n':0}\n"
        "asyncpg.create_pool=lambda **k: calls.__setitem__('n', calls['n']+1)\n"
        "import app.db as d\n"
        "assert calls['n']==0, 'create_pool chamado durante o import'\n"
        "assert d.get_pool() is None, 'pool criado durante o import'\n"
        "print('IMPORT_OK')\n"
    )
    r = subprocess.run([sys.executable, "-c", code], cwd=str(BACKEND),
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "IMPORT_OK" in r.stdout


async def test_init_pool_real_db_smoke():
    """Caminho de PRODUCAO contra o banco real (read-only: SELECT 1). Pula se indisponivel."""
    if not settings.db_dsn:
        pytest.skip("DB_DSN nao configurado")
    db.set_pool(None)
    pool = await db.init_pool()
    if pool is None:
        pytest.skip("PostgreSQL indisponivel")
    try:
        assert await db.check_health() == "ok"
    finally:
        await db.close_pool()
    assert db.get_pool() is None
