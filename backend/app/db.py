"""Pool assincrono PostgreSQL (asyncpg) para a camada Cyber (leitura do cadastro).

Principios:
  * NENHUMA conexao criada no import deste modulo (pool preguicoso).
  * init_pool()/close_pool() sao chamados no startup/shutdown do FastAPI (lifespan).
  * Banco indisponivel NAO derruba a aplicacao: init_pool loga um aviso e segue sem pool;
    o restante do backend (Redis, endpoints atuais) continua funcionando.
  * NUNCA loga o DSN nem credenciais (apenas o tipo da excecao).
  * Pool substituivel em testes via set_pool().

Este modulo e read-only nesta fase: nao grava nada nas tabelas Cyber.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

import asyncpg

from .config import settings

log = logging.getLogger("app.db")

# Estado do modulo. Sem conexao no import (fica None ate init_pool()).
_pool: Optional[asyncpg.Pool] = None


def get_pool() -> Optional[asyncpg.Pool]:
    """Retorna o pool atual ou None se ainda nao inicializado/indisponivel."""
    return _pool


def set_pool(pool: Optional[asyncpg.Pool]) -> None:
    """Substitui o pool (suporte a testes). Nao fecha o pool anterior."""
    global _pool
    _pool = pool


async def init_pool(
    dsn: Optional[str] = None,
    *,
    min_size: Optional[int] = None,
    max_size: Optional[int] = None,
    acquire_timeout: Optional[float] = None,
    connect_timeout: Optional[float] = None,
    command_timeout: Optional[float] = None,
) -> Optional[asyncpg.Pool]:
    """Cria o pool de conexoes. Idempotente (retorna o pool existente).

    Falha de forma segura: se o DSN estiver ausente ou o banco indisponivel/lento,
    retorna None e deixa o app seguir sem pool (o health check reportara o estado).
    """
    global _pool
    if _pool is not None:
        return _pool

    dsn = dsn if dsn is not None else settings.db_dsn
    if not dsn:
        log.warning("DB_DSN nao configurado; pool PostgreSQL NAO inicializado.")
        _pool = None
        return None

    min_size = settings.db_pool_min if min_size is None else min_size
    max_size = settings.db_pool_max if max_size is None else max_size
    acquire_timeout = settings.db_pool_acquire_timeout if acquire_timeout is None else acquire_timeout
    connect_timeout = settings.db_connect_timeout if connect_timeout is None else connect_timeout
    command_timeout = settings.db_command_timeout if command_timeout is None else command_timeout

    pool: Optional[asyncpg.Pool] = None
    try:
        # Vincula o objeto Pool ANTES de aguardar sua inicializacao: assim, se o
        # _initialize() do asyncpg falhar/estourar timeout depois de ja ter aberto
        # conexoes, o except consegue limpa-las (evita vazamento de conexoes).
        pool = asyncpg.create_pool(
            dsn=dsn,
            min_size=min_size,
            max_size=max_size,
            timeout=acquire_timeout,
            command_timeout=command_timeout,
        )
        # Inicializa o pool com teto de tempo para nao travar o startup.
        await asyncio.wait_for(pool, timeout=connect_timeout)
        # Valida conectividade sem propagar erro para o startup.
        async with pool.acquire() as conn:
            await conn.execute("SELECT 1")
        _pool = pool
        log.info("Pool PostgreSQL inicializado (min=%s max=%s).", min_size, max_size)
        return _pool
    except Exception as exc:  # noqa: BLE001 — falha-segura; NAO logar DSN/credenciais
        log.warning(
            "PostgreSQL indisponivel no startup (%s); seguindo sem pool.",
            type(exc).__name__,
        )
        if pool is not None:
            # terminate() e sincrono e seguro apos cancelamento (close() poderia travar).
            try:
                pool.terminate()
            except Exception:  # noqa: BLE001
                pass
        _pool = None
        return None


async def close_pool() -> None:
    """Fecha o pool no shutdown (se houver)."""
    global _pool
    if _pool is not None:
        pool, _pool = _pool, None
        try:
            await pool.close()
        except Exception as exc:  # noqa: BLE001
            log.warning("Falha ao fechar o pool PostgreSQL (%s).", type(exc).__name__)


async def check_health() -> str:
    """Estado do PostgreSQL para o health check: 'ok' | 'error' | 'unavailable'.

    'unavailable' = pool nao inicializado (banco fora no startup ou DSN ausente).
    'error'       = pool existe mas a consulta de sanidade falhou agora.
    """
    pool = _pool
    if pool is None:
        return "unavailable"

    async def _probe() -> None:
        async with pool.acquire() as conn:
            await conn.execute("SELECT 1")

    try:
        # Teto curto: um Postgres acessivel-porem-lento nao pode prolongar o /healthz
        # (probe de liveness) alem de poucos segundos nem arriscar restart do app.
        await asyncio.wait_for(_probe(), timeout=settings.db_healthcheck_timeout)
        return "ok"
    except Exception as exc:  # noqa: BLE001 — NAO logar DSN/credenciais
        log.warning("Health check PostgreSQL falhou (%s).", type(exc).__name__)
        return "error"
