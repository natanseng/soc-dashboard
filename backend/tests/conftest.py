"""Fixtures compartilhadas. Testes de integracao usam um banco TEMPORARIO
(criado a partir da migration real) e NUNCA tocam o banco socdash de producao."""
from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATION = REPO_ROOT / "infra" / "migrations" / "001_cyber_schema.sql"

# tabela base minima (equivalente ao init.sql) exigida pelas FKs da migration
_BASE_TENANT_DDL = (
    "CREATE TABLE tenant ("
    " tenant_id text PRIMARY KEY,"
    " display_name text NOT NULL,"
    " region_base text NOT NULL DEFAULT 'https://api.xdr.trendmicro.com',"
    " created_at timestamptz DEFAULT now());"
)


@pytest.fixture(autouse=True)
def reset_db_pool():
    """Garante isolamento: nenhum pool vaza entre testes."""
    from app import db
    db.set_pool(None)
    yield
    db.set_pool(None)


@pytest_asyncio.fixture
async def reg_pool():
    """Pool asyncpg contra um banco temporario com o schema REAL da migration.
    Pula automaticamente se o PostgreSQL nao estiver acessivel."""
    import asyncpg
    from app.config import settings

    if not settings.db_dsn:
        pytest.skip("DB_DSN nao configurado")
    dbname = "cyber_regtest_pytest"
    try:
        admin = await asyncpg.connect(dsn=settings.db_dsn, timeout=5)
    except Exception:
        pytest.skip("PostgreSQL indisponivel")
    try:
        await admin.execute(f'DROP DATABASE IF EXISTS {dbname} WITH (FORCE)')
        await admin.execute(f'CREATE DATABASE {dbname}')
    finally:
        await admin.close()

    setup = await asyncpg.connect(dsn=settings.db_dsn, database=dbname)
    try:
        await setup.execute(_BASE_TENANT_DDL)
        await setup.execute(MIGRATION.read_text(encoding="utf-8"))
    finally:
        await setup.close()

    pool = await asyncpg.create_pool(dsn=settings.db_dsn, database=dbname, min_size=1, max_size=2)
    try:
        yield pool
    finally:
        await pool.close()
        admin = await asyncpg.connect(dsn=settings.db_dsn)
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS {dbname} WITH (FORCE)')
        finally:
            await admin.close()


async def insert_fixture(pool, orgs, tenants, cfgs):
    """Insere linhas de teste (organization/tenant/cyber_tenant_config)."""
    async with pool.acquire() as c:
        for o in orgs:  # (org_id, name, display_order, enabled, cyber_enabled)
            await c.execute(
                "INSERT INTO organization (organization_id,name,display_order,enabled,cyber_enabled)"
                " VALUES ($1,$2,$3,$4,$5)", *o,
            )
        for t in tenants:  # (tenant_id, display_name)
            await c.execute("INSERT INTO tenant (tenant_id,display_name) VALUES ($1,$2)", *t)
        for cfg in cfgs:  # (tenant_id, org_id, cyber, oat, wb, so)
            await c.execute(
                "INSERT INTO cyber_tenant_config"
                " (tenant_id,organization_id,cyber_enabled,oat_enabled,workbench_enabled,suspicious_objects_enabled)"
                " VALUES ($1,$2,$3,$4,$5,$6)", *cfg,
            )
