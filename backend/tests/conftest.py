"""Fixtures compartilhadas. Testes de integracao usam um banco TEMPORARIO
(criado a partir das migrations reais 001+002) e NUNCA tocam o banco socdash de producao."""
from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_001 = REPO_ROOT / "infra" / "migrations" / "001_cyber_schema.sql"
MIGRATION_002 = REPO_ROOT / "infra" / "migrations" / "002_cyber_tenant_organizations.sql"
MIGRATION_003 = REPO_ROOT / "infra" / "migrations" / "003_cyber_attribution_policy.sql"
MIGRATION_004 = REPO_ROOT / "infra" / "migrations" / "004_cyber_attribution_audit.sql"

_BASE_TENANT_DDL = (
    "CREATE TABLE tenant ("
    " tenant_id text PRIMARY KEY,"
    " display_name text NOT NULL,"
    " region_base text NOT NULL DEFAULT 'https://api.xdr.trendmicro.com',"
    " created_at timestamptz DEFAULT now());"
)


@pytest.fixture(autouse=True)
def reset_db_pool():
    from app import db
    db.set_pool(None)
    yield
    db.set_pool(None)


@pytest_asyncio.fixture
async def reg_pool():
    """Pool asyncpg contra um banco temporario com o schema REAL (migrations 001 + 002).
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
        await setup.execute(MIGRATION_001.read_text(encoding="utf-8"))
        await setup.execute(MIGRATION_002.read_text(encoding="utf-8"))
        await setup.execute(MIGRATION_003.read_text(encoding="utf-8"))
        await setup.execute(MIGRATION_004.read_text(encoding="utf-8"))
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


async def insert_fixture(pool, tenants, orgs, cfgs):
    """Insere linhas de teste na ordem correta de FK: tenant -> organization -> cyber_tenant_config.

    tenants: (tenant_id, display_name)
    orgs:    (organization_id, tenant_id, name, display_order, enabled, cyber_enabled)
    cfgs:    (tenant_id, legacy_org_id, cyber_enabled, oat, wb, so)  [enabled default=true]
    """
    async with pool.acquire() as c:
        for t in tenants:
            await c.execute("INSERT INTO tenant (tenant_id, display_name) VALUES ($1,$2)", *t)
        for o in orgs:
            await c.execute(
                "INSERT INTO organization"
                " (organization_id, tenant_id, name, display_order, enabled, cyber_enabled)"
                " VALUES ($1,$2,$3,$4,$5,$6)", *o,
            )
        for cfg in cfgs:
            await c.execute(
                "INSERT INTO cyber_tenant_config"
                " (tenant_id, organization_id, cyber_enabled, oat_enabled, workbench_enabled, suspicious_objects_enabled)"
                " VALUES ($1,$2,$3,$4,$5,$6)", *cfg,
            )
