"""Testes do scheduler Cyber (collectors/cyber_scheduler.py) — §22."""
import asyncio

from collectors import cyber_scheduler as sch
from collectors.cyber_scheduler import build_scheduler, enabled_tenants, guarded
from tests.conftest import insert_fixture


async def test_guarded_skips_when_running():
    calls = {"n": 0}

    async def slow():
        calls["n"] += 1
        await asyncio.sleep(0.2)

    t1 = asyncio.create_task(guarded(("x",), slow))
    await asyncio.sleep(0.05)
    await guarded(("x",), slow)   # ciclo ativo -> skipped_running
    await t1
    assert calls["n"] == 1


async def test_guarded_runs_after_release():
    calls = {"n": 0}

    async def f():
        calls["n"] += 1

    await guarded(("y",), f)
    await guarded(("y",), f)
    assert calls["n"] == 2


def test_build_scheduler_has_all_jobs():
    s = build_scheduler(object())
    assert {j.id for j in s.get_jobs()} == {"oat", "wb", "so", "geo", "capability", "retention"}


async def test_enabled_tenants_skips_without_token(reg_pool, monkeypatch):
    await insert_fixture(reg_pool, tenants=[("prodesp-sp", "Prodesp"), ("iamspe-sp", "Iamspe")],
                         orgs=[("org-prodesp", "prodesp-sp", "Prodesp", 1, True, True),
                               ("org-iamspe", "iamspe-sp", "Iamspe", 1, True, True)],
                         cfgs=[("prodesp-sp", "org-prodesp", True, True, True, True),
                               ("iamspe-sp", "org-iamspe", True, True, True, True)])
    from app.cyber_tokens import TokenStatus

    def fake_resolve(tid, **k):
        ok = tid == "prodesp-sp"
        return TokenStatus(tid, ok, "V", "tok" if ok else None)

    monkeypatch.setattr(sch, "resolve_token", fake_resolve)
    ids = [t for t, _ in await enabled_tenants(reg_pool)]
    assert ids == ["prodesp-sp"]   # iamspe sem token e pulado
