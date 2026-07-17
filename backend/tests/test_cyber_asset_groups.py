"""Testes de app/cyber_asset_groups.py (Cyber Risk Subindexes por grupo de ativos / ASRM)."""
from app import cyber_asset_groups as mod
from app.cyber_tokens import TokenStatus
from tests.conftest import insert_fixture

SAMPLE = {"items": [
    {"name": "Global", "id": "g", "parent": None, "riskIndex": 48.5, "riskLevel": "medium",
     "assetCount": 4508, "updatedDateTime": "2026-07-17 16:52:56"},
    {"name": "SGGD", "id": "s", "parent": "g", "riskIndex": 44.8, "riskLevel": "medium",
     "assetCount": 100, "updatedDateTime": "2026-07-17 16:52:56"},
    {"name": "PGE", "id": "p", "parent": "g", "riskIndex": 0.0, "riskLevel": "low",
     "assetCount": 0, "updatedDateTime": "2026-07-17 16:52:56"},
]}


SAMPLE_POSTURE = {
    "riskIndex": 48.6,
    "riskCategoryLevel": {"exposure": "medium", "attack": "medium", "securityConfiguration": "low"},
    "cveManagementMetrics": {"count": 1292},
    "exposureStatus": {
        "unexpectedInternetFacingInterfaceStatus": {"publicIpCount": 12, "servicePortCount": 34},
        "insecureHostConnectionStatus": {"insecureHostCount": 5},
        "domainAccountMisconfigurationStatus": {"weakAuthenticationCount": 7},
        "cloudAssetMisconfigurationStatus": {"highRiskCount": 2},
    },
}


class FakeClient:
    def __init__(self, token, *a, **k):
        self.token = token

    async def get_json(self, path, **k):
        if path == mod.ASSET_GROUPS_PATH:
            return SAMPLE
        if path == mod.SECURITY_POSTURE_PATH:
            return SAMPLE_POSTURE
        raise AssertionError("path inesperado: " + path)

    async def aclose(self):
        pass


class FakeClientErr:
    def __init__(self, token, *a, **k):
        pass

    async def get_json(self, path, **k):
        raise RuntimeError("api boom")

    async def aclose(self):
        pass


class DictRedis:
    def __init__(self):
        self.store = {}

    async def get(self, k):
        return self.store.get(k)

    async def set(self, k, v, ex=None):
        self.store[k] = v


_ORGS = [("org-sggd", "sggd", "SGGD", 1, True, True)]
_CFG = [("sggd", "org-sggd", True, True, True, True)]


def test_normalize_flags_root_and_preserves_zero():
    g = mod.normalize(SAMPLE["items"])
    assert g[0]["isRoot"] is True and g[1]["isRoot"] is False
    assert g[1]["name"] == "SGGD" and g[1]["riskIndex"] == 44.8 and g[1]["assetCount"] == 100
    assert g[2]["riskIndex"] == 0.0 and g[2]["assetCount"] == 0   # 0 preservado, nao vira None


def test_parse_surface_maps_fields_and_handles_missing():
    s, lv = mod.parse_surface(SAMPLE_POSTURE)
    assert s["ports"] == 34 and s["insecure_hosts"] == 5 and s["cloud_high"] == 2
    assert lv["config"] == "low" and lv["exposure"] == "medium"
    s2, lv2 = mod.parse_surface({})
    assert s2["public_ip"] is None and lv2["exposure"] is None   # ausente -> None (nunca 0 fabricado)


async def test_pool_none_unavailable():
    out = await mod.get_asset_groups(None, None, "sggd")
    assert out["status"] == "unavailable" and out["reason"] == "db_down"


async def test_invalid_tenant(reg_pool):
    out = await mod.get_asset_groups(reg_pool, None, "naoexiste")
    assert out["status"] == "invalid"


async def test_no_token_unavailable(reg_pool, monkeypatch):
    await insert_fixture(reg_pool, tenants=[("sggd", "SGGD")], orgs=_ORGS, cfgs=_CFG)
    monkeypatch.setattr(mod, "resolve_token",
                        lambda tid, **k: TokenStatus(tid, False, "V1_API_TOKEN_SGGD", None))
    out = await mod.get_asset_groups(reg_pool, None, "sggd")
    assert out["status"] == "unavailable" and out["reason"] == "no_token" and out["tenantName"] == "SGGD"


async def test_api_error_unavailable(reg_pool, monkeypatch):
    await insert_fixture(reg_pool, tenants=[("sggd", "SGGD")], orgs=_ORGS, cfgs=_CFG)
    monkeypatch.setattr(mod, "resolve_token", lambda tid, **k: TokenStatus(tid, True, "V", "tok"))
    out = await mod.get_asset_groups(reg_pool, None, "sggd", client_factory=FakeClientErr)
    assert out["status"] == "unavailable" and out["reason"] == "api_error"


async def test_ok_and_cache_hit(reg_pool, monkeypatch):
    await insert_fixture(reg_pool, tenants=[("sggd", "SGGD")], orgs=_ORGS, cfgs=_CFG)
    monkeypatch.setattr(mod, "resolve_token", lambda tid, **k: TokenStatus(tid, True, "V", "tok"))
    redis = DictRedis()
    out = await mod.get_asset_groups(reg_pool, redis, "sggd", client_factory=FakeClient)
    assert out["status"] == "ok" and out["tenantName"] == "SGGD" and out["cached"] is False
    assert [g["name"] for g in out["groups"]] == ["Global", "SGGD", "PGE"]
    assert out["surface"]["public_ip"] == 12 and out["surface"]["cve_count"] == 1292   # superfície da org
    assert out["levels"]["exposure"] == "medium"
    # 2a chamada: cliente que explodiria; deve vir do cache (nao chama a API)
    out2 = await mod.get_asset_groups(reg_pool, redis, "sggd", client_factory=FakeClientErr)
    assert out2["status"] == "ok" and out2["cached"] is True
