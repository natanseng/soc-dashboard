"""Testes do coletor OAT (collectors/cyber_oat.py): build_observations (puro) + persistencia."""
from collectors.cyber_oat import _persist_obs, build_observations
from tests.conftest import insert_fixture


def _ctx(mode="single_org", orgs=("org-a",), mappings=None, so_block=frozenset()):
    return (mode, list(orgs), mappings or {}, set(so_block))


def _ho(field, typ, value):
    return {"field": field, "type": typ, "value": value}


def _det(uuid="u1", src="detections", prod="pdi", act=None, highlighted=None,
         dt="2026-07-17T10:00:00Z", ids=None):
    detail = {"source": src, "productCode": prod}
    if act is not None:
        detail["act"] = act
    if ids:
        detail.update(ids)
    return {"uuid": uuid, "detectionTime": dt, "ingestedDateTime": dt, "detail": detail,
            "filters": [{"highlightedObjects": highlighted or []}]}


def test_build_obs_external_attributed_single_org():
    det = _det(highlighted=[_ho("src", "ip", "8.8.8.8")], act=["Reset"])
    obs, _ = build_observations(det, "high", _ctx("single_org", ["org-a"]))
    assert len(obs) == 1
    o = obs[0]
    assert o["indicator_type"] == "ip" and o["value_normalized"] == "8.8.8.8"
    assert o["enforcement_status"] == "prevented_confirmed"
    assert o["organization_id"] == "org-a" and o["attr_status"] == "attributed" and o["attr_method"] == "single_org"
    assert o["source_event_id"] == "u1" and o["severity"] == "high"


def test_build_obs_sggd_instance_pending():
    det = _det(highlighted=[_ho("peerIp", "ip", "1.1.1.1")], ids={"managementScopeInstanceId": "sep-x"})
    obs, _ = build_observations(det, "high", _ctx("instance", ["org-sggd", "org-pge"], mappings={}))
    o = obs[0]
    assert o["organization_id"] is None
    assert o["attr_status"] == "unassigned" and o["attr_method"] == "instance_mapping_pending"
    assert "managementScopeInstanceId" in o["attribution_identifiers"]


def test_build_obs_block_policy_matched_never_prevented():
    det = _det(highlighted=[_ho("src", "ip", "8.8.8.8")])   # sem act
    obs, _ = build_observations(det, "high", _ctx("single_org", ["org-a"], so_block={("ip", "8.8.8.8")}))
    o = obs[0]
    assert o["block_policy_matched"] is True and o["policy_match_basis"] == "current_state"
    assert o["enforcement_status"] == "unknown"   # SO nunca vira prevented_confirmed


def test_build_obs_no_external_yields_nothing():
    det = _det(highlighted=[_ho("interestedHost", "host", "victim.local")])
    obs, disc = build_observations(det, "high", _ctx())
    assert obs == [] and disc["role"] >= 1


def test_build_obs_missing_key_fields():
    det = {"detail": {"source": "detections"},
           "filters": [{"highlightedObjects": [_ho("src", "ip", "8.8.8.8")]}]}  # sem uuid/detectionTime
    obs, disc = build_observations(det, "high", _ctx())
    assert obs == [] and disc["missing_key_fields"] == 1


def test_build_obs_multiple_indicators_same_uuid():
    det = _det(highlighted=[_ho("src", "ip", "8.8.8.8"), _ho("peerHost", "host", "bad.example.com")], act=["Pass"])
    obs, _ = build_observations(det, "critical", _ctx())
    assert len(obs) == 2 and {o["source_event_id"] for o in obs} == {"u1"}
    assert all(o["enforcement_status"] == "allowed_confirmed" for o in obs)


async def test_persist_oat_idempotent(reg_pool):
    await insert_fixture(reg_pool, tenants=[("prodesp-sp", "Prodesp")],
                         orgs=[("org-prodesp", "prodesp-sp", "Prodesp", 1, True, True)],
                         cfgs=[("prodesp-sp", "org-prodesp", True, True, True, True)])
    det = _det(highlighted=[_ho("src", "ip", "8.8.8.8")], act=["Reset"])
    obs, _ = build_observations(det, "high", _ctx("single_org", ["org-prodesp"]))
    async with reg_pool.acquire() as c:
        async with c.transaction():
            r1 = await _persist_obs(c, "prodesp-sp", obs[0])
        async with c.transaction():
            r2 = await _persist_obs(c, "prodesp-sp", obs[0])
    assert r1 == "inserted" and r2 == "duplicate"
    async with reg_pool.acquire() as c:
        cnt = await c.fetchval("SELECT count(*) FROM cyber_oat_observation WHERE tenant_id='prodesp-sp'")
        row = await c.fetchrow("SELECT organization_id, organization_attribution_status, enforcement_status, "
                               "block_policy_matched FROM cyber_oat_observation WHERE tenant_id='prodesp-sp'")
    assert cnt == 1 and row["organization_id"] == "org-prodesp"
    assert row["organization_attribution_status"] == "attributed" and row["enforcement_status"] == "prevented_confirmed"
