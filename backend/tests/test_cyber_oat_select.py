"""Testes da selecao externa (§8) e enforcement (§9) do OAT."""
from collectors.cyber_oat_select import classify_enforcement, extract_external_indicators


def _ho(field, typ, value):
    return {"field": field, "type": typ, "value": value}


def _det(highlighted=None, detail=None):
    return {"uuid": "u", "detail": detail or {"source": "detections", "productCode": "pdi"},
            "filters": [{"highlightedObjects": highlighted or []}]}


def test_extract_attacker_peer_request_excludes_victim():
    det = _det([_ho("src", "ip", "8.8.8.8"), _ho("peerIp", "ip", "1.1.1.1"),
                _ho("request", "url", "http://evil.com/a"), _ho("interestedHost", "host", "victim.local")])
    inds, disc = extract_external_indicators(det)
    byrole = {(i.indicator_type, i.value_normalized): i.indicator_role for i in inds}
    assert byrole[("ip", "8.8.8.8")] == "attacker"
    assert byrole[("ip", "1.1.1.1")] == "peer"
    assert byrole[("url", "http://evil.com/a")] == "request"
    assert disc["role"] == 1
    assert not any(i.value_normalized == "victim.local" for i in inds)


def test_extract_denylisthost():
    det = _det([], detail={"source": "detections", "productCode": "pdi", "denyListHost": "bad.example.com"})
    inds, _ = extract_external_indicators(det)
    assert any(i.indicator_role == "c2" and i.value_normalized == "bad.example.com" for i in inds)


def test_extract_excludes_private_counts_nonpublic():
    det = _det([_ho("src", "ip", "10.0.0.1"), _ho("peerIp", "ip", "8.8.8.8")])
    inds, disc = extract_external_indicators(det)
    vals = {i.value_normalized for i in inds}
    assert "8.8.8.8" in vals and "10.0.0.1" not in vals and disc["non_public"] == 1


def test_extract_spgovbr_not_excluded():
    det = _det([_ho("peerHost", "host", "Portal.SP.gov.br")])
    inds, _ = extract_external_indicators(det)
    assert any(i.value_normalized == "portal.sp.gov.br" for i in inds)


def test_extract_ambiguity_counted_not_dropped_silently():
    det = _det([_ho("weirdField", "ip", "8.8.8.8")])
    inds, disc = extract_external_indicators(det)
    assert inds == [] and disc["ambiguity"] == 1


def test_extract_dedup():
    det = _det([_ho("src", "ip", "8.8.8.8"), _ho("src", "ip", "8.8.8.8")])
    inds, _ = extract_external_indicators(det)
    assert len(inds) == 1


def test_enforcement_prevented_variants():
    for act in (["Reset"], ["Quarantine"], ["Deny"], ["Block"]):
        s, _, _ = classify_enforcement(_det(detail={"source": "detections", "act": act}))
        assert s == "prevented_confirmed", act


def test_enforcement_allowed():
    s, _, _ = classify_enforcement(_det(detail={"source": "detections", "act": ["Pass"]}))
    assert s == "allowed_confirmed"


def test_enforcement_not_prevented():
    s, _, _ = classify_enforcement(_det(detail={"source": "detections", "act": ["not blocked"]}))
    assert s == "observed_not_prevented"


def test_enforcement_observed_detection_only_no_act():
    s, _, _ = classify_enforcement(_det(detail={"source": "endpointActivityData"}))
    assert s == "observed"


def test_enforcement_unknown_no_act_on_detections():
    s, _, _ = classify_enforcement(_det(detail={"source": "detections"}))
    assert s == "unknown"


def test_enforcement_empty_detail_act_falls_to_highlighted():
    det = {"detail": {"source": "detections", "act": []},
           "filters": [{"highlightedObjects": [{"field": "act", "type": "text", "value": "Reset"}]}]}
    s, af, _ = classify_enforcement(det)
    assert s == "prevented_confirmed" and af == "act"


def test_infer_type_request_case_insensitive():
    det = _det([_ho("Request", "url", "http://evil.com/x")])
    inds, _ = extract_external_indicators(det)
    assert any(i.indicator_type == "url" and i.value_normalized == "http://evil.com/x" for i in inds)


def test_enforcement_act_from_highlighted_object():
    det = {"detail": {"source": "detections"},
           "filters": [{"highlightedObjects": [{"field": "act", "type": "text", "value": "Reset"}]}]}
    s, af, av = classify_enforcement(det)
    assert s == "prevented_confirmed" and af == "act" and av == "Reset"
