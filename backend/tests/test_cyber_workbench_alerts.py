"""Testes do coletor de inventario de workbenches + regras MTTD/MTTR (vision-one-soc-dashboard)."""
from datetime import datetime, timezone

from collectors import cyber_workbench_alerts as wa


def _dt(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _alert(**kw):
    a = {"id": "WB-1", "createdDateTime": "2026-07-20T00:01:40Z", "updatedDateTime": "2026-07-20T00:01:40Z"}
    a.update(kw)
    return a


# ---------- MTTD (detect_seconds) ----------
def test_detect_preset_uses_first_oat():
    created = _dt("2026-07-20T00:01:40Z")
    # matched 00:00:40 e 00:01:10 -> preset usa o 1o (00:00:40) -> 60s
    assert wa._detect_seconds(created, "preset", _dt("2026-07-20T00:00:40Z"), _dt("2026-07-20T00:01:10Z")) == 60.0


def test_detect_custom_uses_last_oat():
    created = _dt("2026-07-20T00:01:40Z")
    # custom usa o ultimo (00:01:10) -> 30s
    assert wa._detect_seconds(created, "custom", _dt("2026-07-20T00:00:40Z"), _dt("2026-07-20T00:01:10Z")) == 30.0


def test_detect_negative_is_none():
    created = _dt("2026-07-20T00:00:00Z")
    assert wa._detect_seconds(created, "preset", _dt("2026-07-20T00:05:00Z"), _dt("2026-07-20T00:05:00Z")) is None


def test_detect_no_oat_is_none():
    assert wa._detect_seconds(_dt("2026-07-20T00:01:40Z"), "custom", None, None) is None


# ---------- MTTR (resolve_seconds) ----------
def test_resolve_only_closed():
    c, u = _dt("2026-07-20T00:00:00Z"), _dt("2026-07-20T01:00:00Z")
    assert wa._resolve_seconds("Closed", c, u) == 3600.0
    assert wa._resolve_seconds("Open", c, u) is None
    assert wa._resolve_seconds("In Progress", c, u) is None


def test_resolve_negative_is_none():
    c, u = _dt("2026-07-20T01:00:00Z"), _dt("2026-07-20T00:00:00Z")
    assert wa._resolve_seconds("Closed", c, u) is None


# ---------- matchedDateTime de filters E events ----------
def test_matched_times_from_filters_and_events():
    alert = _alert(matchedRules=[{
        "matchedFilters": [{"matchedDateTime": "2026-07-20T00:00:40Z"}],
        "matchedEvents": [{"matchedDateTime": "2026-07-20T00:01:10Z"}]}])
    ts = wa._matched_times(alert)
    assert len(ts) == 2 and min(ts) == _dt("2026-07-20T00:00:40Z") and max(ts) == _dt("2026-07-20T00:01:10Z")


# ---------- build_alert_row (atribuicao single_org + campos) ----------
def test_build_alert_row_single_org():
    ctx = ("single_org", ["org-x"], {})
    alert = _alert(severity="high", status="Closed", modelType="custom", investigationStatus="True Positive",
                   updatedDateTime="2026-07-20T00:31:40Z",
                   matchedRules=[{"matchedFilters": [{"matchedDateTime": "2026-07-20T00:00:40Z"},
                                                      {"matchedDateTime": "2026-07-20T00:01:10Z"}]}])
    r = wa.build_alert_row(alert, ctx)
    assert r["alert_id"] == "WB-1" and r["severity"] == "high" and r["status"] == "Closed"
    assert r["model_type"] == "custom" and r["oat_count"] == 2
    assert r["detect_seconds"] == 30.0            # custom -> ultimo OAT (00:01:10 -> 30s)
    assert r["resolve_seconds"] == 1800.0         # Closed -> 30min
    assert r["attr_status"] == "attributed" and r["organization_id"] == "org-x"


def test_build_alert_row_missing_fields():
    assert wa.build_alert_row({"id": None, "createdDateTime": "2026-07-20T00:00:00Z"}, ("single_org", ["o"], {})) is None
    assert wa.build_alert_row({"id": "WB-2", "createdDateTime": None}, ("single_org", ["o"], {})) is None
