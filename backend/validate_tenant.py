#!/usr/bin/env python3
"""Validação do tenant atual (lido do .env).

PARTE A — panorama painel-a-painel do /overview (dados já processados pelo coletor).
PARTE B — sondagem crua de cada endpoint da API v3.0 (status HTTP por endpoint),
          incluindo endpointSecurity/endpoints (que no TM-LAR retornava 400).

Uso:  cd ~/projetos/soc-dashboard/backend && source .venv/bin/activate && python validate_tenant.py
"""
import json
import sys
import urllib.request

import httpx

from app.config import settings

TENANT = settings.tenant
BASE = settings.v1_api_base
TOK = settings.v1_api_token


def line():
    print("─" * 70)


print()
line()
print(f"  Tenant (key) : {TENANT}")
print(f"  API base     : {BASE}")
print(f"  Token        : {'definido (' + str(len(TOK)) + ' chars)' if TOK else 'VAZIO ❌'}")
line()

# ───────────────────────── PARTE A — /overview ─────────────────────────
print("\nPARTE A — /overview (dados processados pelo coletor)\n")
try:
    with urllib.request.urlopen(f"http://localhost:8000/api/{TENANT}/overview", timeout=30) as resp:
        d = json.load(resp)
    json.dump(d, open("/tmp/overview_prodesp.json", "w"), ensure_ascii=False, indent=2)
except Exception as e:  # noqa: BLE001
    print("❌ não consegui ler /overview (uvicorn no ar? coletor já rodou?):", e)
    sys.exit(1)

gaps = []
empties = []


def cut(x, n=150):
    s = str(x)
    return s if len(s) <= n else s[:n] + "…"


def panel(name, ok, detail, soft_empty=False):
    tag = "OK " if ok else ("·· " if soft_empty else "GAP")
    print(f"  [{tag}] {name}: {detail}")
    if not ok and not soft_empty:
        gaps.append(name)
    if not ok and soft_empty:
        empties.append(name)


po = d.get("posture", {})
panel("Security Posture", bool(po), f"riskIndex={po.get('riskIndex')} | campos={list(po)[:8]}")
wb = d.get("workbench", {})
panel("Workbench Alerts", bool(wb), cut(dict(list(wb.items())[:8])))
ev = d.get("events", {})
panel("Event Tallies 24h/7d/30d", bool(ev), cut(dict(list(ev.items())[:8])))
su = d.get("surface", {})
panel("Attack Surface", bool(su), cut(dict(list(su.items())[:8])))
vu = d.get("vuln", {})
panel("Vulnerabilities", bool(vu), cut(vu))
mi = d.get("mitre", {})
n_mi = len(mi.get("tactics", [])) if isinstance(mi, dict) else (len(mi) if isinstance(mi, list) else 0)
panel("MITRE ATT&CK", bool(mi), f"{n_mi} táticas | {cut(list(mi)[:6] if isinstance(mi, dict) else mi, 80)}")
fe = d.get("feed", [])
panel("Live Detections (OAT)", len(fe) > 0, f"{len(fe)} itens", soft_empty=(len(fe) == 0))
tr = d.get("trend", [])
panel("Threat Trend", len(tr) > 0, f"{len(tr)} buckets", soft_empty=(len(tr) == 0))
idn = d.get("identity", {})
panel("Identity Security", bool(idn), cut(idn))
io = d.get("ioc", {})
panel("Suspicious Objects (IOCs)", bool(io),
      f"total={io.get('total')} | tipos={cut(io.get('byType'), 70)} | geo={len(io.get('geo', []))} | países={cut(io.get('byCountry'), 60)}",
      soft_empty=(isinstance(io, dict) and io.get("total") in (0, None)))
ri = d.get("risk", [])
panel("Risk Indicators", len(ri) > 0, f"{len(ri)} itens", soft_empty=(len(ri) == 0))

# ───────────────────────── PARTE B — endpoints crus ─────────────────────────
print("\nPARTE B — sondagem crua dos endpoints v3.0 (status HTTP por endpoint)\n")
probes = [
    ("workbench/alerts", "/v3.0/workbench/alerts", {"top": "1"}),
    ("oat/detections", "/v3.0/oat/detections", {"top": "1"}),
    ("asrm/securityPosture", "/v3.0/asrm/securityPosture", {}),
    ("asrm/attackSurfaceDevices", "/v3.0/asrm/attackSurfaceDevices", {"top": "10"}),
    ("threatintel/suspiciousObjects", "/v3.0/threatintel/suspiciousObjects", {"top": "50"}),
    ("endpointSecurity/endpoints  ⟵ faltava no TM-LAR", "/v3.0/endpointSecurity/endpoints", {"top": "50"}),
    ("search/networkActivities    ⟵ faltava no TM-LAR", "/v3.0/search/networkActivities", {"top": "10"}),
]
hdr = {"Authorization": f"Bearer {TOK}"}
if not TOK:
    print("  (sem token — pulei a Parte B)")
else:
    with httpx.Client(base_url=BASE, headers=hdr, timeout=25) as c:
        for name, path, params in probes:
            try:
                r = c.get(path, params=params)
                extra = ""
                if r.status_code == 200:
                    try:
                        j = r.json()
                        if isinstance(j, dict):
                            tc = j.get("totalCount")
                            items = j.get("items", [])
                            extra = f"  ✓ totalCount={tc} items={len(items) if isinstance(items, list) else '?'}"
                    except Exception:  # noqa: BLE001
                        extra = "  ✓ (corpo não-JSON)"
                else:
                    try:
                        extra = "  → " + cut(r.json(), 130)
                    except Exception:  # noqa: BLE001
                        extra = "  → " + cut(r.text, 130)
                print(f"  HTTP {r.status_code}  {name}{extra}")
            except Exception as e:  # noqa: BLE001
                print(f"  ERRO   {name}: {type(e).__name__} {e}")

# ───────────────────────── Resumo ─────────────────────────
line()
if gaps:
    print(f"⚠️  GAPS (painel vazio/ausente — investigar escopo do token ou endpoint): {', '.join(gaps)}")
if empties:
    print(f"··  Vazios aceitáveis (podem ser 0 legítimo num tenant tranquilo): {', '.join(empties)}")
if not gaps and not empties:
    print("✅ /overview: todos os painéis com dados reais.")
print("   JSON completo do /overview salvo em /tmp/overview_prodesp.json")
line()
