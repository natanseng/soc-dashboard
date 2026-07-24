"""Coletores por tier — cada função consome um endpoint do Vision One.

Os erros são tratados no scheduler (collectors/run.py): se um endpoint falhar
(ASRM sem créditos CREM, um filtro inexistente no tenant, rede, etc.), o tier é
logado e o restante continua. O backend nunca cai por causa de uma coleta isolada.

NOTA: as chamadas à API real do Vision One não são testáveis fora do tenant.
Por isso os coletores "extra" (attack surface, eventos, risk) são defensivos —
cada bloco opcional é best-effort e devolve None/[] em vez de estourar.
"""
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
import asyncio
import ipaddress
import logging
import re
import socket

from app import geo
from app.vision_one import VisionOneClient

log = logging.getLogger("collector")


def diag(exc: Exception) -> str:
    """Status + innererror.code + mensagem + TraceId de um erro httpx (p/ logs/suporte).

    Erros sem resposta HTTP (timeout, conexão, etc.) costumam ter str() vazio — nesse
    caso devolvemos o nome do tipo para o log nunca ficar em branco.
    """
    resp = getattr(exc, "response", None)
    if resp is None:
        s = str(exc).strip()
        return s or f"{type(exc).__name__} (sem resposta — timeout/conexão)"
    code = msg = trace = ""
    try:
        err = (resp.json() or {}).get("error", {}) or {}
        inner = err.get("innererror", {}) or {}
        code = inner.get("code") or err.get("code") or ""
        msg = err.get("message") or ""
        trace = inner.get("message") or ""
    except Exception:  # noqa: BLE001
        msg = (getattr(resp, "text", "") or "")[:300]
    return f"HTTP {resp.status_code} {code} | {msg} | {trace}".strip()


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


async def _count(v1: VisionOneClient, path: str, params=None, extra_headers=None, top: int = 1) -> int:
    """Lê apenas o totalCount de um endpoint paginado (top pequeno -> payload mínimo)."""
    p = {"top": top}
    if params:
        p.update(params)
    d = await v1.get_json(path, params=p, extra_headers=extra_headers)
    tc = d.get("totalCount")
    return int(tc) if tc is not None else len(d.get("items", []))


# ---------------------------------------------------------------------------
# T1 (60s) — Workbench + Security Posture
# ---------------------------------------------------------------------------
async def workbench_counters(v1: VisionOneClient) -> dict:
    """Contadores de alertas por severidade e status."""
    sevs = ["critical", "high", "medium", "low"]
    stats = ["Open", "In Progress", "Closed"]
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=30)
    base = {"startDateTime": _iso(start), "endDateTime": _iso(end), "orderBy": "createdDateTime desc"}
    out: dict = {"severity": {}, "status": {}}
    for s in sevs:
        d = await v1.get_json("/v3.0/workbench/alerts", params={**base, "top": 1},
                              extra_headers={"TMV1-Filter": f"severity eq '{s}'"})
        out["severity"][s] = d.get("totalCount", len(d.get("items", [])))
    for st in stats:
        d = await v1.get_json("/v3.0/workbench/alerts", params={**base, "top": 1},
                              extra_headers={"TMV1-Filter": f"status eq '{st}'"})
        out["status"][st] = d.get("totalCount", len(d.get("items", [])))
    return out


async def security_posture(v1: VisionOneClient) -> dict:
    """Resposta crua do securityPosture. Requer créditos CREM."""
    return await v1.get_json("/v3.0/asrm/securityPosture")


def parse_posture(posture: dict) -> dict:
    """Achata o securityPosture nos campos que a tela executiva consome.

    O securityPosture (recurso-base / Cyber Risk Overview, sem créditos CREM-Core)
    já traz os AGREGADOS de superfície de ataque, vulnerabilidades e eventos de
    risco. Os endpoints asrm/attackSurface*, asrm/internalAssetVulnerabilities e
    asrm/highRisk* (que dão 403 sem CREM-Core) só entregam o drill-down por ativo
    individual — desnecessário para o wallboard executivo. Por isso os 4 painéis
    de risco são alimentados 100% daqui.

    riskCategoryLevel traz NÍVEIS em texto (low/medium/high), NÃO números.
    Obs.: a API retorna attack=medium; o console às vezes exibe "High" (cálculo
    de UI diferente). Exibimos o valor da API, que é a fonte de verdade.
    """
    rcl = posture.get("riskCategoryLevel") or {}
    cvm = posture.get("cveManagementMetrics") or {}
    exp = posture.get("exposureStatus") or {}
    cloud = exp.get("cloudAssetMisconfigurationStatus") or {}
    inet = exp.get("unexpectedInternetFacingInterfaceStatus") or {}
    host = exp.get("insecureHostConnectionStatus") or {}
    acct = exp.get("domainAccountMisconfigurationStatus") or {}
    cve = cvm.get("count")

    # Risk Factors: highImpactRiskEvents ordenados por ativos afetados (top 6)
    factors = []
    for f in (posture.get("highImpactRiskEvents") or []):
        factors.append({
            "factor": f.get("factor", ""),
            "events": f.get("eventCount", 0),
            "assets": f.get("affectedAssetCount", 0),
        })
    factors.sort(key=lambda x: x["assets"], reverse=True)

    # Tela Adoção (#cs): securityConfigurationStatus = adoção de agentes/features/cobertura
    ecs = posture.get("securityConfigurationStatus") or {}
    eas = ecs.get("endpointAgentStatus") or {}
    avs = eas.get("agentVersionStatus") or {}
    vps = ecs.get("virtualPatchingStatus") or {}
    mail = (ecs.get("emailSensorStatus") or {}).get("exchange") or {}
    capps = ecs.get("cloudAppsStatus") or {}
    feats = eas.get("agentFeatureStatus") or {}

    def _feat_list(arr):
        return [{"feature": f.get("feature", ""), "rate": f.get("adoptionRate")}
                for f in (arr or []) if f.get("adoptionRate") is not None]

    adoption = {
        "agents": eas.get("agentAdoptionCount"),
        "edr": eas.get("edrFeatureAdoptionCount"),
        "ver_latest": avs.get("latestCount"),
        "ver_outdated": avs.get("outdatedCount"),
        "ver_other": avs.get("otherCount"),
        "vp_patched": vps.get("patchedCount"),
        "vp_partial": vps.get("partialPatchedCount"),
        "vp_none": vps.get("notPatchedCount"),
        "mail_enabled": mail.get("enabledMailboxCount"),
        "mail_total": mail.get("totalMailboxCount"),
        "cloud_sanctioned": capps.get("sanctionedAppCount"),
        "cloud_unsanctioned": capps.get("unsanctionedAppCount"),
        "legacy_os": cvm.get("legacyOsEndpointCount"),
        "features": {
            "endpoint": _feat_list(feats.get("standardEndpointProtection")),
            "server": _feat_list(feats.get("serverWorkloadProtection")),
        },
    }

    return {
        # None (não 0) quando ausente: 0 fabricaria "Baixo/verde" na TV (regra NUNCA-zero).
        # O frontend trata None -> "—" (mesmo padrão de cve_count/surface).
        "risk_index": posture.get("riskIndex"),
        "exposure": rcl.get("exposure", ""),
        "attack": rcl.get("attack", ""),
        "config": rcl.get("securityConfiguration", ""),
        "cve_count": "" if cve is None else cve,
        # Painel Vulnerability Mgmt (cveManagementMetrics + cobertura)
        "vuln": {
            "count": cve,
            "coverage": posture.get("vulnerabilityAssessmentCoverageRate"),
            "mttp": cvm.get("mttpDays"),
            "unpatched": cvm.get("averageUnpatchedDays"),
            "vuln_rate": cvm.get("vulnerableEndpointRate"),
            "legacy_os": cvm.get("legacyOsEndpointCount"),
        },
        # Painel Attack Surface (exposureStatus)
        "surface": {
            "public_ip": inet.get("publicIpCount"),
            "ports": inet.get("servicePortCount"),
            "insecure_hosts": host.get("insecureHostCount"),
            "weak_auth": acct.get("weakAuthenticationCount"),
            "acct_risk": acct.get("increaseAttackSurfaceRiskCount"),
            "cloud_high": cloud.get("highRiskCount"),
            "cloud_med": cloud.get("mediumRiskCount"),
        },
        # Painel Risk Factors (highImpactRiskEvents, top 6 por ativos)
        "factors": factors[:6],
        # Tela Adoção (#cs)
        "adoption": adoption,
    }


# ---------------------------------------------------------------------------
# T2 (5min) — Eventos (OAT) + Risk Indicators
# ---------------------------------------------------------------------------
async def event_tallies(v1: VisionOneClient) -> dict:
    """Contagem de detecções (OAT) por janela: 24h, 24h anteriores, 7d, 30d.

    Usa totalCount com top=1 (1 chamada por janela). O delta de 24h é real
    (24h vs 24h anteriores). 7d/30d são contagens reais, sem comparativo
    histórico (ainda não há base de série temporal armazenada).
    """
    now = datetime.now(timezone.utc)

    async def cnt(start: datetime, end: datetime) -> int:
        return await _count(v1, "/v3.0/oat/detections",
                            params={"detectedStartDateTime": _iso(start),
                                    "detectedEndDateTime": _iso(end)})

    e24 = await cnt(now - timedelta(hours=24), now)
    e24p = await cnt(now - timedelta(hours=48), now - timedelta(hours=24))
    e7 = await cnt(now - timedelta(days=7), now)
    e30 = await cnt(now - timedelta(days=30), now)
    delta = round((e24 - e24p) / e24p * 100, 1) if e24p else 0.0
    return {"e24h": e24, "e24h_prev": e24p, "e7d": e7, "e30d": e30, "delta24h": delta}


# IPS Events (Deep Packet Inspection) + Exploit attempts (OAT tecnicas de exploracao High/Critical).
# Card "Intrusion Prevention Events" na tela Vulnerabilidades. Contagens baratas via totalCount.
_IPS_QUERY = "eventName:DEEP_PACKET_INSPECTION_EVENT"
_EXPLOIT_TECHS = ("T1190", "T1203", "T1210", "T1211", "T1212", "T1068")
_EXPLOIT_FILTER = ("(" + " or ".join(f"filterMitreTechniqueId eq '{t}'" for t in _EXPLOIT_TECHS) + ")"
                   " and (riskLevel eq 'high' or riskLevel eq 'critical')")


async def ips_exploit_counts(v1: VisionOneClient) -> dict:
    """Duas contagens por console p/ o card 'Intrusion Prevention Events':
      * IPS Events        -> GET /v3.0/search/detections (mode=countOnly), eventos de Deep Packet
                             Inspection (modulo IPS do Server & Workload Protection / Deep Security).
      * Exploit attempts  -> GET /v3.0/oat/detections, tecnicas MITRE de exploracao
                             (T1190/T1203/T1210/T1211/T1212/T1068) em severidade High/Critical.
    Janelas 24h e 7d. None por metrica em falha (o chamador conserva o ultimo valor bom); um 0 vindo
    de resposta 200 e ZERO REAL (console sem produto de IPS conectado), NAO 'indisponivel'.
    """
    now = datetime.now(timezone.utc)

    async def ips(start: datetime):
        try:
            d = await v1.get_json(
                "/v3.0/search/detections",
                params={"startDateTime": _iso(start), "endDateTime": _iso(now), "mode": "countOnly"},
                extra_headers={"TMV1-Query": _IPS_QUERY})
            tc = d.get("totalCount")
            return int(tc) if tc is not None else None
        except Exception:  # noqa: BLE001
            return None

    async def exploit(start: datetime):
        try:
            d = await v1.get_json(
                "/v3.0/oat/detections",
                params={"detectedStartDateTime": _iso(start), "detectedEndDateTime": _iso(now), "top": 50},
                extra_headers={"TMV1-Filter": _EXPLOIT_FILTER})
            tc = d.get("totalCount")
            return int(tc) if tc is not None else None
        except Exception:  # noqa: BLE001
            return None

    e24 = await ips(now - timedelta(hours=24))
    e7 = await ips(now - timedelta(days=7))
    x24 = await exploit(now - timedelta(hours=24))   # exploit so 24h (1 chamada OAT; reduz carga/429)
    return {"e24h": e24, "e7d": e7, "exploit24h": x24}


async def high_risk(v1: VisionOneClient, top: int = 6) -> list:
    """Usuários + dispositivos de maior risco -> painel Risk Indicators.

    Campo correto é latestRiskScore. Sem orderBy (evita 400 se o nome do campo
    divergir no tenant); ordenamos no cliente. Cada bloco é best-effort; só
    levanta erro se NADA voltar (aí o scheduler loga como indisponível).
    """
    items: list = []
    errors: list = []
    n = max(top, 10)
    try:
        users = await v1.get_paginated("/v3.0/asrm/highRiskUsers", params={"top": n}, limit=n)
        for u in users:
            items.append({
                "name": u.get("name") or u.get("displayName") or u.get("userName") or "—",
                "score": u.get("latestRiskScore") or u.get("riskScore") or 0,
                "sub": u.get("type") or "Usuário",
                "kind": "user",
            })
    except Exception as exc:  # noqa: BLE001
        errors.append(f"highRiskUsers: {exc}")
    try:
        devices = await v1.get_paginated("/v3.0/asrm/highRiskDevices", params={"top": n}, limit=n)
        for d in devices:
            items.append({
                "name": d.get("deviceName") or d.get("name") or "—",
                "score": d.get("latestRiskScore") or d.get("riskScore") or 0,
                "sub": d.get("osName") or "Dispositivo",
                "kind": "device",
            })
    except Exception as exc:  # noqa: BLE001
        errors.append(f"highRiskDevices: {exc}")
    if not items and errors:
        raise RuntimeError("; ".join(errors))
    items.sort(key=lambda x: x.get("score") or 0, reverse=True)
    return items[:top]


# ---------------------------------------------------------------------------
# T3 (15min) — Attack Surface + Mapa (geo)
# ---------------------------------------------------------------------------
async def attack_surface_counts(v1: VisionOneClient) -> dict:
    """Superfície de ataque via ASRM/CREM (escopo Reports, que funciona no tenant).

    As 5 métricas rodam em PARALELO (asyncio.gather) — uma chamada lenta/instável não
    soma no tempo das outras. Cada uma é best-effort com teto de 20s: se falhar, vira
    None, é logada, e o scheduler conserva o último valor bom (não regrava None).
    Usa top=50: os endpoints de inventário rejeitam top=1.
    """
    async def cnt(label, path, extra_headers=None):
        try:
            return label, await asyncio.wait_for(
                _count(v1, path, extra_headers=extra_headers, top=50), timeout=20)
        except Exception as exc:  # noqa: BLE001
            log.warning("surface.%s indisponível: %s", label, diag(exc))
            return label, None

    pairs = await asyncio.gather(
        cnt("devices",   "/v3.0/asrm/attackSurfaceDevices"),
        cnt("critical",  "/v3.0/asrm/attackSurfaceDevices", {"TMV1-Filter": "criticality eq 'high'"}),
        cnt("unmanaged", "/v3.0/asrm/attackSurfaceDevices", {"TMV1-Filter": "deviceType eq 'Unmanaged device'"}),
        cnt("cloud",     "/v3.0/asrm/attackSurfaceCloudAssets"),
        cnt("accounts",  "/v3.0/asrm/attackSurfaceDomainAccounts"),
    )
    return dict(pairs)


async def vuln_metrics(v1: VisionOneClient) -> dict:
    """Vulnerabilidades (CVEs) via ASRM/CREM internalAssetVulnerabilities (escopo Reports).

    - counts: contagem por nível de risco CREM (high/medium/low; CREM não tem 'critical'),
      cada uma best-effort via TMV1-Filter + totalCount.
    - top: principais CVEs ordenados por risco (cveRiskScore/cvssScore desc, top 6),
      com cveId / cvssScore / affectedAssetCount / cveRiskLevel.
    Usa top=50 (mesmo motivo dos endpoints de inventário: top=1 é rejeitado).
    """
    path = "/v3.0/asrm/internalAssetVulnerabilities"
    out = {"counts": {"high": None, "medium": None, "low": None}, "top": []}
    for lvl in ("high", "medium", "low"):
        try:
            out["counts"][lvl] = await asyncio.wait_for(
                _count(v1, path, extra_headers={"TMV1-Filter": f"cveRiskLevel eq '{lvl}'"}, top=50),
                timeout=20)
        except Exception as exc:  # noqa: BLE001
            log.warning("vuln.count.%s indisponível: %s", lvl, diag(exc))
    try:
        d = await asyncio.wait_for(
            v1.get_json(path, params={"top": 50, "orderBy": "cveRiskLevel desc"}), timeout=20)
        items = d.get("items", []) or []
        items.sort(key=lambda x: ((x.get("cveRiskScore") or 0), (x.get("cvssScore") or 0)), reverse=True)
        for it in items[:6]:
            out["top"].append({
                "cve":      it.get("cveId") or "",
                "cvss":     it.get("cvssScore"),
                "affected": it.get("affectedAssetCount"),
                "level":    str(it.get("cveRiskLevel") or "").lower(),
            })
    except Exception as exc:  # noqa: BLE001
        log.warning("vuln.top indisponível: %s", diag(exc))
    return out


# Táticas MITRE ATT&CK Enterprise (ordem aproximada da kill chain) — heat matrix.
MITRE_TACTICS = [
    "TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
    "TA0006", "TA0007", "TA0008", "TA0009", "TA0011", "TA0010", "TA0040",
]


async def mitre_tactics(v1: VisionOneClient, days: int = 1) -> dict:
    """Contagem de detecções OAT por tática MITRE (heat matrix), janela de N dias.

    As 14 táticas rodam em PARALELO com semáforo de 6 (antes eram sequenciais ~10s cada
    ≈ 140s; agora ~30s). Cada uma é best-effort com teto de 20s; falha vira None.
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    base = {"detectedStartDateTime": _iso(start), "detectedEndDateTime": _iso(end)}
    sem = asyncio.Semaphore(6)

    async def one(ta):
        async with sem:
            try:
                return ta, await asyncio.wait_for(
                    _count(v1, "/v3.0/oat/detections", params=base,
                           extra_headers={"TMV1-Filter": f"filterMitreTacticId eq '{ta}'"}, top=1),
                    timeout=45)
            except Exception as exc:  # noqa: BLE001
                log.warning("mitre.%s indisponível: %s", ta, diag(exc))
                return ta, None

    pairs = await asyncio.gather(*(one(ta) for ta in MITRE_TACTICS))
    return dict(pairs)


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


async def detections_feed(v1: VisionOneClient, minutes: int = 10, top: int = 100, limit: int = 15) -> list:
    """Detecções OAT recentes para o feed do SOC.

    A API não suporta orderBy nem documenta a ordem -> janela curta (minutes) +
    ordenação por detectedDateTime desc no cliente, pegando as `limit` mais novas.
    Severidade da linha = maior riskLevel entre os filters[] da detecção.
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)
    params = {"detectedStartDateTime": _iso(start), "detectedEndDateTime": _iso(end), "top": top}
    d = await asyncio.wait_for(v1.get_json("/v3.0/oat/detections", params=params), timeout=20)
    items = d.get("items", []) or []
    items.sort(key=lambda x: x.get("detectedDateTime") or "", reverse=True)
    feed = []
    for it in items[:limit]:
        flts = it.get("filters", []) or []
        sev, best, name = "info", -1, ""
        tacs: list = []
        techs: list = []
        for f in flts:
            rl = str(f.get("riskLevel") or "").lower()
            if _SEV_RANK.get(rl, -1) > best:
                best, sev = _SEV_RANK.get(rl, -1), (rl or sev)
            if not name:
                name = f.get("name") or ""
            tacs += f.get("mitreTacticIds") or []
            techs += f.get("mitreTechniqueIds") or []
        ep = it.get("endpoint") or {}
        feed.append({
            "time":      it.get("detectedDateTime") or "",
            "host":      ep.get("endpointName") or it.get("entityName") or "—",
            "name":      name or "(detecção)",
            "sev":       sev,
            "tactic":    tacs[0] if tacs else "",
            "technique": techs[0] if techs else "",
        })
    return feed


async def threat_trend(v1: VisionOneClient, buckets: int = 12, hours_each: int = 2) -> list:
    """Série de detecções OAT de ALTO RISCO por bucket de tempo (tendência das últimas 24h).

    buckets * hours_each = janela total (12 * 2h = 24h). Cada bucket conta detecções OAT
    com riskLevel=high (top=1 + totalCount), em paralelo (semáforo 6), best-effort com teto de 20s.
    Usa o filtro de risco porque o totalCount geral satura em ~100k para tenants de alto volume
    (a Prodesp satura todos os buckets), deixando a linha sem sinal. O recorte de alto risco
    mantém números menores e com variação real ao longo do dia.
    Não há endpoint de histograma no v3.0 -> 1 chamada por bucket.
    """
    end = datetime.now(timezone.utc)
    sem = asyncio.Semaphore(6)

    async def bucket(i):
        b_end = end - timedelta(hours=hours_each * i)
        b_start = b_end - timedelta(hours=hours_each)
        params = {"detectedStartDateTime": _iso(b_start), "detectedEndDateTime": _iso(b_end)}
        async with sem:
            try:
                n = await asyncio.wait_for(
                    _count(v1, "/v3.0/oat/detections", params=params,
                           extra_headers={"TMV1-Filter": "riskLevel eq 'high'"}, top=1),
                    timeout=20)
            except Exception as exc:  # noqa: BLE001
                log.warning("trend.bucket%d indisponível: %s", i, diag(exc))
                n = None
        return {"t": _iso(b_end), "n": n}

    pairs = await asyncio.gather(*(bucket(i) for i in range(buckets)))
    pairs.sort(key=lambda x: x["t"])  # cronológico (antigo -> novo)
    return pairs


_IDENTITY = [
    ("bruteForce",    "filterMitreTechniqueId eq 'T1110'"),  # Brute Force
    ("validAccounts", "filterMitreTechniqueId eq 'T1078'"),  # Valid Accounts
    ("credDumping",   "filterMitreTechniqueId eq 'T1003'"),  # OS Credential Dumping
    ("privEsc",       "filterMitreTacticId eq 'TA0004'"),    # Privilege Escalation
]


async def identity_counts(v1: VisionOneClient, days: int = 1) -> dict:
    """Detecções OAT de identidade/credencial por técnica/tática MITRE (24h), em paralelo."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    base = {"detectedStartDateTime": _iso(start), "detectedEndDateTime": _iso(end)}
    sem = asyncio.Semaphore(4)

    async def one(key, filt):
        async with sem:
            try:
                return key, await asyncio.wait_for(
                    _count(v1, "/v3.0/oat/detections", params=base,
                           extra_headers={"TMV1-Filter": filt}, top=1), timeout=45)
            except Exception as exc:  # noqa: BLE001
                log.warning("identity.%s indisponível: %s", key, diag(exc))
                return key, None

    pairs = await asyncio.gather(*(one(k, f) for k, f in _IDENTITY))
    return dict(pairs)


_EP_PATH = "/v3.0/endpointSecurity/endpoints"


async def endpoints_summary(v1: VisionOneClient, per_timeout: int = 20) -> dict:
    """Resumo do inventário de Endpoints via contagem filtrada (totalCount), sem puxar 27k+ registros.

    Usa TMV1-Filter (campos PLANOS: osPlatform, type, eppAgentStatus, edrSensorConnectivity,
    eppAgentComponentVersion) + top=50 (o endpoint rejeita top=1). Cada contagem é best-effort:
    se um filtro falhar (400/timeout), a métrica vira None e a tela mostra '—'.
    """
    sem = asyncio.Semaphore(6)

    async def cnt(label, filt=None):
        async with sem:
            headers = {"TMV1-Filter": filt} if filt else None
            try:
                return label, await asyncio.wait_for(
                    _count(v1, _EP_PATH, extra_headers=headers, top=50), timeout=per_timeout)
            except Exception as exc:  # noqa: BLE001
                log.warning("endpoint.%s indisponível: %s", label, diag(exc))
                return label, None

    jobs = [
        cnt("total"),
        cnt("edrConnected",    "edrSensorConnectivity eq 'connected'"),
        cnt("edrDisconnected", "edrSensorConnectivity eq 'disconnected'"),
        cnt("eppOn",           "eppAgentStatus eq 'on'"),
        cnt("eppOff",          "eppAgentStatus eq 'off'"),
        cnt("outdated",        "eppAgentComponentVersion eq 'outdatedVersion'"),
        cnt("osWindows",       "osPlatform eq 'windows'"),
        cnt("osLinux",         "osPlatform eq 'linux'"),
        cnt("osMac",           "osPlatform eq 'mac'"),
        cnt("typeServer",      "type eq 'server'"),
        cnt("typeDesktop",     "type eq 'desktop'"),
    ]
    res = dict(await asyncio.gather(*jobs))
    return {
        "total": res.get("total"),
        "edrConnected": res.get("edrConnected"),
        "edrDisconnected": res.get("edrDisconnected"),
        "eppOn": res.get("eppOn"),
        "eppOff": res.get("eppOff"),
        "outdated": res.get("outdated"),
        "os": {"windows": res.get("osWindows"), "linux": res.get("osLinux"), "mac": res.get("osMac")},
        "type": {"server": res.get("typeServer"), "desktop": res.get("typeDesktop")},
    }


# valor do IOC fica no campo nomeado pelo type (ex.: item["domain"], item["url"], item["ip"], item["fileSha256"])
_SO_TYPES = ["ip", "domain", "url", "fileSha256", "fileSha1", "senderMailAddress"]
_RISK_RANK = {"high": 3, "medium": 2, "low": 1}


def _ioc_host(it: dict):
    """Extrai o host (IP ou domínio) de um IOC de rede."""
    t, v = it.get("type"), it.get("value", "")
    if t in ("ip", "domain"):
        return v or None
    if t == "url":
        try:
            return urlparse(v).hostname
        except Exception:  # noqa: BLE001
            return None
    return None


async def _resolve(host: str, sem: asyncio.Semaphore):
    """domínio -> IP (DNS, best-effort, 4s). Se já for IP, retorna ele mesmo."""
    try:
        ipaddress.ip_address(host)
        return host  # já é IP literal
    except ValueError:
        pass
    loop = asyncio.get_event_loop()
    async with sem:
        try:
            infos = await asyncio.wait_for(loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=4)
        except Exception:  # noqa: BLE001
            return None
    ipv4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
    if ipv4:
        return ipv4[0]
    return infos[0][4][0] if infos else None


async def _geolocate_iocs(rows: list, limit: int = 60) -> list:
    """Geolocaliza IOCs de rede (url/domain/ip) -> marcadores. Agrupa por host. Best-effort.

    URL -> host; domínio -> DNS -> IP; IP -> direto. GeoIP (GeoLite2-City) -> lat/lon/país.
    Hashes não têm geografia e são ignorados. Sem base GeoIP, retorna [] (mapa fica só decorativo).
    """
    by_host: dict = {}
    for r in rows:
        if r.get("type") not in ("url", "domain", "ip"):
            continue
        h = _ioc_host(r)
        if not h:
            continue
        g = by_host.setdefault(h, {"host": h, "risk": "low", "count": 0, "value": r["value"], "type": r["type"]})
        g["count"] += 1
        if _RISK_RANK.get(r["risk"], 0) > _RISK_RANK.get(g["risk"], 0):
            g["risk"], g["value"], g["type"] = r["risk"], r["value"], r["type"]

    hosts = list(by_host.values())[:limit]
    sem = asyncio.Semaphore(10)

    async def one(g):
        ip = await _resolve(g["host"], sem)
        if not ip:
            return None
        loc = geo.lookup_ip(ip)
        if not loc:
            return None
        return {**g, "ip": ip, **loc}

    res = await asyncio.gather(*(one(g) for g in hosts))
    return [x for x in res if x]


async def suspicious_objects(v1: VisionOneClient, top: int = 12, limit: int = 2000) -> dict:
    """Threat Intelligence: lista de Objetos Suspeitos.

    O endpoint NÃO retorna totalCount (paginação por skipToken/nextLink) -> paginamos
    tudo e tabulamos no cliente. Retorna contagens por tipo/risco/ação, lista Top de IOCs
    e marcadores geolocalizados (origem dos IOCs de rede). Tudo best-effort (teto de 40s).
    """
    try:
        items = await asyncio.wait_for(
            v1.get_paginated("/v3.0/threatintel/suspiciousObjects", params={"top": 50}, limit=limit),
            timeout=40)
    except Exception as exc:  # noqa: BLE001
        log.warning("suspiciousObjects indisponível: %s", diag(exc))
        return {}

    by_type: dict = {}
    by_risk = {"high": 0, "medium": 0, "low": 0}
    n_block = n_log = 0
    rows = []
    for it in items:
        t = it.get("type", "?")
        by_type[t] = by_type.get(t, 0) + 1
        rl = str(it.get("riskLevel", "")).lower()
        if rl in by_risk:
            by_risk[rl] += 1
        act = str(it.get("scanAction", "")).lower()
        if act == "block":
            n_block += 1
        elif act == "log":
            n_log += 1
        rows.append({
            "value": it.get(t, ""),                       # valor no campo nomeado pelo type
            "type": t,
            "risk": rl,
            "action": act,
            "modified": it.get("lastModifiedDateTime", ""),
        })

    rows.sort(key=lambda x: (_RISK_RANK.get(x["risk"], 0), x["modified"]), reverse=True)

    geo_markers = await _geolocate_iocs(rows)
    by_country: dict = {}
    for m in geo_markers:
        c = m.get("country") or "?"
        by_country[c] = by_country.get(c, 0) + 1

    return {
        "total": len(items),
        "byType": by_type,
        "byRisk": by_risk,
        "byAction": {"block": n_block, "log": n_log},
        "high": by_risk["high"],
        "top": rows[:top],
        "geo": geo_markers,
        "byCountry": by_country,
    }


async def network_activities(v1: VisionOneClient, minutes: int = 15) -> list:
    """Atividades de rede de alto risco -> alimenta o Attack Map (geo)."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)
    query = "riskLevel:high OR riskLevel:critical"
    return await v1.get_paginated(
        "/v3.0/search/networkActivities",
        params={"startDateTime": _iso(start), "endDateTime": _iso(end)},
        extra_headers={"TMV1-Query": query})


# ---------------------------------------------------------------------------
# Reservados para a Fase 2b (telas SOC) — coletores brutos já prontos
# ---------------------------------------------------------------------------
async def oat_detections(v1: VisionOneClient, minutes: int = 60) -> list:
    """Técnicas MITRE observadas (OAT) -> matriz ATT&CK + feed de detecções."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)
    return await v1.get_paginated(
        "/v3.0/oat/detections",
        params={"detectedStartDateTime": _iso(start), "detectedEndDateTime": _iso(end), "top": 200})


async def endpoint_inventory(v1: VisionOneClient) -> list:
    """Conectividade/saúde dos agentes -> painel de endpoints (SOC)."""
    return await v1.get_paginated(
        "/v3.0/endpointSecurity/endpoints", params={"top": 100})


# ===========================================================================
# Tela VULNERABILIDADES — rankings (amostra por RISCO, do maior para o menor)
# ===========================================================================
# Os endpoints ASRM sao lentos (29-36s/pagina) e so ordenam por risco
# (cveRiskLevel / latestRiskScore), nao pela metrica pedida. Por isso amostramos
# os itens de MAIOR RISCO e re-ranqueamos pela metrica no backend (best-effort;
# marca metadata.partial e limitations). Nunca fabrica dado; ranking ausente/erro
# vira None (nao [] nem 0), para o frontend distinguir vazio x indisponivel.
_APP_STRIP = re.compile(
    r"\b(update|updater|helper|service|background|x64|x86|amd64|arm64|64-bit|32-bit|"
    r"\(x64\)|\(x86\)|el\d+|build)\b", re.I)

def _vuln_status(exc) -> str:
    resp = getattr(exc, "response", None)
    if resp is not None and resp.status_code in (401, 403):
        return "forbidden"
    return "unavailable"

def _norm_app(vendor, name) -> str:
    """Chave de agrupamento normalizada de aplicacao (fornecedor|produto)."""
    n = (name or "").lower()
    n = re.sub(r"\d+([._-]\d+)+", " ", n)         # remove versoes (1.2.3, 0:2.46.6-1)
    n = _APP_STRIP.sub(" ", n)
    n = re.sub(r"[^a-z0-9]+", " ", n).strip()
    v = re.sub(r"[^a-z0-9]+", " ", (vendor or "").lower()).strip()
    return f"{v}|{n}" if n else (v or "?")


# cache em processo do mapa de tipos: o inventario tem ~27k devices (rebuild ~180s).
# O coletor e um processo longo -> o mapa e reusado entre ticks T4 (hourly) por ate _DEVTYPE_TTL.
_DEVTYPE_CACHE = {"ts": -1e9, "map": None}
_DEVTYPE_TTL = 21600  # 6h

# Sistemas operacionais "cliente" (endpoint/desktop) — usados so no fallback quando o
# device nao esta no inventario autoritativo. NAO e adivinhacao por hostname.
_CLIENT_OS = ("windows 11", "windows 10", "windows 8", "windows 7", "windows xp",
              "macos", "mac os", "os x")


def _classify_device(name, os_name, os_platform, tmap: dict):
    """servidor x endpoint: 1) tipo AUTORITATIVO do inventario endpointSecurity (por nome);
    2) fallback pelo sistema operacional (Server -> servidor; Windows client/mac -> endpoint).
    Devolve 'server' | 'desktop' | None (nao classificado). Nunca infere pelo texto do hostname."""
    n = (name or "").strip().lower()
    info = tmap.get(n) or tmap.get(n.split(".")[0])   # casa nome completo (FQDN) e token curto
    if info and info.get("type") in ("server", "desktop"):
        return info["type"]
    osn = str(os_name or "").lower()
    if "server" in osn:
        return "server"
    if any(c in osn for c in _CLIENT_OS):
        return "desktop"
    if str(os_platform or "").lower() in ("mac", "macos"):
        return "desktop"
    return None


async def _device_type_map(v1: VisionOneClient, inv_cap: int = 30000) -> dict:
    """Mapa nome(lower) -> {type, os} via inventario endpointSecurity (top=1000, ~3s/pagina).
    Indexa o nome COMPLETO e o token curto (antes do 1o '.') p/ casar FQDN e nome curto.
    Cache em processo por _DEVTYPE_TTL: so cacheia mapa NAO-VAZIO e reusa o ultimo bom se a
    reconstrucao falhar (nunca serve/poluir com mapa vazio -> classificacao nao degrada em silencio)."""
    now = asyncio.get_event_loop().time()
    cached = _DEVTYPE_CACHE.get("map")
    if cached and (now - _DEVTYPE_CACHE["ts"]) < _DEVTYPE_TTL:   # 'cached' truthy = nao-vazio
        return cached
    try:
        items = await asyncio.wait_for(
            v1.get_paginated("/v3.0/endpointSecurity/endpoints", params={"top": 1000}, limit=inv_cap),
            timeout=300)
    except Exception:  # noqa: BLE001
        if cached:                      # reconstrucao falhou -> reusa mapa velho (stale) se houver
            return cached
        raise
    m = {}
    for e in items:
        nm = (e.get("endpointName") or "").strip().lower()
        if not nm:
            continue
        info = {"type": e.get("type"), "os": e.get("osName")}
        m[nm] = info                                    # nome completo (ex.: host.dominio.local)
        short = nm.split(".")[0]
        if short and short != nm:                       # token curto (ex.: host)
            ex = m.get(short)
            if ex is not None and ex.get("type") != info.get("type"):
                m[short] = {"type": None, "os": info.get("os")}   # colisao ambigua -> nao classifica
            elif short not in m:
                m[short] = info
    if m:                               # 200 vazio (transitorio) nao substitui um bom anterior
        _DEVTYPE_CACHE["map"] = m
        _DEVTYPE_CACHE["ts"] = now
        return m
    return cached or {}


async def vuln_rankings(v1: VisionOneClient, cve_n: int = 500, dev_n: int = 800,
                        app_n: int = 500, inv_cap: int = 30000, budget: int = 360) -> dict:
    """4 rankings da tela Vulnerabilidades. Amostra por risco (maior->menor)."""
    md = {"source": [], "partial": False, "limitations": [],
          "status": {"topCves": "unavailable", "topServers": "unavailable",
                     "topEndpoints": "unavailable", "topApplications": "unavailable",
                     "exploitSummary": "unavailable"},
          "sampled": {}}
    out = {"topCves": None, "topServers": None, "topEndpoints": None,
           "topApplications": None, "exploitSummary": None, "metadata": md}

    # 1) Top CVEs — internalAssetVulnerabilities (orderBy cveRiskLevel desc) -> re-rank por affectedAssetCount
    try:
        items = await asyncio.wait_for(
            v1.get_paginated("/v3.0/asrm/internalAssetVulnerabilities",
                             params={"top": 50, "orderBy": "cveRiskLevel desc"}, limit=cve_n),
            timeout=budget)
        rows = []
        for it in items:
            sw = it.get("affectedSoftwares") or []
            rows.append({
                "cve": it.get("cveId"),
                "impactScore": it.get("cveRiskScore"),   # "Vulnerability impact score" do console
                "affectedAssets": it.get("affectedAssetCount") or 0,
                "cvss": it.get("cvssScore"),
                "level": str(it.get("cveRiskLevel") or "").lower(),
                "exploit": it.get("globalExploitActivityLevel"),
                "product": (sw[0].get("name") if sw and isinstance(sw[0], dict) else None),
                "preventionRules": len(it.get("preventionRules") or []),  # nr de regras de prevencao (virtual patching/IPS)
            })
        rows.sort(key=lambda x: ((x["impactScore"] or 0), (x["affectedAssets"] or 0)), reverse=True)
        out["topCves"] = rows[:10]
        md["status"]["topCves"] = "ok" if rows else "empty"
        md["sampled"]["cves"] = len(items)
        md["source"].append("asrm/internalAssetVulnerabilities")
        if len(items) >= cve_n:
            md["partial"] = True
            md["limitations"].append(
                f"Top CVEs: ranqueado por Vulnerability impact score (cveRiskScore) entre os {len(items)} CVEs "
                "de maior risco (amostra); a API nao ordena diretamente por esse score, entao re-ranqueamos no cliente.")
    except Exception as exc:  # noqa: BLE001
        log.warning("vuln.cves indisponivel: %s", diag(exc))
        md["status"]["topCves"] = _vuln_status(exc)

    # 2/3) Top servidores/endpoints — attackSurfaceDevices (rapido ~4s/pag, tem cveCount) +
    #      classificacao servidor x endpoint pelo tipo AUTORITATIVO do endpointSecurity (fallback: SO).
    try:
        tmap = {}
        try:
            tmap = await _device_type_map(v1, inv_cap=inv_cap)   # cache em processo; best-effort
        except Exception as exc:  # noqa: BLE001
            log.warning("vuln.devtypemap indisponivel: %s", diag(exc))
        if not tmap:
            # sem o inventario autoritativo a classificacao servidor/endpoint fica incompleta
            # (perderia servidores Linux) -> NAO emite ranking degradado; deixa None p/
            # keep-last-good conservar o ultimo bom (ou mostrar indisponivel).
            raise RuntimeError("mapa de tipos (endpointSecurity) indisponivel")
        devs = await asyncio.wait_for(
            v1.get_paginated("/v3.0/asrm/attackSurfaceDevices",
                             params={"top": 50, "orderBy": "latestRiskScore desc"}, limit=dev_n),
            timeout=budget)
        servers, endpoints, unclassified = [], [], 0
        for d in devs:
            nm = (d.get("deviceName") or "").strip()
            typ = _classify_device(nm, d.get("osName"), d.get("osPlatform"), tmap)
            row = {"asset": nm or "—", "cveCount": d.get("cveCount") or 0,
                   "os": d.get("osName"), "criticality": d.get("criticality"),
                   "risk": d.get("latestRiskScore")}
            if typ == "server":
                servers.append(row)
            elif typ == "desktop":
                endpoints.append(row)
            else:
                unclassified += 1
        # cveCount satura em 3600 na API -> desempata por latestRiskScore p/ ordem estavel
        servers.sort(key=lambda x: ((x["cveCount"] or 0), (x["risk"] or 0)), reverse=True)
        endpoints.sort(key=lambda x: ((x["cveCount"] or 0), (x["risk"] or 0)), reverse=True)
        out["topServers"] = servers[:10]
        out["topEndpoints"] = endpoints[:10]
        md["status"]["topServers"] = "ok" if servers else "empty"
        md["status"]["topEndpoints"] = "ok" if endpoints else "empty"
        md["sampled"]["devices"] = len(devs)
        md["sampled"]["unclassified"] = unclassified
        md["source"].append("asrm/attackSurfaceDevices + endpointSecurity/endpoints")
        md["limitations"].append(
            "Top servidores/endpoints: amostra dos devices de MAIOR RISCO (a API nao ordena por nr de CVEs), "
            "re-ranqueada por cveCount (CVEs distintos por device; a API satura em 3600). Classificacao "
            "servidor/endpoint pelo tipo autoritativo do endpointSecurity e, sem correspondencia, pelo SO.")
        if unclassified:
            md["limitations"].append(f"{unclassified} device(s) da amostra sem classificacao (fora dos rankings).")
        if len(devs) >= dev_n:
            md["partial"] = True
    except Exception as exc:  # noqa: BLE001
        log.warning("vuln.devices indisponivel: %s", diag(exc))
        st = _vuln_status(exc)
        md["status"]["topServers"] = st
        md["status"]["topEndpoints"] = st

    # 4) Top aplicacoes — attackSurfaceLocalApps (orderBy latestRiskScore desc) -> agrupa por fornecedor+nome
    try:
        apps = await asyncio.wait_for(
            v1.get_paginated("/v3.0/asrm/attackSurfaceLocalApps",
                             params={"top": 50, "orderBy": "latestRiskScore desc"}, limit=app_n),
            timeout=budget)
        groups = {}
        for a in apps:
            key = _norm_app(a.get("vendor"), a.get("name"))
            g = groups.setdefault(key, {"application": a.get("name") or "—", "vendor": a.get("vendor"),
                                        "cveIndicators": 0, "affectedAssets": 0, "risk": 0, "versions": set()})
            g["cveIndicators"] += (a.get("riskIndicatorEventCount") or 0)
            g["affectedAssets"] += (a.get("deviceCount") or 0)
            g["risk"] = max(g["risk"], a.get("latestRiskScore") or 0)
            if a.get("version"):
                g["versions"].add(a.get("version"))
        rows = [{"application": g["application"], "vendor": g["vendor"],
                 "cveIndicators": g["cveIndicators"], "affectedAssets": g["affectedAssets"],
                 "risk": g["risk"], "versions": len(g["versions"])} for g in groups.values()]
        rows.sort(key=lambda x: (x["cveIndicators"] or 0, x["affectedAssets"] or 0), reverse=True)
        out["topApplications"] = rows[:10]
        md["status"]["topApplications"] = "ok" if rows else "empty"
        md["sampled"]["apps"] = len(apps)
        md["source"].append("asrm/attackSurfaceLocalApps")
        md["limitations"].append(
            "Top aplicacoes: 'cveIndicators' = riskIndicatorEventCount (indicadores de risco ~ CVEs, "
            "nao CVEs distintos exatos); agrupado por fornecedor+nome normalizado.")
        if len(apps) >= app_n:
            md["partial"] = True
    except Exception as exc:  # noqa: BLE001
        log.warning("vuln.apps indisponivel: %s", diag(exc))
        md["status"]["topApplications"] = _vuln_status(exc)

    # 5) Resumo: total de CVEs no ambiente + distribuicao por Global exploit potential.
    #    globalExploitActivityLevel so aceita high/medium/low (somam o total) via TMV1-Filter.
    vpath = "/v3.0/asrm/internalAssetVulnerabilities"
    exp = {"total": None, "high": None, "medium": None, "low": None}
    try:
        exp["total"] = await asyncio.wait_for(_count(v1, vpath, top=50), timeout=60)
    except Exception as exc:  # noqa: BLE001
        log.warning("vuln.exploit.total indisponivel: %s", diag(exc))
    for lvl in ("high", "medium", "low"):
        try:
            exp[lvl] = await asyncio.wait_for(
                _count(v1, vpath, extra_headers={"TMV1-Filter": f"globalExploitActivityLevel eq '{lvl}'"}, top=50),
                timeout=60)
        except Exception as exc:  # noqa: BLE001
            log.warning("vuln.exploit.%s indisponivel: %s", lvl, diag(exc))
    # os 3 niveis particionam o dataset -> se o total direto falhar, deriva da soma
    _lv = [exp[k] for k in ("high", "medium", "low")]
    if exp["total"] is None and all(v is not None for v in _lv):
        exp["total"] = sum(_lv)
    _complete = exp["total"] is not None and all(v is not None for v in _lv)
    if exp["total"] is not None or any(v is not None for v in _lv):
        out["exploitSummary"] = exp
        md["status"]["exploitSummary"] = "ok" if _complete else "partial"
        md["source"].append("asrm/internalAssetVulnerabilities (globalExploitActivityLevel)")

    return out
