"""Scheduler do coletor — orquestra os tiers, escreve no Redis e publica deltas no WebSocket.

Execução:
    python -m collectors.run

Robustez: se um endpoint falhar (ASRM sem créditos CREM, filtro inexistente, rede),
o tier é logado e o scheduler continua. O backend nunca cai por uma coleta isolada.

Tiers:
    T1 (60s)  -> Workbench (sev/status) + Security Posture (riskIndex, níveis, CVEs)
    T2 (5min) -> Eventos OAT (24h/7d/30d) + Risk Indicators (high risk users/devices)
    T3 (15min)-> Attack Surface (contagem de ativos) + Mapa (geo)
"""
import asyncio
import json
import logging
from datetime import datetime, timedelta

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app import geo
from app.cache import get_redis
from app.config import settings
from app.vision_one import VisionOneClient
from collectors import tiers

log = logging.getLogger("collector")

r = get_redis()
TENANT = settings.tenant


def _diag(exc: Exception) -> str:
    """Diagnóstico de um erro httpx: status + innererror.code + mensagem + TraceId (p/ suporte)."""
    resp = getattr(exc, "response", None)
    if resp is None:
        return str(exc)
    code = msg = trace = ""
    try:
        err = (resp.json() or {}).get("error", {}) or {}
        inner = err.get("innererror", {}) or {}
        code = inner.get("code") or err.get("code") or ""
        msg = err.get("message") or ""        # descrição legível da API
        trace = inner.get("message") or ""    # normalmente "TraceId: ..."
    except Exception:  # noqa: BLE001
        msg = (resp.text or "")[:300]
    return f"HTTP {resp.status_code} {code} | {msg} | {trace}".strip()


async def _merge_keep(key: str, fresh: dict) -> dict:
    """Mescla com o último valor bom no Redis: mantém o anterior onde o novo veio None.
    Evita zerar painéis (mitre/identity) quando uma contagem filtrada dá timeout."""
    try:
        prev_raw = await r.get(key)
        prev = json.loads(prev_raw) if prev_raw else {}
    except Exception:  # noqa: BLE001
        prev = {}
    return {k: (v if v is not None else prev.get(k)) for k, v in fresh.items()}


async def _fetch_posture(v1: VisionOneClient, tenant: str, tries=(10.0, 12.0, 18.0)) -> dict:
    """securityPosture com retry de timeout curto.

    O securityPosture do V1 é intermitente em tenants grandes (ex.: prodesp, ~8,6k workbenches):
    às vezes devolve HTTP 500 SÓ depois de 40-65s. Uma única chamada dessas estoura o guard do
    tick (51s) e cancela tudo -> posture nunca é gravado -> após 30min de TTL o painel zera (SEM DADOS).
    Como o 200 volta rápido (~1-2s), abortamos cada tentativa em `tries[i]`s e retentamos: o 500-lento
    é cortado cedo e a retentativa costuma pegar o 200. O último timeout é mais folgado p/ acomodar um
    200 legitimamente lento (cold ~17s). Mantém o dado FRESCO e REAL — nada é fabricado. Soma < guard."""
    last: Exception | None = None
    for i, per in enumerate(tries):
        try:
            return await asyncio.wait_for(tiers.security_posture(v1), per)
        except asyncio.TimeoutError as exc:
            last = exc
            log.info("[%s] posture tentativa %d/%d excedeu %.0fs — retry", tenant, i + 1, len(tries), per)
        except Exception as exc:  # noqa: BLE001  (500/erro rápido -> retenta já)
            last = exc
            log.info("[%s] posture tentativa %d/%d falhou (%s) — retry", tenant, i + 1, len(tries), _diag(exc))
    raise last if last is not None else RuntimeError("posture sem tentativas")


async def _store_posture(tenant: str, flat: dict) -> None:
    """Grava a postura viva (TTL 30min -> alimenta 'AO VIVO') + cópia durável (last-known-good)."""
    payload = json.dumps(flat)
    await r.set(f"v1:{tenant}:posture", payload, ex=1800)
    await r.set(f"v1:{tenant}:posture:lkg", payload)   # sem expiry: rede de segurança anti-branco


async def _keep_posture(tenant: str) -> None:
    """Falha transitória do securityPosture: mantém o painel vivo com o último valor REAL.

    Renova o TTL se a chave viva existe; senão RESTAURA do LKG durável. Isso fecha o buraco do
    cold-start: se o coletor sobe durante um 500-storm, a chave viva nunca existiu e o expire()
    antigo era no-op -> o painel zerava (foi exatamente o que aconteceu). O LKG guarda a última
    leitura boa (dado real), então o painel nunca fica em branco depois do 1o sucesso."""
    try:
        if await r.exists(f"v1:{tenant}:posture"):
            await r.expire(f"v1:{tenant}:posture", 1800)
        else:
            lkg = await r.get(f"v1:{tenant}:posture:lkg")
            if lkg:
                await r.set(f"v1:{tenant}:posture", lkg, ex=1800)
                log.info("[%s] posture restaurado do último valor bom (LKG) — V1 indisponível no momento", tenant)
    except Exception:  # noqa: BLE001
        pass


async def tick_t1(v1: VisionOneClient):
    """60s: contadores de Workbench + Risk Index/postura detalhada."""
    try:
        wb = await tiers.workbench_counters(v1)
        mapping = {
            **{k: v for k, v in wb["severity"].items()},
            **{k.replace(" ", "_").lower(): v for k, v in wb["status"].items()},
        }
        await r.hset(f"v1:{TENANT}:wb:counters", mapping=mapping)
        await r.expire(f"v1:{TENANT}:wb:counters", 300)   # 5x o refresh (60s) — sobrevive a jitter/atraso de tick
        await r.publish(f"ws:{TENANT}", json.dumps({"type": "workbench", "data": mapping}))
        log.info("T1 workbench OK: %s", mapping)
    except Exception as exc:  # noqa: BLE001
        log.warning("T1 workbench falhou: %s", exc)

    try:
        posture = await _fetch_posture(v1, TENANT)   # retry c/ timeout curto p/ 500-intermitente
        flat = tiers.parse_posture(posture)
        # JSON (não hash): carrega vuln/surface/factors aninhados. _store_posture grava a chave viva
        # (TTL 30min) + LKG durável -> sobrevive a 500-storm e a cold-start sem zerar o painel.
        await _store_posture(TENANT, flat)
        await r.publish(f"ws:{TENANT}", json.dumps({"type": "posture", "data": flat}))
        log.info("T1 posture OK: riskIndex=%s exp=%s atk=%s cfg=%s cve=%s surf=%s fatores=%d agentes=%s",
                 flat["risk_index"], flat["exposure"], flat["attack"], flat["config"],
                 flat["cve_count"], flat["surface"].get("public_ip"), len(flat["factors"]),
                 flat["adoption"].get("agents"))
    except Exception as exc:  # noqa: BLE001
        log.warning("T1 posture (ASRM/CREM) indisponível: %s", _diag(exc))
        await _keep_posture(TENANT)   # renova TTL ou restaura do LKG durável (nunca zera)


async def tick_t2(v1: VisionOneClient):
    """5min: eventos OAT (tallies) + Risk Indicators."""
    try:
        ev = await tiers.event_tallies(v1)
        await r.hset(f"v1:{TENANT}:events", mapping=ev)
        await r.expire(f"v1:{TENANT}:events", 600)
        await r.publish(f"ws:{TENANT}", json.dumps({"type": "events", "data": ev}))
        log.info("T2 events OK: 24h=%s (delta %s%%) 7d=%s 30d=%s",
                 ev["e24h"], ev["delta24h"], ev["e7d"], ev["e30d"])
    except Exception as exc:  # noqa: BLE001
        log.warning("T2 events (OAT) falhou: %s", exc)

    try:
        risk = await tiers.high_risk(v1)
        await r.set(f"v1:{TENANT}:risk", json.dumps(risk), ex=600)
        await r.publish(f"ws:{TENANT}", json.dumps({"type": "risk", "data": risk}))
        log.info("T2 risk OK: %d itens%s", len(risk),
                 (" (top: " + risk[0]["name"] + ")" if risk else ""))
    except Exception as exc:  # noqa: BLE001
        log.warning("T2 risk (ASRM/CREM) indisponível: %s", exc)

    try:
        feed = await tiers.detections_feed(v1)
        await r.set(f"v1:{TENANT}:feed", json.dumps(feed), ex=600)
        await r.publish(f"ws:{TENANT}", json.dumps({"type": "feed", "data": feed}))
        log.info("T2 feed OK: %d detecções%s", len(feed),
                 (" (mais recente: " + feed[0]["name"] + ")" if feed else ""))
    except Exception as exc:  # noqa: BLE001
        log.warning("T2 feed (OAT) indisponível: %s", tiers.diag(exc))


async def tick_t3(v1: VisionOneClient):
    """15min: Attack Surface (contagem de ativos) + Mapa (geo)."""
    try:
        surf = await tiers.attack_surface_counts(v1)
        # mantém o último valor bom: grava só as métricas que vieram
        # (None = timeout transitório do backend de attack-surface -> conserva o anterior)
        mapping = {k: v for k, v in surf.items() if v is not None}
        if mapping:
            await r.hset(f"v1:{TENANT}:surface", mapping=mapping)
            await r.expire(f"v1:{TENANT}:surface", 1800)
        await r.publish(f"ws:{TENANT}", json.dumps({"type": "surface", "data": surf}))
        log.info("T3 surface OK: %s", surf)
    except Exception as exc:  # noqa: BLE001
        log.warning("T3 surface falhou: %s", _diag(exc))

    try:
        vuln = await tiers.vuln_metrics(v1)
        await r.set(f"v1:{TENANT}:vuln", json.dumps(vuln), ex=1800)
        await r.publish(f"ws:{TENANT}", json.dumps({"type": "vuln", "data": vuln}))
        log.info("T3 vuln OK: counts=%s top=%d", vuln["counts"], len(vuln["top"]))
    except Exception as exc:  # noqa: BLE001
        log.warning("T3 vuln falhou: %s", _diag(exc))

    try:
        mitre = await tiers.mitre_tactics(v1)
        mitre = await _merge_keep(f"v1:{TENANT}:mitre", mitre)   # keep-last-good: não zera tática que deu timeout
        await r.set(f"v1:{TENANT}:mitre", json.dumps(mitre), ex=1800)
        await r.publish(f"ws:{TENANT}", json.dumps({"type": "mitre", "data": mitre}))
        log.info("T3 mitre OK: %d/%d táticas com dado",
                 sum(1 for x in mitre.values() if x), len(mitre))
    except Exception as exc:  # noqa: BLE001
        log.warning("T3 mitre falhou: %s", _diag(exc))

    try:
        trend = await tiers.threat_trend(v1)
        await r.set(f"v1:{TENANT}:trend", json.dumps(trend), ex=1800)
        await r.publish(f"ws:{TENANT}", json.dumps({"type": "trend", "data": trend}))
        log.info("T3 trend OK: %d buckets", len(trend))
    except Exception as exc:  # noqa: BLE001
        log.warning("T3 trend falhou: %s", _diag(exc))

    try:
        ident = await tiers.identity_counts(v1)
        ident = await _merge_keep(f"v1:{TENANT}:identity", ident)   # keep-last-good
        await r.set(f"v1:{TENANT}:identity", json.dumps(ident), ex=1800)
        await r.publish(f"ws:{TENANT}", json.dumps({"type": "identity", "data": ident}))
        log.info("T3 identity OK: %s", ident)
    except Exception as exc:  # noqa: BLE001
        log.warning("T3 identity falhou: %s", _diag(exc))

    try:
        ioc = await tiers.suspicious_objects(v1)
        await r.set(f"v1:{TENANT}:ioc", json.dumps(ioc), ex=1800)
        await r.publish(f"ws:{TENANT}", json.dumps({"type": "ioc", "data": ioc}))
        log.info("T3 ioc OK: total=%s block=%s high=%s geo=%s tipos=%s",
                 ioc.get("total"), ioc.get("byAction", {}).get("block"),
                 ioc.get("high"), len(ioc.get("geo", [])), ioc.get("byType"))
    except Exception as exc:  # noqa: BLE001
        log.warning("T3 ioc falhou: %s", _diag(exc))

    try:
        ep = await tiers.endpoints_summary(v1)
        await r.set(f"v1:{TENANT}:endpoint", json.dumps(ep), ex=1800)
        await r.publish(f"ws:{TENANT}", json.dumps({"type": "endpoint", "data": ep}))
        log.info("T3 endpoint OK: total=%s edr_conn=%s edr_desc=%s epp_off=%s outdated=%s os=%s tipo=%s",
                 ep.get("total"), ep.get("edrConnected"), ep.get("edrDisconnected"),
                 ep.get("eppOff"), ep.get("outdated"), ep.get("os"), ep.get("type"))
    except Exception as exc:  # noqa: BLE001
        log.warning("T3 endpoint falhou: %s", _diag(exc))


async def tick_vuln(tenant: str, v1: VisionOneClient):
    """3600s POR TENANT: rankings de vulnerabilidade (tela Vulnerabilidades). Coleta pesada/lenta.

    Multi-tenant: agendado para o primario (prodesp) E os secundarios (detran/iamspe/sggd),
    cada um com seu cliente V1 -> escreve v1:{tenant}:vulnerabilities. Antes so o primario coletava."""
    try:
        vr = await tiers.vuln_rankings(v1)
        key = f"v1:{tenant}:vulnerabilities"
        try:
            prev_raw = await r.get(key)
            prev = json.loads(prev_raw) if prev_raw else {}
        except Exception:  # noqa: BLE001
            prev = {}
        # keep-last-good por ranking de topo (None conserva o anterior bom)
        vr = {k: (v if v is not None else prev.get(k)) for k, v in vr.items()}
        # keep-last-good ANINHADO do exploitSummary: total/nivel None conserva o anterior
        # (evita que uma contagem transitoriamente indisponivel vire 0 fabricado na TV)
        es, esp = vr.get("exploitSummary"), (prev or {}).get("exploitSummary")
        if isinstance(es, dict) and isinstance(esp, dict):
            for _k in ("total", "high", "medium", "low"):
                if es.get(_k) is None and esp.get(_k) is not None:
                    es[_k] = esp[_k]
        await r.set(key, json.dumps(vr), ex=7200)
        await r.publish(f"ws:{tenant}", json.dumps({"type": "vulnerabilities", "data": vr}))
        st = (vr.get("metadata") or {}).get("status", {})
        log.info("VULN[%s] OK: cves=%s servers=%s endpoints=%s apps=%s partial=%s", tenant,
                 st.get("topCves"), st.get("topServers"), st.get("topEndpoints"),
                 st.get("topApplications"), (vr.get("metadata") or {}).get("partial"))
    except Exception as exc:  # noqa: BLE001
        log.warning("VULN[%s] falhou: %s", tenant, _diag(exc))


# ---------------------------------------------------------------------------
# Dashboard multi-tenant (T1 leve) — SO a tela Dashboard e multi-tenant.
# Coleta o minimo por tenant secundario: Nivel de risco (posture) + Alertas
# (workbench) + Eventos. As demais telas seguem no tenant primario (Prodesp).
# ---------------------------------------------------------------------------
async def tick_dashboard(tenant: str, v1: VisionOneClient):
    """60s: posture + workbench + eventos de um tenant secundario -> chaves v1:{tenant}:*."""
    try:
        wb = await tiers.workbench_counters(v1)
        mapping = {
            **{k: v for k, v in wb["severity"].items()},
            **{k.replace(" ", "_").lower(): v for k, v in wb["status"].items()},
        }
        await r.hset(f"v1:{tenant}:wb:counters", mapping=mapping)
        await r.expire(f"v1:{tenant}:wb:counters", 300)
        await r.publish(f"ws:{tenant}", json.dumps({"type": "workbench", "data": mapping}))
        log.info("DASH[%s] workbench OK: %s", tenant, mapping)
    except Exception as exc:  # noqa: BLE001
        log.warning("DASH[%s] workbench falhou: %s", tenant, exc)

    try:
        posture = await _fetch_posture(v1, tenant)   # retry c/ timeout curto p/ 500-intermitente
        flat = tiers.parse_posture(posture)
        await _store_posture(tenant, flat)            # chave viva (TTL 30min) + LKG durável
        await r.publish(f"ws:{tenant}", json.dumps({"type": "posture", "data": flat}))
        log.info("DASH[%s] posture OK: riskIndex=%s exp=%s atk=%s cfg=%s cve=%s",
                 tenant, flat["risk_index"], flat["exposure"], flat["attack"],
                 flat["config"], flat["cve_count"])
    except Exception as exc:  # noqa: BLE001
        log.warning("DASH[%s] posture (ASRM/CREM) indisponivel: %s", tenant, _diag(exc))
        await _keep_posture(tenant)   # renova TTL ou restaura do LKG durável (nunca zera)

    try:
        ev = await tiers.event_tallies(v1)
        await r.hset(f"v1:{tenant}:events", mapping=ev)
        await r.expire(f"v1:{tenant}:events", 600)
        await r.publish(f"ws:{tenant}", json.dumps({"type": "events", "data": ev}))
        log.info("DASH[%s] events OK: 24h=%s 7d=%s 30d=%s", tenant, ev["e24h"], ev["e7d"], ev["e30d"])
    except Exception as exc:  # noqa: BLE001
        log.warning("DASH[%s] events falhou: %s", tenant, exc)


async def tick_soc(tenant: str, v1: VisionOneClient):
    """SOC multi-tenant (tenants SECUNDARIOS): feed + mitre + trend + identity -> v1:{tenant}:*.

    A tela Centro agrega os 4 tenants. O primario (prodesp) ja coleta esses tiers via t2/t3;
    aqui coletamos para detran/iamspe/sggd. Cada tier faz varias chamadas OAT (mitre 14, trend 12,
    identity 4, feed 1) -> por isso este job roda em cadencia LENTA (tier3=15min) e ESCALONADO,
    para nao congestionar o event loop e nao reintroduzir o misfire do tick_t1. TTL folgado (40min)
    p/ sobreviver ao intervalo longo + jitter. keep-last-good em mitre/identity (nao zera tatica)."""
    try:
        feed = await tiers.detections_feed(v1)
        await r.set(f"v1:{tenant}:feed", json.dumps(feed), ex=2400)
        log.info("SOC[%s] feed OK: %d detecções", tenant, len(feed))
    except Exception as exc:  # noqa: BLE001
        log.warning("SOC[%s] feed falhou: %s", tenant, tiers.diag(exc))
    try:
        mitre = await tiers.mitre_tactics(v1)
        mitre = await _merge_keep(f"v1:{tenant}:mitre", mitre)
        await r.set(f"v1:{tenant}:mitre", json.dumps(mitre), ex=2400)
        log.info("SOC[%s] mitre OK: %d/%d táticas", tenant, sum(1 for x in mitre.values() if x), len(mitre))
    except Exception as exc:  # noqa: BLE001
        log.warning("SOC[%s] mitre falhou: %s", tenant, _diag(exc))
    try:
        trend = await tiers.threat_trend(v1)
        await r.set(f"v1:{tenant}:trend", json.dumps(trend), ex=2400)
        log.info("SOC[%s] trend OK: %d buckets", tenant, len(trend))
    except Exception as exc:  # noqa: BLE001
        log.warning("SOC[%s] trend falhou: %s", tenant, _diag(exc))
    try:
        ident = await tiers.identity_counts(v1)
        ident = await _merge_keep(f"v1:{tenant}:identity", ident)
        await r.set(f"v1:{tenant}:identity", json.dumps(ident), ex=2400)
        log.info("SOC[%s] identity OK: %s", tenant, ident)
    except Exception as exc:  # noqa: BLE001
        log.warning("SOC[%s] identity falhou: %s", tenant, _diag(exc))


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if not settings.v1_api_token or settings.v1_api_token.startswith("__"):
        raise SystemExit("Defina V1_API_TOKEN em backend/.env antes de rodar o coletor.")

    v1 = VisionOneClient(settings.v1_api_token, settings.v1_api_base)
    # misfire_grace_time ALTO: com o loop congestionado (multi-tenant DASH + VULN pesados), um tick que
    # dispara alguns segundos atrasado NAO pode ser descartado. O default do APScheduler e 1s -> jobs
    # que caem no pico do minuto (ex.: tick_t1/posture do prodesp) chegavam 1-4s atrasados e eram
    # PERPETUAMENTE pulados -> posture do prodesp zerava (SEM DADOS). Com grace amplo + coalesce, o tick
    # atrasado ainda roda (uma vez). max_instances=1 evita overlap (o _guarded ja limita a duracao).
    sched = AsyncIOScheduler(job_defaults={"misfire_grace_time": 55, "coalesce": True, "max_instances": 1})
    now = datetime.now()

    def _to(interval):
        return max(20, int(interval * 0.85))   # timeout do tick < intervalo (evita overlap e hang permanente)

    def _guarded(fn, name, timeout):
        """Envolve um tick com timeout. Um tick travado é cancelado e NÃO bloqueia os próximos —
        com max_instances=1 do APScheduler, um await pendurado paralisaria o tier inteiro
        (foi o que zerou o painel do tenant primário: tick_t1 travou e workbench+posture pararam)."""
        async def _job(*args):
            try:
                await asyncio.wait_for(fn(*args), timeout)
            except asyncio.TimeoutError:
                log.warning("%s excedeu %ss e foi cancelado; o próximo tick seguirá normalmente", name, timeout)
            except Exception as exc:  # noqa: BLE001
                log.warning("%s erro não tratado: %s", name, exc)
        return _job

    # Execução imediata escalonada na subida (não espera o 1º intervalo de cada tier)
    sched.add_job(_guarded(tick_t1, "T1", _to(settings.tier1_interval)), "interval",
                  seconds=settings.tier1_interval, args=[v1], next_run_time=now)
    sched.add_job(_guarded(tick_t2, "T2", _to(settings.tier2_interval)), "interval",
                  seconds=settings.tier2_interval, args=[v1], next_run_time=now + timedelta(seconds=8))
    sched.add_job(_guarded(tick_t3, "T3", _to(settings.tier3_interval)), "interval",
                  seconds=settings.tier3_interval, args=[v1], next_run_time=now + timedelta(seconds=16))
    # --- Dashboard multi-tenant: tenants secundarios (posture+workbench+eventos) ---
    # sggd entra aqui p/ ter posture (headline de vuln da tela Vulnerabilidades); NAO altera a tela
    # Dashboard (que usa lista propria de 3 colunas no front).
    dash_clients = []
    _secondary = [("detran-sp", settings.v1_api_token_detran),
                  ("iamspe-sp", settings.v1_api_token_iamspe),
                  ("sggd", settings.v1_api_token_sggd),
                  ("poupatempo", settings.v1_api_token_poupatempo),
                  ("spi", settings.v1_api_token_spi),
                  ("alesp", settings.v1_api_token_alesp),
                  ("cptm", settings.v1_api_token_cptm)]
    _vuln_clients = [(TENANT, v1)]   # coleta de vuln: primario + secundarios com token
    for _i, (_tid, _tok) in enumerate(_secondary):
        if not _tok:
            log.warning("Dashboard: token de %s ausente -> tenant pulado", _tid)
            continue
        _c = VisionOneClient(_tok, settings.v1_api_base)
        dash_clients.append(_c)
        _vuln_clients.append((_tid, _c))
        # stagger ESPALHADO ao longo do minuto (2..~46s): com 7 secundarios, concentrar as chamadas
        # no mesmo instante atrasaria o tick_t1 do prodesp (misfire). Espalhar reduz o pico do loop.
        sched.add_job(_guarded(tick_dashboard, f"DASH[{_tid}]", _to(settings.tier1_interval)), "interval",
                      seconds=settings.tier1_interval, args=[_tid, _c], next_run_time=now + timedelta(seconds=2 + _i * 7))
    # --- Vulnerabilidades multi-tenant: rankings pesados por tenant, horario e ESCALONADO ---
    for _j, (_tid, _cli) in enumerate(_vuln_clients):
        sched.add_job(_guarded(tick_vuln, f"VULN[{_tid}]", _to(settings.tier4_interval)), "interval",
                      seconds=settings.tier4_interval, args=[_tid, _cli], next_run_time=now + timedelta(seconds=24 + _j * 20))
    # --- SOC (tela Centro) multi-tenant: feed/mitre/trend/identity dos SECUNDARIOS, LENTO (15min) e ESCALONADO ---
    # ~31 chamadas OAT por tenant; cadencia longa + stagger de 120s evita congestionar o loop (protege o tick_t1).
    _soc_secondary = [(t, c) for (t, c) in _vuln_clients if t != TENANT]
    for _k, (_tid, _cli) in enumerate(_soc_secondary):
        sched.add_job(_guarded(tick_soc, f"SOC[{_tid}]", _to(settings.tier3_interval)), "interval",
                      seconds=settings.tier3_interval, args=[_tid, _cli], next_run_time=now + timedelta(seconds=40 + _k * 120))
    sched.start()
    log.info("Coletor iniciado | primario=%s | dashboard=%s | vuln=%s | soc=%s | T1=%ss T2=%ss T3=%ss T4=%ss",
             TENANT, [t for t, _ in _secondary], [t for t, _ in _vuln_clients], [t for t, _ in _soc_secondary],
             settings.tier1_interval, settings.tier2_interval, settings.tier3_interval, settings.tier4_interval)
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        await v1.aclose()
        for _c in dash_clients:
            await _c.aclose()
        await r.aclose()


if __name__ == "__main__":
    asyncio.run(main())
