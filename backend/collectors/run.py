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
        posture = await tiers.security_posture(v1)
        flat = tiers.parse_posture(posture)
        # JSON (não hash): agora carrega vuln/surface/factors aninhados.
        # ex=1800 mantém o último valor bom durante 500s intermitentes do securityPosture.
        await r.set(f"v1:{TENANT}:posture", json.dumps(flat), ex=1800)
        await r.publish(f"ws:{TENANT}", json.dumps({"type": "posture", "data": flat}))
        log.info("T1 posture OK: riskIndex=%s exp=%s atk=%s cfg=%s cve=%s surf=%s fatores=%d agentes=%s",
                 flat["risk_index"], flat["exposure"], flat["attack"], flat["config"],
                 flat["cve_count"], flat["surface"].get("public_ip"), len(flat["factors"]),
                 flat["adoption"].get("agents"))
    except Exception as exc:  # noqa: BLE001
        log.warning("T1 posture (ASRM/CREM) indisponível: %s", _diag(exc))
        try:  # keep-last-good: renova o TTL do último valor bom p/ não zerar o painel numa falha transitória
            await r.expire(f"v1:{TENANT}:posture", 1800)
        except Exception:  # noqa: BLE001
            pass


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


async def tick_t4(v1: VisionOneClient):
    """3600s: rankings de vulnerabilidade (tela Vulnerabilidades). Coleta pesada/lenta."""
    try:
        vr = await tiers.vuln_rankings(v1)
        key = f"v1:{TENANT}:vulnerabilities"
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
        await r.publish(f"ws:{TENANT}", json.dumps({"type": "vulnerabilities", "data": vr}))
        st = (vr.get("metadata") or {}).get("status", {})
        log.info("T4 vulnerabilities OK: cves=%s servers=%s endpoints=%s apps=%s partial=%s",
                 st.get("topCves"), st.get("topServers"), st.get("topEndpoints"),
                 st.get("topApplications"), (vr.get("metadata") or {}).get("partial"))
    except Exception as exc:  # noqa: BLE001
        log.warning("T4 vulnerabilities falhou: %s", _diag(exc))


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
        posture = await tiers.security_posture(v1)
        flat = tiers.parse_posture(posture)
        await r.set(f"v1:{tenant}:posture", json.dumps(flat), ex=1800)
        await r.publish(f"ws:{tenant}", json.dumps({"type": "posture", "data": flat}))
        log.info("DASH[%s] posture OK: riskIndex=%s exp=%s atk=%s cfg=%s cve=%s",
                 tenant, flat["risk_index"], flat["exposure"], flat["attack"],
                 flat["config"], flat["cve_count"])
    except Exception as exc:  # noqa: BLE001
        log.warning("DASH[%s] posture (ASRM/CREM) indisponivel: %s", tenant, _diag(exc))
        try:  # keep-last-good: renova o TTL do último valor bom (nao zera o painel do tenant)
            await r.expire(f"v1:{tenant}:posture", 1800)
        except Exception:  # noqa: BLE001
            pass

    try:
        ev = await tiers.event_tallies(v1)
        await r.hset(f"v1:{tenant}:events", mapping=ev)
        await r.expire(f"v1:{tenant}:events", 600)
        await r.publish(f"ws:{tenant}", json.dumps({"type": "events", "data": ev}))
        log.info("DASH[%s] events OK: 24h=%s 7d=%s 30d=%s", tenant, ev["e24h"], ev["e7d"], ev["e30d"])
    except Exception as exc:  # noqa: BLE001
        log.warning("DASH[%s] events falhou: %s", tenant, exc)


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if not settings.v1_api_token or settings.v1_api_token.startswith("__"):
        raise SystemExit("Defina V1_API_TOKEN em backend/.env antes de rodar o coletor.")

    v1 = VisionOneClient(settings.v1_api_token, settings.v1_api_base)
    sched = AsyncIOScheduler()
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
    sched.add_job(_guarded(tick_t4, "T4", _to(settings.tier4_interval)), "interval",
                  seconds=settings.tier4_interval, args=[v1], next_run_time=now + timedelta(seconds=24))
    # --- Dashboard multi-tenant: tenants secundarios (so posture+workbench+eventos) ---
    dash_clients = []
    _secondary = [("detran-sp", settings.v1_api_token_detran),
                  ("iamspe-sp", settings.v1_api_token_iamspe)]
    for _i, (_tid, _tok) in enumerate(_secondary):
        if not _tok:
            log.warning("Dashboard: token de %s ausente -> tenant pulado", _tid)
            continue
        _c = VisionOneClient(_tok, settings.v1_api_base)
        dash_clients.append(_c)
        sched.add_job(_guarded(tick_dashboard, f"DASH[{_tid}]", _to(settings.tier1_interval)), "interval",
                      seconds=settings.tier1_interval, args=[_tid, _c], next_run_time=now + timedelta(seconds=4 + _i * 2))
    sched.start()
    log.info("Coletor iniciado | primario=%s | dashboard=%s | T1=%ss T2=%ss T3=%ss",
             TENANT, [t for t, _ in _secondary], settings.tier1_interval,
             settings.tier2_interval, settings.tier3_interval)
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
