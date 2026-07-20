"""Backend FastAPI — leitura do cache (Redis) + push via WebSocket + serve o dashboard.

Endpoints:
  GET  /healthz                 -> liveness + status do Redis
  GET  /api/{tenant}/overview   -> snapshot consumido pela tela executiva
  WS   /ws/{tenant}             -> deltas em tempo real (posture/workbench/attack)
  GET  /                        -> serve o dashboard (backend/static/index.html), MESMA ORIGEM
"""
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .cache import get_redis
from . import db, cyber_registry, cyber_tokens, cyber_api, cyber_asset_groups, cyber_alerts_api


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.redis = get_redis()  # conexão preguiçosa; não falha se o Redis estiver fora ainda
    await db.init_pool()           # pool PostgreSQL (Cyber); falha-segura se o banco estiver fora
    yield
    await db.close_pool()
    await app.state.redis.aclose()


app = FastAPI(title="SOC Dashboard API", version="1.0", lifespan=lifespan)

# Mantido por compatibilidade (ex.: abrir o dashboard em :5173). Servindo na mesma origem, nem é exigido.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/healthz")
async def healthz():
    # Redis: comportamento atual PRESERVADO (mesmas chaves status/redis[/error]).
    try:
        pong = await app.state.redis.ping()
        result = {"status": "ok", "redis": bool(pong)}
    except Exception as exc:  # noqa: BLE001
        result = {"status": "degraded", "redis": False, "error": str(exc)}
    # PostgreSQL: aditivo e isolado — uma falha aqui NAO altera o status do Redis acima.
    try:
        result["postgres"] = await db.check_health()  # 'ok' | 'error' | 'unavailable'
    except Exception:  # noqa: BLE001
        result["postgres"] = "error"
    return result


@app.get("/api/{tenant}/overview")
async def overview(tenant: str):
    r = app.state.redis
    posture_raw = await r.get(f"v1:{tenant}:posture")
    risk_raw = await r.get(f"v1:{tenant}:risk")
    vuln_raw = await r.get(f"v1:{tenant}:vuln")
    mitre_raw = await r.get(f"v1:{tenant}:mitre")
    feed_raw = await r.get(f"v1:{tenant}:feed")
    trend_raw = await r.get(f"v1:{tenant}:trend")
    ident_raw = await r.get(f"v1:{tenant}:identity")
    ioc_raw = await r.get(f"v1:{tenant}:ioc")
    endpoint_raw = await r.get(f"v1:{tenant}:endpoint")
    vulns_raw = await r.get(f"v1:{tenant}:vulnerabilities")
    return {
        "tenant": tenant,
        "posture": json.loads(posture_raw) if posture_raw else {},
        "workbench": await r.hgetall(f"v1:{tenant}:wb:counters"),
        "events": await r.hgetall(f"v1:{tenant}:events"),
        "surface": await r.hgetall(f"v1:{tenant}:surface"),
        "vuln": json.loads(vuln_raw) if vuln_raw else {},
        "mitre": json.loads(mitre_raw) if mitre_raw else {},
        "feed": json.loads(feed_raw) if feed_raw else [],
        "trend": json.loads(trend_raw) if trend_raw else [],
        "identity": json.loads(ident_raw) if ident_raw else {},
        "ioc": json.loads(ioc_raw) if ioc_raw else {},
        "endpoint": json.loads(endpoint_raw) if endpoint_raw else {},
        "vulnerabilities": json.loads(vulns_raw) if vulns_raw else {},
        "risk": json.loads(risk_raw) if risk_raw else [],
        "attackers": await r.zrevrange(f"v1:{tenant}:map:attackers", 0, 9, withscores=True),
    }


@app.websocket("/ws/{tenant}")
async def ws(sock: WebSocket, tenant: str):
    await sock.accept()
    r = get_redis()
    pubsub = r.pubsub()
    await pubsub.subscribe(f"ws:{tenant}")
    try:
        async for msg in pubsub.listen():
            if msg["type"] == "message":
                await sock.send_text(msg["data"])
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(f"ws:{tenant}")
        await pubsub.aclose()
        await r.aclose()


@app.get("/cyber/tenants")
async def cyber_tenants():
    """Cadastro Cyber (read-only) para uso futuro. Nao expoe token/DSN/variavel/headers.

    - Banco indisponivel: status='unavailable', organizations=[] (nao derruba nada).
    - Tenant habilitado sem token: permanece na lista com credentialsConfigured=false.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    pool = db.get_pool()
    if pool is None:
        return {"status": "unavailable", "tenants": [], "updatedAt": now_iso}
    try:
        tenants = await cyber_registry.fetch_cyber_registry(pool)
    except Exception:  # noqa: BLE001 — nao vazar detalhes internos/DSN
        return {"status": "unavailable", "tenants": [], "updatedAt": now_iso}
    return cyber_registry.build_payload(
        tenants, cyber_tokens.resolve_token, updated_at=now_iso
    )


@app.get("/cyber/asset-groups")
async def cyber_asset_groups_route(tenantId: str):
    """Cyber Risk Subindexes por grupo de ativos (ASRM) de um tenant.

    status: ok | unavailable (sem token/DB/erro de API) | invalid (tenant nao habilitado).
    Cache curto em Redis; nunca expoe token.
    """
    pool = db.get_pool()
    redis = getattr(app.state, "redis", None)
    return await cyber_asset_groups.get_asset_groups(pool, redis, tenantId)


# ---------------------------------------------------------------------------
# Tela "Alertas": workbenches consolidados (read-only sobre cyber_workbench_alert)
# ---------------------------------------------------------------------------
async def _alerts_call(fn, **kw):
    pool = db.get_pool()
    if pool is None:
        return {"status": "unavailable"}
    try:
        return await fn(pool, **kw)
    except Exception:  # noqa: BLE001 — nao vaza detalhes internos/DSN
        return {"status": "unavailable"}


@app.get("/alerts/summary")
async def alerts_summary():
    return await _alerts_call(cyber_alerts_api.summary)


@app.get("/alerts/by-tenant")
async def alerts_by_tenant():
    return await _alerts_call(cyber_alerts_api.by_tenant)


@app.get("/alerts/by-organization")
async def alerts_by_organization(tenantId: Optional[str] = None):
    return await _alerts_call(cyber_alerts_api.by_organization, tenant_id=tenantId)


@app.get("/alerts/by-subindex")
async def alerts_by_subindex(tenantId: str):
    return await _alerts_call(cyber_alerts_api.by_subindex, tenant_id=tenantId)


@app.get("/alerts/history")
async def alerts_history(days: int = 30):
    return await _alerts_call(cyber_alerts_api.history, days=days)


@app.get("/alerts/events")
async def alerts_events(tenantId: Optional[str] = None, organizationId: Optional[str] = None,
                        severity: Optional[str] = None, status: Optional[str] = None,
                        modelType: Optional[str] = None, unassigned: bool = False, limit: int = 100):
    return await _alerts_call(cyber_alerts_api.events, tenant_id=tenantId, organization_id=organizationId,
                              severity=severity, status=status, model_type=modelType,
                              unassigned=unassigned, limit=limit)


@app.get("/cyber/summary")
async def cyber_summary(tenantId: Optional[str] = None, organizationId: Optional[str] = None,
                        severity: Optional[str] = None, enforcementStatus: Optional[str] = None,
                        attributionStatus: Optional[str] = None, hours: Optional[int] = None):
    pool = db.get_pool()
    if pool is None:
        return {"status": "unavailable"}
    if not await cyber_api.validate_org_in_tenant(pool, tenantId, organizationId):
        return {"status": "invalid", "error": "organization does not belong to tenant"}
    try:
        return await cyber_api.summary(pool, tenant_id=tenantId, organization_id=organizationId, severity=severity,
                                       enforcement_status=enforcementStatus, attribution_status=attributionStatus, hours=hours)
    except Exception:  # noqa: BLE001
        return {"status": "unavailable"}


@app.get("/cyber/by-tenant")
async def cyber_by_tenant():
    pool = db.get_pool()
    if pool is None:
        return {"status": "unavailable", "tenants": []}
    try:
        return await cyber_api.by_tenant(pool)
    except Exception:  # noqa: BLE001
        return {"status": "unavailable", "tenants": []}


@app.get("/cyber/by-organization")
async def cyber_by_organization(tenantId: Optional[str] = None, organizationId: Optional[str] = None,
                                severity: Optional[str] = None, enforcementStatus: Optional[str] = None,
                                hours: Optional[int] = None):
    pool = db.get_pool()
    if pool is None:
        return {"status": "unavailable", "organizations": []}
    if not await cyber_api.validate_org_in_tenant(pool, tenantId, organizationId):
        return {"status": "invalid", "error": "organization does not belong to tenant"}
    try:
        return await cyber_api.by_organization(pool, tenant_id=tenantId, organization_id=organizationId,
                                               severity=severity, enforcement_status=enforcementStatus, hours=hours)
    except Exception:  # noqa: BLE001
        return {"status": "unavailable", "organizations": []}


@app.get("/cyber/organizations")
async def cyber_organizations():
    pool = db.get_pool()
    if pool is None:
        return {"status": "unavailable", "tenants": []}
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        tenants = await cyber_registry.fetch_cyber_registry(pool)
        return cyber_registry.build_payload(tenants, cyber_tokens.resolve_token, updated_at=now_iso)
    except Exception:  # noqa: BLE001
        return {"status": "unavailable", "tenants": []}


@app.get("/cyber/map")
async def cyber_map(tenantId: Optional[str] = None, organizationId: Optional[str] = None,
                    severity: Optional[str] = None, layer: Optional[str] = None, hours: Optional[int] = None):
    pool = db.get_pool()
    if pool is None:
        return {"status": "unavailable", "clusters": []}
    if not await cyber_api.validate_org_in_tenant(pool, tenantId, organizationId):
        return {"status": "invalid", "error": "organization does not belong to tenant"}
    try:
        return await cyber_api.map_points(pool, layer=layer, tenant_id=tenantId, organization_id=organizationId,
                                          severity=severity, hours=hours)
    except Exception:  # noqa: BLE001
        return {"status": "unavailable", "clusters": []}


@app.get("/cyber/events")
async def cyber_events(tenantId: Optional[str] = None, organizationId: Optional[str] = None,
                       severity: Optional[str] = None, enforcementStatus: Optional[str] = None,
                       attributionStatus: Optional[str] = None, hours: Optional[int] = None, limit: int = 100):
    pool = db.get_pool()
    if pool is None:
        return {"status": "unavailable", "events": []}
    if not await cyber_api.validate_org_in_tenant(pool, tenantId, organizationId):
        return {"status": "invalid", "error": "organization does not belong to tenant"}
    try:
        return await cyber_api.events(pool, limit=min(max(limit, 1), 1000), tenant_id=tenantId,
                                      organization_id=organizationId, severity=severity,
                                      enforcement_status=enforcementStatus, attribution_status=attributionStatus, hours=hours)
    except Exception:  # noqa: BLE001
        return {"status": "unavailable", "events": []}


@app.get("/cyber/coverage")
async def cyber_coverage():
    pool = db.get_pool()
    if pool is None:
        return {"status": "unavailable"}
    try:
        return await cyber_api.coverage(pool)
    except Exception:  # noqa: BLE001
        return {"status": "unavailable"}


@app.get("/cyber/waf")
async def cyber_waf():
    pool = db.get_pool()
    if pool is None:
        return {"status": "unavailable"}
    try:
        return await cyber_api.waf_blocks(pool)
    except Exception:  # noqa: BLE001
        return {"status": "unavailable"}


@app.get("/cyber/status")
async def cyber_status():
    pool = db.get_pool()
    if pool is None:
        return {"status": "unavailable", "collectors": []}
    try:
        return await cyber_api.status(pool)
    except Exception:  # noqa: BLE001
        return {"status": "unavailable", "collectors": []}


# ---- Dashboard estático (mesma origem -> sem CORS) ----
# Coloque o index.html em backend/static/. O mount fica POR ÚLTIMO para não
# sombrear as rotas de API acima; '/' passa a servir o dashboard.
_STATIC = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.isdir(_STATIC):
    app.mount("/", StaticFiles(directory=_STATIC, html=True), name="static")
