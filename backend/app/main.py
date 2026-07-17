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

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .cache import get_redis
from . import db, cyber_registry, cyber_tokens


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
        return {"status": "unavailable", "organizations": [], "updatedAt": now_iso}
    try:
        organizations = await cyber_registry.fetch_cyber_registry(pool)
    except Exception:  # noqa: BLE001 — nao vazar detalhes internos/DSN
        return {"status": "unavailable", "organizations": [], "updatedAt": now_iso}
    return cyber_registry.build_payload(
        organizations, cyber_tokens.resolve_token, updated_at=now_iso
    )


# ---- Dashboard estático (mesma origem -> sem CORS) ----
# Coloque o index.html em backend/static/. O mount fica POR ÚLTIMO para não
# sombrear as rotas de API acima; '/' passa a servir o dashboard.
_STATIC = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.isdir(_STATIC):
    app.mount("/", StaticFiles(directory=_STATIC, html=True), name="static")
