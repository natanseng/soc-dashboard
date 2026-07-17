"""Cyber Risk Subindexes por grupo de ativos (ASRM /v3.0/asrm/assetGroups), por tenant.

Endpoint read-only, multi-tenant: token resolvido por tenant (sem hardcode). Cache curto
em Redis (dado pequeno, muda ~por hora) para nao chamar a V1 a cada refresh do wallboard.
Nunca expoe token/DSN. Nunca lanca: retorna status ok | unavailable | invalid.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from .cyber_tokens import resolve_token

log = logging.getLogger("cyber.asset_groups")

ASSET_GROUPS_PATH = "/v3.0/asrm/assetGroups"
SECURITY_POSTURE_PATH = "/v3.0/asrm/securityPosture"
CACHE_TTL = 600          # 10 min
CACHE_PREFIX = "cyber:assetgroups:"


def normalize(items) -> list:
    """Achata os grupos do assetGroups nos campos que o wallboard consome.

    riskIndex/assetCount podem ser 0 (validos). O frontend diferencia assetCount==0
    (grupo sem ativos -> subindice '—') de indisponivel (status != ok).
    """
    out = []
    for it in items or []:
        out.append({
            "name": it.get("name"),
            "riskIndex": it.get("riskIndex"),
            "riskLevel": it.get("riskLevel"),
            "assetCount": it.get("assetCount"),
            "isRoot": not it.get("parent"),          # parent None/"" -> raiz (Global / organizacao)
            "updatedDateTime": it.get("updatedDateTime"),
        })
    return out


def parse_surface(posture) -> tuple:
    """Superfície de ataque + níveis da organização a partir do securityPosture (mesmos
    campos da tela executiva). None quando ausente -> frontend mostra '—' (regra nunca-zero)."""
    p = posture or {}
    exp = p.get("exposureStatus") or {}
    inet = exp.get("unexpectedInternetFacingInterfaceStatus") or {}
    host = exp.get("insecureHostConnectionStatus") or {}
    acct = exp.get("domainAccountMisconfigurationStatus") or {}
    cloud = exp.get("cloudAssetMisconfigurationStatus") or {}
    cvm = p.get("cveManagementMetrics") or {}
    rcl = p.get("riskCategoryLevel") or {}
    surface = {
        "public_ip": inet.get("publicIpCount"),
        "ports": inet.get("servicePortCount"),
        "insecure_hosts": host.get("insecureHostCount"),
        "weak_auth": acct.get("weakAuthenticationCount"),
        "cloud_high": cloud.get("highRiskCount"),
        "cve_count": cvm.get("count"),
    }
    levels = {"exposure": rcl.get("exposure"), "attack": rcl.get("attack"),
              "config": rcl.get("securityConfiguration")}
    return surface, levels


async def _tenant_name(pool, tenant_id):
    """display_name do tenant habilitado p/ Cyber; None se nao existir/inhabilitado."""
    row = await pool.fetchrow(
        "SELECT t.display_name FROM cyber_tenant_config c JOIN tenant t ON t.tenant_id=c.tenant_id "
        "WHERE c.tenant_id=$1 AND c.cyber_enabled AND c.enabled", tenant_id)
    return row["display_name"] if row else None


async def get_asset_groups(pool, redis, tenant_id, *, client_factory=None) -> dict:
    """Subindices por grupo de ativos de um tenant. Nunca lanca; nunca expoe token."""
    now_iso = datetime.now(timezone.utc).isoformat()

    def _payload(status, groups=None, **extra):
        return {"status": status, "tenantId": tenant_id, "groups": groups or [],
                "updatedAt": now_iso, **extra}

    if pool is None:
        return _payload("unavailable", reason="db_down")
    try:
        name = await _tenant_name(pool, tenant_id)
    except Exception:  # noqa: BLE001 — nao vazar detalhes internos/DSN
        return _payload("unavailable", reason="db_error")
    if name is None:
        return _payload("invalid")

    ts = resolve_token(tenant_id)
    if not ts.configured:
        return _payload("unavailable", reason="no_token", tenantName=name)

    cache_key = CACHE_PREFIX + tenant_id
    if redis is not None:
        try:
            cached = await redis.get(cache_key)
            if cached:
                p = json.loads(cached)
                p["cached"] = True
                return p
        except Exception:  # noqa: BLE001
            pass

    from collectors.cyber_http import CyberClient  # import tardio: evita dependencia no import do app
    client = (client_factory or CyberClient)(ts.token)
    surface, levels = None, {}
    try:
        try:
            d = await client.get_json(ASSET_GROUPS_PATH, timeout=60)
        except Exception as exc:  # noqa: BLE001 — assetGroups e o dado principal (subindices)
            log.warning("assetGroups falhou tenant=%s: %s", tenant_id, type(exc).__name__)
            return _payload("unavailable", reason="api_error", tenantName=name)
        try:                       # superficie de ataque da organizacao (complementar; nao derruba)
            posture = await client.get_json(SECURITY_POSTURE_PATH, timeout=60)
            surface, levels = parse_surface(posture)
        except Exception as exc:  # noqa: BLE001
            log.info("securityPosture indisponivel tenant=%s: %s", tenant_id, type(exc).__name__)
    finally:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001
            pass

    payload = _payload("ok", groups=normalize(d.get("items")), tenantName=name,
                       surface=surface, levels=levels, cached=False)
    if redis is not None:
        try:
            await redis.set(cache_key, json.dumps(payload), ex=CACHE_TTL)
        except Exception:  # noqa: BLE001
            pass
    return payload
