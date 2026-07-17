"""Cadastro dinamico Cyber (read-only) — modelo TENANT -> N ORGANIZATIONS.

Fonte unica de verdade de quais tenants e, dentro deles, quais orgaos participam da tela
Cyber: `tenant` + `cyber_tenant_config` + `organization` (organization.tenant_id). NAO ha
lista hardcoded de tenants/orgaos — novos registros aparecem apenas inserindo linhas.

Cardinalidade: um tenant pode conter 1..N orgaos. Um orgao pertence a exatamente um tenant.

Criterios de tenant habilitado:
  * cyber_tenant_config.cyber_enabled = true
  * cyber_tenant_config.enabled = true
Criterios de orgao habilitado (dentro do tenant):
  * organization.enabled = true
  * organization.cyber_enabled = true
Ordenacao: tenants por display_name; orgaos por (display_order, name).

Este modulo NAO grava nada e NAO manipula tokens (resolucao de token e feita a parte).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List

from .cyber_tokens import TokenStatus, resolve_token

_TENANTS_SQL = """
SELECT t.tenant_id,
       t.display_name AS tenant_name,
       t.region_base,
       c.oat_enabled,
       c.workbench_enabled,
       c.suspicious_objects_enabled
FROM cyber_tenant_config c
JOIN tenant t ON t.tenant_id = c.tenant_id
WHERE c.cyber_enabled = true
  AND c.enabled = true
ORDER BY t.display_name, t.tenant_id
"""

_ORGS_SQL = """
SELECT tenant_id,
       organization_id,
       name AS organization_name,
       display_order,
       cyber_enabled,
       attribution_enabled
FROM organization
WHERE enabled = true
  AND cyber_enabled = true
ORDER BY tenant_id, display_order, name
"""


@dataclass(frozen=True)
class CyberOrganization:
    organization_id: str
    organization_name: str
    display_order: int
    cyber_enabled: bool
    attribution_enabled: bool


@dataclass
class CyberTenant:
    tenant_id: str
    tenant_name: str
    region_base: str
    oat_enabled: bool
    workbench_enabled: bool
    suspicious_objects_enabled: bool
    organizations: List[CyberOrganization] = field(default_factory=list)


async def fetch_cyber_registry(pool) -> List[CyberTenant]:
    """Le tenants habilitados e, dentro de cada um, seus orgaos habilitados (tenant -> N orgs).

    Um tenant sem orgaos habilitados aparece com organizations=[] (nao e removido)."""
    async with pool.acquire() as conn:
        tenant_rows = await conn.fetch(_TENANTS_SQL)
        org_rows = await conn.fetch(_ORGS_SQL)

    orgs_by_tenant: dict[str, List[CyberOrganization]] = {}
    for r in org_rows:
        orgs_by_tenant.setdefault(r["tenant_id"], []).append(
            CyberOrganization(
                organization_id=r["organization_id"],
                organization_name=r["organization_name"],
                display_order=r["display_order"],
                cyber_enabled=r["cyber_enabled"],
                attribution_enabled=r["attribution_enabled"],
            )
        )

    tenants: List[CyberTenant] = []
    for r in tenant_rows:
        tenants.append(
            CyberTenant(
                tenant_id=r["tenant_id"],
                tenant_name=r["tenant_name"],
                region_base=r["region_base"],
                oat_enabled=r["oat_enabled"],
                workbench_enabled=r["workbench_enabled"],
                suspicious_objects_enabled=r["suspicious_objects_enabled"],
                organizations=orgs_by_tenant.get(r["tenant_id"], []),
            )
        )
    return tenants


def build_payload(
    tenants: List[CyberTenant],
    resolve: Callable[[str], TokenStatus] = resolve_token,
    *,
    updated_at: str,
) -> dict:
    """Monta o objeto publico de GET /cyber/tenants no formato TENANT -> ORGANIZATIONS.

    NUNCA inclui token, nome de variavel de ambiente, DSN, senha ou headers.
    Tenant sem token: credentialsConfigured=false e status='configuration_error' (os orgaos
    do tenant continuam listados; a indisponibilidade e do tenant, nao derruba outros tenants).
    """
    out_tenants = []
    for t in tenants:
        status = resolve(t.tenant_id)
        configured = bool(status.configured)
        out_tenants.append(
            {
                "tenantId": t.tenant_id,
                "tenantName": t.tenant_name,
                "regionBase": t.region_base,
                "status": "ok" if configured else "configuration_error",
                "credentialsConfigured": configured,
                "sources": {
                    "oat": bool(t.oat_enabled),
                    "workbench": bool(t.workbench_enabled),
                    "suspiciousObjects": bool(t.suspicious_objects_enabled),
                },
                "organizations": [
                    {
                        "organizationId": o.organization_id,
                        "organizationName": o.organization_name,
                        "displayOrder": o.display_order,
                        "cyberEnabled": bool(o.cyber_enabled),
                        "attributionEnabled": bool(o.attribution_enabled),
                    }
                    for o in t.organizations
                ],
            }
        )
    return {"status": "ok", "tenants": out_tenants, "updatedAt": updated_at}
