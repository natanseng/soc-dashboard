"""Cadastro dinamico de organizacoes e tenants Cyber (read-only).

Fonte unica de verdade para "quais orgaos/tenants participam da tela Cyber": as tabelas
`organization`, `cyber_tenant_config` e `tenant`. NAO ha lista hardcoded de orgaos — novos
orgaos/tenants aparecem apenas inserindo linhas (seed/DML), sem alterar codigo.

Criterios (todos obrigatorios):
  * organization.enabled       = true
  * organization.cyber_enabled = true
  * cyber_tenant_config.cyber_enabled = true
  * tenant existente (garantido pelo JOIN). Obs.: a tabela base `tenant` nao possui coluna
    de habilitacao propria; a habilitacao Cyber do tenant vive em cyber_tenant_config.

Ordenacao: organization.display_order, organization.name, tenant.display_name.

Este modulo NAO grava nada e NAO manipula tokens (a resolucao de token e feita a parte).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List

from .cyber_tokens import TokenStatus, resolve_token

# tenant existente e habilitado via JOIN + flags; ordenacao exigida no contrato.
_REGISTRY_SQL = """
SELECT o.organization_id,
       o.name              AS organization_name,
       o.display_order,
       t.tenant_id,
       t.display_name      AS tenant_name,
       t.region_base,
       c.oat_enabled,
       c.workbench_enabled,
       c.suspicious_objects_enabled
FROM organization o
JOIN cyber_tenant_config c ON c.organization_id = o.organization_id
JOIN tenant t             ON t.tenant_id = c.tenant_id
WHERE o.enabled = true
  AND o.cyber_enabled = true
  AND c.cyber_enabled = true
ORDER BY o.display_order, o.name, t.display_name
"""


@dataclass(frozen=True)
class CyberTenant:
    tenant_id: str
    tenant_name: str
    region_base: str
    oat_enabled: bool
    workbench_enabled: bool
    suspicious_objects_enabled: bool


@dataclass
class CyberOrganization:
    organization_id: str
    organization_name: str
    display_order: int
    tenants: List[CyberTenant] = field(default_factory=list)


async def fetch_cyber_registry(pool) -> List[CyberOrganization]:
    """Le o cadastro habilitado do banco e agrupa por organizacao (um orgao -> N tenants)."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(_REGISTRY_SQL)

    orgs: dict[str, CyberOrganization] = {}
    order: List[str] = []
    for r in rows:
        oid = r["organization_id"]
        if oid not in orgs:
            orgs[oid] = CyberOrganization(
                organization_id=oid,
                organization_name=r["organization_name"],
                display_order=r["display_order"],
            )
            order.append(oid)
        orgs[oid].tenants.append(
            CyberTenant(
                tenant_id=r["tenant_id"],
                tenant_name=r["tenant_name"],
                region_base=r["region_base"],
                oat_enabled=r["oat_enabled"],
                workbench_enabled=r["workbench_enabled"],
                suspicious_objects_enabled=r["suspicious_objects_enabled"],
            )
        )
    return [orgs[o] for o in order]


def build_payload(
    organizations: List[CyberOrganization],
    resolve: Callable[[str], TokenStatus] = resolve_token,
    *,
    updated_at: str,
) -> dict:
    """Monta o objeto publico de GET /cyber/tenants (funcao pura, sem I/O).

    NUNCA inclui token, nome de variavel de ambiente, DSN, senha ou headers.
    Tenant habilitado sem token: permanece na resposta com credentialsConfigured=false e
    status='configuration_error' (nao derruba os demais).
    """
    out_orgs = []
    for org in organizations:
        tenants_out = []
        org_all_ready = True
        for t in org.tenants:
            status = resolve(t.tenant_id)
            configured = bool(status.configured)
            if not configured:
                org_all_ready = False
            tenants_out.append(
                {
                    "tenantId": t.tenant_id,
                    "tenantName": t.tenant_name,
                    "regionBase": t.region_base,
                    "cyberEnabled": True,
                    "sources": {
                        "oat": bool(t.oat_enabled),
                        "workbench": bool(t.workbench_enabled),
                        "suspiciousObjects": bool(t.suspicious_objects_enabled),
                    },
                    "credentialsConfigured": configured,
                    "status": "ok" if configured else "configuration_error",
                }
            )
        out_orgs.append(
            {
                "organizationId": org.organization_id,
                "organizationName": org.organization_name,
                "displayOrder": org.display_order,
                "status": "ok" if org_all_ready else "degraded",
                "tenants": tenants_out,
            }
        )
    return {"status": "ok", "organizations": out_orgs, "updatedAt": updated_at}
