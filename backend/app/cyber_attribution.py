"""Atribuicao de observacoes a ORGAOS dentro do tenant (§2, §10) + reatribuicao idempotente.

Regras:
  * Preserva TODOS os identificadores de instancia (reatribuicao sem recoleta).
  * mode 'single_org': tenant com exatamente 1 orgao habilitado -> atribui a ele (determinismo,
    NAO "primeiro orgao como padrao").
  * mode 'instance'/'mapping': atribui SOMENTE por mapeamento (instancia/tag/id). Sem match ->
    unassigned (method 'instance_mapping_pending' no modo instance; 'unknown' no modo mapping).
    >1 orgao candidato -> ambiguous (organization_id nulo). NUNCA espalha/distribui/duplica/adivinha.
  * mode 'none': sempre unassigned.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

# Identificadores de instancia preservados (empiricos §2.2 + lista do usuario).
IDENTIFIER_FIELDS = (
    "managementScopeInstanceId", "managementScopeGroupId", "instanceId", "productInstanceId",
    "sourceId", "connectorId", "endpointGUID", "endpointGuid", "groupId", "interestedGroup",
    "appGroup", "source", "productCode",
)
TAG_FIELDS = ("customAssetTags", "platformAssetTags", "tags")

# identifier -> mapping_type(s) candidatos p/ lookup em cyber_organization_mapping (ordem=prioridade)
_ID_MAPPING_TYPES = {
    "managementScopeInstanceId": ("management_scope_instance", "sep_instance", "swp_instance"),
    "managementScopeGroupId": ("management_scope_group",),
    "instanceId": ("product_instance_id", "sep_instance", "swp_instance"),
    "productInstanceId": ("product_instance_id",),
    "sourceId": ("source_id",),
    "connectorId": ("connector_id",),
    "groupId": ("endpoint_group",),
    "interestedGroup": ("endpoint_group",),
    "appGroup": ("asset_group",),
    # endpointGUID e preservado, mas correlaciona por inventario (nao por mapping direto): fora daqui.
}
_CONF_RANK = {"high": 0, "medium": 1, "low": 2}

# assinatura do lookup: (mapping_type, value_hash_bytes) -> list[(organization_id, confidence)]
MappingLookup = Callable[[str, bytes], List[Tuple[str, str]]]


def _hash(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def extract_identifiers(detail, source=None, product_code=None, extra=None) -> dict:
    """Coleta os identificadores presentes (sanitizados) p/ persistir em attribution_identifiers."""
    ids: dict = {}
    detail = detail or {}
    for k in IDENTIFIER_FIELDS:
        v = detail.get(k)
        if v not in (None, "", [], {}):
            ids[k] = v if isinstance(v, (dict, list)) else str(v)[:200]
    for k in TAG_FIELDS:
        v = detail.get(k)
        if v not in (None, "", [], {}):
            ids[k] = v
    if source and "source" not in ids:
        ids["source"] = source
    if product_code and "productCode" not in ids:
        ids["productCode"] = product_code
    for k, v in (extra or {}).items():
        if v not in (None, "", [], {}):
            ids[k] = v
    return ids


@dataclass(frozen=True)
class AttributionResult:
    organization_id: Optional[str]
    status: str          # attributed | ambiguous | unassigned | unavailable
    method: str
    confidence: str      # high | medium | low | unavailable
    evidence: Optional[str] = None


def _mapping_candidates(identifiers: dict) -> List[Tuple[str, bytes]]:
    """(mapping_type, value_hash) a partir dos identificadores preservados."""
    out: List[Tuple[str, bytes]] = []
    for key, mtypes in _ID_MAPPING_TYPES.items():
        val = identifiers.get(key)
        if not isinstance(val, (str, int)) or val in ("", None):
            continue
        vh = _hash(str(val))
        for mt in mtypes:
            out.append((mt, vh))
    for tkey in TAG_FIELDS:
        tv = identifiers.get(tkey)
        if isinstance(tv, dict):
            vals = [str(x) for x in tv.values()]
        elif isinstance(tv, list):
            vals = [str(x) for x in tv]
        elif isinstance(tv, str) and tv:
            vals = [tv]
        else:
            vals = []
        for v in vals:
            vh = _hash(v)
            out.append(("organization_tag", vh))
            out.append(("custom_tag", vh))
    return out


def resolve_organization(mode: str, enabled_org_ids, identifiers: dict,
                         mapping_lookup: MappingLookup) -> AttributionResult:
    if mode == "single_org":
        if len(enabled_org_ids) == 1:
            return AttributionResult(enabled_org_ids[0], "attributed", "single_org", "high")
        return AttributionResult(None, "unassigned", "unknown", "unavailable",
                                 evidence=f"single_org_mode_but_{len(enabled_org_ids)}_orgs")
    if mode == "none":
        return AttributionResult(None, "unassigned", "unknown", "unavailable")

    # modo instance / mapping: por evidencia
    matches: dict = {}  # org_id -> (confidence, mapping_type)
    for mtype, vh in _mapping_candidates(identifiers):
        for org_id, conf in (mapping_lookup(mtype, vh) or []):
            prev = matches.get(org_id)
            if prev is None or _CONF_RANK.get(conf, 3) < _CONF_RANK.get(prev[0], 3):
                matches[org_id] = (conf, mtype)
    if len(matches) == 1:
        org_id, (conf, mtype) = next(iter(matches.items()))
        return AttributionResult(org_id, "attributed", mtype, conf)
    if len(matches) > 1:
        return AttributionResult(None, "ambiguous", "unknown", "unavailable",
                                 evidence="candidates:" + ",".join(sorted(matches)))
    pending = "instance_mapping_pending" if mode == "instance" else "unknown"
    return AttributionResult(None, "unassigned", pending, "unavailable")


# ------------------------- reatribuicao idempotente (DB) -------------------------

async def load_mappings(conn, tenant_id: str) -> dict:
    """Mapeamentos ativos do tenant -> {(mapping_type, value_hash_bytes): [(org_id, confidence)]}."""
    rows = await conn.fetch(
        "SELECT mapping_type, mapping_value_hash, organization_id, confidence "
        "FROM cyber_organization_mapping "
        "WHERE tenant_id = $1 AND enabled = true "
        "  AND valid_from <= now() AND (valid_to IS NULL OR valid_to > now())",
        tenant_id,
    )
    idx: dict = {}
    for r in rows:
        idx.setdefault((r["mapping_type"], bytes(r["mapping_value_hash"])), []).append(
            (r["organization_id"], r["confidence"]))
    return idx


async def reattribute_unassigned(pool, tenant_id: str, *, limit: int = 1000) -> dict:
    """Reprocessa observacoes unassigned do tenant tentando casar mapeamentos. Idempotente:
    so altera linhas unassigned; nao duplica; nao toca linhas ja atribuidas."""
    result = {"scanned": 0, "reattributed": 0, "ambiguous": 0, "still_unassigned": 0}
    async with pool.acquire() as conn:
        mode_row = await conn.fetchrow(
            "SELECT attribution_mode FROM cyber_tenant_config WHERE tenant_id = $1", tenant_id)
        if mode_row is None:
            return result
        mode = mode_row["attribution_mode"]
        mappings = await load_mappings(conn, tenant_id)

        def lookup(mt, vh):
            return mappings.get((mt, vh), [])

        rows = await conn.fetch(
            "SELECT observation_id, attribution_identifiers FROM cyber_oat_observation "
            "WHERE tenant_id = $1 AND organization_attribution_status = 'unassigned' "
            "ORDER BY observation_id LIMIT $2", tenant_id, limit)
        for r in rows:
            result["scanned"] += 1
            ids = r["attribution_identifiers"] or {}
            if isinstance(ids, (str, bytes)):
                ids = json.loads(ids)
            res = resolve_organization(mode, [], ids, lookup)
            if res.status == "attributed" and res.organization_id:
                await conn.execute(
                    "UPDATE cyber_oat_observation SET organization_id=$1, "
                    "organization_attribution_status='attributed', organization_attribution_method=$2, "
                    "organization_attribution_confidence=$3, organization_attribution_evidence=$4 "
                    "WHERE observation_id=$5",
                    res.organization_id, res.method, res.confidence, res.evidence, r["observation_id"])
                result["reattributed"] += 1
            elif res.status == "ambiguous":
                await conn.execute(
                    "UPDATE cyber_oat_observation SET organization_attribution_status='ambiguous', "
                    "organization_attribution_method='unknown', organization_attribution_evidence=$1 "
                    "WHERE observation_id=$2", res.evidence, r["observation_id"])
                result["ambiguous"] += 1
            else:
                result["still_unassigned"] += 1
    return result
