"""Selecao de indicadores externos (§8) + classificacao de enforcement (§9) do OAT. Puro.

Regras:
  * So indicadores PUBLICOS externos (ip/domain/url) com PAPEL semantico externo entram.
  * Papel por campo (source×productCode×field): externos (attacker/peer/c2/request/denylist)
    entram; vitima/interno saem (contabilizados); ambiguos NAO entram e sao contabilizados
    (nunca descarte silencioso). Escopo publico via cyber_normalize.
  * Enforcement em 3 dimensoes independentes: enforcement_status, block_policy_matched (calculado
    a parte, por cross-ref SO), policy_match_basis. SO NUNCA vira prevented_confirmed.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import List, Optional, Tuple

from app.cyber_normalize import is_public_indicator, normalize_ip, normalize_indicator

# campo (lower) -> papel externo
ATTACKER_FIELDS = {
    "src": "attacker", "sourceip": "attacker", "srcip": "attacker", "attackerip": "attacker",
    "shost": "attacker",
    "peerip": "peer", "peerhost": "peer", "peer": "peer",
    "cnc": "c2", "c2": "c2", "cncip": "c2", "cnchost": "c2", "cncdomain": "c2", "cnclist": "c2",
    "externalsource": "attacker", "request": "request",
}
# campos de vitima/interno (excluidos, contabilizados como disc_role)
VICTIM_FIELDS = {
    "endpointip", "endpointhostname", "interestedhost", "interestedip", "dst", "dsthost",
    "destinationip", "dhost", "dvchost", "asset", "victim", "targetip", "targethost",
    "endpointguid", "deviceip",
}

# enforcement: act normalizado -> enforcement_status
_PREVENTED = {"block", "blocked", "reset", "quarantine", "quarantined", "deny", "denied",
              "drop", "dropped", "terminate", "terminated", "clean", "cleaned", "delete", "deleted"}
_ALLOWED = {"pass", "allow", "allowed", "permit", "permitted"}
_NOT_PREVENTED = {"not blocked", "notblocked", "log", "logged", "monitor", "monitored",
                  "detected", "detectonly", "audit", "observed", "alert"}
# fontes puramente de deteccao (sem enforcement) -> observed quando nao ha act
_DETECTION_ONLY_SOURCES = {"endpointactivitydata"}


@dataclass(frozen=True)
class ExternalIndicator:
    indicator_type: str
    value_normalized: str
    value_raw: str
    value_hash: bytes
    source_field: str
    indicator_role: str


def _ho_value(ho) -> Optional[str]:
    v = ho.get("value")
    if isinstance(v, dict):
        v = v.get("value")
    if isinstance(v, list):
        v = v[0] if v else None
    return v if isinstance(v, str) and v else None


def _infer_type(ho_type: str, field: str, raw: str) -> Optional[str]:
    t = (ho_type or "").lower()
    if t == "url" or field == "request":
        return "url"
    if t == "ip":
        return "ip"
    if t in ("host", "domain"):
        return "ip" if normalize_ip(raw) else "domain"
    # sem type confiavel: tenta ip depois dominio
    if normalize_ip(raw):
        return "ip"
    return "domain"


def _build_indicator(field: str, role: str, ho_type: str, raw: str, disc: Counter) -> Optional[ExternalIndicator]:
    itype = _infer_type(ho_type, field, raw)
    norm = normalize_indicator(itype, raw)
    if norm is None:
        disc["type"] += 1
        return None
    value_normalized, value_hash = norm
    if not is_public_indicator(itype, value_normalized):
        disc["non_public"] += 1
        return None
    return ExternalIndicator(itype, value_normalized, raw, value_hash, field, role)


def extract_external_indicators(detection: dict) -> Tuple[List[ExternalIndicator], Counter]:
    """Extrai indicadores externos publicos (denyListHost + highlightedObjects). Retorna
    (indicadores unicos, contadores de descarte). Sem descarte silencioso."""
    disc = Counter()
    out: dict = {}   # (type, value_normalized, field, role) -> ExternalIndicator (dedup)
    detail = detection.get("detail") or {}

    dlh = detail.get("denyListHost")
    if isinstance(dlh, str) and dlh:
        ind = _build_indicator("denyListHost", "c2", "host", dlh, disc)
        if ind:
            out[(ind.indicator_type, ind.value_normalized, ind.source_field, ind.indicator_role)] = ind

    for f in (detection.get("filters") or []):
        for ho in (f.get("highlightedObjects") or []):
            field = str(ho.get("field", ""))
            fl = field.lower()
            raw = _ho_value(ho)
            if not raw:
                continue
            if fl in VICTIM_FIELDS:
                disc["role"] += 1
                continue
            role = ATTACKER_FIELDS.get(fl)
            if role is None:
                # so conta ambiguidade se parecer um indicador de rede (evita ruido de campos texto)
                if (ho.get("type") or "").lower() in ("ip", "host", "domain", "url"):
                    disc["ambiguity"] += 1
                continue
            ind = _build_indicator(field, role, ho.get("type"), raw, disc)
            if ind:
                out[(ind.indicator_type, ind.value_normalized, ind.source_field, ind.indicator_role)] = ind
    return list(out.values()), disc


def _norm_act(v):
    if v is None:
        return None
    if isinstance(v, list):
        v = v[0] if v else None
    if isinstance(v, dict):
        v = v.get("value")
    if v in (None, ""):
        return None
    return str(v).strip().lower()


def classify_enforcement(detection: dict) -> Tuple[str, Optional[str], Optional[str]]:
    """Retorna (enforcement_status, action_field, action_value_raw). NAO usa SO (dimensao a parte)."""
    detail = detection.get("detail") or {}
    action_field = None
    raw_act = None
    # 1) act no detail
    if "act" in detail:
        action_field, raw_act = "detail.act", detail.get("act")
    else:
        # 2) act em highlightedObjects
        for f in (detection.get("filters") or []):
            for ho in (f.get("highlightedObjects") or []):
                if str(ho.get("field", "")).lower() == "act":
                    action_field, raw_act = "act", _ho_value(ho) or ho.get("value")
                    break
            if raw_act is not None:
                break

    act = _norm_act(raw_act)
    if act is None:
        src = str(detail.get("source") or detection.get("source") or "").lower()
        status = "observed" if src in _DETECTION_ONLY_SOURCES else "unknown"
        return status, action_field, None

    action_value_raw = str(raw_act)
    if act in _PREVENTED:
        return "prevented_confirmed", action_field, action_value_raw
    if act in _ALLOWED:
        return "allowed_confirmed", action_field, action_value_raw
    if act in _NOT_PREVENTED:
        return "observed_not_prevented", action_field, action_value_raw
    return "unknown", action_field, action_value_raw
