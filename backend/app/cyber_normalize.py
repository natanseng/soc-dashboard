"""Normalizacao deterministica de indicadores (§6) + escopo publico externo (§8).

Compartilhado por todas as fontes (OAT / Workbench / Suspicious Objects). Puro, sem I/O.
Chave de indicador: value_hash = SHA-256("<indicator_type>|<value_normalized>").
value_normalized e preservado integralmente; value_raw deve ser guardado a parte pelo coletor.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

# sufixos claramente internos (NAO excluir .sp.gov.br — regra §8)
_PRIVATE_DOMAIN_SUFFIXES = (
    ".local", ".localhost", ".internal", ".intranet", ".lan", ".corp",
    ".home", ".home.arpa", ".test", ".invalid", ".example", ".localdomain",
)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9_-]{1,63}\.)+[a-z]{2,63}$")
_DOC_NETS = (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
)
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def value_hash(indicator_type: str, value_normalized: str) -> bytes:
    """SHA-256 (32 bytes) da representacao canonica <type>|<value>. NUNCA SHA-1."""
    return hashlib.sha256(f"{indicator_type}|{value_normalized}".encode("utf-8")).digest()


def _idna(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except Exception:  # noqa: BLE001 — mantem o host lower se IDNA falhar
        return host


def normalize_ip(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    try:
        return ipaddress.ip_address(raw.strip()).compressed
    except ValueError:
        return None


def normalize_domain(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    s = raw.strip().lower().rstrip(".")
    if not s:
        return None
    try:  # se for IP, nao e dominio
        ipaddress.ip_address(s)
        return None
    except ValueError:
        pass
    s = _idna(s)
    return s if _DOMAIN_RE.match(s) else None


def normalize_url(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    try:
        parts = urlsplit(raw.strip())
    except ValueError:
        return None
    if not parts.scheme or not parts.hostname:
        return None
    host = _idna(parts.hostname.lower())
    netloc = f"{host}:{parts.port}" if parts.port else host
    # preserva path e query (parte do IOC); descarta fragmento
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "", parts.query or "", ""))


def normalize_indicator(indicator_type: str, raw: Optional[str]) -> Optional[Tuple[str, bytes]]:
    """Retorna (value_normalized, value_hash) ou None se invalido/nao suportado."""
    fn = {"ip": normalize_ip, "domain": normalize_domain, "url": normalize_url}.get(indicator_type)
    if fn is None:
        return None
    n = fn(raw)
    if not n:
        return None
    return n, value_hash(indicator_type, n)


def is_public_ip(value: Optional[str]) -> bool:
    """Verdadeiro so p/ IP publico roteavel (rejeita privado/loopback/link-local/multicast/
    reservado/unspecified/CGNAT/faixa de documentacao)."""
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return False
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified):
        return False
    if ip.version == 4 and ip in _CGNAT:
        return False
    for net in _DOC_NETS:
        if ip in ipaddress.ip_network(net):
            return False
    return bool(ip.is_global)


def is_public_domain(value: Optional[str]) -> bool:
    """Verdadeiro p/ dominio publico valido. NAO exclui .sp.gov.br (regra §8)."""
    d = (value or "").strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(d):
        return False
    return not any(d == suf.lstrip(".") or d.endswith(suf) for suf in _PRIVATE_DOMAIN_SUFFIXES)


def url_host(value: Optional[str]) -> Optional[str]:
    try:
        return (urlsplit(value).hostname or "").lower() or None
    except (ValueError, AttributeError):
        return None


def is_public_indicator(indicator_type: str, value_normalized: str) -> bool:
    """Escopo publico externo por tipo (§8). Para URL, avalia o host."""
    if indicator_type == "ip":
        return is_public_ip(value_normalized)
    if indicator_type == "domain":
        return is_public_domain(value_normalized)
    if indicator_type == "url":
        host = url_host(value_normalized)
        if not host:
            return False
        return is_public_ip(host) or is_public_domain(host)
    return False
