"""Geo-enrichment do Attack Map. Carregamento PREGUIÇOSO: não abre o .mmdb no import.
Se GEOIP_DB estiver vazio ou o arquivo não existir, enrich() retorna None e o mapa fica inativo
(o resto do backend continua funcionando normalmente)."""
import os

import geoip2.database
import geoip2.errors

from .config import settings

_reader = None
_tried = False

# Destino (tenant/SOC). Ajuste por tenant conforme necessário.
_DEST = {"lat": -23.55, "lon": -46.63, "country": "BR", "city": "São Paulo"}


def _get_reader():
    global _reader, _tried
    if _tried:
        return _reader
    _tried = True
    path = settings.geoip_db
    if path and os.path.exists(path):
        _reader = geoip2.database.Reader(path)
    return _reader


def enrich(net_event: dict) -> dict | None:
    reader = _get_reader()
    if reader is None:
        return None
    src_ip = net_event.get("src") or net_event.get("sourceIp") or net_event.get("srcIp")
    if not src_ip:
        return None
    try:
        g = reader.city(src_ip)
        return {
            "event_id": net_event.get("uuid") or net_event.get("eventId"),
            "src_ip": src_ip,
            "src_country": g.country.iso_code,
            "src_city": g.city.name,
            "src_lat": float(g.location.latitude or 0),
            "src_lon": float(g.location.longitude or 0),
            "dst_country": _DEST["country"],
            "dst_lat": _DEST["lat"],
            "dst_lon": _DEST["lon"],
            "threat_type": net_event.get("detectionType", "network"),
            "severity": net_event.get("riskLevel", "medium"),
        }
    except geoip2.errors.AddressNotFoundError:
        return None  # IP privado/desconhecido -> ignora no mapa


def lookup_ip(ip: str):
    """IP -> {country, city, lat, lon} via GeoLite2-City. None se base ausente ou IP desconhecido."""
    reader = _get_reader()
    if reader is None or not ip:
        return None
    try:
        g = reader.city(ip)
        lat, lon = g.location.latitude, g.location.longitude
        if lat is None or lon is None:
            return None
        return {
            "country": g.country.iso_code,
            "city": g.city.name,
            "lat": float(lat),
            "lon": float(lon),
        }
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return None
