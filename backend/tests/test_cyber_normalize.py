"""Testes da normalizacao de indicadores (app/cyber_normalize.py) — §6 e §8."""
from app.cyber_normalize import (
    is_public_domain,
    is_public_indicator,
    is_public_ip,
    normalize_domain,
    normalize_indicator,
    normalize_ip,
    normalize_url,
    value_hash,
)


def test_ip_v4_canonical():
    assert normalize_ip(" 8.8.8.8 ") == "8.8.8.8"


def test_ip_v6_canonical():
    assert normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"


def test_ip_invalid():
    assert normalize_ip("999.1.1.1") is None
    assert normalize_ip("nope") is None
    assert normalize_ip("") is None


def test_domain_lower_strip_dot():
    assert normalize_domain("Evil.Example.COM.") == "evil.example.com"


def test_domain_spgovbr_allowed():
    assert normalize_domain("Portal.SP.gov.br") == "portal.sp.gov.br"
    assert is_public_domain("portal.sp.gov.br") is True  # NAO excluir .sp.gov.br


def test_domain_internal_rejected_by_public_scope():
    assert is_public_domain("srv.local") is False
    assert is_public_domain("host.intranet") is False


def test_domain_ip_is_not_domain():
    assert normalize_domain("8.8.8.8") is None


def test_url_normalized_keeps_path_and_query_drops_fragment():
    assert normalize_url("HTTPS://Evil.Example/Path?a=1#frag") == "https://evil.example/Path?a=1"


def test_url_long_is_handled():
    raw = "http://evil.example/" + "a" * 5000
    u = normalize_url(raw)
    assert u.startswith("http://evil.example/") and len(u) > 5000
    out = normalize_indicator("url", raw)
    assert out is not None and len(out[1]) == 32  # value_hash SHA-256


def test_value_hash_deterministic_sha256_includes_type():
    h1 = value_hash("ip", "8.8.8.8")
    assert h1 == value_hash("ip", "8.8.8.8") and len(h1) == 32
    assert value_hash("domain", "8.8.8.8") != h1


def test_public_ip_classification():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("10.0.0.1") is False        # privado
    assert is_public_ip("127.0.0.1") is False       # loopback
    assert is_public_ip("169.254.1.1") is False     # link-local
    assert is_public_ip("100.64.0.1") is False      # CGNAT
    assert is_public_ip("203.0.113.9") is False     # documentacao
    assert is_public_ip("224.0.0.1") is False       # multicast


def test_is_public_indicator_url_uses_host():
    assert is_public_indicator("url", "http://8.8.8.8/x") is True
    assert is_public_indicator("url", "http://10.0.0.1/x") is False
    assert is_public_indicator("domain", "portal.sp.gov.br") is True
    assert is_public_indicator("ip", "8.8.8.8") is True


def test_normalize_indicator_invalid_and_unknown_type():
    assert normalize_indicator("ip", "nope") is None
    assert normalize_indicator("bogustype", "x") is None
