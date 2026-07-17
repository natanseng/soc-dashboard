"""Testes da resolucao de token (app/cyber_tokens.py) — nunca expoe/loga token."""
from app.cyber_tokens import resolve_token


class FakeSettings:
    """Settings falso, sem depender do .env real."""
    def __init__(self, tenant="prodesp-sp", cyber_token_env_map="", **tokens):
        self.tenant = tenant
        self.cyber_token_env_map = cyber_token_env_map
        for k, v in tokens.items():
            setattr(self, k, v)


def test_primary_tenant_uses_base_var():
    s = FakeSettings(tenant="prodesp-sp", v1_api_token="TOK-PRODESP")
    r = resolve_token("prodesp-sp", settings_obj=s, environ={})
    assert r.env_var == "V1_API_TOKEN"
    assert r.configured is True
    assert r.token == "TOK-PRODESP"


def test_secondary_convention_matches_existing_vars():
    s = FakeSettings(
        v1_api_token_detran="D", v1_api_token_iamspe="I", v1_api_token_sggd="S",
    )
    assert resolve_token("detran-sp", settings_obj=s, environ={}).env_var == "V1_API_TOKEN_DETRAN"
    assert resolve_token("iamspe-sp", settings_obj=s, environ={}).env_var == "V1_API_TOKEN_IAMSPE"
    assert resolve_token("sggd", settings_obj=s, environ={}).env_var == "V1_API_TOKEN_SGGD"
    assert resolve_token("detran-sp", settings_obj=s, environ={}).configured is True


def test_missing_token_is_unavailable_not_fatal():
    s = FakeSettings()  # nenhum token definido
    r = resolve_token("iamspe-sp", settings_obj=s, environ={})
    assert r.configured is False
    assert r.token is None
    assert r.env_var == "V1_API_TOKEN_IAMSPE"


def test_explicit_map_override():
    s = FakeSettings(cyber_token_env_map='{"foo-sp":"CUSTOM_VAR"}')
    r = resolve_token("foo-sp", settings_obj=s, environ={"CUSTOM_VAR": "XYZ"})
    assert r.env_var == "CUSTOM_VAR"
    assert r.configured is True and r.token == "XYZ"


def test_new_tenant_via_environment_no_code_change():
    s = FakeSettings()  # sem atributo para o novo tenant
    r = resolve_token("novo-sp", settings_obj=s, environ={"V1_API_TOKEN_NOVO": "NT"})
    assert r.env_var == "V1_API_TOKEN_NOVO"
    assert r.configured is True


def test_public_dict_never_leaks_token():
    s = FakeSettings(v1_api_token_detran="SENHA_SECRETA")
    r = resolve_token("detran-sp", settings_obj=s, environ={})
    pub = r.public_dict()
    assert pub == {"credentialsConfigured": True}
    assert "SENHA_SECRETA" not in str(pub)
    assert "V1_API_TOKEN" not in str(pub)
