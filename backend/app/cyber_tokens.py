"""Resolucao de token da Vision One por tenant_id — USO INTERNO.

Os tokens permanecem no .env (ou em variaveis de ambiente/secret), NUNCA no banco.
Este modulo apenas descobre QUAL variavel guarda o token de cada tenant e le o valor.

Regras:
  * O token e de uso interno: nunca deve entrar no objeto publico do cadastro nem em logs.
  * Configuracao ausente NAO derruba os demais tenants: retorna TokenStatus(configured=False).
  * Sem lista hardcoded de orgaos. A associacao tenant_id -> variavel usa:
      1) override explicito CYBER_TOKEN_ENV_MAP (JSON tenant_id->NOME_DA_VAR), se definido; senao
      2) convencao: o tenant primario (settings.tenant) usa V1_API_TOKEN; os demais usam
         V1_API_TOKEN_<LABEL>, onde LABEL = primeiro rotulo do tenant_id em maiusculas
         (ex.: detran-sp -> V1_API_TOKEN_DETRAN, sggd -> V1_API_TOKEN_SGGD).

Como associar um NOVO tenant ao seu token: ver docs/cyber-tenants.md.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Mapping, Optional

from .config import settings


@dataclass(frozen=True)
class TokenStatus:
    """Resultado da resolucao. `token` e interno e NUNCA deve ser serializado/logado."""
    tenant_id: str
    configured: bool
    env_var: str
    token: Optional[str] = None

    def public_dict(self) -> dict:
        """Projecao segura: apenas se ha credencial (sem token, sem nome da variavel)."""
        return {"credentialsConfigured": self.configured}


def _parse_map(raw: str) -> dict[str, str]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return {str(k): str(v) for k, v in data.items()}
    except (ValueError, AttributeError, TypeError):
        return {}


def _env_var_for(tenant_id: str, primary_tenant: str, explicit: Mapping[str, str]) -> str:
    if tenant_id in explicit:
        return explicit[tenant_id]
    if tenant_id == primary_tenant:
        return "V1_API_TOKEN"
    label = re.split(r"[-_]", tenant_id, maxsplit=1)[0]
    slug = re.sub(r"[^A-Z0-9]+", "_", label.upper()).strip("_")
    return f"V1_API_TOKEN_{slug}"


def _read_value(env_var: str, settings_obj, environ: Mapping[str, str]) -> str:
    # 1) atributo ja carregado pelo pydantic-settings a partir do .env
    val = getattr(settings_obj, env_var.lower(), None)
    if val:
        return str(val)
    # 2) variavel de ambiente crua (novos tenants / secrets injetados no ambiente)
    return environ.get(env_var, "") or ""


def resolve_token(tenant_id: str, *, settings_obj=None, environ: Optional[Mapping[str, str]] = None) -> TokenStatus:
    """Resolve o token de um tenant. Nunca lanca por token ausente (retorna configured=False)."""
    s = settings_obj if settings_obj is not None else settings
    env = environ if environ is not None else os.environ
    env_var = _env_var_for(tenant_id, getattr(s, "tenant", ""), _parse_map(getattr(s, "cyber_token_env_map", "") or ""))
    value = _read_value(env_var, s, env)
    return TokenStatus(tenant_id=tenant_id, configured=bool(value), env_var=env_var, token=(value or None))
