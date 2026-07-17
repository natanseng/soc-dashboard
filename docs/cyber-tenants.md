# Cyber — conexão PostgreSQL, cadastro dinâmico e tokens

Camada de **infraestrutura interna** (branch `feat/cyber-multitenant`). Nada aqui é visível
ao usuário do dashboard. O endpoint `GET /cyber/tenants` existe para **uso futuro** e ainda
**não** é integrado ao frontend. Nenhuma tabela Cyber recebe dados operacionais nesta fase.

## 1. Camada de conexão — `backend/app/db.py`
- Pool assíncrono **asyncpg**, criado no **startup** do FastAPI (lifespan) e fechado no **shutdown**.
- **Sem conexão no import** (pool preguiçoso). Substituível em testes via `set_pool()`.
- **Falha-segura**: banco indisponível/lento **não derruba** o app; o health check reporta o estado.
- **Nunca loga DSN nem credenciais** (apenas o tipo da exceção).
- Configuração (`.env`, todas com default seguro e aditivas — não afetam a Fase 1):

| Variável | Default | Função |
|---|---|---|
| `DB_DSN` | (existente) | string de conexão PostgreSQL |
| `DB_POOL_MIN` | 1 | conexões mínimas do pool |
| `DB_POOL_MAX` | 5 | conexões máximas do pool |
| `DB_POOL_ACQUIRE_TIMEOUT` | 10.0 | s para obter conexão do pool |
| `DB_CONNECT_TIMEOUT` | 5.0 | s para estabelecer o pool no startup |
| `DB_COMMAND_TIMEOUT` | 10.0 | s por comando SQL |

## 2. Cadastro dinâmico — `backend/app/cyber_registry.py`
Fonte **única de verdade** de quais órgãos/tenants participam da tela Cyber:
`organization` + `cyber_tenant_config` + `tenant`. **Sem listas hardcoded de órgãos.**

Retorna somente registros com: `organization.enabled = true`, `organization.cyber_enabled = true`,
`cyber_tenant_config.cyber_enabled = true` e `tenant` existente (garantido pelo JOIN — a tabela
base `tenant` não tem coluna de habilitação própria; a habilitação Cyber vive em `cyber_tenant_config`).
Ordenação: `organization.display_order`, `organization.name`, `tenant.display_name`.

## 3. Endpoint `GET /cyber/tenants` (read-only)
Resposta:
```json
{
  "status": "ok",
  "organizations": [
    {
      "organizationId": "org-prodesp",
      "organizationName": "Prodesp",
      "displayOrder": 1,
      "status": "ok",
      "tenants": [
        {
          "tenantId": "prodesp-sp",
          "tenantName": "Prodesp",
          "regionBase": "https://api.xdr.trendmicro.com",
          "cyberEnabled": true,
          "sources": { "oat": true, "workbench": true, "suspiciousObjects": true },
          "credentialsConfigured": true,
          "status": "ok"
        }
      ]
    }
  ],
  "updatedAt": "2026-07-17T12:00:00+00:00"
}
```
Estados:
- **Banco indisponível** → `status: "unavailable"`, `organizations: []` (não derruba nada).
- **Tenant habilitado sem token** → permanece na lista com `credentialsConfigured: false` e
  `status: "configuration_error"`; o órgão fica `status: "degraded"`; os demais não são afetados.
- **Nunca** expõe token, nome de variável de ambiente, DSN, senha, headers ou detalhes internos.

## 4. Tokens — nunca no banco
Tokens ficam no `.env` / variáveis de ambiente / secret. A associação `tenant_id → variável`:
- **Tenant primário** (`TENANT` no `.env`, hoje `prodesp-sp`) → `V1_API_TOKEN`.
- **Demais tenants** (convenção) → `V1_API_TOKEN_<LABEL>`, onde `LABEL` = primeiro rótulo do
  `tenant_id` em maiúsculas. Ex.: `detran-sp → V1_API_TOKEN_DETRAN`, `iamspe-sp → V1_API_TOKEN_IAMSPE`,
  `sggd → V1_API_TOKEN_SGGD`. (Bate com as variáveis atuais **sem renomear**.)
- **Exceções** → override explícito via `CYBER_TOKEN_ENV_MAP` (JSON `{"tenant_id":"NOME_DA_VAR"}`) no `.env`.

O token é de **uso interno** (resolução `app/cyber_tokens.py`): nunca entra na resposta pública nem em log.
Um tenant sem token é marcado `unavailable`/`configuration_error` sem derrubar os demais.

## 5. Adicionar um novo órgão/tenant (sem alterar código)
1. `INSERT INTO organization (organization_id, name, display_order, enabled, cyber_enabled) VALUES (...);`
2. `INSERT INTO tenant (tenant_id, display_name) VALUES (...);`  *(reusa a tabela base)*
3. `INSERT INTO cyber_tenant_config (tenant_id, organization_id, cyber_enabled, oat_enabled, workbench_enabled, suspicious_objects_enabled) VALUES (...);`
4. Defina o token do novo tenant no `.env`/secret conforme a convenção da seção 4.

O órgão/tenant passa a aparecer automaticamente no cadastro e no endpoint — **sem deploy de código**.

## 6. Health check
`GET /healthz` passa a incluir `"postgres": "ok" | "error" | "unavailable"`, **além** de `redis`
(comportamento do Redis **inalterado**). Uma falha do PostgreSQL **não** afeta o reporte do Redis.

## 7. Testes
`backend/tests` (pytest + pytest-asyncio). Rodar: `cd backend && .venv/bin/python -m pytest`.
Dependências de teste: `backend/requirements-dev.txt`. Os testes de integração criam um banco
**temporário** a partir da migration real e **não tocam** o banco `socdash`.
