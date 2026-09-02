# CLAUDE.md — Instruções permanentes para o Claude Code

Este arquivo orienta qualquer instância do Claude Code que trabalhe neste repositório.
Leia-o **inteiro** antes de tocar em qualquer arquivo.

## 1. Contexto do projeto
Wallboard de TV **SOC SMART** em tempo real para o **Trend Vision One**, integrado com a **Prefeitura de Salvador**.
Objetivo: exibir em uma TV, 24/7, a postura de segurança, detecções, MITRE ATT&CK, mapa de ameaças, endpoints e
identidade, de forma legível à distância e sempre "ao vivo".

- **Autor/operador:** analista de Customer Success técnico (Trend Micro Brasil). Interage em **pt-BR**.
- **Ambiente do operador:** Windows 11 + WSL2 (Ubuntu). Projeto em `~/projetos/soc-dashboard`.
- Nem sempre o ambiente de dev alcança a API real (`api.xdr.trendmicro.com`). Chamadas reais são
  validadas pelo operador via `curl`/logs. **Nunca invente respostas de API** — se não puder testar,
  diga e proponha um comando de validação.

## 2. Arquitetura (resumo)
Coletor (`collectors/run.py`, APScheduler) executa "tiers" (`collectors/tiers.py`) que chamam a
**Vision One API v3.0** e gravam no **Redis** (chaves `v1:{tenant}:...`), publicando deltas em
`ws:{tenant}` (pub/sub). O **FastAPI** (`app/main.py`) lê o Redis e expõe `GET /api/{tenant}/overview`,
faz push por `WS /ws/{tenant}` e serve o dashboard estático (`static/index.html`) em `/` (mesma origem).
O **frontend** é um HTML único com ECharts: no boot faz `fetch` do overview e depois aplica deltas do WebSocket.

Fluxo: `Vision One API → tiers → Redis (+pub/sub) → FastAPI → (HTTP overview / WS deltas) → index.html`.

O **TimescaleDB** (`infra/init.sql`) está provisionado mas **NÃO é usado pelo código** — nenhum tier
escreve no banco. Não assuma que há dados históricos persistidos.

## 3. Estrutura de diretórios
```
soc-dashboard/
├── infra/
│   ├── docker-compose.yml   # Redis + TimescaleDB (REQUER VALIDAÇÃO do conteúdo exato)
│   └── init.sql             # schema TimescaleDB (provisionado, não integrado)
├── backend/
│   ├── requirements.txt
│   ├── Dockerfile           # uvicorn app.main:app --workers 2 (porta 8000)
│   ├── .env.example
│   ├── .venv/               # venv (não versionar)
│   ├── app/
│   │   ├── config.py        # Settings (pydantic-settings) — lê .env
│   │   ├── main.py          # FastAPI: /healthz, /api/{tenant}/overview, /ws/{tenant}, mount static
│   │   ├── vision_one.py    # Cliente V1: get_json (429 backoff), get_paginated (nextLink), aclose
│   │   ├── cache.py         # get_redis() (redis.asyncio, decode_responses=True)
│   │   └── geo.py           # GeoLite2 lazy: enrich(), lookup_ip()
│   ├── collectors/
│   │   ├── tiers.py         # TODAS as coletas + parsing (workbench, posture, oat, asrm, endpoints, ioc)
│   │   └── run.py           # scheduler: tick_t1/t2/t3 -> Redis + pub/sub
│   ├── static/
│   │   └── index.html       # FRONTEND single-file (ECharts, 4 telas)
│   └── data/GeoLite2-City.mmdb  # base geo (opcional, ~66MB, não versionar)
```

## 4. Comandos principais
```bash
# Infra (a partir de infra/)
cd infra && docker compose up -d          # sobe Redis + TimescaleDB
docker compose stop                        # desliga preservando dados  (NUNCA down -v)

# Coletor (backend/, venv ativo)
python -m collectors.run

# API + dashboard (backend/, venv ativo)
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Verificação
curl http://localhost:8000/healthz
curl http://localhost:8000/api/prodesp-sp/overview
```

## 5. Convenções
- **Idioma:** comentários de código, mensagens de log e textos de UI em **pt-BR**.
- **Frontend single-file:** todo o HTML/CSS/JS vive em `backend/static/index.html`. Não fragmentar
  em múltiplos arquivos sem alinhamento — o deploy assume 1 arquivo.
- **ECharts** é servido localmente (`static/echarts.min.js`), não por CDN.
- **Fontes:** Oxanium (display/números), Inter (texto), JetBrains Mono (timestamps).
- **Chaves Redis:** sempre no padrão `v1:{tenant}:{recurso}`. Canal pub/sub: `ws:{tenant}`.
- **Resiliência dos tiers:** cada coleta é try/except isolado; falha de um recurso não derruba os
  demais. Use `_merge_keep`/keep-last-good para não zerar painéis em timeout.

## 6. Regras de negócio críticas (NÃO alterar sem entender)
- **Teto de 100.000 do OAT:** `_count` lê `totalCount` de `/v3.0/oat/detections`, que **satura em ~100k**.
  Vários painéis (MITRE, eventos) exibem `100.001` — **isso é limite da API, não bug**. Não "corrija".
- **Threat Trends usa alto risco:** a série de tendência filtra `riskLevel eq 'high'` justamente para
  fugir da saturação (o total satura e vira linha reta). Não voltar para contagem total.
- **ASRM/CREM em 403:** `attackSurface*`, `highRisk*`, `internalAssetVulnerabilities` retornam
  `403 (AccessDeny_000403)` para a Prodesp (licença CREM-Core expirada). É **esperado**. A fonte
  principal do dashboard é `/v3.0/asrm/securityPosture` (retorna 200 e traz os agregados). Manter o
  tratamento tolerante a 403.
- **Workbench sem "In Progress":** a Prodesp fecha alertas direto (Open → Closed); `firstInvestigatedDateTime`
  quase sempre vem vazio. Não construir métricas que dependam desse campo.

## 7. Padrões de layout do frontend (aprendidos na prática)
- Painel cujo conteúdo estoura a `grid-row` → tornar os itens `flex:1` (dividem a altura igualmente;
  nunca cortam nem deixam vazio). Listas dentro de wrappers horizontais precisam de `height:100%`.
- Célula de grid com texto `nowrap` que invade a vizinha → usar `grid-template-columns: ... minmax(0,1fr) ...`
  (o `min-width:0` no item sozinho não basta em Grid) para truncar com reticências.
- Formatação numérica pt-BR (`toLocaleString('pt-BR')`).

## 8. Regras para testes / validação (antes de concluir QUALQUER tarefa)
- **JS:** extrair o maior bloco `<script>` de `index.html` e rodar `node --check`.
- **Python:** `python -m py_compile` nos arquivos alterados.
- **Não há suíte de testes automatizados** (ver docs/TESTING.md). Validação é manual + o operador
  confere em tela/`curl`. Se criar testes, documente como rodá-los.

## 9. Restrições que NÃO podem ser quebradas
- Nunca `docker compose down -v`.
- Não commitar `.env`, tokens, nem o `.mmdb` (grande).
- Não trocar o frontend single-file por um framework sem pedido explícito.
- Não remover o tratamento tolerante a 403/timeout dos tiers.
- Não alterar o padrão de chaves Redis sem atualizar `app/main.py` e o frontend juntos.

## 10. Arquivos sensíveis (analisar antes de alterar)
- `backend/app/main.py` — muda a rota `overview`/WS → **reiniciar uvicorn** e conferir o frontend.
- `backend/collectors/tiers.py` e `run.py`, `app/geo.py`, `app/config.py` — **reiniciar o coletor**.
- `backend/static/index.html` — só copiar + `Ctrl+Shift+R` (sem reiniciar processo).
- `infra/init.sql`, `infra/docker-compose.yml` — mudanças de schema/infra: cuidado com volumes.

## 11. Procedimento obrigatório antes de concluir
1. Rodar as validações da seção 8 (node --check / py_compile).
2. Se mexeu no frontend, garantir que os 4 painéis afetados não cortam/sobrepõem.
3. Indicar **o que precisa reiniciar** (coletor? uvicorn? só Ctrl+Shift+R?).
4. Não afirmar que algo "funciona com a API" sem o operador validar via `curl`/logs.

## 12. Formato esperado de relatório de alteração
Ao concluir uma tarefa, reporte: (a) arquivos alterados, (b) o que mudou e por quê,
(c) validações executadas e resultado, (d) o que precisa reiniciar/deployar, (e) o que ainda
requer validação no ambiente real (chamadas de API, dados do tenant).
