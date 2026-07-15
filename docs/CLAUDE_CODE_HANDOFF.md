# 24–25. Pacote de Transferência para o Claude Code

## 24.1 O que é este pacote
Documentação técnica completa do **SOC/Executive Wallboard (Trend Vision One)** para que uma instância do
**Claude Code** continue o desenvolvimento **sem** acesso ao histórico de conversas anterior. Foi escrita
**lendo os arquivos-fonte reais**, não de memória.

## 24.2 Estrutura do pacote
```
handoff/
├── README.md                 # porta de entrada + índice
├── CLAUDE.md                 # instruções operacionais para o Claude Code (ler PRIMEIRO)
├── .env.example              # template de configuração
└── docs/
    ├── PROJECT_OVERVIEW.md   ├── ARCHITECTURE.md      ├── BACKEND.md
    ├── FRONTEND.md           ├── API_REFERENCE.md     ├── DATABASE.md
    ├── INFRASTRUCTURE.md     ├── INTEGRATIONS.md      ├── BUSINESS_RULES.md
    ├── DEVELOPMENT_SETUP.md  ├── DEPLOYMENT.md        ├── SECURITY.md
    ├── TESTING.md            ├── TROUBLESHOOTING.md   ├── TECHNICAL_DEBT.md
    ├── ROADMAP.md            ├── DECISIONS.md         ├── GLOSSARY.md
    ├── PROJECT_HISTORY.md    └── CLAUDE_CODE_HANDOFF.md (este arquivo)
```

## 24.3 Onde estão os FONTES reais (não incluídos como código neste pacote)
- **Projeto em operação (WSL):** `~/projetos/soc-dashboard/` (estrutura em ARCHITECTURE.md/BACKEND.md).
- **Cópia de trabalho do CSTA (OneDrive):**
  `/mnt/c/Users/lucaso/OneDrive - TrendMicro/Documents/Dash Detran/Versão 2`
  (Lucas edita aqui e copia para o projeto).
- Ao iniciar, o Claude Code deve **abrir os fontes reais** desses caminhos; esta documentação descreve o que esperar.

## 24.4 Ordem de leitura recomendada
1. `CLAUDE.md` (regras operacionais) → 2. `PROJECT_OVERVIEW.md` → 3. `ARCHITECTURE.md` →
4. `BACKEND.md` + `API_REFERENCE.md` → 5. `FRONTEND.md` → 6. `INTEGRATIONS.md` + `BUSINESS_RULES.md` →
7. `DEVELOPMENT_SETUP.md` + `DEPLOYMENT.md` → 8. `DATABASE.md` → 9. `SECURITY.md`/`TESTING.md`/`TROUBLESHOOTING.md`
→ 10. `TECHNICAL_DEBT.md`/`ROADMAP.md`/`DECISIONS.md`/`GLOSSARY.md`.

## 24.5 Princípios de trabalho (NÃO violar)
- **Não inventar.** O que não foi confirmado no código está marcado **`REQUER VALIDAÇÃO`** — validar antes de assumir.
- **Best-effort/keep-last-good** é design, não bug. Não "consertar" a resiliência a falhas.
- **Teto de 100k** (RN02) e **painéis via `securityPosture`** (ADR-002) são intencionais.
- **Nunca** `docker compose down -v` (apaga Redis/Timescale). Parar com `docker compose stop`.
- Respeitar a **matriz "o que reiniciar"** (DEPLOYMENT.md): coletor × uvicorn × só-copiar-o-HTML.
- **Idioma:** responder ao CSTA em **português do Brasil**, conciso.

## 24.6 Checklist "validar primeiro" (itens em aberto)
- [ ] Conteúdo real do `infra/docker-compose.yml` (imagens, volumes, env do Postgres, se sobe o app).
- [ ] Existe repositório **Git**? (para rollback confiável)
- [ ] **Versão do ECharts** (`static/echarts.min.js`).
- [ ] Como orquestrar o **coletor** em container/serviço (o Dockerfile só sobe a API).
- [ ] `map:attackers` (zset lida no overview, sem alimentador) — remover ou implementar.
- [ ] Formatos marcados `REQUER VALIDAÇÃO` no front (`_fmtTime`, painel `p-health`).

## 24.7 Estado do projeto (resumo)
Funcional e em uso: **4 telas** (Dashboard, SOC, Attack Map, Adoção) alimentadas ao vivo (Redis + WS)
a partir da Vision One do tenant `prodesp-sp`. Backend FastAPI + coletor APScheduler. TimescaleDB
**provisionado mas não integrado**. Operação via WSL + scripts `.bat`. Sem auth/CI/testes (dívidas mapeadas).

---

# 25. Prompt inicial sugerido (colar no Claude Code)

> **Contexto do projeto**
> Você vai continuar o desenvolvimento de um **wallboard SOC/Executivo do Trend Vision One** para o tenant
> **PRODESP** (`prodesp-sp`), usado em TV no modo quiosque. Toda a documentação técnica está na pasta
> `handoff/` — **leia `handoff/CLAUDE.md` primeiro**, depois os arquivos em `handoff/docs/` na ordem do
> `CLAUDE_CODE_HANDOFF.md §24.4`. Os **fontes reais** estão em `~/projetos/soc-dashboard/`.
>
> **Stack:** Backend FastAPI (`app/`) + coletor APScheduler (`collectors/`), estado no **Redis**
> (`v1:{tenant}:*`), tempo real por **WebSocket** (pub/sub `ws:{tenant}`). Frontend **single-file**
> (`static/index.html`) com ECharts local + mapa Canvas. TimescaleDB está **provisionado mas não integrado**.
>
> **Como rodar (dev, WSL):** `cd infra && docker compose up -d`; em `backend/` com venv:
> `python -m collectors.run` (Terminal A) e `uvicorn app.main:app --host 0.0.0.0 --port 8000` (Terminal B);
> abrir `http://localhost:8000/`. Verificar com `curl /healthz`.
>
> **Regras críticas (não violar):**
> - Não invente; itens `REQUER VALIDAÇÃO` devem ser confirmados no código antes de assumir.
> - **Teto de 100k** do OAT (mostra `100.001`) e **painéis via `securityPosture`** (evita 403 do CREM) são
>   comportamentos **corretos** — não "corrigir".
> - Coletas **best-effort / keep-last-good** são design. **Nunca** `docker compose down -v`.
> - Respeite a **matriz "o que reiniciar"** (coletor × uvicorn × só copiar o HTML).
> - Responda em **português do Brasil**, de forma concisa.
>
> **Primeiras tarefas candidatas (ver `ROADMAP.md`):** proteger a porta 8000 + TLS/`wss`; empacotar as
> fontes localmente; adicionar testes de unidade dos parsers (`parse_posture`, `delta24h`, feed,
> `_count`/100k, `_merge_keep`); decidir o destino de `map:attackers`. Antes de mudar qualquer regra de
> cálculo, confirme em `BUSINESS_RULES.md` e `DECISIONS.md`.
>
> **Sua primeira ação:** leia `handoff/CLAUDE.md` e `handoff/docs/PROJECT_OVERVIEW.md`, depois me diga um
> plano curto para a tarefa que eu escolher.
