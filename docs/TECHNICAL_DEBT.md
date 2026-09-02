# 19. Dívida Técnica

Itens conhecidos, com impacto e prioridade sugerida. (Ver ROADMAP.md para o plano.)

## Alta
- **Sem autenticação no dashboard/API.** Qualquer host na rede lê dados sensíveis via `:8000`.
  → mitigar por rede/proxy (SECURITY.md). *Impacto: exposição de dados.*
- **TimescaleDB provisionado mas NÃO integrado.** `asyncpg` ocioso; nenhum tier escreve no banco.
  Consequência: **sem série temporal** — 7d/30d são contagens pontuais, sem tendência histórica/YoY.
  *Impacto: limita análise; retrabalho futuro para popular o schema.*
- **Sem testes automatizados / CI.** Validação só manual/empírica. *Impacto: risco de regressão.*

## Média
- **CORS `*`** em produção (deveria ser mesma origem). *Impacto: exposição desnecessária.*
- **Fontes via CDN** (Google Fonts) → dependência de internet no navegador da TV. *Impacto: operação offline.*
- **`map:attackers` (zset) é lida pelo `overview` mas nunca escrita** por nenhum tier (provável legado).
  → decidir: remover a leitura ou implementar o alimentador. *Impacto: código morto/confuso.*
- **Coletor não orquestrado em container.** O compose sobe só infra; a imagem do Dockerfile é só a API.
  → definir serviço do coletor (systemd/container). *Impacto: deploy de produção incompleto.*
- **Sem observabilidade estruturada.** Só logs de texto; sem métricas/health além de `/healthz`.

## Baixa
- **Frontend single-file (~1.340 linhas)** sem módulos/build. Funciona bem para wallboard, mas dificulta
  manutenção conforme cresce. *Impacto: manutenibilidade.*
- **Coletores reservados não usados** (`network_activities`, `oat_detections`, `endpoint_inventory`).
  → usar ou remover para reduzir ruído.
- **Sparkline decorativa** no Dashboard (`threatSpark`) ainda não reflete dado real.
- **Hardcodes de tenant** (`TENANT_LABELS`, default `prodesp-sp`) — parametrizar para multi-tenant.
- **Versão do ECharts local** não documentada (`REQUER VALIDAÇÃO`).
- **Rótulos/formatos marcados `REQUER VALIDAÇÃO`** no front (`_fmtTime`, painel `p-health`).
- **`docker-compose.yml` não auditado** nesta documentação (`REQUER VALIDAÇÃO` de imagens/volumes/env).

## Itens que **não** são dívida (design intencional — não "corrigir")
- **Teto de 100k** exibido como `100.001` — limite da API (RN02).
- **Painéis alimentados por `securityPosture`** em vez de `asrm/*` — evita 403 CREM (ADR-002).
- **Contagem via `totalCount` + `top` pequeno** — economia de payload (ADR-004).
- **Coletas best-effort com keep-last-good** — resiliência a timeouts (ADR-008).
