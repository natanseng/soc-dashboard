# 21. Decisões de Arquitetura (ADRs)

Formato: Contexto → Decisão → Consequência. Registram o "porquê" para o próximo desenvolvedor não reverter sem querer.

## ADR-001 — Redis como estado quente (não um banco relacional)
- **Contexto:** wallboard precisa de leitura instantânea e push em tempo real; dados são "fotos" recentes.
- **Decisão:** guardar os agregados no **Redis** (chaves `v1:{tenant}:*`, TTL curto) e usar **pub/sub**
  (`ws:{tenant}`) para empurrar deltas ao WebSocket. TimescaleDB fica para histórico (fase futura).
- **Consequência:** simples e rápido; estado é **volátil** (recriado a cada tick). Sem histórico até integrar o banco.

## ADR-002 — Painéis de risco alimentados por `securityPosture`, não por `asrm/*`
- **Contexto:** `asrm/attackSurface*`, `asrm/highRisk*`, `asrm/internalAssetVulnerabilities` dão **403** sem CREM-Core (caso da Prodesp).
- **Decisão:** usar `asrm/securityPosture` (recurso-base, **200**), que já traz os **agregados** de superfície,
  vulnerabilidades e eventos de risco. Os endpoints `asrm/*` (drill-down por ativo) ficam opcionais/best-effort.
- **Consequência:** dashboard funciona **sem** CREM-Core. Drill-down por ativo só com CREM renovado.

## ADR-003 — Threat Trend por ALTO RISCO
- **Contexto:** `totalCount` do OAT **satura em ~100k**; a série total vira linha reta.
- **Decisão:** contar por bucket apenas `riskLevel eq 'high'` (12×2h = 24h).
- **Consequência:** números menores, com **variação real**. (Ver RN02/RN03.)

## ADR-004 — Contagem via `totalCount` com `top` pequeno
- **Contexto:** a maioria dos painéis precisa de **contagens**, não de listas.
- **Decisão:** `_count()` lê só `totalCount` com `top` mínimo; puxar itens só quando há lista (feed, IOCs, top CVEs).
- **Consequência:** payloads mínimos, coleta rápida. Endpoints de inventário exigem `top=50` (rejeitam `top=1`) — ADR-010.

## ADR-005 — Ordenação client-side em `high_risk`
- **Contexto:** `orderBy` com nome de campo divergente causa **400** em alguns tenants.
- **Decisão:** buscar sem `orderBy` e ordenar por `latestRiskScore` no cliente.
- **Consequência:** robusto a diferenças de tenant; custo de ordenar poucos itens é irrelevante.

## ADR-006 — Frontend single-file + ECharts local, sem build
- **Contexto:** alvo é uma **TV em modo quiosque**; deploy precisa ser trivial.
- **Decisão:** um `index.html` (HTML+CSS+JS) com ECharts servido localmente; atualização = copiar o arquivo.
- **Consequência:** deploy simplíssimo (sem npm/bundler). Custo: manutenibilidade e dependência de CDN das fontes (dívida).

## ADR-007 — Coletor e API como processos separados
- **Contexto:** uma coleta lenta/instável não pode derrubar a interface.
- **Decisão:** `collectors/run.py` (APScheduler) e `uvicorn app.main:app` rodam **separados**, comunicando via Redis.
- **Consequência:** isolamento de falhas; a API serve sempre o último estado do Redis. Custo: dois processos para operar.

## ADR-008 — Keep-last-good + TTLs generosos
- **Contexto:** timeouts pontuais (uma tática MITRE, uma técnica) zerariam painéis.
- **Decisão:** `_merge_keep` preserva o último valor bom quando o novo é `None`; TTLs ~5× o intervalo do tier.
- **Consequência:** painéis estáveis sob instabilidade transitória. Custo: pode exibir valor levemente defasado.

## ADR-009 — WebSocket para deltas + pull de 60s como rede de segurança
- **Contexto:** quer-se tempo real, mas sem depender só do WS (proxies podem bloquear upgrade).
- **Decisão:** boot faz `GET /overview`; depois aplica deltas via `WS /ws/{tenant}`; um refresh periódico
  re-puxa o overview.
- **Consequência:** tempo real quando o WS funciona; **degradação graciosa** para polling quando não.

## ADR-010 — `top=50` nos endpoints de inventário
- **Contexto:** `attackSurface*`, `internalAssetVulnerabilities`, `endpointSecurity/endpoints` rejeitam `top=1`.
- **Decisão:** usar `top=50` nessas contagens (ainda lendo só `totalCount`).
- **Consequência:** compatível com a API; payload continua pequeno.
