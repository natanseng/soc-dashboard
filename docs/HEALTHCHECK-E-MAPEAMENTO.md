# SOC Dashboard — Health Check & Mapeamento de Dados

**Sistema:** `soc-dashboard` (wallboard SOC multi-tenant sobre a API Trend Vision One v3.0)
**Data:** Julho/2026 · **Branch:** `feat/cyber-multitenant` · **Ambiente:** WSL (dev) + EC2 RHEL 9 (prod, `56.124.32.75`)
**Método:** auditoria multi-agente (10 agentes, ~884k tokens, 205 leituras de código) + verificação manual dos achados de maior severidade.

> Snapshot ponto-no-tempo. Cita `arquivo:linha` do estado atual do repositório.

---

## Sumário executivo

Arquitetura em 2 pipelines: **Fase-1** (coletor APScheduler → Redis → `/api/{tenant}/overview`) alimenta Dashboard/Vulnerabilidades/Centro/Mapa; **Cyber** (Postgres, por *backfill*) alimenta Alertas e o painel WAF. 4 profiles por querystring (prodesp/soc/apresentacao/salvador). Padrão **"nunca-zero"/keep-last-good** (None conserva o último bom; 0 de resposta 200 é zero REAL).

**Saúde geral: funcional e com bons padrões de qualidade de dado, mas com riscos operacionais e de segurança relevantes para um ambiente governamental multi-órgão.**

Top 5 prioridades:

| # | Área | Achado | Sev |
|---|------|--------|-----|
| 1 | Segurança | API **sem autenticação** + CORS `*` + isolamento de profile **só no cliente** → qualquer um que alcance o host lê os dados de **todos os órgãos** | 🔴 Alta |
| 2 | Deploy | **Ponto único de falha** (1 EC2, sem HA/CI/IaC) + **sem backup do Postgres** (histórico Cyber) | 🔴 Alta |
| 3 | Deploy | **Sem observabilidade de frescor** — coletor morto fica "verde" (LKG mantém painel populado; `/healthz` só vê liveness) | 🔴 Alta |
| 4 | Coletor | `_DEVTYPE_CACHE` global (não por tenant) → inventário do prodesp classifica servidor/endpoint dos outros | 🔴 Alta |
| 5 | Frontend | Dashboard **apaga a coluna** do órgão num 500 transitório (viola keep-last-good que a tela Vuln respeita) | 🔴 Alta |

---

# PARTE 1 — Mapeamento: de qual API vem cada dado e como é tratado

Convenções: **V1** = API Vision One v3.0. Fluxo Fase-1 = `coletor(tiers.py)→Redis v1:{tenant}:*→FastAPI /api/{tenant}/overview→front`. Fluxo Cyber = `V1→Postgres(backfill)→/alerts|/cyber→front`.

## 1. Dashboard (`#exec`) — colunas de risco por tenant + Cyber Risk Subindexes

Fonte quase toda **`GET /v3.0/asrm/securityPosture`** (recurso-base Cyber Risk Overview, sem CREM-Core), coletado no T1/60s (`tick_t1` primário, `tick_dashboard` secundários), gravado em `v1:{tenant}:posture` (+ cópia `:lkg` durável). A página de subíndices é **request-time** (chama a V1 na hora).

| Painel | API V1 | Rota / Redis | Tratamento antes de exibir |
|--------|--------|--------------|----------------------------|
| Gauge **Risk Index** | `securityPosture.riskIndex` | `/api/{t}/overview → posture` (`v1:{t}:posture`) | `parse_posture`: ausente→`None` (nunca 0). Front `_tGaugeSet`: arredonda 1 casa, cor <30 verde/<70 amarelo/≥70 vermelho; não-finito→ponteiro 0 + "—". Selo "AO VIVO/SEM DADOS". LKG durável (`:lkg`). |
| **Níveis** Exposição/Ataque/Config | `securityPosture.riskCategoryLevel.{exposure,attack,securityConfiguration}` (texto low/med/high) | mesma chave | Valor **cru** da API (comentário `tiers.py:98-100`: API=fonte da verdade, mesmo que console mostre outro). `_LVL`: low→Baixo, medium→Médio, **high→Alto/vermelho** (`c-crit`); ''→"—". |
| **Superfície de Ataque** (6 tiles) | `securityPosture.exposureStatus.*` (publicIpCount, servicePortCount, insecureHostCount, weakAuthenticationCount, cloud highRiskCount) + `cveManagementMetrics.count` | `posture.surface` (aninhado) | `_sv`: null/''→"—" (nunca fabrica 0). Cores fixas por tile. `cve_count` fica '' (não None) quando ausente. |
| **Fatores de risco** (barras) | `securityPosture.highImpactRiskEvents[]` (factor, eventCount, affectedAssetCount) | `posture.factors` | Coletor ordena por `affectedAssetCount` desc, corta **TOP 6**. Front pega **TOP 4**; barra=assets/max; nome traduzido por `_FACTOR_PT`. |
| **Subíndices** — faixa org (Cyber Risk Index) | `assetGroups` (item raiz) + `securityPosture` (superfície) | `/cyber/asset-groups?tenantId=sggd` (**request-time**, cache `cyber:assetgroups:{t}` 600s) | `renderOrgBand`: índice arredondado 1 casa, exibido só se riskIndex≠null E (>0 OU assetCount>0). **Nota:** `d.levels` é retornado mas nunca consumido (campo morto). |
| **Subíndices** — grade de gauges | `assetGroups` (itens não-raiz: name/riskIndex/riskLevel/assetCount) | mesmo payload | 1 gauge por grupo de ativos; skeleton só reconstruído quando o conjunto de nomes muda. assetCount 0 = "—" legítimo. Nome anonimizado (`_subLabel`) só no profile *apresentacao*. |

> Salvador (`SUBINDEX_TENANT=null`) não tem a página de subíndices.

## 2. Alertas (`#alertas`) — 100% Postgres (pipeline Cyber)

Única origem V1: **`GET /v3.0/workbench/alerts`**, coletado por `collectors/cyber_workbench_alerts.py::run_wb_alerts` (**não** `tiers.py`, **sem** Redis) → tabela `cyber_workbench_alert`. ⚠️ `cyber_scheduler` **não roda** → tabela populada por **backfill manual**. `loadAlertas()` dispara 5 fetches. Falha → `{status:'unavailable'}` → "Dados indisponíveis" (0 é zero REAL).

| Painel | API V1 | Rota | Tratamento |
|--------|--------|------|-----------|
| **Banda** Total 30d / Ativos / Fechados | workbench/alerts | `/alerts/summary` (scoped `?tenants=`) | SQL: `total30d`=count WIN30, `active`=Open+In Progress, Closed via byStatus. Front `_alNum` (pt-BR), null→"—". Título alterna "consoles do SOC" vs "todas as consoles". |
| **Chips por severidade** 30d | workbench/alerts (campo severity) | `/alerts/summary` | `GROUP BY severity` sobre WIN30. Ordem critical>high>medium>low>info; chaves **dinâmicas**; null→"unknown". |
| **Cards por console** | workbench/alerts por tenant | `/alerts/by-tenant` (**não** aceita `?tenants` — recorte no front) | open/inProgress/active/total30d + MTTD/MTTR (avg detect/resolve_seconds) + severityActive (snapshot). Front pula `sggd` e `!_inProfile`; paginado 6/página, 10s. |
| **Cards por subíndice** | (a) `assetGroups` (nomes) + (b) workbench/alerts correlacionado | `/cyber/asset-groups?tenantId=sggd` + `/alerts/by-subindex?tenantId=sggd` | `by_subindex`: `WHERE subindex IS NOT NULL GROUP BY subindex`. Front faz **união** dos nomes de asset-groups + subíndices com workbench (não perde grupo sem alerta → 0). |
| **Histograma 30d** (ECharts empilhado) | workbench/alerts (createdDateTime) | `/alerts/history?days=30` | `GROUP BY tenant_id, dia` → `byTenant` + `consolidated`. Front empilha só tenants `_inProfile`; cor `_AL_ACCENT`. Selo "AO VIVO" é cosmético (dado é backfill). |

> Rotas `/alerts/by-organization` e `/alerts/events` existem e funcionam mas **não** são usadas por esta tela.

## 3. Vulnerabilidades (`#vuln`) — rotativa por tenant (10s/slot)

Tudo de **um snapshot** `GET /api/{tenant}/overview` (`applyVulnScreen(d.vulnerabilities, d.posture)`). Keep-last-good por tenant.

| Painel | API V1 | Coletor→Redis | Tratamento |
|--------|--------|---------------|-----------|
| **"Vulnerabilidades no ambiente"** (total distinto + contexto) | `securityPosture.cveManagementMetrics.count` + coverage/mttp/vulnerableEndpointRate | `parse_posture`→`posture.vuln.*` (T1/60s) | Total = `cveManagementMetrics.count` (**distinto**, bate com console "Group by: CVE event"). **Nunca** usa `internalAssetVulnerabilities.totalCount` (que é POR-ATIVO = milhões). Contexto: Cobertura%, Endpoints vulneráveis%, MTTP dias. |
| **Top 10 CVEs** (tabela) | `internalAssetVulnerabilities` (top=50, orderBy cveRiskLevel desc, até 500) — requer CREM-Core | `vuln_rankings` step 1, `tick_vuln` T4/1h → `v1:{t}:vulnerabilities` | Endpoint vem **por-ativo** → coletor **deduplica por cveId** (`by_cve`): mantém maior `cveRiskScore`, soma affectedAssetCount ("Máquinas"). Re-rank cliente por (impactScore, máquinas). "Exploração global"=`globalExploitActivityLevel`; "Regras IPS"=`len(preventionRules)`. |
| **Top 10 Servidores** | `attackSurfaceDevices` (top=50, até 800) + `endpointSecurity/endpoints` (tipo autoritativo) | `vuln_rankings` step 2/3 | `_classify_device` usa tipo do inventário (fallback SO). **Sem** o mapa autoritativo → `raise` + keep-last-good (não emite ranking degradado). Sort (cveCount, latestRiskScore). ANON→"Servidor N". |
| **Top 10 Endpoints** | mesma fonte (ramo `desktop`) | mesmo loop | idêntico; ANON→"Endpoint N". Status compartilhado com Servidores. |
| **Top 10 Aplicações** | `attackSurfaceLocalApps` (top=50, até 500) | `vuln_rankings` step 4 | Agrupa por `_norm_app(vendor,name)`: soma riskIndicatorEventCount (`cveIndicators`, **aproximação** ~ CVEs), soma deviceCount, max risk. Sem barra de criticidade. |
| **Intrusion Prevention Events** (IPS + Exploit) | (1) `search/detections` countOnly `eventName:DEEP_PACKET_INSPECTION_EVENT`; (2) `oat/detections` MITRE T1190/T1203/T1210/T1211/T1212/T1068 high/crit | `ips_exploit_counts`, **tick próprio** `tick_ips` T3/15min → `v1:{t}:ips` (injetado em `vulnerabilities.ipsEvents`) | Só `totalCount`. IPS 24h+7d; exploit 24h (1 chamada, reduz 429). keep-last-good **por métrica**; 0 de 200 = zero REAL (console sem IPS). Tick separado do vuln_rankings (não fica preso atrás da coleta lenta de CVE). |

## 4. Centro (`#soc`) — multi-tenant, agregado no cliente

Todos os 4 painéis derivam de **`GET /v3.0/oat/detections`** (janelas/filtros diferentes). `pullSoc` busca `/api/{t}/overview` de cada tenant `_inProfile` e agrega. Coleta: primário via T2/T3; secundários via `tick_soc` (15min, escalonado).

| Painel | API V1 (filtro) | Redis | Tratamento |
|--------|-----------------|-------|-----------|
| **Heatmap MITRE** (14 táticas, 24h) | oat/detections `TMV1-Filter: filterMitreTacticId eq 'TA…'`, top=1 (só totalCount), 1 chamada/tática, paralelo sem=6 | `v1:{t}:mitre` | **Soma** contagem por tática entre tenants (sem dedup — detecção não repete entre consoles). `_mitreHeat`: bucket de calor por razão n/max (>0.7,>0.35,>0.1). É **lista** de 14 linhas, não matriz. null→"—". |
| **Live Detections feed** | oat/detections janela 10min, top=100, sem filtro/orderBy | `v1:{t}:feed` | Coletor ordena por data desc (cliente), top 15; severidade=maior riskLevel dos filters[]. Front faz **merge** dos feeds, marca tenant+cor, top 40, **anima** deslizando 1 linha/2.6s. Host→"ativo" no ANON. |
| **Threat Trends 24h** (linha) | oat/detections `riskLevel eq 'high'`, 12 buckets×2h, só totalCount | `v1:{t}:trend` | Filtro high-risk porque totalCount geral satura ~100k. **Soma por índice** de bucket (aproximação, não por timestamp). Único painel que ainda usa ECharts. |
| **Identity Security** (4 cards, 24h) | oat/detections: T1110 (brute), T1078 (valid), T1003 (cred dump), TA0004 (priv esc) | `v1:{t}:identity` | Soma as 4 chaves entre tenants; null pula (mantém "—"). Brute/Valid vermelho-suave, Cred/Priv crítico. |

## 5. Cyber / Mapa (`#map`)

Mapa e "Top ataques externos" vêm do Redis (`search/detections`); WAF vem do Postgres (`workbench/alerts`).

| Painel | API V1 | Rota / Coletor | Tratamento |
|--------|--------|----------------|-----------|
| **Mapa de ataques** (canvas, cor=ferramenta) | `search/detections`, **5 queries** (DPI→Servidor/TippingPoint; SECURITY_RISK+pdi→DDI; WEB_THREAT→CAS; SUSPICIOUS_OBJECT; SECURITY_RISK+"Network Content Inspection"→Endpoint C&C), janela 6h, top=100 | `attack_map_markers`, `tick_map` T3/15min → `v1:{t}:map` | `productCode→ferramenta` (`_MAP_PRODUCTS`). Extrai indicador **externo**: IP público (`is_global`) de src/dst; host de URL; domínio C&C (dedup por denylist `_is_grayware`). Geolocaliza via **GeoLite2** (host→DNS→IP→lat/lon); sem lat/lon é descartado. Ordena por count, corta 70. Front: arco-cometa origem→São Paulo, cor `PROD_COLOR`. Dash SOC: `mergeAttackMaps` soma count. |
| **Bloqueios WAF** | `workbench/alerts` (indicators `requests`, de coletores WAF) | `/cyber/waf?tenants=` (**Postgres**) | `cyber_workbench_alert` (waf_collector, waf_url_host). SQL: total30d + active + Top 10 host `GROUP BY waf_url_host`. `_shorten_host` remove scheme/www/porta/path. **Depende de backfill + seed `cyber_waf_collector`**. |
| **Top ataques externos** (6 linhas) | mesma fonte do mapa (reusa markers) | `/api/{t}/overview → attackMap` | `applyAttackMap`: top 6; país por extenso (`Intl.DisplayNames pt-BR`); "Ferramenta: Cidade - País". Já ordenado por count. |

> ⚠️ **Código morto na tela Cyber:** `loadCyber()` (renderiza em elementos inexistentes, mas ainda dispara 4 fetches `/cyber/*` a cada refresh), `applyIoc` (IDs inexistentes; só acende selos "AO VIVO"), e todo o **engine simulado** `spawnArc`/`renderIOC`/`iocs[]` com IPs C2/TOR **fictícios** (nunca chamado, mas presente).

---

# PARTE 2 — Health Check: achados e melhorias

44 achados. Contagem por severidade: **🔴 Alta ×10 · 🟡 Média ×22 · 🟢 Baixa ×12** (+1 nota positiva).

## 🎯 Prioridades (Alta severidade)

### Segurança
1. **API sem autenticação alguma** (`main.py`: nenhum `Depends`/auth em `/api/{tenant}/overview`, `/alerts/*`, `/cyber/*`, `/ws/*`). Único controle = "atrás de proxy" (comentário). → *Auth na borda (basic/SSO no proxy) ou bind 127.0.0.1; auditar o Security Group da EC2.*
2. **Isolamento de profile é só no cliente** — `{tenant}` é path livre sem allow-list no servidor. `GET /api/salvador/overview` (ou qualquer id) responde a qualquer requisitante, ignorando `?profile=`. A exclusividade do Salvador **não existe na camada de dados**. → *Amarrar profile→tenants no backend; rejeitar tenant fora de escopo (403).* **Não há injeção SQL** (filtros parametrizados `= ANY($1)` — confirmado).
3. **CORS `allow_origins=['*']`** com métodos/headers curinga + zero auth (`main.py:35-40`) → qualquer site que um analista visite pode ler os dados cross-origin. Servindo same-origin, CORS nem é necessário. → *Remover o middleware ou restringir à origem do wallboard.*

> Impacto combinado: num wallboard de **múltiplos órgãos governamentais**, a segmentação só-frontend é contornável trivialmente. **Controle compensatório crítico = isolamento de rede (a porta 8000 só pode ser acessível pelo proxy/rede do wallboard). Verificar e documentar isso é a ação #1.**

### Deploy & operação
4. **Ponto único de falha total** — 1 EC2 roda API + coletor + Postgres + Redis; sem HA, sem CI/CD, sem IaC (provisionamento = shell script imperativo à mão). Instância morre = wallboard cai, recriação manual. → *AMI dourada/Terraform + ASG size=1 (auto-recreate) + snapshots EBS + runbook de DR testado.*
5. **Sem backup do Postgres** — histórico Cyber/Alertas só existe no volume `db_data`; única menção a `pg_dump` é 1 linha manual no runbook; e o próprio deploy documenta `podman volume rm db_data` como recuperação (a um passo de apagar tudo). → *Timer diário pg_dump→gzip→S3 versionado + snapshot EBS; bloquear wipe atrás de dump obrigatório.*
6. **Sem observabilidade de frescor** — `/healthz` só vê liveness (Redis ping + PG). Com keep-last-good/LKG, os painéis ficam populados **mesmo com o coletor morto** (token expirado, API fora) → dados envelhecem e o `/healthz` responde "ok". → *Heartbeat por tier no Redis (`v1:collector:heartbeat`), `/healthz` ler idade do heartbeat, e monitor externo (uptime + alerta Teams/e-mail).*

### Coletor
7. **`_DEVTYPE_CACHE` global, não por tenant** (`tiers.py:899,926`) — o primeiro tenant a rodar (prodesp) popula o mapa nome→tipo com o inventário **dele**, e por 6h todos os outros classificam servidor×endpoint usando o inventário do prodesp (com fallback por SO). Sem lock → race no rebuild (300s, pesado). *(Verificado.)* → *`_DEVTYPE_CACHE[tenant]` + `asyncio.Lock` por tenant.*
8. **keep-last-good do posture pulado sob cancelamento** (`run.py:135-137,413-424`) — `_guarded` cancela via `CancelledError` (BaseException), que **não** cai no `except Exception` → `_keep_posture` (renova TTL/restaura LKG) é pulado. E o orçamento é apertado (workbench 7 chamadas seriais ~10-14s + posture retry até 40s > guard 51s). Ou seja, no exato 500-storm que o LKG deveria cobrir, o painel de risco pode zerar após 30min. → *Mover `_keep_posture` para `finally`; paralelizar o workbench.*

### Frontend
9. **Dashboard viola keep-last-good** (`index.html:2073`) — `catch(e){ renderTenantColumn(t, null) }` reescreve a coluna inteira com "—"/"SEM DADOS" num único 500/timeout de um refresh de 60s. A tela Vuln (mesmo endpoint) faz o certo (conserva o anterior). É a tela mais exibida → flicker "SEM DADOS" engana o operador. → *No catch, só marcar selo "ATRASADO" e preservar os últimos valores.*

## ✅ Quick wins (baixo esforço, alto valor)

| Ação | Onde | Benefício |
|------|------|-----------|
| **Apagar `.env.bak.1784680962`** (4 tokens vivos em texto puro, pasta OneDrive) | `backend/` | Reduz superfície de vazamento de credenciais. *(Verificado: gitignored/não-tracked, mas é cópia não gerenciada.)* |
| **Restringir CORS** (remover `*`) | `main.py:35-40` | Fecha exfiltração cross-origin |
| **Corrigir keep-last-good do Dashboard** (#9) | `index.html:2073` | Fim do flicker "SEM DADOS" |
| **Remover código morto** `loadCyber`+chamadas / engine `spawnArc`/`iocs[]` fictícios | `index.html` | −4 fetches inúteis/refresh; elimina risco de exibir threat-intel FABRICADA |
| **Paralelizar `workbench_counters`** (7 `await` seriais → `gather`) | `tiers.py:72-79` | ~10s→~2s no caminho crítico do T1 ×9 tenants; devolve orçamento ao posture |
| **Heartbeat do coletor** | `run.py` + `/healthz` | Torna staleness observável antes do painel branco |
| **Elastic IP** na EC2 | AWS | URL fixa; para de quebrar as TVs em stop/start |
| **Logar `type(exc).__name__`** nos ~12 `except` de rota | `main.py` | Diagnóstico ("unavailable" hoje esconde db-down vs erro SQL vs timeout) |
| **Reemitir 4 tokens de ~15 anos** (Poupatempo/SPI/Alesp/CPTM expiram ~2041) | Console V1 | Blast-radius de token vazado cai de 15 anos p/ ≤1 ano |

## Demais achados por dimensão (média/baixa)

### Coletor
- 🟡 `tick_dashboard` empacota workbench+posture(retry 40s)+events num guard de 51s → o bloco **events** (último) é cronicamente cancelado nos secundários com posture lento. *(Reordenar events antes do posture, ou jobs separados.)*
- 🟡 **Sem limitador de concorrência** por cliente; só backoff reativo de 429. Rajada de startup (T1/T2/T3 + 8×DASH + 9×VULN/IPS/MAP) → 429-storm; o `sleep(2^n)` do backoff roda dentro do tick e consome o guard. *(Semáforo 6-8 req/cliente em `get_json`.)*
- 🟡 **Stagger do DASH hardcoded** `2+i*7` (`run.py:455`) — com 8 secundários o último cai aos 51s (comentário diz "~46s", desatualizado); com 9+ colapsa. *(Espaçamento dinâmico `tier1/(n+2)` + jitter.)*
- 🟡 **DNS `getaddrinfo` não cancelável** (`tiers.py:565-581`) — no timeout de 4s a thread do executor segue bloqueada; map(30 hosts)+SO(60 hosts)×9 tenants pode esgotar o ThreadPool e travar o loop. *(Semáforo global de DNS + cache host→IP; ou `aiodns`.)*
- 🟢 **Backoff de 429 frágil**: `int(Retry-After)` quebra se vier como data HTTP; sem jitter/cap; não trata 503. *(Parse defensivo + jitter + 503.)*
- 🟢 Guards externos de T3/T4 praticamente inertes (timeout>>real) + docstring do módulo descreve só T1/T2/T3. *(Alinhar + documentar a topologia atual: ~46 jobs, 6 tipos, 9 clientes.)*

### Backend & integridade
- 🟡 **`validate_org_in_tenant` fora do try/except** (`/cyber/summary|by-organization|map|events`) — soluço do Postgres vira **HTTP 500** (quebra o contrato falha-segura de todas as outras rotas). *(Mover para dentro do try.)*
- 🟡 **`/api/{tenant}/overview` sem try/except nem MGET** — Redis fora ou JSON corrompido = 500 na tela mais crítica; 11 `GET` + hgetall/zrevrange **em série** (15 idas/chamada). *(try/except + `mget`/pipeline + `_loads_or_default`.)*
- 🟡 **Agregações de tabela cheia vs `command_timeout=10s`** — `count(*)` all-time (byStatus/totalStored) e sem janela varrem `cyber_workbench_alert`/`cyber_oat_observation` inteiras; conforme o backfill cresce, passam de 10s → viram "unavailable" **silenciosamente**. *(Janela default 90d + índices (tenant_id, created_at/event_time) + rollup.)*
- 🟡 **0-vs-indisponível no caminho Redis** — chave ausente e vazio real retornam `{}`/`[]` idênticos, sem marcador de status (diferente das rotas Cyber que têm `status`). *(Bloco de frescor/disponibilidade por seção no overview.)*
- 🟡 `'observed'` tem definições diferentes em `summary` (=valor exato) vs `map_points` (=resíduo) → totais não reconciliam; `NOT block_policy_matched` descarta NULLs. *(Fonte SQL única por camada; `IS NOT TRUE`.)*
- 🟢 Dedup de vuln assume `affectedAssetCount==1/linha` — se algum tenant devolver a contagem real, "Máquinas" infla (N×valor). *(DISTINCT de assetId, ou detectar em runtime.)*
- 🟢 `/alerts/events` e `/alerts/history` sem piso de limit/days (limit≤0 → SQL erro silencioso); `validate_org_in_tenant` aceita organizationId sem tenantId. *(Clampar `min(max(x,1),500)`; exigir tenant_id.)*

### Segurança (média/baixa)
- 🟡 4 tokens (~15 anos, expiram ~2041) vs 5 outros (≤1 ano). — *Reemitir.*
- 🟡 **`.env.bak.1784680962`** com 4 JWTs vivos (verificado). — *Apagar.*
- 🟡 DSN com senha placeholder **`dev_change_me`** (=`.env.example`); confirmar se foi para produção. — *Rotacionar.*
- 🟢 Anonimização *apresentacao* é só cosmética — a API ainda devolve ids/nomes reais (visível no devtools). — *Documentar como visual, ou mapear no servidor.*
- 🟢 Roster de clientes hardcoded no `index.html` servido sem auth → carteira vaza mesmo sem tocar a API. — *Proteger o bundle.*
- 🟢➕ **Nota positiva:** higiene de segredos adequada — tokens só no `.env`, nunca serializados/logados (`diag()` extrai só status; `cyber_tokens.public_dict` expõe só boolean), `.gitignore` cobre `.env*`. *(Manter; adicionar gitleaks no CI.)*

### Deploy (média/baixa)
- 🟡 **HTTP em claro `0.0.0.0:8000` sem TLS/auth** no script automatizado — contradiz o runbook manual (Nginx+TLS+127.0.0.1). Dois caminhos de deploy divergentes. *(Padronizar no seguro.)*
- 🟡 **`socdash-cyber` com `Restart=always` + `return` limpo** se DB_DSN vazio → crash-loop a cada 10s no journal, mascarando que o pipeline não popula. *(Decidir: habilitar de verdade OU remover o unit.)*
- 🟡 **Imagens em tags flutuantes** (`timescaledb:latest-pg16`, `redis:7-alpine`) + pacotes sem pin → recriação da instância pode puxar versão diferente no pior momento. *(Fixar por versão/digest.)*
- 🟡 **Deploy manual scp+tar com segredos em claro**, sem tag/rollback, de branch não-mergeada (`master` desatualizada). *(Release branch + tags; `git pull` no host; secrets fora do tarball.)*
- 🟢 Senha `dev_change_me` no Quadlet do script. 🟢 Sem rotação/retenção de logs (só journald local). 🟢 Bootstrap de migrations com ordem crítica e recuperação destrutiva, sem teste de fresh-install.

### Frontend (média/baixa)
- 🟡 **Nenhum `fetch` tem timeout/AbortController** — backend lento (Poupatempo 500/504) pendura requests, satura ~6 conexões/origem e congela a tela; sem watchdog de staleness (pill fica "AO VIVO" com horário velho). *(Helper `fetchJSON` com AbortController + watchdog.)*
- 🟡 **`loadCyber()` código morto** ainda dispara 4 fetches `/cyber/*` a cada refresh do Mapa. *(Remover.)*
- 🟡 **Engine simulado** (`spawnArc`/`renderIOC`/`iocs[]` com IPs C2/TOR **fictícios**) — morto hoje, mas reativar exibiria threat-intel FABRICADA num SOC real. *(Excluir.)*
- 🟡 **Google Fonts via CDN externo** (`index.html:7-8`) — única dependência de rede externa; em rede segregada de governo pode bloquear/atrasar o `<head>`. *(Self-hostar as fontes, como já é o echarts.)*
- 🟢 `echarts.min.js` bloqueante sem `onerror` (se o AV quarentenar, gráficos somem sem aviso). 🟢 keep-last-good parcial em `applyWorkbench` (objeto meio-preenchido zera severidades ausentes). 🟢 `animateCounts` re-anima de 0 a cada 60s (KPIs "resetam" visualmente).

---

## Roadmap sugerido

**Sprint 1 — Segurança & quick wins (baixo esforço):** apagar `.env.bak`; restringir CORS; corrigir keep-last-good do Dashboard; remover código morto (`loadCyber`, engine simulado); logar exceções nas rotas; Elastic IP; reemitir os 4 tokens longos. **+ verificar/documentar o isolamento de rede da porta 8000 (crítico).**

**Sprint 2 — Resiliência do coletor:** `_DEVTYPE_CACHE` por tenant + lock; `_keep_posture` em `finally`; paralelizar `workbench_counters`; semáforo de concorrência/DNS; heartbeat + monitor externo.

**Sprint 3 — Robustez de backend/dados:** `validate_org_in_tenant` dentro do try; try/except + MGET no overview; janela temporal + índices nas agregações Cyber; marcador de frescor no overview.

**Sprint 4 — Deploy/operação:** backup automatizado do Postgres (timer + S3) + snapshot EBS; autenticação na borda + TLS; IaC/AMI + runbook de DR; fixar versões de imagem; decidir o destino do `socdash-cyber`.
