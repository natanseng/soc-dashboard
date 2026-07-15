# 9. Frontend

## Tecnologia
- **HTML + CSS + JavaScript vanilla**, em **arquivo único**: `backend/static/index.html` (~1.340 linhas).
- **ECharts** para gráficos (servido localmente: `echarts.min.js`; versão exata `REQUER VALIDAÇÃO`, provável 5.x).
- **Mapa de ameaças:** engine própria em **Canvas 2D** (sem lib de mapa).
- **Sem build/npm/framework.** Editar o HTML e recarregar (`Ctrl+Shift+R`) — nenhuma etapa de compilação.
- **Fontes (Google Fonts CDN):** Oxanium (display/números), Inter (texto), JetBrains Mono (timestamps).
  `REQUER VALIDAÇÃO`: dependência de internet para as fontes na TV (considerar empacotar p/ offline).

## Configuração por URL (query string)
- `?tenant=<id>` — tenant a consultar (default `prodesp-sp`). Rótulo via `TENANT_LABELS`.
- `?api=<base>` — base da API. Vazio = **mesma origem**; em dev (porta 5173 / `file://`) usa `http://localhost:8000`.
- `WS_BASE` derivado de `API_BASE` (`http→ws`, `https→wss`).

## Gerenciamento de estado / comunicação
- **Boot** (`boot()`): registra os charts ECharts (`reg(id,opt)`), monta o mapa (`sizeMap/buildDots/drawMap`),
  instala tooltip de IOC, e chama `initLive()`.
- **`initLive()`**: `setTenantLabel()` + `pullLive()` (carga inicial) + `connectWS()` (tempo real).
- **`pullLive()`**: `fetch(API_BASE + '/api/{tenant}/overview')` → `applyLive(d)`; guarda em `lastLive`; `setApiState(ok)`.
- **`connectWS()`**: abre `WS /ws/{tenant}`; em `onmessage`, roteia por `m.type`:
  - `posture` → `applyPosture` + `applySurface` + `applyVuln` + `renderRiskFactors` + `applyAdoption`
  - `workbench` → `applyWorkbench` + `applyThreatDet({workbench})`
  - `events` → `applyEvents` + `applyThreatDet({events})`
  - `mitre|feed|trend|identity|ioc|endpoint` → `applyMitre|applyFeed|applyTrend|applyIdentity|applyIoc|applyEndpoint`
  - Reconecta em 5s ao fechar (`onclose`).
- **`refreshData()`** (loop): re-render de sparkline decorativa + `pullLive()` + anima contadores da tela ativa.
- **Estado de conexão:** pílula `#apiState` (verde "AO VIVO · hora" / vermelho "SEM CONEXÃO").
- **Sem localStorage/sessionStorage.** Estado só em memória (`lastLive`, variáveis do módulo).

## Rotação de telas
- `screens = ['exec','soc','map','cs']`, `ROT = 20000` (20s). `go(i)` ativa a tela e redimensiona charts.
- **Teclas:** `→`/`←` navega, `espaço` pausa/retoma, `F` fullscreen. Hover no palco (`.stage`) pausa.
- Barra de progresso da rotação via `requestAnimationFrame(rotLoop)`.

## Telas e painéis
### Tela 1 — `#exec` (Dashboard Executivo)
| Painel | id | Conteúdo | Função(ões) |
|---|---|---|---|
| Security Posture | `p-score` | Risk Index em gauge (cor: 0–30 verde, 30–70 âmbar, 70–100 vermelho) | `scoreGaugeOpt`, `applyPosture`, `_setLvl` |
| Threat Overview | `p-threat` | KPIs de eventos (24h/7d/30d + delta) | `applyEvents`, `_fmtEv` |
| Workbench | `p-wb` | Alertas por severidade/status | `applyWorkbench` |
| Attack Surface | `p-surface` | IPs públicos, portas, hosts inseguros, cloud, contas fracas | `applySurface` |
| Vulnerability Mgmt | `p-vuln` | CVEs, MTTP, dias sem patch, % vulnerável, cobertura (donut) | `donutOpt`, `applyVuln`, `renderCVE` |
| Risk Factors | `p-risk` | Ranking de barras (fatores por ativos afetados) | `renderRiskFactors`, `_factorPt` |

### Tela 2 — `#soc` (Centro de Operações)
| Painel | id | Conteúdo | Função(ões) |
|---|---|---|---|
| Threat Detection | `p-det` | 4 KPIs (alertas ativos/críticos, detecções XDR 24h/7d) | `applyThreatDet` |
| MITRE ATT&CK | `p-mitre` | 14 táticas (heat), dividem a altura | `renderMitre`, `applyMitre`, `_mitreHeat` |
| Live Detections | `p-feed` | Feed de detecções recentes (dividem a altura) | `applyFeed`, `_fmtTime` |
| Threat Trends | `p-trend` | Série 24h de **alto risco** (área+gradiente, pico) | `trendOpt`, `applyTrend` |
| Endpoint Security | `p-ep` | Total, EDR conn/disc, EPP off, desatualizados, OS/tipo | `applyEndpoint` |
| Identity Security | (painel do #soc) | Brute force, contas válidas, cred dumping, priv esc | `applyIdentity` |

### Tela 3 — `#map` (Cyber Attack Map)
- **Mapa Canvas:** projeção proporcional (`computeProj`/`proj`), continentes preenchidos (`buildDots`,
  `landCells`), **comets de IOC animados** convergindo para São Paulo (`drawMap`, `bez`), tooltip por IOC.
- **Top IOCs / IOCs por tipo / atacantes:** `applyIoc`, `renderIOC`, `renderAttackers`, `bumpAttacker`.
- Dados de `ioc` (suspiciousObjects) — inclui `geo` (marcadores geolocalizados).

### Tela 4 — `#cs` (Adoção & Valor)
| Painel | id | Conteúdo | Função(ões) |
|---|---|---|---|
| Adoção | `p-adopt` | Recursos endpoint × servidor (barras agrupadas) | `adoptOpt`, `applyAdoption`, `_featPt` |
| Saúde | `p-health` | Indicadores de saúde da plataforma | `applyAdoption`/derivados (`REQUER VALIDAÇÃO`) |
| Valor / ROI | `p-value`, `p-roi` | Valor gerado / gauge ROI | `roiGaugeOpt` |

## Regras/padrões de layout (importantes)
- **Sem cortes/sobreposição:** painéis cujo conteúdo estoura a `grid-row` usam itens `flex:1` (dividem a
  altura). Listas em wrappers horizontais precisam `height:100%`.
- **Truncamento em Grid:** colunas com texto `nowrap` usam `minmax(0,1fr)` (o `min-width:0` no item
  sozinho não basta) para reticências em vez de invadir a coluna vizinha.
- **Números:** `toLocaleString('pt-BR')`. Valores saturados aparecem como `100.001` (teto do OAT).
- **Cores por severidade** via CSS vars (`--crit/--high/--med/--low/--ok`).

## Tratamento de carregamento/erros
- Charts montados em `try/catch`; se um widget falhar, `initLive()` roda mesmo assim (dados reais não
  dependem dos widgets decorativos).
- Sem dados → painel mostra `—`/vazio; pílula "SEM CONEXÃO" quando o `overview` falha.
- Placeholder `_esc()` para escapar texto de dados externos (XSS defensivo).
