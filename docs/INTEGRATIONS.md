# 10. Integrações Externas

## 10.1 Trend Vision One API v3.0 (integração principal)
Fonte de **todos** os dados do dashboard.

- **URL base:** `https://api.xdr.trendmicro.com` (`V1_API_BASE`; região US/LATAM da Prodesp).
- **Autenticação:** `Authorization: Bearer <API_TOKEN>` (token gerado em Administration → API Keys).
  `Content-Type: application/json;charset=utf-8`.
- **Cliente:** `app/vision_one.py` (`httpx.AsyncClient`, timeout **60s**).
- **Paginação:** por `nextLink` (URL absoluta; o cliente remove a base e reenvia sem params). `get_paginated(limit=...)`.
- **Filtros:** header `TMV1-Filter` (ex.: `severity eq 'high'`, `status eq 'Closed'`, `criticality eq 'high'`,
  `cveRiskLevel eq 'high'`, `filterMitreTacticId eq 'TA0001'`, `riskLevel eq 'high'`, `osPlatform eq 'windows'`).
  Busca textual por `TMV1-Query` (ex.: `riskLevel:high OR riskLevel:critical`, em `networkActivities`).
- **Rate limit:** `get_json` trata **HTTP 429** com backoff exponencial (`2**attempt`), respeitando `Retry-After`, `max_retries=5`.
- **Timeouts por coleta (via `asyncio.wait_for`):** attack surface 20s, vuln 20s (por nível) e 20s (top),
  mitre 45s/tática, feed 20s, trend 20s/bucket, identity 45s, endpoints 20s, suspiciousObjects 40s.
- **Permissões necessárias:** escopos que cobrem Workbench, Observed Attack Techniques (OAT),
  ASRM/Cyber Risk, Endpoint Security, Threat Intelligence. **CREM-Core** é necessário para o drill-down
  de ASRM (ver riscos).

### Endpoints usados e mapeamento
| Endpoint | Coleta | Campos consumidos (após parsing) |
|---|---|---|
| `/v3.0/workbench/alerts` | `workbench_counters` | `totalCount` por `severity`/`status` |
| `/v3.0/asrm/securityPosture` | `security_posture`+`parse_posture` | `riskIndex`, `riskCategoryLevel`, `cveManagementMetrics`, `exposureStatus`, `highImpactRiskEvents`, `securityConfigurationStatus` |
| `/v3.0/oat/detections` | `event_tallies`, `detections_feed`, `mitre_tactics`, `threat_trend`, `identity_counts` | `totalCount`; `items[].filters[].riskLevel/name/mitre*Ids`, `items[].detectedDateTime`, `items[].endpoint.endpointName` |
| `/v3.0/asrm/highRiskUsers` · `/highRiskDevices` | `high_risk` | `latestRiskScore`, `name/deviceName`, `type/osName` |
| `/v3.0/asrm/attackSurfaceDevices` · `attackSurfaceCloudAssets` · `attackSurfaceDomainAccounts` | `attack_surface_counts` | `totalCount` (com filtros) |
| `/v3.0/asrm/internalAssetVulnerabilities` | `vuln_metrics` | `totalCount` por `cveRiskLevel`; `cveId/cvssScore/affectedAssetCount/cveRiskLevel/cveRiskScore` |
| `/v3.0/endpointSecurity/endpoints` | `endpoints_summary` | `totalCount` por `osPlatform/type/eppAgentStatus/edrSensorConnectivity/eppAgentComponentVersion` |
| `/v3.0/threatintel/suspiciousObjects` | `suspicious_objects` | `type`, `riskLevel`, `scanAction`, `lastModifiedDateTime`, valor no campo homônimo ao `type` |
| `/v3.0/search/networkActivities` | `network_activities` (**reservado, não usado**) | — |

### Frequência de coleta
T1 (60s): workbench, posture. T2 (5min): eventos, high risk, feed. T3 (15min): surface, vuln, mitre,
trend, identity, ioc, endpoint. (Ver `BACKEND.md`.)

### Riscos conhecidos
- **CREM-Core expirado (Prodesp):** `asrm/attackSurface*`, `asrm/highRisk*`, `asrm/internalAssetVulnerabilities`
  retornam **403 (AccessDeny_000403)**. É **esperado** — o dashboard usa `securityPosture` (200) como fonte.
  Tratamento tolerante (keep-last-good). Renovar CREM habilitaria o drill-down por ativo.
- **Teto de 100.000 no OAT:** `totalCount` de `/oat/detections` satura em ~100k; painéis de alto volume
  exibem `100.001`. Limite da API, não bug (ver BUSINESS_RULES.md).
- **Filtros dependem do tenant:** nomes de campo em `orderBy`/`TMV1-Filter` podem divergir e causar 400;
  por isso `high_risk` ordena no cliente e várias coletas usam `top=50` (inventário rejeita `top=1`).
- **Sem histórico de série temporal:** 7d/30d são contagens pontuais (sem base persistida).

## 10.2 MaxMind GeoLite2-City (opcional)
- **Uso:** geolocalizar IOCs de rede para o Attack Map (`app/geo.py`, `geoip2`).
- **Arquivo:** `data/GeoLite2-City.mmdb` (~66 MB). `GEOIP_DB` vazio → mapa inativo (backend segue normal).
- **Fluxo:** URL→host, domínio→**DNS** (`getaddrinfo`, 4s)→IP, IP direto → `lookup_ip` → lat/lon/país. Destino fixo São Paulo.
- **Risco:** licença/atualização do `.mmdb` é responsabilidade do operador; não versionar (tamanho/licença).

## 10.3 DNS (resolução para geo dos IOCs)
- `_resolve()` usa `socket.getaddrinfo` (via loop async), best-effort, timeout 4s, semáforo 10.
- **Risco:** resolução depende da rede do host; domínios internos/privados podem não resolver (ignorados no mapa).

## 10.4 Google Fonts (CDN)
- `index.html` carrega Oxanium/Inter/JetBrains Mono de `fonts.googleapis.com`.
- **Risco:** requer internet no navegador da TV. `REQUER VALIDAÇÃO`: empacotar fontes localmente p/ operação offline.
