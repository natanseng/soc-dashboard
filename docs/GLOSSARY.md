# 22. Glossário

Termos do domínio (Trend Vision One) e do projeto. Foco no que aparece no código/documentação.

## Plataforma e módulos
- **Trend Vision One** — plataforma XDR/SecOps da Trend Micro; origem de todos os dados (API v3.0).
- **XDR** — Extended Detection & Response; correlação de telemetria de endpoint, e-mail, rede, identidade, nuvem.
- **Workbench** — módulo de **alertas** correlacionados (endpoint `/workbench/alerts`); tem `severity` e `status` (Open/In Progress/Closed).
- **OAT (Observed Attack Techniques)** — **detecções** de técnicas observadas (`/oat/detections`); base de eventos, feed, MITRE, trend, identidade.
- **ASRM (Attack Surface Risk Management)** / **Cyber Risk** — gestão de risco/superfície de ataque; expõe `securityPosture` e endpoints de drill-down `asrm/*`.
- **CREM / CREM-Core** — licença/módulo que habilita o **drill-down por ativo** do ASRM (attack surface, high-risk, internal vulnerabilities). Sem ela, esses endpoints dão **403** (o dashboard usa `securityPosture`).
- **Threat Intelligence / Suspicious Objects** — lista de **IOCs** (`/threatintel/suspiciousObjects`): IP/domínio/URL/hashes/e-mail, com `riskLevel` e `scanAction` (block/log).
- **EPP** — Endpoint Protection Platform (antivírus/prevenção); campo `eppAgentStatus` (on/off).
- **EDR** — Endpoint Detection & Response (sensor); campo `edrSensorConnectivity` (connected/disconnected).

## Métricas e conceitos
- **Risk Index** — índice 0–100 de risco (maior = pior) do `securityPosture`; alimenta o gauge do Dashboard.
- **Security Posture** — resposta agregada (`/asrm/securityPosture`) com Risk Index, níveis (exposure/attack/config), CVEs, superfície e adoção.
- **MITRE ATT&CK** — base de **táticas** (`TAxxxx`, o "porquê") e **técnicas** (`Txxxx`, o "como"). O projeto usa 14 táticas fixas na heat matrix.
- **IOC (Indicator of Compromise)** — indicador (IP, domínio, URL, hash, e-mail) associado a ameaça.
- **Attack Surface** — superfície de ataque: IPs públicos, portas expostas, hosts inseguros, contas fracas, ativos de nuvem em risco.
- **High-Risk Users/Devices** — usuários/dispositivos com maior `latestRiskScore` (ASRM).
- **MTTP (Mean Time To Patch)** — tempo médio para aplicar patch; campo `mttpDays` do `cveManagementMetrics` (exibido no painel de vulnerabilidades).
- **CVE / CVSS** — identificador de vulnerabilidade / pontuação de severidade (0–10).

## API e integração
- **Tenant** — instância/cliente na Vision One (aqui `prodesp-sp`). Usado como chave Redis e path da API.
- **Business ID** — identificador do tenant na Vision One (PRODESP: `5758c7b8-936b-410e-9105-71c0c31c7f94`).
- **`TMV1-Filter`** — header de filtro estruturado (ex.: `severity eq 'high'`).
- **`TMV1-Query`** — header de busca textual (ex.: `riskLevel:high OR riskLevel:critical`).
- **`totalCount`** — total de itens de um endpoint paginado; base das contagens (RN01).
- **`nextLink`** — URL da próxima página (paginação seguida por `get_paginated`).
- **Teto de 100k** — `totalCount` do OAT satura em ~100.000 → exibido como `100.001` (RN02).
- **GeoLite2** — base MaxMind (`.mmdb`) para geolocalizar IPs no Attack Map.

## Projeto (termos internos)
- **Coletor** — processo `collectors/run.py` (APScheduler) que consulta a API e grava no Redis.
- **Tier (T1/T2/T3)** — grupos de coleta por frequência (60s / 5min / 15min).
- **Keep-last-good** — estratégia (`_merge_keep`) de manter o último valor bom quando a nova coleta falha (RN14).
- **Wallboard** — painel para exibição contínua em TV (modo quiosque/fullscreen).
- **PRODESP** — Companhia de Processamento de Dados do Estado de São Paulo; tenant-alvo do dashboard.
