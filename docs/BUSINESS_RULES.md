# 12. Cálculos e Regras de Negócio

Todas as datas de coleta são calculadas em **UTC** (`_iso` → `strftime('%Y-%m-%dT%H:%M:%SZ')`).
A exibição de hora ("AO VIVO · hh:mm") usa `toLocaleTimeString('pt-BR')` no navegador.
Números são formatados com `toLocaleString('pt-BR')`. Valores ausentes (`None`) viram `—` no frontend.

## RN01 — Contagem via `totalCount` (padrão de todas as métricas)
`_count()` lê `totalCount` da resposta paginada com `top` pequeno (payload mínimo). Se `totalCount`
ausente, usa `len(items)`. **Fonte:** cada endpoint V1. **Função:** `tiers._count`.

## RN02 — Teto de 100.000 do OAT (CRÍTICO — não "corrigir")
`/v3.0/oat/detections` satura `totalCount` em ~100.000. Onde o volume real excede, a UI mostra
**`100.001`** (ex.: várias táticas MITRE, eventos, brute force). É **limite da API**, não erro.
Consequência de projeto: qualquer métrica que deva **variar** precisa de recorte (ver RN03).

## RN03 — Threat Trends por ALTO RISCO
Série de 24h em **12 buckets de 2h**; cada bucket conta OAT com `TMV1-Filter: riskLevel eq 'high'`.
Motivo: a contagem **total** satura (RN02) e vira linha reta; o recorte de alto risco tem números
menores e variação real. **Saída:** `[{t,n}]` cronológica. **Função:** `tiers.threat_trend`.
Casos de borda: bucket com erro/timeout → `n=None` (lacuna na linha).

## RN04 — Delta de 24h (Threat Overview)
`delta24h = round((e24h - e24h_prev) / e24h_prev * 100, 1)`, com `e24h` = OAT nas últimas 24h e
`e24h_prev` = 24h imediatamente anteriores. Se `e24h_prev == 0` → `delta = 0.0` (evita divisão por zero).
7d e 30d são contagens pontuais (sem comparativo histórico). **Função:** `tiers.event_tallies`.

## RN05 — Severidade da linha do feed
Para cada detecção OAT, a severidade exibida é o **maior `riskLevel` entre os `filters[]`**, usando o
ranking `critical=4, high=3, medium=2, low=1, info=0` (`_SEV_RANK`). Nome/tática/técnica saem do 1º filtro.
Ordena por `detectedDateTime` desc (a API não garante ordem), pega as 15 mais novas. **Função:** `tiers.detections_feed`.

## RN06 — Ranking de usuários/dispositivos de risco
Une `highRiskUsers` + `highRiskDevices`, ordena por `latestRiskScore` (fallback `riskScore`) **desc** no
cliente (sem `orderBy` para evitar 400), top 6. Best-effort: só falha se ambos falharem. **Função:** `tiers.high_risk`.

## RN07 — Risk Factors (Dashboard)
`highImpactRiskEvents` do `securityPosture`, cada um `{factor, eventCount, affectedAssetCount}`, ordenado
por **ativos afetados desc**, top 6. No frontend vira ranking de barras (largura ∝ ativos, cor por faixa).
**Função:** `tiers.parse_posture` + `renderRiskFactors`.

## RN08 — Top CVEs
`internalAssetVulnerabilities`, ordena por `(cveRiskScore, cvssScore)` **desc**, top 6. `counts` por
`cveRiskLevel` (high/medium/low — CREM não tem "critical"). **Função:** `tiers.vuln_metrics`.

## RN09 — MITRE ATT&CK (14 táticas)
Lista fixa `MITRE_TACTICS` (ordem aproximada da kill chain: TA0043, TA0042, TA0001, TA0002, TA0003,
TA0004, TA0005, TA0006, TA0007, TA0008, TA0009, TA0011, TA0010, TA0040). Uma contagem OAT por tática
(`filterMitreTacticId`), janela 24h. **Função:** `tiers.mitre_tactics`. (Táticas de alto volume saturam — RN02.)

## RN10 — Identity Security (técnicas MITRE)
4 métricas: **bruteForce** `T1110`, **validAccounts** `T1078`, **credDumping** `T1003`,
**privEsc** `TA0004` (tática). Contagem OAT 24h por técnica/tática. **Função:** `tiers.identity_counts`.

## RN11 — Endpoint Security (contagens filtradas)
Contagens por campos planos do inventário: `total`; `edrSensorConnectivity` connected/disconnected;
`eppAgentStatus` on/off; `eppAgentComponentVersion = outdatedVersion`; `osPlatform` windows/linux/mac;
`type` server/desktop. `top=50` (endpoint rejeita `top=1`). **Função:** `tiers.endpoints_summary`.

## RN12 — IOCs (Threat Intelligence)
`suspiciousObjects` (sem `totalCount` → pagina tudo). Tabula `byType`, `byRisk` (high/medium/low),
`byAction` (block/log via `scanAction`), top 12 (ordena por `riskLevel` e `lastModifiedDateTime` desc),
`geo` (marcadores) e `byCountry`. Ranking de risco `_RISK_RANK = {high:3, medium:2, low:1}`.
Agrupa IOCs de rede por host (mantém o de maior risco). **Função:** `tiers.suspicious_objects`.

## RN13 — Gauge do Risk Index (escala de cor)
Risk Index 0–100 onde **maior = pior**. Faixas de cor: **0–30 verde** (baixo), **30–70 âmbar** (médio),
**70–100 vermelho** (alto). Exibe o valor da API (`riskCategoryLevel`), mesmo quando o console mostra
faixa diferente (cálculo de UI distinto). **Função:** `scoreGaugeOpt` + `applyPosture`.

## RN14 — Keep-last-good (não zerar painéis)
No T3, `mitre` e `identity` passam por `_merge_keep`: onde a nova coleta trouxe `None` (timeout de uma
tática/técnica), mantém o último valor bom do Redis. Evita "buracos" nos painéis. **Função:** `run._merge_keep`.

## RN15 — TTLs e "keep last good" por expiração
Cada chave Redis tem TTL ~5× o intervalo do tier (ex.: workbench 300s p/ tick de 60s), de modo que
jitter/atraso de um tick não zera o painel. Ver tabela em `BACKEND.md`.

## Observações sobre datas/fuso e arredondamento
- Coleta: janelas em UTC (`detectedStartDateTime`/`detectedEndDateTime`, `startDateTime`/`endDateTime`).
- `delta24h`: arredondado a 1 casa. CVSS: `NUMERIC(3,1)` no schema (não usado hoje).
- Exibição de horário do feed: `_fmtTime` (frontend) — `REQUER VALIDAÇÃO` do formato exato (provável HH:MM:SS local).
