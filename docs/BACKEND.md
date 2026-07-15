# 8. Backend

## Stack e versões
- **Python 3.12** (Dockerfile: `python:3.12-slim`).
- **FastAPI** `0.115.*`, **Uvicorn[standard]** `0.30.*`.
- **APScheduler** `3.10.*` (agendador do coletor).
- **httpx** `0.27.*` (cliente HTTP async da Vision One).
- **redis** `5.0.*` (cliente async; `redis.asyncio`).
- **pydantic-settings** `2.*`, **python-dotenv** `1.*` (config via `.env`).
- **geoip2** `4.8.*` (GeoLite2, opcional).
- **asyncpg** `0.29.*` — declarado, mas **não usado** pelo código atual (banco não integrado).

## Estrutura (backend/)
```
backend/
├── requirements.txt
├── Dockerfile                # uvicorn app.main:app --workers 2 (porta 8000)
├── .env.example
├── app/
│   ├── __init__.py
│   ├── config.py             # Settings (pydantic-settings)
│   ├── main.py               # FastAPI (API + WebSocket + serve estático)
│   ├── vision_one.py         # cliente HTTP Vision One
│   ├── cache.py              # get_redis()
│   └── geo.py                # GeoLite2 (lazy)
├── collectors/
│   ├── __init__.py
│   ├── tiers.py              # todas as coletas + parsing
│   └── run.py                # scheduler (tick_t1/t2/t3)
├── static/
│   └── index.html            # frontend single-file
│   └── echarts.min.js        # ECharts servido localmente (REQUER VALIDAÇÃO: caminho/local exato)
└── data/GeoLite2-City.mmdb   # base geo (opcional)
```

## Processos
Dois processos independentes compartilhando o Redis:
1. **Coletor** (`python -m collectors.run`) — grava no Redis + publica deltas.
2. **API/Uvicorn** (`uvicorn app.main:app`) — lê o Redis, serve API+WS+dashboard.
> O coletor **não** é iniciado pelo FastAPI; são processos separados (dois terminais / dois `.bat`).

## `app/config.py` — Settings (via `.env`, case-insensitive)
`v1_api_base` (default `https://api.xdr.trendmicro.com`), `v1_api_token` (obrigatório),
`tenant` (`prodesp-sp`), `redis_url` (`redis://localhost:6379/0`), `db_dsn` (não usado),
`geoip_db` (`data/GeoLite2-City.mmdb`), `tier1_interval` 60, `tier2_interval` 300,
`tier3_interval` 900, `tier4_interval` 3600.

## `app/vision_one.py` — cliente Vision One
- `__init__(api_key, base)` — header `Authorization: Bearer <token>`, `Content-Type: application/json;charset=utf-8`, timeout 60s.
- `get_json(path, params, extra_headers, max_retries=5)` — GET com **retry em 429** (respeita `Retry-After`, backoff `2**attempt`), `raise_for_status()` no resto.
- `get_paginated(path, params, extra_headers, limit=10_000)` — segue `nextLink` (URL absoluta → limpa params) até esgotar/limite.
- `aclose()` — fecha o cliente httpx.

## `app/cache.py`
`get_redis()` → `redis.asyncio.from_url(redis_url, decode_responses=True)` (valores como str).

## `app/geo.py` — GeoLite2 (carregamento preguiçoso)
- Não abre o `.mmdb` no import; abre no 1º uso. Se `GEOIP_DB` vazio/inexistente → retorna `None` (mapa inativo, resto segue).
- `enrich(net_event)` — normaliza evento de rede em marcador geo (src/dst). Destino fixo `_DEST` = São Paulo (`-23.55, -46.63`).
- `lookup_ip(ip)` → `{country, city, lat, lon}` ou `None`.

## `collectors/run.py` — scheduler
- `AsyncIOScheduler` com 3 jobs `interval`: **T1** (`tier1_interval`, imediato), **T2** (`+8s`), **T3** (`+16s`).
- Valida `V1_API_TOKEN` no start (aborta se vazio/placeholder `__`).
- `_diag(exc)` — extrai `status | innererror.code | message | TraceId` de erros httpx (para logs/suporte).
- `_merge_keep(key, fresh)` — **keep-last-good**: mantém o valor anterior do Redis onde o novo veio `None` (usado em `mitre` e `identity` para não zerar painéis em timeout).
- Cada coleta é `try/except` isolado: falha loga e **não** derruba o coletor.

### Mapa tier → coleta → chave Redis → TTL
| Tier | Função (tiers.py) | Endpoint V1 | Chave Redis | Tipo | TTL |
|---|---|---|---|---|---|
| T1 60s | `workbench_counters` | `/workbench/alerts` | `v1:{t}:wb:counters` | hash | 300s |
| T1 60s | `security_posture`→`parse_posture` | `/asrm/securityPosture` | `v1:{t}:posture` | json | 1800s |
| T2 5min | `event_tallies` | `/oat/detections` | `v1:{t}:events` | hash | 600s |
| T2 5min | `high_risk` | `/asrm/highRiskUsers` + `/highRiskDevices` | `v1:{t}:risk` | json | 600s |
| T2 5min | `detections_feed` | `/oat/detections` | `v1:{t}:feed` | json | 600s |
| T3 15min | `attack_surface_counts` | `/asrm/attackSurface*` | `v1:{t}:surface` | hash | 1800s |
| T3 15min | `vuln_metrics` | `/asrm/internalAssetVulnerabilities` | `v1:{t}:vuln` | json | 1800s |
| T3 15min | `mitre_tactics` | `/oat/detections` (×14 táticas) | `v1:{t}:mitre` | json | 1800s |
| T3 15min | `threat_trend` | `/oat/detections` (risk high, ×12) | `v1:{t}:trend` | json | 1800s |
| T3 15min | `identity_counts` | `/oat/detections` (×4 técnicas) | `v1:{t}:identity` | json | 1800s |
| T3 15min | `suspicious_objects` | `/threatintel/suspiciousObjects` | `v1:{t}:ioc` | json | 1800s |
| T3 15min | `endpoints_summary` | `/endpointSecurity/endpoints` | `v1:{t}:endpoint` | json | 1800s |

Cada `hset`/`set` é seguido de `publish` em `ws:{tenant}` com `{"type": "<recurso>", "data": <payload>}`.

## `collectors/tiers.py` — detalhe das coletas
- **Helpers:** `diag()`; `_iso(dt)`; `_count(path, params, extra_headers, top=1)` (lê `totalCount`; se ausente, usa `len(items)`).
- **`workbench_counters`** — janela 30d; 7 chamadas (4 severidades + 3 status via `TMV1-Filter`), cada uma só `totalCount`. Saída `{severity:{critical,high,medium,low}, status:{open,in_progress,closed}}` (o `run.py` **achata** as chaves de status para `open`/`in_progress`/`closed`).
- **`parse_posture`** — achata `securityPosture` em: `risk_index`; níveis `exposure/attack/config` (texto low/medium/high — exibe o valor da API, mesmo que o console mostre diferente); `vuln{count,coverage,mttp,unpatched,vuln_rate,legacy_os}`; `surface{public_ip,ports,insecure_hosts,weak_auth,acct_risk,cloud_high,cloud_med}`; `factors[]` (top 6 `highImpactRiskEvents` por `affectedAssetCount`); `adoption{agents,edr,ver_*,vp_*,mail_*,cloud_*,legacy_os,features{endpoint,server}}`.
- **`event_tallies`** — 4 janelas OAT (24h, 24h anterior, 7d, 30d) + `delta24h` (%). Saída `{e24h,e24h_prev,e7d,e30d,delta24h}`.
- **`high_risk`** — `highRiskUsers` + `highRiskDevices`, ordena por `latestRiskScore` desc (client-side; sem `orderBy` para evitar 400), top 6. Best-effort: só levanta erro se **ambos** falharem.
- **`attack_surface_counts`** — 5 contagens em paralelo (`gather`), teto 20s cada: devices, critical (`criticality eq 'high'`), unmanaged (`deviceType eq 'Unmanaged device'`), cloud, accounts. `top=50` (inventário rejeita `top=1`).
- **`vuln_metrics`** — `counts` por `cveRiskLevel` (high/medium/low; CREM não tem 'critical') + `top` 6 CVEs (`cveId/cvssScore/affectedAssetCount/cveRiskLevel`).
- **`mitre_tactics`** — 14 táticas (`MITRE_TACTICS`, IDs `TA...`) via `filterMitreTacticId`, paralelo (semáforo 6), teto 45s.
- **`detections_feed`** — janela 10min, `top=100`, ordena por `detectedDateTime` desc, pega 15. Severidade da linha = maior `riskLevel` entre `filters[]`. Saída `[{time,host,name,sev,tactic,technique}]`.
- **`threat_trend`** — 12 buckets de 2h (24h), cada um conta OAT com `riskLevel eq 'high'` (evita saturação de 100k). Saída `[{t,n}]` cronológica.
- **`identity_counts`** — 4 métricas: bruteForce (`T1110`), validAccounts (`T1078`), credDumping (`T1003`), privEsc (`TA0004`).
- **`endpoints_summary`** — contagens filtradas (campos planos): total, edrConnected/Disconnected, eppOn/Off, outdated (`eppAgentComponentVersion eq 'outdatedVersion'`), OS (windows/linux/mac), type (server/desktop). `top=50`.
- **`suspicious_objects`** — pagina tudo (sem `totalCount`), tabula `byType/byRisk/byAction(block,log)`, `top` 12 IOCs, `geo` (marcadores geolocalizados: URL→host, domínio→DNS→IP, IP direto; via GeoLite2), `byCountry`.
- **Reservados/não usados no fluxo atual:** `network_activities` (`/search/networkActivities`, `TMV1-Query`), `oat_detections`, `endpoint_inventory`.

## Logs e exceções
- `logging` nível INFO (`%(asctime)s %(levelname)s %(name)s: %(message)s`), logger `collector`.
- Padrão de log por tier: `T1 workbench OK: {...}`, `T3 mitre OK: n/14 táticas...`; falhas como `WARNING ... indisponível: HTTP 403 ...`.
- `raise_for_status()` no cliente → cada tier trata e loga com `diag()`/`_diag()`.

## `app/main.py` — API
Ver `API_REFERENCE.md` (endpoints, formatos, exemplos).
