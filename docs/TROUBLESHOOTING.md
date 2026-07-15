# 18. Troubleshooting (Runbook)

Fluxo geral: **olhar os logs do coletor** → **conferir o Redis** → **conferir a API/uvicorn** → **conferir o navegador (console/WS)**.

## Sintomas → causa → ação
| Sintoma | Causa provável | Diagnóstico | Ação |
|---|---|---|---|
| Um painel vazio (`—`) | tier ainda não rodou, timeout, ou 403 | log do coletor p/ o tier; `redis-cli TTL v1:prodesp-sp:<chave>` | aguardar tick; se 403 CREM, é esperado (posture cobre) |
| **Vários painéis mostram `100.001`** | **teto de 100k do OAT** (RN02) | — | comportamento correto; **não** é bug |
| Painéis de risco (surface/vuln/high-risk) vazios + `403` nos logs | **CREM-Core expirado** (Prodesp) | log `WARNING ... HTTP 403 AccessDeny` | esperado; renovar CREM habilita drill-down |
| Pílula **"SEM CONEXÃO"** | uvicorn fora do ar / URL errada | `curl http://localhost:8000/healthz` | subir uvicorn; conferir `?api=`/porta |
| Dashboard carrega mas **não atualiza ao vivo** (só no F5) | WebSocket bloqueado (proxy sem upgrade) | console do navegador (erro de WS) | habilitar upgrade WS/`wss` no proxy; fallback é o pull de 60s |
| Coletor **aborta ao iniciar** | `V1_API_TOKEN` vazio/placeholder | log inicial do `run.py` | preencher `.env` e reiniciar |
| `docker compose` "cannot connect to the Docker daemon" | Docker Desktop não iniciou | `docker ps` | abrir Docker Desktop e aguardar |
| Porta 8000 ocupada | outro processo usa a porta | `ss -ltnp | grep 8000` | `--port 8001` (ajustar `?api=`/`.bat`) |
| **Mapa** sem marcadores | `GEOIP_DB` vazio/ausente, IOCs sem geo (hashes), ou DNS interno | log `suspiciousObjects`/geo; existência do `.mmdb` | apontar `GEOIP_DB` p/ o `.mmdb`; hashes não têm geo (normal) |
| Fontes/estilo estranhos na TV | CDN do Google Fonts bloqueada | rede/console | empacotar fontes localmente (`REQUER VALIDAÇÃO`) |
| Painel **cortado/sobreposto** | item estourando a `grid-row` | inspecionar CSS do painel | aplicar `flex:1`+`min-height:0` (listas) / `minmax(0,1fr)` (colunas nowrap) — ver FRONTEND.md |
| Valor difere do **console** Vision One (ex.: Attack "medium" vs "High") | posture exibe o **valor da API** (cálculo de UI do console difere) | comparar com `securityPosture` cru | esperado; a API é a fonte de verdade aqui |
| Sem dados **e sem 403** | rede sem egress p/ `api.xdr.trendmicro.com` | `curl` do host à API | liberar saída HTTPS na rede corporativa |

## Comandos úteis
```bash
# Redis
docker exec -it <redis> redis-cli KEYS 'v1:prodesp-sp:*'
docker exec -it <redis> redis-cli HGETALL 'v1:prodesp-sp:wb:counters'
docker exec -it <redis> redis-cli GET 'v1:prodesp-sp:posture'
docker exec -it <redis> redis-cli TTL 'v1:prodesp-sp:mitre'

# API
curl -s http://localhost:8000/healthz
curl -s http://localhost:8000/api/prodesp-sp/overview | python -m json.tool | head -n 60

# Processos
pgrep -af collectors.run
pgrep -af uvicorn
```

## Regras de ouro
- **Nunca** `docker compose down -v` (apaga Redis/Timescale). Para parar: `docker compose stop`.
- Painel vazio raramente é "bug de código": quase sempre é **tier sem tick**, **403 esperado** ou **rede**.
- Antes de mexer no frontend por "corte", lembrar do padrão flex/min-height (FRONTEND.md).
