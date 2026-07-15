# 14. Setup de Desenvolvimento

## Pré-requisitos
- **Windows 11 + WSL2 (Ubuntu)** com **Docker Desktop** (integração WSL habilitada).
- **Python 3.12** dentro do WSL.
- **VS Code** (opcional; com extensão WSL). Git (`REQUER VALIDAÇÃO` de repositório remoto).
- Rede que alcance `https://api.xdr.trendmicro.com`.
- **`V1_API_TOKEN`** válido (Vision One → Administration → API Keys, com escopos de Workbench/OAT/ASRM/Endpoint/Threat Intel).

## Passo a passo (do zero)
```bash
# 1) No Ubuntu (WSL), ir ao projeto
cd ~/projetos/soc-dashboard

# 2) Subir infraestrutura (Redis + TimescaleDB) — RODAR DE DENTRO DE infra/
cd infra
docker compose up -d
docker ps            # deve listar redis (6379) e timescaledb (5432)

# 3) Backend: ambiente virtual + dependências
cd ../backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 4) Configuração
cp .env.example .env
#   editar .env e preencher:
#     V1_API_TOKEN=<token>
#     TENANT=prodesp-sp
#     V1_API_BASE=https://api.xdr.trendmicro.com
#     REDIS_URL=redis://localhost:6379/0
#     GEOIP_DB=data/GeoLite2-City.mmdb   (opcional; deixar vazio desativa o mapa)

# 5) Terminal A — Coletor (fica em foreground, logando)
python -m collectors.run
#   esperar linhas como: "T1 workbench OK", "T1 posture OK", depois T2/T3

# 6) Terminal B — API/Dashboard (novo terminal, reativar venv)
cd ~/projetos/soc-dashboard/backend
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000

# 7) Abrir o dashboard
#   http://localhost:8000/   (F11 = tela cheia na TV; F = fullscreen via app)
```

## Verificação
```bash
curl http://localhost:8000/healthz
#   {"status":"ok","redis":true}
curl http://localhost:8000/api/prodesp-sp/overview | head -c 400
#   JSON com posture/workbench/events/... (chaves podem vir {} até o 1º tick de cada tier)
```

## Diagnóstico
```bash
# Chaves no Redis
docker exec -it <redis_container> redis-cli KEYS 'v1:prodesp-sp:*'
docker exec -it <redis_container> redis-cli TTL  'v1:prodesp-sp:wb:counters'
docker exec -it <redis_container> redis-cli HGETALL 'v1:prodesp-sp:wb:counters'

# Logs dos containers
docker logs <redis_container> --tail 50
docker logs <timescaledb_container> --tail 50
```
- O coletor loga cada tier (OK / `WARNING ... indisponível: HTTP <status> ...`). Comece por aí.

## Problemas comuns
| Sintoma | Causa provável | Ação |
|---|---|---|
| Coletor aborta no start | `V1_API_TOKEN` vazio/placeholder | preencher `.env` (o `run.py` valida no boot) |
| Painéis de risco vazios + 403 nos logs | **CREM-Core expirado** (esperado na Prodesp) | ignorar; posture (200) alimenta os painéis. Renovar CREM p/ drill-down |
| `100.001` em vários painéis | **teto de 100k do OAT** (RN02) | comportamento correto; não é bug |
| Pílula "SEM CONEXÃO" | uvicorn fora do ar ou `?api` errado | subir uvicorn; conferir URL/porta |
| Porta 8000 ocupada | outro processo | `--port 8001` (ajustar `?api=` ou o `.bat`) |
| `docker compose` "cannot connect" | Docker Desktop não iniciou | abrir o Docker Desktop e aguardar |
| Sem dados + sem 403 | rede sem egress p/ `api.xdr.trendmicro.com` | liberar saída HTTPS na rede corporativa |
| Fontes/estilo estranho na TV | CDN do Google Fonts bloqueada | rede offline → empacotar fontes (`REQUER VALIDAÇÃO`) |

## Fluxo de edição (o que reiniciar)
- `collectors/*.py`, `app/geo.py`, `app/config.py` → **reiniciar o coletor**.
- `app/main.py`, `app/vision_one.py`, `app/cache.py` → **reiniciar o uvicorn**.
- `static/index.html` → **só copiar + Ctrl+Shift+R** (sem reiniciar processo).
(Detalhes em DEPLOYMENT.md.)
