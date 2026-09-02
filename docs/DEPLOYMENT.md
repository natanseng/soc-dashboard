# 16. Deploy

## Estado atual
Deploy **manual**, na estação do CSTA (WSL), com dois scripts `.bat` na área de trabalho do Windows.
**Não há CI/CD, registry de imagem nem ambiente de produção formal.**

### Scripts de operação (Windows)
- **`ligar-dashboard.bat`** — aguarda o Docker Desktop; `cd infra && docker compose up -d`; abre o
  **Coletor** e a **API** em janelas separadas do WSL; abre o navegador em `http://localhost:8000/`.
- **`desligar-dashboard.bat`** — `pkill -f collectors.run` + `pkill -f uvicorn`; `docker compose stop`
  (mantém volumes).
- **Config no topo dos `.bat`:** `set "DISTRO="` (use `-d Ubuntu` se houver mais de uma distro WSL —
  checar `wsl -l -v`) e `set "PROJ=~/projetos/soc-dashboard"`.
- Arquivos `.bat` devem estar em **CRLF** (formato batch do Windows).

### Atualização de arquivos (OneDrive → projeto)
Lucas salva os fontes no OneDrive e copia para o projeto:
```bash
SRC="/mnt/c/Users/lucaso/OneDrive - TrendMicro/Documents/Dash Detran/Versão 2"
cp "$SRC/index.html" ~/projetos/soc-dashboard/backend/static/index.html
# (idem para tiers.py, run.py, main.py, etc., conforme o que mudou)
```

## Matriz "o que reiniciar" (essencial)
| Alterou | Ação | Reinicia processo? |
|---|---|---|
| `collectors/tiers.py`, `collectors/run.py` | reiniciar **coletor** | sim |
| `app/geo.py`, `app/config.py` | reiniciar **coletor** | sim |
| `app/main.py`, `app/vision_one.py`, `app/cache.py` | reiniciar **uvicorn** | sim |
| `static/index.html` (e assets) | **copiar** + `Ctrl+Shift+R` no navegador | não |
| `.env` | reiniciar **ambos** (coletor lê no boot; uvicorn idem) | sim |

## Build de container (opcional, já disponível)
```bash
cd backend
docker build -t soc-dashboard-api:latest .
docker run --rm -p 8000:8000 --env-file .env soc-dashboard-api:latest
```
- A imagem sobe **apenas a API** (`uvicorn ... --workers 2`). O **coletor** precisa de serviço próprio
  (container/systemd/WSL) — `REQUER VALIDAÇÃO` de como orquestrar junto (o compose atual sobe só infra).

## Health checks e monitoramento
- `GET /healthz` → `{"status":"ok","redis":true}` (usar como liveness/readiness).
- Pílula **"AO VIVO · hh:mm"** (verde) / **"SEM CONEXÃO"** (vermelho) no dashboard.
- **Logs do coletor** são a principal observabilidade (OK por tier / `WARNING ... indisponível`).
- Não há métricas Prometheus/telemetria estruturada ainda (`REQUER VALIDAÇÃO` / ver ROADMAP.md).

## Rollback
- **Frontend:** manter cópia anterior do `index.html` (ou versionar em Git) e recopiar. É o rollback mais comum.
- **Backend:** reverter o(s) arquivo(s) e reiniciar o processo afetado.
- **Docker:** `docker compose stop`/`up -d`. **Nunca** `down -v` (apaga Redis/Timescale).
- `REQUER VALIDAÇÃO`: se há repositório Git com histórico (recomendado para rollback confiável).

## Produção (PROPOSTO — ainda NÃO implementado; tudo `REQUER VALIDAÇÃO`)
Opções para tirar da estação e rodar como serviço:
1. **Docker Compose completo:** um serviço para a **API**, um para o **coletor**, além de redis/timescale;
   `.env` como secrets; `restart: unless-stopped`.
2. **Linux + systemd + Nginx:** dois units (`socdash-api`, `socdash-collector`); **Nginx** como proxy
   reverso `:443 → :8000` com **TLS** e upgrade de **WebSocket** (para `wss://.../ws/...`). Frontend na mesma origem.
3. **Windows Server + IIS:** IIS como reverse proxy (ARR) para o Uvicorn; coletor como serviço (NSSM/Task Scheduler).
- Em produção, servir na **mesma origem** (API_BASE vazio) → o front usa `wss` automaticamente; dispensa CORS `*`.

## Diferenças entre ambientes
| Aspecto | Dev (atual) | Produção (proposto) |
|---|---|---|
| Origem do front | `localhost:8000` (ou `?api=`) | mesma origem atrás de proxy |
| WebSocket | `ws://` | `wss://` (TLS no proxy) |
| Processos | 2 terminais WSL / `.bat` | systemd/containers com restart |
| CORS | `*` | restrito (mesma origem) |
| Segredos | `.env` local | secrets do orquestrador |
