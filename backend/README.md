# Backend — Plataforma de Dashboards SOC (Vision One)

Fase 1: coletor T1 (Workbench + Risk Index) -> Redis -> API -> tela executiva.

## Rodar em dev (a partir desta pasta `backend/`)
```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # edite V1_API_TOKEN
# Terminal 1 — API
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
# Terminal 2 — coletor
python -m collectors.run
```

## Smoke test
```bash
curl http://localhost:8000/healthz
curl http://localhost:8000/api/prodesp-sp/overview
```

## Estrutura
- `app/config.py`     — settings via .env
- `app/vision_one.py` — cliente Vision One (auth, paginação, backoff 429)
- `app/cache.py`      — conexão Redis
- `app/geo.py`        — geo-enrichment opcional (GeoLite2)
- `app/main.py`       — FastAPI (/healthz, /api/{tenant}/overview, /ws/{tenant})
- `collectors/tiers.py` — funções de coleta por endpoint
- `collectors/run.py`   — scheduler (APScheduler)
