# 6. Infraestrutura

## Ambiente atual (desenvolvimento/operação)
Roda hoje na **estação de trabalho do CSTA**: **Windows 11 + WSL2 (Ubuntu) + Docker Desktop**
(integração WSL habilitada). Não há ambiente de produção formal ainda (ver DEPLOYMENT.md).

## Componentes de runtime
| Componente | Onde roda | Porta | Observação |
|---|---|---|---|
| Redis | container Docker | **6379** | estado quente do dashboard (chaves `v1:{tenant}:*`) + pub/sub `ws:{tenant}` |
| TimescaleDB | container Docker | **5432** | **provisionado, não integrado** (só schema; nenhuma escrita) |
| Coletor | processo Python (WSL) | — | `python -m collectors.run` (APScheduler) |
| API/Dashboard | processo Python (WSL) | **8000** | `uvicorn app.main:app` (serve API + WS + `index.html`) |

Os **containers** e os **processos Python** são independentes: subir/parar o Docker não sobe o
coletor/uvicorn (e vice-versa).

## `infra/docker-compose.yml`
- Sobe **redis** e **timescaledb**. **Executar de dentro de `infra/`** (`cd infra && docker compose up -d`).
- **`REQUER VALIDAÇÃO`:** o conteúdo exato do compose não foi lido nesta documentação — validar imagens,
  nomes de volume, variáveis de ambiente do Postgres e se o compose sobe **apenas infra** ou também o app.
- **Volumes:** dados de Redis/Timescale persistem em volumes Docker. **NUNCA** use `docker compose down -v`
  (apaga os volumes). Para desligar sem perder dados: `docker compose stop`.

## Dockerfile do backend (`backend/Dockerfile`)
- Base `python:3.12-slim`; instala `requirements.txt`; copia o app.
- Comando: `uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2`. `EXPOSE 8000`.
- Constrói só a **API**; o coletor precisaria de container/serviço próprio (ou rodar via WSL) — `REQUER VALIDAÇÃO`.

## Portas e rede
- **6379 / 5432** internas (containers). **8000** exposta para o navegador da TV.
- **Egress obrigatório do backend:** `https://api.xdr.trendmicro.com` (Vision One). Se a rede corporativa
  bloquear, o coletor loga falhas e os painéis ficam sem dados.
- **DNS** (resolução de IOCs) e **fonts.googleapis.com** (navegador) — ver INTEGRATIONS.md.

## Segredos e configuração
- Tudo via `.env` na raiz de `backend/` (carregado por `pydantic-settings`). **Não versionar** o `.env`.
- Segredo principal: **`V1_API_TOKEN`** (Bearer da Vision One). Template em `.env.example`.
- `TENANT=prodesp-sp`, `REDIS_URL=redis://localhost:6379/0`, `V1_API_BASE`, `GEOIP_DB`.

## Artefatos de dados
- `data/GeoLite2-City.mmdb` (~66 MB, MaxMind) — **não versionar** (licença/tamanho); baixado à parte.
- `static/echarts.min.js` — ECharts local (`REQUER VALIDAÇÃO` do local/caminho exato de origem).

## Recursos / capacidade
- Footprint modesto: Redis in-memory pequeno (contadores/JSONs curtos), Uvicorn 2 workers, coletas leves
  (só `totalCount`, sem puxar milhares de registros). Sem GPU. Roda confortavelmente na estação atual.
- `REQUER VALIDAÇÃO`: dimensionamento para múltiplos tenants simultâneos (hoje o foco é 1 tenant, prodesp-sp).

## Ambientes
- **Dev/operação (atual):** WSL local; dashboard em `http://localhost:8000/`.
- **Homologação / Produção:** **não formalizados** — propostas (Docker Compose full, Linux+systemd+Nginx,
  Windows Server+IIS) em DEPLOYMENT.md, todas marcadas `REQUER VALIDAÇÃO`.
