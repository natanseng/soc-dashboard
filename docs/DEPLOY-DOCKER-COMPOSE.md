# Deploy — Docker Compose

Guia para subir a dashboard em ambiente local ou de desenvolvimento usando Docker Compose.

## Pré-requisitos

- Docker Engine 20.10+
- Docker Compose 2.0+
- Git
- ~2GB de RAM disponível
- ~10GB de espaço em disco

## Setup rápido

### 1. Clone o repositório

```bash
git clone https://github.com/natanseng/soc-dashboard.git
cd soc-dashboard
```

### 2. Configure o `.env`

Copie o exemplo e edite:

```bash
cp backend/.env.example backend/.env
```

Edite `backend/.env` com suas credenciais:

```env
# Trend Vision One
V1_API_BASE=https://api.xdr.trendmicro.com
V1_API_TOKEN=seu_token_aqui
TENANT=salvador

# Infra local
REDIS_URL=redis://redis:6379/0
DB_DSN=postgresql://socdash:dev_change_me@postgres:5432/socdash

# Mapa (opcional)
GEOIP_DB=
```

### 3. Inicie os containers

```bash
cd infra
docker compose up -d
```

Isso sobe:
- **Redis** na porta 6379
- **PostgreSQL** na porta 5432
- **pgAdmin** na porta 5050 (admin/admin)

Verifique a saúde:

```bash
docker compose ps
```

### 4. Inicialize o banco de dados

```bash
docker compose exec postgres psql -U socdash -d socdash < init.sql
```

### 5. Inicie o backend em outro terminal

```bash
cd backend

# Ative o venv
python -m venv .venv
source .venv/bin/activate
# (Windows: .venv\Scripts\activate)

# Instale dependências
pip install -r requirements.txt

# Rode o API + frontend
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 6. Inicie o coletor em um terceiro terminal (opcional)

```bash
cd backend
source .venv/bin/activate

python -m collectors.run
```

### 7. Acesse a dashboard

Abra o navegador em `http://localhost:8000` e escolha uma das abas:

- **Executiva**: KPIs e ativos
- **SOC**: Workbench e detecções
- **Cyber**: Risco consolidado
- **Alertas**: Alertas e eventos

## Validação

### Health check

```bash
curl http://localhost:8000/healthz
```

Resposta esperada:

```json
{
  "status": "ok",
  "redis": true,
  "postgres": "ok"
}
```

### Snapshot da dashboard

```bash
curl http://localhost:8000/api/salvador/overview | jq .
```

### WebSocket em tempo real

```bash
wscat -c ws://localhost:8000/ws/salvador
```

Você deve ver deltas sendo publicadas a cada tick do coletor.

## Parar os containers

```bash
# Parar sem remover
docker compose stop

# Remover (cuidado: perde dados se não tiver backup)
docker compose down
```

## Troubleshooting

### PostgreSQL recusa conexão

```
psycopg2.OperationalError: could not translate host name "postgres" to address
```

Verifique se os containers estão rodando:

```bash
docker compose ps
```

Se o postgres não aparece, reinicie:

```bash
docker compose restart postgres
```

### Redis não responde

```
redis.exceptions.ConnectionError: Error -2 connecting to redis:6379
```

Verifique logs:

```bash
docker compose logs redis
```

### Portal "Desconectado" no frontend

Se a dashboard mostra "● DESCONECTADO" no topo-direito, a conexão WebSocket caiu. Recarregue a página:

```
Ctrl+Shift+R  (macOS: Cmd+Shift+R)
```

### Porta já em uso

Se 8000, 6379 ou 5432 já estão ocupadas, edite `infra/docker-compose.yml`:

```yaml
services:
  redis:
    ports:
      - "6380:6379"  # mude 6380 conforme necessário
```

E atualize `REDIS_URL` no `.env`:

```env
REDIS_URL=redis://localhost:6380/0
```

## Desenvolvimento

### Reload automático do backend

Use `--reload` para reiniciar a cada mudança de código:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Limpar logs e cache

```bash
# Remover e recriar containers
docker compose down -v
docker compose up -d
```

### Debugar com logs

```bash
docker compose logs -f postgres   # PostgreSQL
docker compose logs -f redis      # Redis
```

Para o backend:

```bash
# Ativo no terminal atual (não em background)
uvicorn app.main:app --log-level debug
```

## Dados de teste

Se quiser dados fictícios para testar sem conectar ao Vision One, veja `docs/TESTING.md`.

## Próximos passos

- Para produção em **AL2023 ou RHEL9**, veja `DEPLOY-AL2023.md` ou `DEPLOY-RHEL9.md`
- Para **OKD/OpenShift**, veja `DEPLOY-OKD.md`
- Para **Kubernetes genérico**, veja `DEPLOY-KUBERNETES.md` (em breve)
