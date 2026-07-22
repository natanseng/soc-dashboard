# Deploy em Amazon Linux 2023 — passo a passo

Runbook para subir o **SOC Dashboard (TrendAI Vision One)** numa instância **Amazon Linux 2023**
(EC2 x86_64). A stack é: **Docker Compose** (TimescaleDB/PG16 + Redis) + **backend Python** (venv)
com 3 processos — **API** (uvicorn, serve o front `index.html` + `/api`,`/alerts`,`/cyber`),
**coletor Fase‑1** (`collectors.run` → Redis: telas Dashboard/Vulnerabilidades/Centro) e
**pipeline Cyber** (`collectors.cyber_scheduler` → Postgres: telas Alertas/Cyber).

> Convenções: instância EC2 com usuário `ec2-user`; projeto em `/opt/soc-dashboard`.
> Comandos com `sudo` quando exigem root. Ajuste caminhos/senhas conforme seu ambiente.

---

## 0. Pré‑requisitos

- EC2 **Amazon Linux 2023**, x86_64, ≥ 2 vCPU / 4 GB RAM / 20 GB disco (o Timescale cresce com histórico).
- **Security Group**: liberar **80/443** (se for usar Nginx/TLS) ou **8000** (acesso direto à API) apenas
  para as origens que vão exibir o wallboard. **NÃO** exponha 5432 (Postgres) nem 6379 (Redis) publicamente.
- Acesso de saída HTTPS para `api.xdr.trendmicro.com` (Vision One) e para o Docker Hub / GitHub (imagens e plugin).
- Os **tokens de API** dos 8 tenants (Vision One → Administração → API Keys).

---

## 1. Pacotes do sistema

```bash
sudo dnf update -y
sudo dnf install -y git python3.11 python3.11-pip python3.11-devel gcc
```

> O projeto roda em Python 3.11+ (as dependências têm wheels para cp311). `gcc`/`-devel` só entram
> em cena se algum pacote precisar compilar; normalmente o pip usa wheels prontos.

---

## 2. Docker + Docker Compose (plugin v2)

```bash
# Docker Engine
sudo dnf install -y docker
sudo systemctl enable --now docker
sudo usermod -aG docker ec2-user      # rode um novo shell (ou 'newgrp docker') p/ valer sem sudo

# Plugin do Compose v2 (AL2023 não traz por padrão)
sudo mkdir -p /usr/libexec/docker/cli-plugins
sudo curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
  -o /usr/libexec/docker/cli-plugins/docker-compose
sudo chmod +x /usr/libexec/docker/cli-plugins/docker-compose

docker --version && docker compose version   # valida
```

> **Graviton (arm64):** troque o binário do compose por `...-linux-aarch64` e confirme que as imagens
> `timescale/timescaledb` e `redis` têm tag arm64.

---

## 3. Obter o código

Clone o repositório (ou copie os fontes) para `/opt/soc-dashboard`, **na branch com o trabalho multi‑tenant**:

```bash
sudo mkdir -p /opt/soc-dashboard && sudo chown ec2-user:ec2-user /opt/soc-dashboard
git clone <URL_DO_SEU_REMOTE> /opt/soc-dashboard
cd /opt/soc-dashboard
git checkout feat/cyber-multitenant     # todo o multi-tenant está aqui (NÃO na master antiga)
```

> Se não houver remote Git, copie a árvore do projeto (rsync/scp) para `/opt/soc-dashboard`
> preservando `infra/`, `backend/` e `docs/`. **Não** copie `backend/.venv` nem `backend/logs`.

---

## 4. Subir a infra (Postgres/Timescale + Redis)

> **Antes de subir**, troque a senha padrão do banco. Edite `infra/docker-compose.yml`:
> `POSTGRES_PASSWORD` (de `dev_change_me` para uma senha forte) e adicione persistência de boot.

```bash
cd /opt/soc-dashboard/infra
# recomendado: garantir restart automático no boot dos containers
sed -i 's/^  db:/  db:\n    restart: unless-stopped/' docker-compose.yml   # (ou edite à mão)
sed -i 's/^  redis:/  redis:\n    restart: unless-stopped/' docker-compose.yml

docker compose up -d
docker compose ps          # aguarde db e redis "healthy"
```

- Na **primeira** subida do `db`, o `infra/init.sql` roda automaticamente (extensões/estrutura base).
- Containers ficam `infra-db-1` e `infra-redis-1`, expostos em `127.0.0.1:5432` e `127.0.0.1:6379`.

---

## 5. Backend: venv + dependências

```bash
cd /opt/soc-dashboard/backend
python3.11 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
```

---

## 6. Configuração (`.env`) — inclui os 8 tenants

Crie `backend/.env` a partir do exemplo e preencha os tokens. **O `.env` é gitignored — nunca comite tokens.**

```bash
cd /opt/soc-dashboard/backend
cp .env.example .env
chmod 600 .env
```

Edite `backend/.env` deixando assim (troque a senha do `DB_DSN` para a mesma do compose e cole os tokens):

```ini
# ---- Vision One ----
V1_API_BASE=https://api.xdr.trendmicro.com
TENANT=prodesp-sp

# Tokens por tenant (V1_API_TOKEN_<LABEL>). O primario usa V1_API_TOKEN.
V1_API_TOKEN=<token_prodesp>
V1_API_TOKEN_DETRAN=<token_detran>
V1_API_TOKEN_IAMSPE=<token_iamspe>
V1_API_TOKEN_SGGD=<token_sggd>
V1_API_TOKEN_POUPATEMPO=<token_poupatempo>
V1_API_TOKEN_SPI=<token_spi>
V1_API_TOKEN_ALESP=<token_alesp>
V1_API_TOKEN_CPTM=<token_cptm>

# ---- Infra (mesma máquina) ----
REDIS_URL=redis://localhost:6379/0
DB_DSN=postgresql://socdash:<SENHA_FORTE>@localhost:5432/socdash

# ---- Mapa (opcional) ----
GEOIP_DB=

# ---- Cadência dos tiers (segundos) ----
TIER1_INTERVAL=60
TIER2_INTERVAL=300
TIER3_INTERVAL=900
TIER4_INTERVAL=3600
```

---

## 7. Banco: migrations + seeds

Aplique as **migrations** (imutáveis, controladas por checksum) usando o psql do próprio container:

```bash
cd /opt/soc-dashboard
PSQL="docker exec -i infra-db-1 psql -U socdash -d socdash" bash infra/migrate.sh
```

Aplique os **seeds** na ordem (dados de ambiente: tenants/orgs/coletores). **Não** aplique o `rollback_*`:

```bash
for f in 001_cyber_current_environment 002_cyber_attribution_modes \
         003_sggd_subindex_collectors 004_waf_collectors 005_new_tenants; do
  echo ">> seed $f"
  docker exec -i infra-db-1 psql -U socdash -d socdash < infra/seeds/$f.sql
done

# conferência: devem aparecer os 8 tenants
docker exec -i infra-db-1 psql -U socdash -d socdash \
  -c "select tenant_id from cyber_tenant_config order by 1;"
```

---

## 8. Teste manual (antes de virar serviço)

Em 3 terminais (ou `&`), a partir de `/opt/soc-dashboard/backend`:

```bash
# API (serve o front + endpoints)
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2

# Coletor Fase-1 (Redis: Dashboard / Vulnerabilidades / Centro)
.venv/bin/python -m collectors.run

# Pipeline Cyber (Postgres: Alertas / Cyber)
.venv/bin/python -m collectors.cyber_scheduler
```

Valide:

```bash
curl -s http://localhost:8000/healthz          # {"status":"ok","redis":true}
curl -s http://localhost:8000/api/prodesp-sp/overview | head -c 300
```

Abra `http://<IP_ou_DNS>:8000/` no navegador do wallboard. Se estiver OK, pare os processos manuais
(Ctrl+C) e siga para os serviços systemd.

---

## 9. Serviços systemd (persistência + restart)

Crie os três units (rodam como `ec2-user`, `WorkingDirectory` no `backend/` para achar o `.env`):

```bash
sudo tee /etc/systemd/system/socdash-api.service >/dev/null <<'UNIT'
[Unit]
Description=SOC Dashboard - API (uvicorn)
After=network-online.target docker.service
Wants=network-online.target
[Service]
User=ec2-user
WorkingDirectory=/opt/soc-dashboard/backend
ExecStart=/opt/soc-dashboard/backend/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT

sudo tee /etc/systemd/system/socdash-collector.service >/dev/null <<'UNIT'
[Unit]
Description=SOC Dashboard - Coletor Fase 1 (Redis)
After=network-online.target docker.service
Wants=network-online.target
[Service]
User=ec2-user
WorkingDirectory=/opt/soc-dashboard/backend
ExecStart=/opt/soc-dashboard/backend/.venv/bin/python -m collectors.run
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
UNIT

sudo tee /etc/systemd/system/socdash-cyber.service >/dev/null <<'UNIT'
[Unit]
Description=SOC Dashboard - Pipeline Cyber (Postgres: Alertas/Cyber)
After=network-online.target docker.service
Wants=network-online.target
[Service]
User=ec2-user
WorkingDirectory=/opt/soc-dashboard/backend
ExecStart=/opt/soc-dashboard/backend/.venv/bin/python -m collectors.cyber_scheduler
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now socdash-api socdash-collector socdash-cyber
sudo systemctl status socdash-api --no-pager
```

Logs:

```bash
journalctl -u socdash-collector -f      # OK por tier / WARNING ... indisponível
journalctl -u socdash-cyber -f
journalctl -u socdash-api -f
```

> `Restart=always` garante que, se a instância reiniciar antes dos containers ficarem prontos,
> os processos tentam de novo até o Redis/Postgres subir (com `restart: unless-stopped` no compose).

---

## 10. (Opcional, recomendado) Nginx + TLS — mesma origem, `wss://`

Servir atrás de um proxy TLS deixa o front na **mesma origem** (o `API_BASE` fica vazio e o WebSocket
vira `wss://` automaticamente; dispensa CORS aberto).

```bash
sudo dnf install -y nginx
# Se o SELinux estiver em enforcing, permita o proxy p/ o uvicorn:
sudo setsebool -P httpd_can_network_connect 1 || true

sudo tee /etc/nginx/conf.d/socdash.conf >/dev/null <<'NGINX'
server {
    listen 80;
    server_name _;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        # upgrade de WebSocket (/ws/...)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
    }
}
NGINX

sudo systemctl enable --now nginx
sudo nginx -t && sudo systemctl reload nginx
```

Para **HTTPS**, adicione um certificado (ACM+ALB na frente, ou `certbot`/`nginx` na porta 443) e
troque o `listen 80` por `listen 443 ssl;` com `ssl_certificate`/`ssl_certificate_key`. Abra 443 no
Security Group. Acesse `https://<DNS>/`.

---

## 11. Verificação final e operação

- **Wallboard:** abra a URL (`http://<IP>:8000/` ou `https://<DNS>/`) em tela cheia (tecla **F**).
  As 5 telas (Dashboard, Alertas, Vulnerabilidades, Centro, Cyber) rotacionam sozinhas.
- **Saúde:** `curl -s http://localhost:8000/healthz` → `{"status":"ok","redis":true}`.
- **Reiniciar um processo:** `sudo systemctl restart socdash-collector` (idem `-api`, `-cyber`).
- **Atualizar código:** `git pull` (na branch), então:
  - mudou `static/index.html` → nada a reiniciar (só recarregar o navegador, Ctrl+F5);
  - mudou `app/*` (API) → `sudo systemctl restart socdash-api`;
  - mudou `collectors/*` ou `.env` → `sudo systemctl restart socdash-collector socdash-cyber` (e `-api` se `.env`).
- **Novo tenant:** adicione o token no `.env` + campo em `app/config.py`, insira em `tenant`/`organization`/
  `cyber_tenant_config` (ver `infra/seeds/005_new_tenants.sql` como modelo), adicione o id nas listas do
  coletor (`_secondary` em `collectors/run.py`) e do front (`DASH_TENANTS`/`VULN_TENANTS`/`_AL_ACCENT` em
  `static/index.html`), reinicie os serviços e rode o backfill de workbench se quiser histórico imediato em Alertas.

### Cuidados
- **Nunca** `docker compose down -v` (o `-v` apaga os volumes → perde Redis e todo o histórico do Timescale).
  Para parar sem perder dados: `docker compose stop`.
- Migrations são **imutáveis** (checksum). Mudanças de schema entram como `00N_*.sql` novos.
- Backup: `docker exec infra-db-1 pg_dump -U socdash socdash | gzip > backup_$(date +%F).sql.gz`.
- Segredos só no `.env` (chmod 600); os tokens nunca vão para o Git nem para logs.
