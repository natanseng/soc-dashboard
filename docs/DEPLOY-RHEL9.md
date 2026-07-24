# Deploy em Red Hat Enterprise Linux 9.8 (AWS) — passo a passo

Runbook para subir o **SOC Dashboard (TrendAI Vision One)** numa instância EC2 com a AMI
**`RHEL-9.8.0_HVM_GA-20260521-x86_64-0-Hourly2-GP3`** (RHEL 9.8, x86_64, GA, faturamento **Hourly2/PAYG**).

Stack: **Podman + Quadlet** (TimescaleDB/PG16 + Redis como serviços systemd) + **backend Python 3.12 (venv)**
com 3 processos — **API** (uvicorn, serve o front `index.html` + `/api`,`/alerts`,`/cyber`), **coletor Fase‑1**
(`collectors.run` → Redis: telas Dashboard/Vulnerabilidades/Centro) e **pipeline Cyber**
(`collectors.cyber_scheduler` → Postgres: telas Alertas/Cyber) — atrás de **Nginx** (reverse proxy + TLS).

> **Diferenças-chave vs. Amazon Linux 2023** (as fontes comuns de erro ao migrar): no RHEL o **SELinux fica
> *Enforcing*** por padrão, há **firewalld** (instalado, mas geralmente **inativo** na AMI de nuvem), o container
> runtime nativo é **Podman** (não Docker), e a imagem PAYG **não** exige `subscription-manager register`.
> Este guia foi montado a partir de documentação oficial Red Hat/AWS/Podman/Nginx verificada; onde a doc
> específica da AMI é login-gated, os passos incluem um **comando de conferência no host**.

> Convenções: usuário de login **`ec2-user`** (padrão das AMIs Red Hat na AWS); projeto em `/opt/soc-dashboard`;
> comandos privilegiados com `sudo`. Ajuste caminhos/senhas/DNS ao seu ambiente.

---

## 0. Pré‑requisitos

- EC2 **RHEL 9.8** (a AMI acima), x86_64, ≥ 2 vCPU / 4 GB RAM / 20 GB gp3 (o Timescale cresce com histórico).
- **Security Group** (borda real na AWS — independente do firewalld): liberar **80/443** (Nginx). **Não** exponha
  5432 (Postgres) nem 6379 (Redis) — eles ficam em `127.0.0.1`. Se for terminar TLS num **ALB**, o SG da instância
  libera **80 apenas a partir do SG do ALB**.
- Acesso de saída HTTPS para `api.xdr.trendmicro.com` (Vision One), Docker Hub / registries (imagens) e Red Hat CDN.
- (Para TLS no host via certbot) um **registro DNS público** apontando para o IP da instância.
- Os **tokens de API** dos 8 tenants (Vision One → Administração → API Keys).

---

## 1. Primeiro acesso e base do sistema

```bash
ssh -i /caminho/chave.pem ec2-user@<IP_PUBLICO>
sudo -i     # ou prefixe cada comando com sudo
```

**Subscription/repos — NÃO registre manualmente.** A AMI 9.8 (≥ 9.7) se **auto‑registra no CDN da Red Hat**
no primeiro boot; o `dnf` já funciona. Confirme (não execute `subscription-manager register`):

```bash
sudo subscription-manager identity     # deve mostrar a instância já registrada (CDN)
dnf repolist                           # deve listar rhel-9-*-baseos-rpms e rhel-9-*-appstream-rpms
sudo dnf -y update                     # atualiza tudo
sudo dnf install -y dnf-plugins-core
needs-restarting -r || sudo reboot     # reinicia só se kernel/glibc/systemd foram atualizados
```

**Confira o estado de SELinux e firewalld (diferente do AL2023):**

```bash
getenforce                             # esperado: Enforcing  (NÃO desative)
systemctl is-active firewalld          # provavelmente "inactive" na AMI de nuvem
systemctl is-active chronyd            # esperado: active (Amazon Time Sync já configurado)
```

Se quiser o firewall do host ativo (recomendado, além do Security Group):

```bash
sudo systemctl enable --now firewalld
```

---

## 2. Pacotes (tudo do AppStream — sem EPEL, sem registro extra)

```bash
sudo dnf install -y git python3.12 python3.12-pip python3.12-devel podman container-tools nginx
python3.12 --version        # confirma a micro-versão empacotada nesta AMI
podman --version            # RHEL 9.8 traz Podman 5.x (Quadlet embutido)
```

> `python3.12` é um stream **não‑modular** do AppStream (desde o 9.4) e convive com o `python3` do sistema
> (3.9 — **não** altere `/usr/bin/python3`, o `dnf` depende dele). `gcc` **não** é necessário: `asyncpg`, `uvloop`,
> `httptools` e `pydantic-core` têm wheels `cp312` manylinux compatíveis com a glibc 2.34 do RHEL 9 (por isso o
> `pip install --upgrade pip` mais adiante, para reconhecer a tag `manylinux_2_28`). Só instale `gcc` se algum
> pacote cair para build de sdist.

---

## 3. Obter o código

Clone (ou copie) o repositório para `/opt/soc-dashboard`, **na branch com o trabalho multi‑tenant**:

```bash
sudo mkdir -p /opt/soc-dashboard && sudo chown ec2-user:ec2-user /opt/soc-dashboard
git clone <URL_DO_SEU_REMOTE> /opt/soc-dashboard
cd /opt/soc-dashboard
git checkout feat/cyber-multitenant     # todo o multi-tenant está aqui (NÃO na master antiga)
```

> Sem remote Git? Copie a árvore (rsync/scp) preservando `infra/`, `backend/`, `docs/` — **sem** `backend/.venv`
> nem `backend/logs`. O `infra/init.sql` precisa existir em `/opt/soc-dashboard/infra/init.sql` (usado no passo 4).

---

## 4. Infra (TimescaleDB + Redis) via Podman + Quadlet

> **Antes:** troque a senha padrão do banco (`dev_change_me`) nos units abaixo **e** no `DB_DSN` do `.env` (passo 6).
> Imagens do Docker Hub exigem nome **totalmente qualificado** (`docker.io/...`) no Podman.

Crie os quatro units do Quadlet em `/etc/containers/systemd/`:

```bash
# --- /etc/containers/systemd/db_data.volume ---
sudo tee /etc/containers/systemd/db_data.volume >/dev/null <<'UNIT'
[Unit]
Description=TimescaleDB data volume
[Volume]
VolumeName=db_data
UNIT

# --- /etc/containers/systemd/socdash.network ---
sudo tee /etc/containers/systemd/socdash.network >/dev/null <<'UNIT'
[Unit]
Description=SOC Dashboard internal network
[Network]
NetworkName=socdash
UNIT

# --- /etc/containers/systemd/db.container ---
sudo tee /etc/containers/systemd/db.container >/dev/null <<'UNIT'
[Unit]
Description=TimescaleDB (PostgreSQL 16) - SOC Dashboard
After=network-online.target
Wants=network-online.target

[Container]
ContainerName=socdash-db
Image=docker.io/timescale/timescaledb:latest-pg16
Environment=POSTGRES_USER=socdash
Environment=POSTGRES_PASSWORD=TROQUE_ESTA_SENHA
Environment=POSTGRES_DB=socdash
Volume=db_data.volume:/var/lib/postgresql/data
Volume=/opt/soc-dashboard/infra/init.sql:/docker-entrypoint-initdb.d/init.sql:ro,Z
PublishPort=127.0.0.1:5432:5432
Network=socdash.network
HealthCmd=pg_isready -U socdash
HealthInterval=10s
HealthTimeout=5s
HealthRetries=5
HealthStartPeriod=30s

[Service]
Restart=always
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
UNIT

# --- /etc/containers/systemd/redis.container ---
sudo tee /etc/containers/systemd/redis.container >/dev/null <<'UNIT'
[Unit]
Description=Redis 7 - SOC Dashboard
After=network-online.target
Wants=network-online.target

[Container]
ContainerName=socdash-redis
Image=docker.io/library/redis:7-alpine
Exec=redis-server --save 60 1 --appendonly no
PublishPort=127.0.0.1:6379:6379
Network=socdash.network
HealthCmd=redis-cli ping
HealthInterval=10s
HealthTimeout=5s
HealthRetries=5

[Service]
Restart=always
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
UNIT
```

Suba os containers (o Quadlet gera `db.service`/`redis.service` a partir dos `.container`):

```bash
sudo systemctl daemon-reload            # dispara o gerador do Quadlet
sudo systemctl start db.service redis.service
systemctl status db.service redis.service
sudo podman ps                          # deve mostrar socdash-db e socdash-redis (healthy)
```

> **Pontos que a doc oficial confirma e são pegadinhas comuns:**
> - Units gerados pelo Quadlet **não** aceitam `systemctl enable` (são transientes). A persistência no boot vem do
>   `[Install] WantedBy=multi-user.target` + `daemon-reload` — não rode `systemctl enable db.service`.
> - O **nome do container** não é o nome do unit; o default é `systemd-<unit>`. Por isso fixamos
>   `ContainerName=socdash-db`/`socdash-redis`, para os `podman exec` do passo 7 serem determinísticos.
> - O `init.sql` só roda no **primeiro** start com o volume vazio (idêntico ao compose) — migrations vão por `exec`.
> - **Segredo em texto claro:** `POSTGRES_PASSWORD` no unit aparece no `podman inspect`/journal. Para produção,
>   prefira `podman secret` + `Secret=` ou um `EnvironmentFile=` com permissão restrita.
> - Como ambos publicam em `127.0.0.1`, **não** é preciso abrir 5432/6379 no firewalld.

<details>
<summary><b>Alternativas ao Quadlet</b> (se preferir reaproveitar o compose ou usar Docker)</summary>

- **podman-compose** (reaproveita `infra/docker-compose.yml`): precisa de EPEL — `sudo dnf install -y
  https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm && sudo dnf install -y podman-compose`;
  então `cd infra && sudo podman-compose up -d`. Atenção: nomes de container ficam `infra_db_1` (underscore) —
  ajuste o `PSQL=` do passo 7. Não é a via recomendada pela Red Hat para produção.
- **Docker CE**: `sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo &&
  sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin` (remove o Podman; suportado
  pela Docker Inc, não pela Red Hat). Aí o fluxo é idêntico ao guia do Amazon Linux (`docker compose`).
</details>

---

## 5. Backend: venv (Python 3.12) + dependências

```bash
cd /opt/soc-dashboard/backend
python3.12 -m venv .venv
.venv/bin/pip install --upgrade pip setuptools wheel
.venv/bin/pip install -r requirements.txt
```

---

## 6. Configuração (`.env`) — inclui os 8 tenants

```bash
cd /opt/soc-dashboard/backend
cp .env.example .env
chmod 600 .env
```

Edite `backend/.env` (a senha do `DB_DSN` **igual** à do `db.container`; **nunca** comite tokens):

```ini
# ---- Vision One ----
V1_API_BASE=https://api.xdr.trendmicro.com
TENANT=prodesp-sp

V1_API_TOKEN=<token_prodesp>
V1_API_TOKEN_DETRAN=<token_detran>
V1_API_TOKEN_IAMSPE=<token_iamspe>
V1_API_TOKEN_SGGD=<token_sggd>
V1_API_TOKEN_POUPATEMPO=<token_poupatempo>
V1_API_TOKEN_SPI=<token_spi>
V1_API_TOKEN_ALESP=<token_alesp>
V1_API_TOKEN_CPTM=<token_cptm>

# ---- Infra (mesma máquina, via loopback publicado pelo Podman) ----
REDIS_URL=redis://localhost:6379/0
DB_DSN=postgresql://socdash:TROQUE_ESTA_SENHA@localhost:5432/socdash

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

Migrations (imutáveis, por checksum) usando o `psql` do container `socdash-db`:

```bash
cd /opt/soc-dashboard
PSQL="sudo podman exec -i socdash-db psql -U socdash -d socdash" bash infra/migrate.sh
```

Seeds na ordem (dados de ambiente: tenants/orgs/coletores) — **não** aplique o `rollback_*`:

```bash
for f in 001_cyber_current_environment 002_cyber_attribution_modes \
         003_sggd_subindex_collectors 004_waf_collectors 005_new_tenants; do
  echo ">> seed $f"
  sudo podman exec -i socdash-db psql -U socdash -d socdash < infra/seeds/$f.sql
done

# conferência: devem aparecer os 8 tenants
sudo podman exec -i socdash-db psql -U socdash -d socdash \
  -c "select tenant_id from cyber_tenant_config order by 1;"
```

---

## 8. Teste manual (antes de virar serviço)

A partir de `/opt/soc-dashboard/backend`:

```bash
# API (só loopback; o Nginx do passo 11 expõe para fora)
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 &
.venv/bin/python -m collectors.run &            # coletor Fase-1 (Redis)
.venv/bin/python -m collectors.cyber_scheduler &  # pipeline Cyber (Postgres)

curl -s http://127.0.0.1:8000/healthz           # {"status":"ok","redis":true}
curl -s http://127.0.0.1:8000/api/prodesp-sp/overview | head -c 300
```

Se estiver OK, encerre os processos de teste (`kill %1 %2 %3` ou `pkill -f uvicorn; pkill -f collectors`) e siga.

---

## 9. Serviços systemd do backend (persistência + restart)

Rodam como `ec2-user`, com `WorkingDirectory` no `backend/` (para achar o `.env`) e **ordenados após os
containers** (`db.service`/`redis.service` gerados pelo Quadlet):

```bash
sudo tee /etc/systemd/system/socdash-api.service >/dev/null <<'UNIT'
[Unit]
Description=SOC Dashboard - API (uvicorn)
After=network-online.target db.service redis.service
Wants=network-online.target
[Service]
User=ec2-user
WorkingDirectory=/opt/soc-dashboard/backend
ExecStart=/opt/soc-dashboard/backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 2
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT

sudo tee /etc/systemd/system/socdash-collector.service >/dev/null <<'UNIT'
[Unit]
Description=SOC Dashboard - Coletor Fase 1 (Redis)
After=network-online.target db.service redis.service
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
After=network-online.target db.service redis.service
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
systemctl status socdash-api --no-pager
```

> Estes são units **próprios** (não do Quadlet), então `systemctl enable` funciona normalmente.
> Sob SELinux, um serviço systemd rodando um binário em `/opt` roda no domínio `unconfined_service_t` **sem AVC**.
> Se houver erro `203/EXEC` ou negação, corrija o rótulo: `sudo restorecon -Rv /opt/soc-dashboard`.
> Logs: `journalctl -u socdash-collector -f` (OK por tier / `WARNING ... indisponível`).

---

## 10. Firewall (firewalld) + SELinux para o proxy

```bash
# firewalld (host) — abra HTTP/HTTPS. Lembre: o Security Group da AWS também precisa liberar 80/443.
sudo systemctl enable --now firewalld            # se ainda estava inativo
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
sudo firewall-cmd --list-all

# SELinux: permitir que o Nginx (domínio httpd_t) conecte no uvicorn em 127.0.0.1:8000.
# Sem isto -> 502 Bad Gateway + AVC. Vale mesmo sendo loopback (SELinux trata como conexão de rede).
sudo setsebool -P httpd_can_network_connect 1
getsebool httpd_can_network_connect              # -> on
```

---

## 11. Nginx (reverse proxy) + TLS

Nginx vem do AppStream (nesta AMI o `dnf install nginx` instala o stream **1.22.1**; todos os streams do RHEL 9
são < 1.29, então **`proxy_http_version 1.1;` é obrigatório** para o WebSocket funcionar).

```bash
# map de upgrade do WebSocket — DEVE ficar em escopo http (arquivo próprio em conf.d)
sudo tee /etc/nginx/conf.d/websocket_map.conf >/dev/null <<'NGINX'
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
NGINX

sudo tee /etc/nginx/conf.d/socdash.conf >/dev/null <<'NGINX'
server {
    listen 80;
    server_name _;                      # troque pelo seu FQDN se usar certbot

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade           $http_upgrade;
        proxy_set_header Connection        $connection_upgrade;
        proxy_read_timeout  3600s;       # não derruba WebSocket ocioso
        proxy_send_timeout  3600s;
    }
}
NGINX

sudo nginx -t
sudo systemctl enable --now nginx
sudo systemctl reload nginx
```

Acesse `http://<IP_ou_DNS>/`. Para **HTTPS**, escolha **uma** opção:

**Opção A — ALB + ACM (recomendada na AWS):** crie um listener HTTPS:443 no ALB com certificado do ACM
(auto-renova) e um target group HTTP:80 apontando para a instância. O Nginx fica **só em `listen 80`** (sem cert
no host); o SG da instância libera 80 **apenas do SG do ALB**. O ALB repassa WebSocket nativamente e envia
`X-Forwarded-Proto: https` — garanta que a app confie nesse header (não no `$scheme`) para montar URLs/cookies.

**Opção B — certbot no host (DNS público apontando para a instância):**
```bash
sudo subscription-manager repos --enable codeready-builder-for-rhel-9-x86_64-rpms   # dependência do EPEL
sudo dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
sudo dnf install -y certbot python3-certbot-nginx
# troque server_name _ pelo seu FQDN no socdash.conf, então:
sudo certbot --nginx -d app.seu-dominio.com
sudo certbot renew --dry-run
```
> Com a opção B, **443 precisa estar aberto no firewalld E no Security Group** (abrir só um bloqueia silenciosamente).
> Não combine A e B (dupla terminação de TLS).

---

## 12. Verificação final e operação

- **Wallboard:** abra a URL em tela cheia (tecla **F**). As 5 telas (Dashboard, Alertas, Vulnerabilidades, Centro,
  Cyber) rotacionam sozinhas; com TLS same-origin o front usa `wss://` automaticamente.
- **Saúde:** `curl -s http://127.0.0.1:8000/healthz` → `{"status":"ok","redis":true}`.
- **Reiniciar processos do app:** `sudo systemctl restart socdash-collector` (idem `-api`, `-cyber`).
- **Reiniciar infra:** `sudo systemctl restart db.service redis.service`.
- **Atualizar código:** `git pull` na branch, então:
  - `static/index.html` → nada a reiniciar (recarregar o navegador, Ctrl+F5);
  - `app/*` (API) → `sudo systemctl restart socdash-api`;
  - `collectors/*` ou `.env` → `sudo systemctl restart socdash-collector socdash-cyber` (+ `-api` se `.env`).
- **Novo tenant:** token no `.env` + campo em `app/config.py`; inserir em `tenant`/`organization`/
  `cyber_tenant_config` (modelo: `infra/seeds/005_new_tenants.sql`); adicionar o id nas listas do coletor
  (`_secondary` em `collectors/run.py`) e do front (`DASH_TENANTS`/`VULN_TENANTS`/`_AL_ACCENT` em
  `static/index.html`); reiniciar os serviços.

### Cuidados
- **Não** apague o volume de dados: `sudo podman volume rm db_data` destrói o histórico do Timescale. Para parar
  sem perder dados: `sudo systemctl stop db.service` (o volume `db_data` persiste).
- **SELinux fica Enforcing** — não desative. Se algo der 502/permission-denied, investigue com
  `sudo ausearch -m avc -ts recent` antes de qualquer `setenforce 0`.
- **Dois firewalls** na EC2: firewalld (host) **e** Security Group (AWS) — 80/443 precisam estar abertos em ambos.
- **Backup:** `sudo podman exec socdash-db pg_dump -U socdash socdash | gzip > backup_$(date +%F).sql.gz`.
- Segredos só no `.env` (chmod 600) e, idealmente, a senha do DB via `podman secret` — nunca no Git nem em logs.

---

### Notas de validação (pontos a confirmar no host, por serem específicos da imagem)
Estes itens foram verificados contra documentação oficial no geral, mas o estado exato **nesta build da AMI** só
se confirma na instância — os comandos de conferência já estão nos passos acima:
- **RHUI × CDN:** a 9.8 (≥ 9.7) auto-registra no **CDN**; se `dnf` não resolver (ex.: saída para o CDN bloqueada),
  reative o RHUI com `sudo rhui-reenable`. Confira com `sudo subscription-manager identity` / `dnf repolist`.
- **firewalld:** costuma vir **inativo** na AMI de nuvem (a borda é o Security Group). Confirme com
  `systemctl is-active firewalld` e ative se quiser o firewall do host.
- **Versões:** `python3.12 --version`, `podman --version`, `nginx -v` — confirmam o que a AMI empacotou.
