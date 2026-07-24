#!/usr/bin/env bash
# =====================================================================================
# deploy-rhel9.sh  |  Sobe o SOC Dashboard numa EC2 Amazon Linux? NAO — RHEL 9.8 (x86_64)
# -------------------------------------------------------------------------------------
# Cria uma COPIA FIEL do ambiente do WSL, reutilizando o backend/.env que veio no bundle
# (mesmos tokens de API e a mesma senha 'dev_change_me' do banco). O script:
#   - NAO pede/gera tokens de API (usa os do .env empacotado)
#   - NAO troca senhas de banco (mantem exatamente o que esta no compose/.env)
# Runtime de containers = Podman + Quadlet (nativo do RHEL). App = venv Python 3.12.
# 3 servicos systemd: socdash-api (uvicorn), socdash-collector (Fase 1), socdash-cyber.
#
# Funciona nos dois casos:
#   (a) arvore ja extraida (voce compactou a pasta soc-dashboard do WSL e descompactou aqui);
#   (b) bundle gerado por infra/package-for-rhel.sh.
# Se a arvore veio do WSL, o .venv do WSL NAO serve no RHEL — este script o RECRIA.
#
# USO (no host RHEL):
#   sudo bash /opt/soc-dashboard/infra/deploy-rhel9.sh
#   (tambem funciona se voce salvar este arquivo na RAIZ do projeto, ex. /opt/soc-dashboard/deploy.sh)
# (ou, como usuario com sudo NOPASSWD:)  bash .../deploy-rhel9.sh
#
# Idempotente: pode rodar de novo (migrations por checksum, seeds idempotentes,
# units reescritos, venv recriado so se ausente/estrangeiro). NAO destroi o volume do Postgres.
# =====================================================================================
set -euo pipefail

# ---------- localizacao: detecta a RAIZ do projeto (pasta com backend/ e infra/) ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
find_root(){
  local d
  for d in "$SCRIPT_DIR" "$SCRIPT_DIR/.." "/opt/soc-dashboard" "$PWD" "$PWD/soc-dashboard"; do
    if [ -d "$d/backend" ] && [ -d "$d/infra" ]; then (cd "$d" && pwd); return 0; fi
  done
  return 1
}
APP_DIR="$(find_root)" || { echo "ERRO: nao achei a raiz do projeto (pasta com backend/ e infra/). Rode de dentro de /opt/soc-dashboard." >&2; exit 1; }
BACKEND="$APP_DIR/backend"
INFRA="$APP_DIR/infra"
ENV_FILE="$BACKEND/.env"
INIT_SQL="$INFRA/init.sql"
RUN_USER="${SUDO_USER:-$(id -un)}"
PY=python3.12

log(){ printf '\n\033[1;36m>>> %s\033[0m\n' "$*"; }
die(){ printf '\n\033[1;31mERRO: %s\033[0m\n' "$*" >&2; exit 1; }
# roda um comando como o usuario alvo (nao-root), esteja o script sob sudo ou nao
as_user(){ if [ "$(id -u)" -eq 0 ]; then sudo -u "$RUN_USER" "$@"; else "$@"; fi; }

# ---------- 0. pre-checagens ----------
command -v sudo >/dev/null 2>&1 || die "sudo e necessario."
[ -f /etc/redhat-release ] || echo "Aviso: /etc/redhat-release ausente — este script foi feito para RHEL 9.x."
[ -f "$ENV_FILE" ] || die "backend/.env NAO encontrado em: $ENV_FILE
Este script usa o .env que veio no bundle do WSL (com os tokens e a senha do banco).
No WSL rode  infra/package-for-rhel.sh  para gerar o bundle (que inclui o .env) e extraia-o aqui."
grep -q '^V1_API_TOKEN' "$ENV_FILE" || die ".env presente mas sem V1_API_TOKEN — bundle incompleto."
[ -f "$INIT_SQL" ] || die "infra/init.sql ausente — bundle incompleto."
[ -f "$BACKEND/requirements.txt" ] || die "backend/requirements.txt ausente — bundle incompleto."

. /etc/os-release 2>/dev/null || true
log "Alvo: ${PRETTY_NAME:-RHEL}  |  app: $APP_DIR  |  servicos como usuario: $RUN_USER"
log "Reutilizando $ENV_FILE ($(grep -c '^V1_API_TOKEN' "$ENV_FILE") tokens) — sem trocar senhas nem pedir chaves."

# ---------- 1. pacotes (tudo do AppStream; sem EPEL, sem 'dnf update' p/ evitar reboot) ----------
log "1/8  Instalando pacotes (python3.12, podman)…"
sudo dnf install -y python3.12 python3.12-pip podman

# ---------- 2. propriedade + rotulos SELinux do app ----------
log "2/8  Ajustando propriedade e rotulos SELinux…"
sudo chown -R "$RUN_USER":"$RUN_USER" "$APP_DIR"
sudo chmod 600 "$ENV_FILE"
# no RHEL o SELinux fica Enforcing; garante rotulos corretos p/ o venv executar via systemd
sudo restorecon -R "$APP_DIR" >/dev/null 2>&1 || true

# ---------- 3. Quadlet: Postgres/Timescale + Redis (valores IDENTICOS ao compose) ----------
log "3/8  Criando units Quadlet (containers db + redis)…"
sudo mkdir -p /etc/containers/systemd

sudo tee /etc/containers/systemd/db_data.volume >/dev/null <<'UNIT'
[Unit]
Description=TimescaleDB data volume (SOC Dashboard)
[Volume]
VolumeName=db_data
UNIT

sudo tee /etc/containers/systemd/socdash.network >/dev/null <<'UNIT'
[Unit]
Description=SOC Dashboard internal network
[Network]
NetworkName=socdash
UNIT

# db.container: heredoc SEM aspas p/ expandir $INIT_SQL (unico $ do arquivo)
sudo tee /etc/containers/systemd/db.container >/dev/null <<UNIT
[Unit]
Description=TimescaleDB (PostgreSQL 16) - SOC Dashboard
After=network-online.target
Wants=network-online.target

[Container]
ContainerName=socdash-db
Image=docker.io/timescale/timescaledb:latest-pg16
Environment=POSTGRES_USER=socdash
Environment=POSTGRES_PASSWORD=dev_change_me
Environment=POSTGRES_DB=socdash
Volume=db_data.volume:/var/lib/postgresql/data
Volume=${INIT_SQL}:/docker-entrypoint-initdb.d/init.sql:ro,Z
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

# ---------- 4. subir containers + esperar o Postgres ----------
log "4/8  Subindo containers…"
sudo systemctl daemon-reload
sudo systemctl start db.service redis.service
log "Aguardando Postgres (socdash-db) ficar pronto…"
ready=""
for _ in $(seq 1 60); do
  if sudo podman exec socdash-db pg_isready -U socdash >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
[ -n "$ready" ] || die "Postgres nao respondeu. Diagnostique com: sudo journalctl -u db.service -n 50"
sudo podman ps --format '  {{.Names}}  {{.Status}}'

# ---------- 5. venv + dependencias ----------
# Recria o venv se estiver ausente OU se for "estrangeiro" (copiado do WSL: os shebangs
# apontam para /home/lucas/... e nao funcionam neste host).
log "5/8  Preparando venv Python 3.12…"
need_venv=1
if [ -x "$BACKEND/.venv/bin/python" ] && head -1 "$BACKEND/.venv/bin/pip" 2>/dev/null | grep -q "$BACKEND/.venv"; then
  need_venv=""
fi
if [ -n "$need_venv" ]; then
  echo "  (re)criando venv em $BACKEND/.venv"
  sudo rm -rf "$BACKEND/.venv"
  as_user "$PY" -m venv "$BACKEND/.venv"
else
  echo "  venv existente e valido — reutilizando"
fi
log "Instalando dependencias…"
as_user "$BACKEND/.venv/bin/pip" install --upgrade pip setuptools wheel
as_user "$BACKEND/.venv/bin/pip" install -r "$BACKEND/requirements.txt"

# ---------- 6. migrations + seeds (via psql do container) ----------
log "6/8  Aplicando migrations…"
PSQL="sudo podman exec -i socdash-db psql -U socdash -d socdash" bash "$INFRA/migrate.sh"
log "Aplicando seeds (idempotentes)…"
for f in 001_cyber_current_environment 002_cyber_attribution_modes \
         003_sggd_subindex_collectors 004_waf_collectors 005_new_tenants; do
  if [ -f "$INFRA/seeds/$f.sql" ]; then
    echo "  >> seed $f"
    sudo podman exec -i socdash-db psql -U socdash -d socdash -v ON_ERROR_STOP=1 < "$INFRA/seeds/$f.sql" >/dev/null
  fi
done
echo -n "  tenants no banco: "
sudo podman exec -i socdash-db psql -U socdash -d socdash -tAc \
  "select string_agg(tenant_id, ', ' order by tenant_id) from cyber_tenant_config;"

# ---------- 7. servicos systemd do backend ----------
log "7/8  Criando servicos systemd (api / collector / cyber)…"
sudo tee /etc/systemd/system/socdash-api.service >/dev/null <<UNIT
[Unit]
Description=SOC Dashboard - API (uvicorn)
After=network-online.target db.service redis.service
Wants=network-online.target
[Service]
User=$RUN_USER
WorkingDirectory=$BACKEND
ExecStart=$BACKEND/.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT

sudo tee /etc/systemd/system/socdash-collector.service >/dev/null <<UNIT
[Unit]
Description=SOC Dashboard - Coletor Fase 1 (Redis)
After=network-online.target db.service redis.service
Wants=network-online.target
[Service]
User=$RUN_USER
WorkingDirectory=$BACKEND
ExecStart=$BACKEND/.venv/bin/python -m collectors.run
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
UNIT

sudo tee /etc/systemd/system/socdash-cyber.service >/dev/null <<UNIT
[Unit]
Description=SOC Dashboard - Pipeline Cyber (Postgres: Alertas/Cyber)
After=network-online.target db.service redis.service
Wants=network-online.target
[Service]
User=$RUN_USER
WorkingDirectory=$BACKEND
ExecStart=$BACKEND/.venv/bin/python -m collectors.cyber_scheduler
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now socdash-api socdash-collector socdash-cyber

# ---------- 8. firewall (best-effort) + verificacao de saude ----------
log "8/8  Firewall e verificacao…"
# so mexe no firewalld se ele ja estiver ativo (na AMI de nuvem costuma vir inativo; a borda e o Security Group)
if systemctl is-active --quiet firewalld; then
  sudo firewall-cmd --permanent --add-service=ssh   >/dev/null || true
  sudo firewall-cmd --permanent --add-port=8000/tcp  >/dev/null || true
  sudo firewall-cmd --reload >/dev/null || true
  echo "  firewalld ativo: liberadas ssh + 8000/tcp."
else
  echo "  firewalld inativo (padrao da AMI) — controle de acesso e o Security Group da AWS."
fi

health=""
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8000/healthz >/dev/null 2>&1; then health=1; break; fi
  sleep 2
done

# tenta descobrir o IP publico (IMDSv2) — best-effort
TOKEN="$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null || true)"
PUBIP="$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || true)"

echo
if [ -n "$health" ]; then
  printf '\033[1;32m==== SOC Dashboard no ar ====\033[0m\n'
  echo "  /healthz: $(curl -s http://127.0.0.1:8000/healthz)"
else
  printf '\033[1;33m==== Deploy concluido, mas /healthz ainda nao respondeu ====\033[0m\n'
  echo "  verifique: sudo journalctl -u socdash-api -n 50"
fi
echo
echo "Wallboard:   http://${PUBIP:-<IP-da-instancia>}:8000/"
echo "IMPORTANTE:  libere a porta 8000/tcp no Security Group da EC2 (inbound) para acessar de fora."
echo
echo "Servicos:    sudo systemctl status socdash-api socdash-collector socdash-cyber"
echo "Containers:  sudo podman ps"
echo "Logs:        journalctl -u socdash-collector -f   (idem -api / -cyber)"
echo
echo "TLS/mesma-origem (opcional): ver docs/DEPLOY-RHEL9.md (Nginx + ALB/ACM ou certbot)."
