#!/usr/bin/env bash
# =====================================================================================
# package-for-rhel.sh  |  Empacota o projeto (COPIA FIEL do WSL) para deploy no RHEL 9.8
# -------------------------------------------------------------------------------------
# Gera um tar.gz com backend/ + infra/ + docs/, INCLUINDO:
#   - backend/.env  (os 8 tokens de API e a senha 'dev_change_me' — para NAO redigitar nada)
#   - backend/data/GeoLite2-City.mmdb  (base do mapa)
#   - infra/deploy-rhel9.sh  (o instalador que roda no host RHEL)
# Exclui o que e local/gerado: .venv, logs, __pycache__, .git, tarballs soltos.
#
# USO (no WSL):  bash infra/package-for-rhel.sh  [saida.tar.gz]
# (default: /tmp/socdash-deploy.tar.gz)
#
# ATENCAO: o pacote CONTEM SEGREDOS (tokens no .env). Trate-o como confidencial:
# transfira por canal seguro (scp) e apague-o do destino apos extrair.
# =====================================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT="${1:-/tmp/socdash-deploy.tar.gz}"
cd "$ROOT"

[ -f backend/.env ] || { echo "ERRO: backend/.env nao existe — nada a empacotar com tokens." >&2; exit 1; }
[ -f infra/deploy-rhel9.sh ] || { echo "ERRO: infra/deploy-rhel9.sh nao encontrado." >&2; exit 1; }

echo ">> Empacotando a partir de: $ROOT"
tar --exclude='backend/.venv' \
    --exclude='backend/logs' \
    --exclude='*__pycache__*' \
    --exclude='*.pyc' \
    --exclude='.git' \
    --exclude='*.tar.gz' \
    --exclude='DashSOCtar.gz' \
    -czf "$OUT" \
    backend infra docs

SIZE="$(du -h "$OUT" | cut -f1)"
echo ">> Bundle criado: $OUT  ($SIZE)"
echo "   inclui backend/.env (8 tokens) + GeoLite2 + infra/deploy-rhel9.sh"
echo
echo "Proximos passos (troque IP/chave/AMI conforme o seu ambiente):"
echo "  scp -i chave.pem $OUT ec2-user@<IP_PUBLICO>:/tmp/"
echo "  ssh -i chave.pem ec2-user@<IP_PUBLICO>"
echo "  sudo mkdir -p /opt/soc-dashboard"
echo "  sudo tar -xzf /tmp/$(basename "$OUT") -C /opt/soc-dashboard"
echo "  sudo bash /opt/soc-dashboard/infra/deploy-rhel9.sh"
echo "  rm -f /tmp/$(basename "$OUT")   # apague o pacote com segredos do destino"
