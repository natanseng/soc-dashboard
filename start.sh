#!/bin/bash
#
# SOC SMART Dashboard — Hit & Run Startup
# Um comando para tudo: infra + backend + coletor
#
# Uso:
#   ./start.sh              # Tudo automaticamente
#   ./start.sh --help       # Ajuda
#   ./start.sh --dev        # Dev com auto-reload

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
INFRA_DIR="$PROJECT_ROOT/infra"
BACKEND_DIR="$PROJECT_ROOT/backend"
VENV_DIR="$BACKEND_DIR/.venv"
ENV_FILE="$BACKEND_DIR/.env"

DEV_MODE=false

print_help() {
    cat << EOF
${BLUE}SOC SMART Dashboard — Inicializador${NC}

${GREEN}Uso:${NC}
  ./start.sh           # Tudo (hit & run)
  ./start.sh --dev     # Dev com auto-reload
  ./start.sh --help    # Este texto

${GREEN}O que faz:${NC}
  1. Sobe infra (Redis + PostgreSQL)
  2. Configura Python venv
  3. Instala dependências
  4. Inicia API (uvicorn)
  5. Inicia coletor em background (se V1_API_TOKEN definido)
  6. Abre dashboard no navegador

${YELLOW}URL:${NC}
  http://localhost:8000

${YELLOW}Requisitos:${NC}
  • Docker + Docker Compose
  • Python 3.9+
  • ~2GB RAM

EOF
}

log_section() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}▶ $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

log_ok() {
    echo -e "${GREEN}✓ $1${NC}"
}

log_err() {
    echo -e "${RED}✗ $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

log_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --help) print_help; exit 0 ;;
        --dev) DEV_MODE=true; shift ;;
        *) log_err "Opção desconhecida: $1"; print_help; exit 1 ;;
    esac
done

# Check requisitos
check_requirements() {
    log_section "Validando requisitos"

    command -v docker &>/dev/null || { log_err "Docker não instalado"; exit 1; }
    log_ok "Docker $(docker --version | grep -o 'version [0-9.]*' | cut -d' ' -f2)"

    command -v python3 &>/dev/null || { log_err "Python 3 não instalado"; exit 1; }
    log_ok "Python $(python3 --version | cut -d' ' -f2)"

    [ -f "$PROJECT_ROOT/CLAUDE.md" ] || { log_err "Não está no diretório raiz"; exit 1; }
    log_ok "Localização: $PROJECT_ROOT"
}

# Infra
start_infra() {
    log_section "Iniciando infra (Redis + PostgreSQL)"

    cd "$INFRA_DIR"

    docker-compose up -d db redis 2>&1 | grep -E "Creating|Already|done" || true

    # Aguardar health checks
    log_info "Aguardando serviços..."
    sleep 3

    if docker-compose exec -T db pg_isready -U socdash &>/dev/null; then
        log_ok "PostgreSQL online"
    else
        log_warn "PostgreSQL inicializando..."
    fi

    if docker-compose exec -T redis redis-cli ping &>/dev/null; then
        log_ok "Redis online"
    else
        log_warn "Redis inicializando..."
    fi

    cd "$PROJECT_ROOT"
}

# Backend setup
setup_backend() {
    log_section "Configurando backend"

    cd "$BACKEND_DIR"

    # Venv
    if [ ! -f "$VENV_DIR/bin/python" ]; then
        log_info "Criando venv..."
        python3 -m venv "$VENV_DIR" || {
            log_err "Falha ao criar venv"
            exit 1
        }
    fi

    source "$VENV_DIR/bin/activate"
    log_ok "venv ativado"

    # Dependências
    if ! python -c "import uvicorn" 2>/dev/null; then
        log_info "Instalando dependências..."
        pip install -q -r requirements.txt
        log_ok "Dependências instaladas"
    else
        log_info "Dependências já instaladas"
    fi

    # .env
    if [ ! -f "$ENV_FILE" ] && [ -f ".env.example" ]; then
        log_warn ".env não existe, copiando .env.example"
        cp .env.example "$ENV_FILE"
        log_warn "Configure V1_API_TOKEN no .env para usar o coletor"
    fi

    cd "$PROJECT_ROOT"
}

# Coletor
start_collector() {
    # Verificar se V1_API_TOKEN está definido
    if [ -f "$ENV_FILE" ]; then
        V1_TOKEN=$(grep -m1 "^V1_API_TOKEN=" "$ENV_FILE" | cut -d'=' -f2 | xargs)
        if [ -z "$V1_TOKEN" ] || [ "$V1_TOKEN" = "seu_token_aqui" ]; then
            log_warn "V1_API_TOKEN não configurado — coletor desativado"
            log_info "Configure em: $ENV_FILE"
            return
        fi
    fi

    (
        cd "$BACKEND_DIR"
        source "$VENV_DIR/bin/activate"

        log_section "Iniciando coletor (background)"
        log_info "Conectando à Vision One API..."

        python -m collectors.run &
        COLLECTOR_PID=$!

        log_ok "Coletor rodando (PID: $COLLECTOR_PID)"
    ) &
}

# API
start_api() {
    log_section "Iniciando API (uvicorn)"

    cd "$BACKEND_DIR"
    source "$VENV_DIR/bin/activate"

    if [ "$DEV_MODE" = "true" ]; then
        log_info "Modo dev (auto-reload ativado)"
        uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    else
        log_info "Produção"
        uvicorn app.main:app --host 0.0.0.0 --port 8000
    fi
}

# Main
main() {
    echo -e "\n${BLUE}╔═══════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  SOC SMART Dashboard — Hit & Run Startup    ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}\n"

    check_requirements
    start_infra
    setup_backend
    start_collector
    start_api
}

trap 'log_info "Encerrando..."; exit 0' INT TERM

main "$@"
