#!/bin/bash
#
# SOC SMART Dashboard — Script de inicialização
# Inicia toda a stack em um único comando
#
# Uso:
#   ./start.sh                 # Iniciar tudo (infra + backend + coletor)
#   ./start.sh --help          # Mostrar ajuda
#   ./start.sh --infra-only    # Só infra (Redis + PostgreSQL)
#   ./start.sh --backend-only  # Só backend (uvicorn)
#   ./start.sh --collector     # Incluir coletor
#   ./start.sh --reload        # Backend com auto-reload

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variáveis
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
INFRA_DIR="$PROJECT_ROOT/infra"
BACKEND_DIR="$PROJECT_ROOT/backend"
VENV_DIR="$BACKEND_DIR/.venv"

# Flags
START_INFRA=true
START_BACKEND=true
START_COLLECTOR=false
USE_RELOAD=false

# Funções
print_help() {
    cat << EOF
${BLUE}SOC SMART Dashboard — Inicializador${NC}

${GREEN}Uso:${NC}
  ./start.sh [opções]

${GREEN}Opções:${NC}
  --help              Mostra esta mensagem
  --infra-only        Inicia apenas infra (Redis + PostgreSQL)
  --backend-only      Inicia apenas backend (uvicorn)
  --collector         Inicia coletor (APScheduler) em paralelo
  --reload            Backend com auto-reload (dev)
  --clean             Remove containers antigos e inicia do zero

${GREEN}Exemplos:${NC}
  ./start.sh                    # Tudo (infra + backend)
  ./start.sh --reload           # Dev com hot-reload
  ./start.sh --infra-only       # Só containers
  ./start.sh --backend-only     # Só uvicorn (infra já rodando)

${GREEN}Variáveis de ambiente:${NC}
  TENANT                Tenant a usar (default: salvador)
  V1_API_TOKEN         Token Vision One (obrigatório para coletor)

${YELLOW}Requisitos:${NC}
  • Docker + Docker Compose 2.0+
  • Python 3.9+
  • ~2GB RAM livres
  • Portas 8000, 5432, 6379 livres

EOF
}

print_section() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}▶ $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Parse argumentos
while [[ $# -gt 0 ]]; do
    case $1 in
        --help)
            print_help
            exit 0
            ;;
        --infra-only)
            START_BACKEND=false
            START_COLLECTOR=false
            shift
            ;;
        --backend-only)
            START_INFRA=false
            shift
            ;;
        --collector)
            START_COLLECTOR=true
            shift
            ;;
        --reload)
            USE_RELOAD=true
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        *)
            print_error "Opção desconhecida: $1"
            print_help
            exit 1
            ;;
    esac
done

# Validações iniciais
check_requirements() {
    print_section "Validando requisitos"

    if ! command -v docker &> /dev/null; then
        print_error "Docker não encontrado. Instale: https://docs.docker.com/install"
        exit 1
    fi
    print_success "Docker encontrado ($(docker --version))"

    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "Docker Compose não encontrado"
        exit 1
    fi
    print_success "Docker Compose encontrado"

    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 não encontrado"
        exit 1
    fi
    print_success "Python encontrado ($(python3 --version))"

    if [ ! -f "$PROJECT_ROOT/CLAUDE.md" ]; then
        print_error "Não está no diretório raiz do projeto"
        exit 1
    fi
    print_success "Localização correta: $PROJECT_ROOT"
}

# Setup infra
setup_infra() {
    if [ "$START_INFRA" != "true" ]; then
        return
    fi

    print_section "Iniciando infra (Redis + PostgreSQL)"

    cd "$INFRA_DIR"

    if [ "$CLEAN" = "true" ]; then
        print_warning "Limpando containers antigos..."
        docker-compose down -v 2>/dev/null || true
    fi

    if docker-compose ps | grep -q "db.*Up"; then
        print_info "PostgreSQL já rodando"
    else
        print_info "Iniciando PostgreSQL..."
        docker-compose up -d db
        sleep 3
    fi

    if docker-compose ps | grep -q "redis.*Up"; then
        print_info "Redis já rodando"
    else
        print_info "Iniciando Redis..."
        docker-compose up -d redis
        sleep 2
    fi

    print_success "Infra pronta"

    # Health check
    print_info "Health check..."
    if ! docker-compose exec -T db pg_isready -U socdash &> /dev/null; then
        print_warning "PostgreSQL não respondeu (pode estar inicializando)"
        sleep 3
    fi

    if ! docker-compose exec -T redis redis-cli ping &> /dev/null; then
        print_warning "Redis não respondeu"
    fi

    cd "$PROJECT_ROOT"
}

# Setup backend
setup_backend() {
    if [ "$START_BACKEND" != "true" ]; then
        return
    fi

    print_section "Inicializando backend"

    cd "$BACKEND_DIR"

    # Criar venv se não existe
    if [ ! -d "$VENV_DIR" ]; then
        print_info "Criando venv..."
        python3 -m venv "$VENV_DIR"
    fi

    # Ativar venv
    source "$VENV_DIR/bin/activate"
    print_success "venv ativado"

    # Instalar dependências
    if [ ! -f "$VENV_DIR/bin/uvicorn" ]; then
        print_info "Instalando dependências..."
        pip install -q -r requirements.txt
        print_success "Dependências instaladas"
    else
        print_info "Dependências já instaladas"
    fi

    # Preparar .env
    if [ ! -f ".env" ] && [ -f ".env.example" ]; then
        print_warning ".env não encontrado, copiando .env.example"
        cp .env.example .env
        print_info "Edite .env com seus valores antes de usar o coletor"
    fi

    # Iniciar uvicorn
    print_info "Iniciando uvicorn..."

    if [ "$USE_RELOAD" = "true" ]; then
        print_info "Modo dev (com auto-reload)"
        uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    else
        uvicorn app.main:app --host 0.0.0.0 --port 8000
    fi
}

# Setup coletor
setup_collector() {
    if [ "$START_COLLECTOR" != "true" ]; then
        return
    fi

    # Executar em background após o backend estar ready
    (
        sleep 5  # Dar tempo para backend iniciar
        print_section "Iniciando coletor"

        cd "$BACKEND_DIR"
        source "$VENV_DIR/bin/activate"

        if [ -z "$V1_API_TOKEN" ]; then
            print_warning "V1_API_TOKEN não definido — coletor não iniciará"
            print_info "Defina: export V1_API_TOKEN=seu_token"
            return
        fi

        python -m collectors.run
    ) &
}

# Main
main() {
    echo -e "\n${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     SOC SMART Dashboard — Sistema de inicialização    ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}\n"

    check_requirements

    setup_infra
    setup_collector
    setup_backend  # Deve ser último pois bloqueia
}

# Trap para limpar em caso de Ctrl+C
trap 'print_info "Shutting down..."; exit 0' INT TERM

# Executar
main "$@"
