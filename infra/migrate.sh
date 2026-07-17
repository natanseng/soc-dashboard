#!/usr/bin/env bash
# =====================================================================================
# infra/migrate.sh  |  Runner minimo de migrations com controle de versao
# -------------------------------------------------------------------------------------
# - Tabela de controle: schema_migrations (version, checksum, applied_at).
# - Aplica em ordem os arquivos infra/migrations/*.sql ainda nao registrados.
# - Cada migration roda em UMA transacao (BEGIN; <arquivo>; INSERT registro; COMMIT).
# - RECUSA aplicar/registrar uma migration ja registrada com CHECKSUM DIFERENTE
#   (migrations aplicadas sao imutaveis; mudancas usam 002_*, 003_*...).
# - Idempotente: migration ja aplicada com mesmo checksum = SKIP.
# - NAO aplica seeds (infra/seeds/*) — dados de ambiente sao aplicados a parte.
#
# Uso (producao):
#   PSQL="psql postgresql://socdash:***@localhost:5432/socdash" ./infra/migrate.sh
# Uso (via container, ex. testes):
#   PSQL="docker exec -i infra-db-1 psql -U socdash -d cyber_migtest" ./infra/migrate.sh
# Variaveis:
#   PSQL  comando psql base (default: "psql"); deve aceitar -c e stdin.
#   DIR   diretorio de migrations (default: <dir do script>/migrations)
# Saidas de erro: exit 3 = checksum divergente.
# =====================================================================================
set -euo pipefail

DIR="${DIR:-$(cd "$(dirname "$0")" && pwd)/migrations}"
PSQL="${PSQL:-psql}"

run(){ $PSQL -v ON_ERROR_STOP=1 -q "$@"; }
scalar(){ $PSQL -tA -c "$1" | tr -d '[:space:]'; }

# bootstrap da tabela de controle (fora da transacao das migrations)
run -c "CREATE TABLE IF NOT EXISTS schema_migrations (
          version    text        PRIMARY KEY,
          checksum   text        NOT NULL,
          applied_at timestamptz NOT NULL DEFAULT now());"

shopt -s nullglob
applied=0; skipped=0
for f in "$DIR"/*.sql; do
    version="$(basename "$f" .sql)"
    checksum="$(sha256sum "$f" | awk '{print $1}')"
    registered="$(scalar "SELECT checksum FROM schema_migrations WHERE version = '${version}';")"

    if [ -n "$registered" ]; then
        if [ "$registered" = "$checksum" ]; then
            echo "SKIP   $version (ja aplicada; checksum confere)"
            skipped=$((skipped+1)); continue
        fi
        echo "ERRO   $version ja registrada com checksum DIFERENTE." >&2
        echo "       registrado=$registered" >&2
        echo "       arquivo=   $checksum" >&2
        echo "       Migrations aplicadas sao imutaveis. Crie 002_*, 003_*..." >&2
        exit 3
    fi

    echo "APLICA $version ..."
    { echo "BEGIN;"
      cat "$f"
      echo                 # garante newline apos o arquivo (evita comentar/concatenar o INSERT)
      echo "INSERT INTO schema_migrations (version, checksum) VALUES ('${version}', '${checksum}');"
      echo "COMMIT;"
    } | run
    echo "OK     $version"
    applied=$((applied+1))
done

echo "migrate: concluido (aplicadas=$applied, ignoradas=$skipped)."
