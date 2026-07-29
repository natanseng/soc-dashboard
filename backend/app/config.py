"""Configuração central — lê tudo do .env (case-insensitive)."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Vision One
    v1_api_base: str = "https://api.xdr.trendmicro.com"
    v1_api_token: str = ""
    tenant: str = "prodesp-sp"
    # Tokens dos tenants secundarios do Dashboard multi-tenant (so a tela Dashboard)
    v1_api_token_detran: str = ""
    v1_api_token_iamspe: str = ""
    # Console SGGD — Cyber Risk Subindexes (SGGD/PGE/CGE/SPPREV/SGRI) por tag
    v1_api_token_sggd: str = ""
    # Tenants adicionais (2026-07-21): Poupatempo, SPI, Alesp, CPTM
    v1_api_token_poupatempo: str = ""
    v1_api_token_spi: str = ""
    v1_api_token_alesp: str = ""
    v1_api_token_cptm: str = ""
    # Cliente separado (fora da familia Prodesp): Prefeitura de Salvador — perfil proprio ?profile=salvador
    v1_api_token_salvador: str = ""

    # Infra
    redis_url: str = "redis://localhost:6379/0"
    db_dsn: str = ""

    # PostgreSQL pool (Fase Cyber — leitura do cadastro). Aditivo; NAO afeta a Fase 1.
    db_pool_min: int = 1              # conexoes minimas do pool
    db_pool_max: int = 5             # conexoes maximas do pool
    db_pool_acquire_timeout: float = 10.0   # s p/ obter conexao do pool
    db_connect_timeout: float = 5.0         # s p/ estabelecer o pool no startup
    db_command_timeout: float = 10.0        # s por comando SQL
    db_healthcheck_timeout: float = 2.0     # teto do probe de saude do PG (protege o /healthz)
    # Override opcional tenant_id -> nome da variavel de token (JSON). Vazio = convencao.
    cyber_token_env_map: str = ""

    # Attack Map (opcional)
    geoip_db: str = "data/GeoLite2-City.mmdb"

    # Cadência dos tiers (segundos)
    tier1_interval: int = 60
    tier2_interval: int = 300
    tier3_interval: int = 900
    tier4_interval: int = 3600


settings = Settings()
