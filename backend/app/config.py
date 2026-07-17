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

    # Infra
    redis_url: str = "redis://localhost:6379/0"
    db_dsn: str = ""

    # Attack Map (opcional)
    geoip_db: str = "data/GeoLite2-City.mmdb"

    # Cadência dos tiers (segundos)
    tier1_interval: int = 60
    tier2_interval: int = 300
    tier3_interval: int = 900
    tier4_interval: int = 3600


settings = Settings()
