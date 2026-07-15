"""Fábrica de conexão Redis (async), lendo REDIS_URL do config."""
import redis.asyncio as aioredis

from .config import settings


def get_redis() -> aioredis.Redis:
    return aioredis.from_url(settings.redis_url, decode_responses=True)
