from cachetools import TTLCache
import pytest
from flask_oidc_verifier.caches import RedisCache


@pytest.fixture  # type: ignore
def default_cache() -> TTLCache:  # type: ignore
    return TTLCache(maxsize=10, ttl=60 * 10)


@pytest.fixture  # type: ignore
def redis_cache() -> RedisCache:
    return RedisCache(host="localhost", port=6379)
