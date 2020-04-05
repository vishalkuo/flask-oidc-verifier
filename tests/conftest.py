from cachetools import TTLCache
import pytest
from flask_oidc_verifier.caches import RedisCache
import typing as t


@pytest.fixture  # type: ignore
def default_cache() -> TTLCache:  # type: ignore
    return TTLCache(maxsize=10, ttl=60 * 10)


@pytest.fixture  # type: ignore
def redis_cache() -> RedisCache:
    return RedisCache(conn_url="redis://localhost:6379/0")


@pytest.fixture  # type: ignore
def reset_redis() -> t.Callable[[], None]:
    import redis

    def reset() -> None:
        client = redis.Redis(host="localhost", port=6379)
        client.flushall()

    return reset
