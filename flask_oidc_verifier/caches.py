import typing as t
import pickle
from typing_extensions import Protocol


class Cache(Protocol):
    def get(self, key: str, default: t.Optional[t.Any] = None) -> t.Any:  # type: ignore
        ...

    def __setitem__(self, key: str, item: t.Any) -> None:  # type: ignore
        ...


class RedisCache:
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        password: t.Optional[str] = None,
        db: int = 0,
        ttl_s: int = 60 * 10,
        conn_url: t.Optional[str] = None,
    ) -> None:
        import redis

        if conn_url is not None:
            self.client = redis.Redis.from_url(conn_url, db=db)
        else:
            self.client = redis.Redis(host=host, port=port, password=password, db=db)
        self.ttl_s = ttl_s

    def get(self, key: str, default: t.Optional[t.Any] = None) -> t.Any:  # type: ignore
        res_bytes = self.client.get(key)
        if res_bytes is None:
            return default

        return pickle.loads(res_bytes)

    def __setitem__(self, key: str, item: t.Any) -> None:  # type: ignore
        serialized = pickle.dumps(item)
        self.client.set(key, serialized, ex=self.ttl_s)
