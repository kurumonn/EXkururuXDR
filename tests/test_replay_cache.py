from __future__ import annotations

from exkururuxdr.replay_cache import ReplayCache


class _FakeRedis:
    def __init__(self, clock):
        self._clock = clock
        self._values: dict[str, float] = {}

    def set(self, key, value, nx=False, ex=None):
        now = float(self._clock())
        current = self._values.get(key)
        if nx and current is not None and current > now:
            return False
        self._values[key] = now + float(ex or 0)
        return True


class _BrokenRedis:
    def set(self, key, value, nx=False, ex=None):  # pragma: no cover - exercised by the test
        raise RuntimeError("redis unavailable")


def test_replay_cache_uses_shared_redis_state() -> None:
    clock = lambda: 1000.0
    fake_redis = _FakeRedis(clock)
    cache1 = ReplayCache(
        namespace="xdr",
        backend="redis",
        redis_url="redis://example.invalid/0",
        fallback_to_memory=True,
        max_items=10,
        default_ttl_sec=60,
        redis_client_factory=lambda: fake_redis,
        clock=clock,
    )
    cache2 = ReplayCache(
        namespace="xdr",
        backend="redis",
        redis_url="redis://example.invalid/0",
        fallback_to_memory=True,
        max_items=10,
        default_ttl_sec=60,
        redis_client_factory=lambda: fake_redis,
        clock=clock,
    )
    assert cache1.add("shared-key", ttl_sec=60) is True
    assert cache2.add("shared-key", ttl_sec=60) is False


def test_replay_cache_falls_back_to_memory_on_redis_failure() -> None:
    clock = lambda: 1000.0
    cache = ReplayCache(
        namespace="xdr",
        backend="redis",
        redis_url="redis://example.invalid/0",
        fallback_to_memory=True,
        max_items=10,
        default_ttl_sec=60,
        redis_client_factory=lambda: _BrokenRedis(),
        clock=clock,
    )
    assert cache.add("fallback-key", ttl_sec=60) is True
    assert cache.add("fallback-key", ttl_sec=60) is False
