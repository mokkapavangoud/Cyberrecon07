"""Small in-process sliding-window rate limiter keyed by client address.

Limits: it is per-process memory, so with several workers each has its own counter. Put a reverse proxy / API gateway
rate limit in front for real deployments (see docs/SECURITY.md).
"""
from __future__ import annotations

import time
from collections import deque


class RateLimiter:
    def __init__(self, limit_per_minute: int, window: float = 60.0, max_keys: int = 10_000):
        self.limit, self.window, self.max_keys = limit_per_minute, window, max_keys
        self._hits: dict[str, deque[float]] = {}

    def check(self, key: str) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds)."""
        if self.limit <= 0:
            return True, 0
        now = time.monotonic()
        q = self._hits.get(key)
        if q is None:
            if len(self._hits) >= self.max_keys:  # bound memory under address-spraying
                self._evict(now)
            q = self._hits.setdefault(key, deque())
        while q and now - q[0] >= self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False, max(1, int(self.window - (now - q[0])) + 1)
        q.append(now)
        return True, 0

    def _evict(self, now: float) -> None:
        for k in [k for k, q in self._hits.items() if not q or now - q[-1] >= self.window]:
            del self._hits[k]
        if len(self._hits) >= self.max_keys:
            self._hits.clear()
