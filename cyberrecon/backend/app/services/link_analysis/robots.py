"""robots.txt parsing and an RFC 9309-style matcher (longest match wins, allow wins ties)."""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

UA_TOKEN = "cyberrecon"


@dataclass
class RobotsRule:
    type: str  # allow | disallow
    path: str


@dataclass
class RobotsGroup:
    agents: list[str]
    rules: list[RobotsRule] = field(default_factory=list)
    crawl_delay: float | None = None


@dataclass
class RobotsInfo:
    groups: list[RobotsGroup]
    sitemaps: list[str]

    def _group_for(self, token: str) -> RobotsGroup | None:
        token = token.lower()
        best, best_len = None, -1
        for g in self.groups:
            for a in g.agents:
                if a == "*":
                    if best is None:
                        best, best_len = g, 0
                elif a in token or token in a:
                    if len(a) > best_len:
                        best, best_len = g, len(a)
        return best

    def allowed(self, path_with_query: str, token: str = UA_TOKEN) -> bool:
        g = self._group_for(token)
        if g is None:
            return True
        best_len, verdict = -1, True
        for rule in g.rules:
            if not rule.path:  # "Disallow:" with empty value allows everything
                continue
            if _matches(rule.path, path_with_query):
                n = len(rule.path)
                if n > best_len or (n == best_len and rule.type == "allow"):
                    best_len, verdict = n, rule.type == "allow"
        return verdict


def _matches(pattern: str, path: str) -> bool:
    anchored = pattern.endswith("$")
    if anchored:
        pattern = pattern[:-1]
    regex = "^" + ".*".join(re.escape(p) for p in pattern.split("*"))
    if anchored:
        regex += "$"
    return re.match(regex, path) is not None


def parse_robots(text: str) -> RobotsInfo:
    groups: list[RobotsGroup] = []
    sitemaps: list[str] = []
    current: RobotsGroup | None = None
    last_was_agent = False
    for raw in text.splitlines()[:5000]:
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = (x.strip() for x in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            if not last_was_agent or current is None:
                current = RobotsGroup(agents=[])
                groups.append(current)
            current.agents.append(value.lower())
            last_was_agent = True
            continue
        last_was_agent = False
        if key == "sitemap":
            if value:
                sitemaps.append(value[:500])
        elif current is not None:
            if key in ("allow", "disallow"):
                current.rules.append(RobotsRule(key, value[:500]))
            elif key == "crawl-delay":
                try:
                    current.crawl_delay = float(value)
                except ValueError:
                    pass
    return RobotsInfo(groups=groups, sitemaps=sitemaps[:20])


def robots_summary(info: RobotsInfo, *, max_rules: int = 60) -> dict:
    groups = []
    for g in info.groups[:25]:
        groups.append({
            "user_agents": g.agents[:10],
            "allow": len([r for r in g.rules if r.type == "allow"]),
            "disallow": len([r for r in g.rules if r.type == "disallow" and r.path]),
            "crawl_delay": g.crawl_delay,
            "rules": [{"type": r.type, "path": r.path} for r in g.rules[:max_rules]],
        })
    return {"groups": groups, "sitemaps": info.sitemaps}


class RobotsCache:
    """Per-origin robots.txt cache so link checking honours robots restrictions."""

    def __init__(self, fetcher):
        self.fetcher = fetcher
        self._cache: dict[str, RobotsInfo | None] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self.fetched = 0

    def seed(self, origin: str, info: RobotsInfo | None) -> None:
        self._cache[origin] = info

    async def allowed(self, url: str) -> bool:
        sp = urlsplit(url)
        origin = f"{sp.scheme}://{sp.netloc}"
        if origin not in self._cache:
            lock = self._locks.setdefault(origin, asyncio.Lock())
            async with lock:
                if origin not in self._cache:
                    self._cache[origin] = await self._load(origin)
        info = self._cache[origin]
        if info is None:
            return True
        path = (sp.path or "/") + (("?" + sp.query) if sp.query else "")
        return info.allowed(path)

    async def _load(self, origin: str) -> RobotsInfo | None:
        try:
            self.fetched += 1
            res = await self.fetcher.fetch(origin + "/robots.txt", max_bytes=200_000, scope_host=urlsplit(origin).hostname, accept="text/plain,*/*;q=0.5")
        except Exception:
            return None  # unreachable robots.txt -> treated as no restrictions (RFC 9309 allows this for 4xx; errors are logged elsewhere)
        if res.status != 200:
            return None
        return parse_robots(res.body.decode("utf-8", "replace"))
