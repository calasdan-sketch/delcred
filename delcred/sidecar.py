"""`delcred sidecar` — forward proxy that injects delegation credentials.

The agent never touches a token. It makes plain HTTP calls to
``http://localhost:8080`` with a target upstream; the sidecar mints (and
caches) a delegation credential for that upstream's configured
(scope, resource) and injects ``Authorization: Bearer …``.

Mapping: ``upstream_host = "scope|resource[|api-key]"`` — append
``|api-key`` to inject an opaque broker key instead of a JWT. The
delegation's user/agent come from the sidecar's own --user-token /
--agent-token; the mapping only declares what each upstream may receive.

The sidecar holds the user/actor tokens in memory only. Cache entries are
refreshed 60s before expiry. This is the recommended deployment pattern:
blast radius of a compromised agent = what the sidecar will mint for it,
which is exactly its policy grant — nothing more.
"""

from __future__ import annotations

import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.parse import urlparse

from . import _common as _c
from .broker import Broker
from .exchange import TOKEN_TYPE_BROKER_KEY, ExchangeError, exchange
from .policy import PolicyError
from .revocation import RevocationList
from .tokens import ExpiredToken, InvalidToken, TokenError, verify_signature


class _CacheEntry:
    def __init__(self, credential: str, expires_at: int, kind: str = "jwt"):
        self.credential = credential
        self.expires_at = expires_at
        self.kind = kind  # "jwt" or "broker-key"


class _ProxyHandler(BaseHTTPRequestHandler):
    mapping: ClassVar[dict[str, str]] = {}
    user_token: ClassVar[str] = ""
    agent_token: ClassVar[str] = ""
    base: ClassVar[Path | None] = None
    _cache: ClassVar[dict[str, _CacheEntry]] = {}
    _lock = threading.Lock()
    timeout = 10  # drop clients that stall mid-request

    def log_message(self, *a):
        pass

    @classmethod
    def _cache_valid(cls, entry: _CacheEntry) -> bool:
        """Finding #3: a cache hit is a performance shortcut, not a trust
        decision — re-verify signature, expiry, and revocation every time."""
        if entry.expires_at - 60 < int(time.time()):
            return False
        if entry.kind == "broker-key":
            return Broker(cls.base).check(entry.credential)
        try:
            claims = verify_signature(entry.credential, base=cls.base)
        except (InvalidToken, ExpiredToken):
            return False
        revoked, _ = RevocationList(cls.base).is_revoked(claims)
        return not revoked

    @classmethod
    def _credential_for(cls, upstream: str) -> str:
        now = int(time.time())
        with cls._lock:
            hit = cls._cache.get(upstream)
            if hit is not None and cls._cache_valid(hit):
                return hit.credential
        # Pipe-delimited so scopes/resources may contain colons:
        #   "scope|resource[|api-key]"
        # The delegation's user/agent come from the sidecar's own tokens —
        # the mapping only declares what each upstream may receive.
        parts = cls.mapping[upstream].split("|")
        as_key = parts[-1] == "api-key"
        if as_key:
            parts = parts[:-1]
        if len(parts) != 2:
            raise ValueError(
                f"bad sidecar mapping for {upstream!r}: want 'scope|resource[|api-key]'"
            )
        scope, resource = parts
        result = exchange(
            subject_token=cls.user_token,
            actor_token=cls.agent_token,
            scope=scope,
            resource=resource,
            requested_token_type=(
                TOKEN_TYPE_BROKER_KEY
                if as_key
                else "urn:ietf:params:oauth:token-type:jwt"
            ),
            ttl=900,
            base=cls.base,
        )
        # Finding #4: single-use credentials must never be cached — the
        # upstream's first verify burns the jti and every later request
        # would fail.
        if not result.claims.get("single_use"):
            with cls._lock:
                cls._cache[upstream] = _CacheEntry(
                    result.credential,
                    now + result.ttl,
                    kind="broker-key" if as_key else "jwt",
                )
        return result.credential

    def _proxy(self):
        target = self.headers.get("X-Delcred-Upstream") or urlparse(self.path).netloc
        if not target or target not in self.mapping:
            self.send_error(403, "upstream not allowlisted in sidecar mapping")
            return
        try:
            credential = self._credential_for(target)
        except (ExchangeError, PolicyError, TokenError, ValueError) as e:
            # policy denial etc. → 403, never leak internals
            self.send_error(403, f"delegation failed: {type(e).__name__}")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else None
        # Rebuild the upstream URL: path may be origin-form (proxy request).
        parsed = urlparse(self.path)
        if parsed.scheme:
            url = self.path
        else:
            url = f"https://{target}{parsed.path}"
            if parsed.query:
                url += "?" + parsed.query
        req = urllib.request.Request(url, data=body, method=self.command)
        for k, v in self.headers.items():
            kl = k.lower()
            if kl in (
                "host",
                "content-length",
                "x-delcred-upstream",
                "proxy-connection",
                "connection",
            ):
                continue
            req.add_header(k, v)
        req.add_header("Authorization", f"Bearer {credential}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    if k.lower() not in (
                        "content-length",
                        "transfer-encoding",
                        "connection",
                    ):
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except (OSError, urllib.error.URLError) as e:
            self.send_error(502, f"upstream error: {type(e).__name__}")

    do_GET = _proxy
    do_POST = _proxy
    do_PUT = _proxy
    do_PATCH = _proxy
    do_DELETE = _proxy


def run_sidecar(
    port: int = 8080,
    mapping: dict | None = None,
    user_token: str = "",
    agent_token: str = "",
    host: str = "127.0.0.1",
    base: Path | None = None,
) -> None:
    base = base or _c.home()
    _ProxyHandler.mapping = mapping or {}
    _ProxyHandler.user_token = user_token
    _ProxyHandler.agent_token = agent_token
    _ProxyHandler.base = base
    httpd = ThreadingHTTPServer((host, port), _ProxyHandler)
    httpd.daemon_threads = True
    print(
        f"delcred sidecar on http://{host}:{port} "
        f"({len(_ProxyHandler.mapping)} upstream(s) allowlisted)"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
