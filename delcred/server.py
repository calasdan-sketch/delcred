"""`delcred serve` — minimal HTTP API for the exchange service (stdlib only).

Endpoints (JSON request/response):

    POST /exchange        RFC 8693-style exchange
      {"subject_token","actor_token","scope","resource",
       "requested_token_type"?, "ttl"?}
      → {"token_type","credential","claims","ttl"} | 403 {"error"}

    POST /token           RFC 8693 §2 token exchange, form-encoded
      grant_type=urn:ietf:params:oauth:grant-type:token-exchange
      &subject_token=…&subject_token_type=…&actor_token=…&actor_token_type=…
      &scope=…&resource=…[&requested_token_type=…]
      → 200 {"access_token","issued_token_type","token_type":"Bearer",
             "expires_in","scope"} | 400 {"error","error_description"}

    POST /verify          {"token","resource","scope"?} → {"valid":true,"claims"}
                          | 403 {"error"[,"missing"]}
    POST /broker/redeem   {"key","resource"?,"scope"?} → {"valid":true,"capability"} | 403
    GET  /.well-known/jwks.json  → issuer public key(s) (RFC 7517 JWK Set; includes
                                   retired keys still inside their overlap window)
    GET  /revocations.jwt → signed revocation bulletin (application/jwt) for
                            third-party verifiers (see delcred.offline)
    POST /revoke          {"jti"?,"agent"?,"user"?,"issuer"?,"reason"?} → {"revoked":true}
                          requires ``Authorization: Bearer <admin token>`` when an
                          admin token is configured, else loopback clients only
    GET  /.well-known/oauth-authorization-server  → RFC 8414 metadata
    GET  /health          → {"status":"ok"}

Security notes: bind to localhost by default; put TLS + auth in front for
anything beyond a dev box. Requests are served on threads with a 10 s socket
timeout (one slow client cannot freeze the server), and ``/token``,
``/exchange`` and ``/revoke`` are rate-limited per client IP (HTTP 429). The API never returns secrets except the freshly
minted credential in /exchange (unavoidable — that IS the product).
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import _common as _c
from .audit import AuditLog
from .broker import Broker, BrokerError, BrokerScopeError
from .exchange import (
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_BROKER_KEY,
    TOKEN_TYPE_JWT,
    ExchangeError,
    exchange,
)
from .keys import jwks as _jwks
from .mcp import www_authenticate
from .policy import PolicyError
from .revocation import RevocationList
from .tokens import InsufficientScope, TokenError

GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
# Input token types accepted on /token (RFC 8693 §3).
_ACCEPTED_INPUT_TYPES = {TOKEN_TYPE_JWT, TOKEN_TYPE_ACCESS, "urn:ietf:params:oauth:token-type:id_token"}
_POLICY_TO_OAUTH = {
    "no_grant": "invalid_grant",
    "scope": "invalid_scope",
    "resource": "invalid_target",
    "request": "invalid_request",
    "delegation": "invalid_grant",
}


# Revocation fields are identifiers, not documents: cap them so /revoke
# cannot be used to grow the revocation file with huge rows.
MAX_ID_LEN = 256
MAX_REASON_LEN = 512
RATE_LIMITED_PATHS = frozenset({"/token", "/exchange", "/revoke"})


class RateLimiter:
    """Per-key token bucket (thread-safe, bounded memory).

    ``rate`` requests per ``per`` seconds, with bursts up to ``rate``.
    At most ``max_keys`` clients are tracked (least recently seen evicted).
    """

    def __init__(self, rate: int = 60, per: float = 60.0, max_keys: int = 10_000):
        if rate <= 0 or per <= 0:
            raise ValueError("rate and per must be positive")
        self.rate = float(rate)
        self.per = float(per)
        self.max_keys = max_keys
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.pop(key, (self.rate, now))
            tokens = min(self.rate, tokens + (now - last) * self.rate / self.per)
            ok = tokens >= 1.0
            if ok:
                tokens -= 1.0
            self._buckets[key] = (tokens, now)
            while len(self._buckets) > self.max_keys:
                self._buckets.popitem(last=False)
            retry = 0 if ok else max(1, int((1.0 - tokens) * self.per / self.rate + 0.999))
            return ok, retry


def _is_loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr.split("%")[0]).is_loopback
    except ValueError:
        return False


class _Handler(BaseHTTPRequestHandler):
    base: Path  # set by serve()
    # Socket timeout for every read/write: a client that sends headers and
    # then stalls is dropped after this many seconds.
    timeout = 10
    rate_limiter: RateLimiter | None = None  # set by serve()
    admin_token: str | None = None  # set by serve(); guards /revoke
    public_url: str | None = None  # issuer URL for RFC 8414 metadata

    # Exchange payloads are small JWTs; cap the body so a malicious client
    # cannot make the (localhost) server buffer gigabytes.
    MAX_BODY_BYTES = 1024 * 1024

    def log_message(self, *a):  # keep stdout clean; audit log is the record
        pass

    def _read_json(self) -> dict | None:
        """Read a JSON body. Returns None after responding with an error."""
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            self._send(400, {"error": "bad Content-Length"})
            return None
        if length > self.MAX_BODY_BYTES:
            self._send(413, {"error": "request body too large"})
            return None
        if length < 0:
            self._send(400, {"error": "bad Content-Length"})
            return None
        if not length:
            return {}
        raw = self.rfile.read(length) or b""
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype == "application/x-www-form-urlencoded":
            try:
                form = parse_qs(raw.decode("utf-8"), keep_blank_values=True, strict_parsing=False)
            except UnicodeDecodeError:
                self._send(400, {"error": "invalid_request", "error_description": "body is not UTF-8"})
                return None
            # RFC 6749 §3.2: parameters MUST NOT be repeated.
            if any(len(v) > 1 for v in form.values()):
                self._send(400, {"error": "invalid_request", "error_description": "repeated parameter"})
                return None
            return {k: v[0] for k, v in form.items()}
        try:
            data = json.loads(raw or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
        if not isinstance(data, dict):
            self._send(400, {"error": "JSON body must be an object"})
            return None
        return data

    def _send(self, code: int, obj: dict, headers: dict | None = None) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Responses may carry fresh credentials: never cache (RFC 6749 §5.1).
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            self._send(200, {"status": "ok"})
        elif path == "/.well-known/jwks.json":
            self._send(200, _jwks(self.base))
        elif path == "/.well-known/oauth-authorization-server":
            self._send(200, self._as_metadata())
        elif path == "/revocations.jwt":
            from . import bulletin as _bulletin

            body = _bulletin.export(self.base).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/jwt")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send(404, {"error": "not found"})

    def _base_url(self) -> str:
        if self.public_url:
            return self.public_url.rstrip("/")
        host, port = self.server.server_address[:2]
        if ":" in str(host):
            host = f"[{host}]"
        return f"http://{host}:{port}"

    def _as_metadata(self) -> dict:
        """RFC 8414 authorization-server metadata so OAuth/MCP clients can
        discover ``/token``. Note: the ``iss`` claim inside delcred tokens is
        ``"delcred"``, not this URL (see README Limitations)."""
        u = self._base_url()
        return {
            "issuer": u,
            "token_endpoint": u + "/token",
            "jwks_uri": u + "/.well-known/jwks.json",
            "grant_types_supported": [GRANT_TOKEN_EXCHANGE],
            "dpop_signing_alg_values_supported": ["EdDSA"],
            "delcred_revocations_uri": u + "/revocations.jwt",
            "token_endpoint_auth_methods_supported": ["none"],
            "response_types_supported": [],
            "delcred_token_issuer": _c.ISSUER_ID,
        }

    def _rate_limited(self, path: str) -> bool:
        if self.rate_limiter is None or path not in RATE_LIMITED_PATHS:
            return False
        ok, retry = self.rate_limiter.allow(self.client_address[0])
        if ok:
            return False
        self._send(
            429,
            {"error": "slow_down", "error_description": "rate limit exceeded"},
            headers={"Retry-After": str(retry)},
        )
        return True

    def _revoke_authorized(self) -> bool:
        if self.admin_token:
            from .mcp import bearer_token

            got = bearer_token(self.headers.get("Authorization")) or ""
            if hmac.compare_digest(got.encode(), self.admin_token.encode()):
                return True
            self._send(
                401, {"error": "admin token required"},
                headers={"WWW-Authenticate": 'Bearer realm="delcred-admin"'},
            )
            return False
        if _is_loopback(self.client_address[0]):
            return True
        self._send(403, {"error": "/revoke is loopback-only without an admin token"})
        return False

    def _token_endpoint(self, body: dict) -> None:
        """RFC 8693 §2.1/2.2 — standard request and response shapes."""

        def err(code: str, desc: str) -> None:
            self._send(400, {"error": code, "error_description": desc})

        if body.get("grant_type") != GRANT_TOKEN_EXCHANGE:
            return self._send(
                400,
                {"error": "unsupported_grant_type", "error_description": "token-exchange only"},
            )
        for name in ("subject_token", "subject_token_type", "actor_token", "actor_token_type", "scope", "resource"):
            if not isinstance(body.get(name), str) or not body.get(name):
                return err("invalid_request", f"missing parameter: {name}")
        for name in ("subject_token_type", "actor_token_type"):
            if body[name] not in _ACCEPTED_INPUT_TYPES:
                return err("invalid_request", f"unsupported {name}")
        requested = body.get("requested_token_type") or TOKEN_TYPE_ACCESS
        if requested not in (TOKEN_TYPE_ACCESS, TOKEN_TYPE_JWT, TOKEN_TYPE_BROKER_KEY):
            return err("invalid_request", "unsupported requested_token_type")
        try:
            ttl = int(body.get("ttl") or _c.DEFAULT_TTL)
        except (TypeError, ValueError):
            return err("invalid_request", "ttl must be an integer")
        dpop_header = self.headers.get("DPoP")
        dpop_jkt = body.get("dpop_jkt")
        if dpop_jkt is not None and not isinstance(dpop_jkt, str):
            return err("invalid_request", "dpop_jkt must be a string")
        if dpop_header and dpop_jkt:
            return err("invalid_dpop_proof", "send a DPoP header or dpop_jkt, not both")
        try:
            result = exchange(
                subject_token=body["subject_token"],
                actor_token=body["actor_token"],
                scope=body["scope"],
                resource=body["resource"],
                requested_token_type=requested,
                ttl=ttl,
                dpop_jkt=dpop_jkt or None,
                dpop_proof=dpop_header or None,
                dpop_url=self._base_url() + "/token",
                base=self.base,
            )
        except PolicyError as e:
            return err(_POLICY_TO_OAUTH.get(getattr(e, "code", "request"), "invalid_request"), str(e))
        except ExchangeError as e:
            code = "invalid_dpop_proof" if "DPoP proof" in str(e) else "invalid_grant"
            return err(code, str(e))
        self._send(
            200,
            {
                "access_token": result.credential,
                "issued_token_type": result.token_type,
                "token_type": "DPoP" if result.claims.get("cnf") else "Bearer",
                "expires_in": result.ttl,
                "scope": result.claims.get("scope", ""),
            },
            headers={"Pragma": "no-cache"},
        )

    def do_POST(self):
        path = urlparse(self.path).path
        if self._rate_limited(path):
            return
        if path == "/revoke" and not self._revoke_authorized():
            return
        body = self._read_json()
        if body is None:
            return  # error already sent
        if path == "/token":
            self._token_endpoint(body)
            return
        try:
            if path == "/exchange":
                try:
                    ttl = int(body.get("ttl", _c.DEFAULT_TTL))
                except (TypeError, ValueError):
                    self._send(400, {"error": "ttl must be an integer"})
                    return
                result = exchange(
                    subject_token=body["subject_token"],
                    actor_token=body["actor_token"],
                    scope=body["scope"],
                    resource=body["resource"],
                    requested_token_type=body.get(
                        "requested_token_type",
                        "urn:ietf:params:oauth:token-type:jwt",
                    ),
                    ttl=ttl,
                    dpop_jkt=body.get("dpop_jkt") or None,
                    base=self.base,
                )
                self._send(
                    200,
                    {
                        "token_type": result.token_type,
                        "credential": result.credential,
                        "claims": result.claims,
                        "ttl": result.ttl,
                    },
                )
            elif path == "/verify":
                from .exchange import verify as _verify

                if not body.get("resource"):
                    self._send(
                        400, {"error": "resource is required (audience pinning)"}
                    )
                    return
                try:
                    claims = _verify(
                        body["token"],
                        expected_resource=body["resource"],
                        required_scopes=body.get("scope") or None,
                        base=self.base,
                        dpop_proof=self.headers.get("DPoP") or None,
                        http_method=body.get("http_method") or None,
                        http_url=body.get("http_url") or None,
                    )
                except InsufficientScope as e:
                    self._send(
                        403,
                        {"error": "insufficient_scope", "missing": e.missing},
                        headers={
                            "WWW-Authenticate": www_authenticate(
                                error="insufficient_scope", scope=e.required
                            )
                        },
                    )
                    return
                self._send(200, {"valid": True, "claims": claims})
            elif path == "/broker/redeem":
                try:
                    rec = Broker(self.base).redeem(
                        body["key"],
                        expected_resource=body.get("resource") or None,
                        required_scopes=body.get("scope") or None,
                    )
                except BrokerScopeError as e:
                    self._send(
                        403,
                        {"error": "insufficient_scope", "missing": e.missing},
                        headers={
                            "WWW-Authenticate": www_authenticate(
                                error="insufficient_scope", scope=e.required
                            )
                        },
                    )
                    return
                self._send(200, {"valid": True, "capability": rec})
            elif path == "/revoke":
                rl = RevocationList(self.base)
                reason = body.get("reason", "") or ""
                fields = {k: body.get(k) for k in ("jti", "agent", "user", "issuer")}
                for k, v in fields.items():
                    if v is not None and (not isinstance(v, str) or len(v) > MAX_ID_LEN):
                        self._send(400, {"error": f"{k} must be a string of at most {MAX_ID_LEN} chars"})
                        return
                if not isinstance(reason, str) or len(reason) > MAX_REASON_LEN:
                    self._send(400, {"error": f"reason must be a string of at most {MAX_REASON_LEN} chars"})
                    return
                if body.get("jti"):
                    rl.revoke_jti(body["jti"], reason=reason)
                elif body.get("agent"):
                    rl.revoke_agent(body["agent"], reason=reason)
                elif body.get("user"):
                    rl.revoke_user(body["user"], reason=reason, issuer=body.get("issuer") or None)
                else:
                    self._send(400, {"error": "need jti, agent, or user"})
                    return
                AuditLog(self.base).record(
                    "api_revoke",
                    **{k: body[k] for k in ("jti", "agent", "user", "issuer") if body.get(k)},
                )
                self._send(200, {"revoked": True})
            else:
                self._send(404, {"error": "not found"})
        except KeyError as e:
            self._send(400, {"error": f"missing field: {e}"})
        except (ExchangeError, PolicyError, TokenError, BrokerError) as e:
            self._send(403, {"error": str(e)})
        except (TypeError, ValueError) as e:
            self._send(400, {"error": f"bad request: {type(e).__name__}"})


def make_server(
    port: int = 8400,
    host: str = "127.0.0.1",
    base: Path | None = None,
    *,
    rate: int = 60,
    admin_token: str | None = None,
    public_url: str | None = None,
) -> ThreadingHTTPServer:
    """Build (but do not start) the threaded exchange server."""
    base = base or _c.home()
    handler = type(
        "_BoundHandler",
        (_Handler,),
        {
            "base": base,
            "rate_limiter": RateLimiter(rate=rate) if rate > 0 else None,
            "admin_token": admin_token or os.environ.get("DELCRED_ADMIN_TOKEN") or None,
            "public_url": public_url,
        },
    )
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    return httpd


def serve(
    port: int = 8400,
    host: str = "127.0.0.1",
    base: Path | None = None,
    *,
    rate: int = 60,
    admin_token: str | None = None,
    public_url: str | None = None,
) -> None:
    httpd = make_server(
        port, host, base, rate=rate, admin_token=admin_token, public_url=public_url
    )
    print(
        f"delcred serve on http://{host}:{port} (localhost only — "
        f"put TLS+auth in front for shared networks)"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
