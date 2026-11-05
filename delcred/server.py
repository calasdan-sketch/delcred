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
    GET  /.well-known/jwks.json  → issuer public key (RFC 7517 JWK Set)
    POST /revoke          {"jti"?,"agent"?,"user"?,"reason"?} → {"revoked":true}
    GET  /health          → {"status":"ok"}

Security notes: bind to localhost by default; put TLS + auth in front for
anything beyond a dev box. The API never returns secrets except the freshly
minted credential in /exchange (unavoidable — that IS the product).
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import _common as _c
from .audit import AuditLog
from .broker import Broker, BrokerError
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
}


class _Handler(BaseHTTPRequestHandler):
    base: Path  # set by serve()

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
        else:
            self._send(404, {"error": "not found"})

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
        try:
            result = exchange(
                subject_token=body["subject_token"],
                actor_token=body["actor_token"],
                scope=body["scope"],
                resource=body["resource"],
                requested_token_type=requested,
                ttl=ttl,
                base=self.base,
            )
        except PolicyError as e:
            return err(_POLICY_TO_OAUTH.get(getattr(e, "code", "request"), "invalid_request"), str(e))
        except ExchangeError as e:
            return err("invalid_grant", str(e))
        self._send(
            200,
            {
                "access_token": result.credential,
                "issued_token_type": result.token_type,
                "token_type": "Bearer",
                "expires_in": result.ttl,
                "scope": result.claims.get("scope", ""),
            },
            headers={"Pragma": "no-cache"},
        )

    def do_POST(self):
        path = urlparse(self.path).path
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
                rec = Broker(self.base).redeem(
                    body["key"],
                    expected_resource=body.get("resource") or None,
                    required_scopes=body.get("scope") or None,
                )
                self._send(200, {"valid": True, "capability": rec})
            elif path == "/revoke":
                rl = RevocationList(self.base)
                reason = body.get("reason", "")
                if body.get("jti"):
                    rl.revoke_jti(body["jti"], reason=reason)
                elif body.get("agent"):
                    rl.revoke_agent(body["agent"], reason=reason)
                elif body.get("user"):
                    rl.revoke_user(body["user"], reason=reason)
                else:
                    self._send(400, {"error": "need jti, agent, or user"})
                    return
                AuditLog(self.base).record(
                    "api_revoke",
                    **{k: body[k] for k in ("jti", "agent", "user") if body.get(k)},
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


def serve(port: int = 8400, host: str = "127.0.0.1", base: Path | None = None) -> None:
    base = base or _c.home()
    _Handler.base = base
    httpd = HTTPServer((host, port), _Handler)
    print(
        f"delcred serve on http://{host}:{port} (localhost only — "
        f"put TLS+auth in front for shared networks)"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
