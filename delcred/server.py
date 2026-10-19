"""`delcred serve` — minimal HTTP API for the exchange service (stdlib only).

Endpoints (JSON request/response):

    POST /exchange        RFC 8693-style exchange
      {"subject_token","actor_token","scope","resource",
       "requested_token_type"?, "ttl"?}
      → {"token_type","credential","claims","ttl"} | 403 {"error"}

    POST /verify          {"token","resource"?} → {"valid":true,"claims"} | 403
    POST /broker/redeem   {"key"} → {"valid":true,"capability"} | 403
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
from urllib.parse import urlparse

from . import _common as _c
from .audit import AuditLog
from .broker import Broker, BrokerError
from .exchange import ExchangeError, exchange
from .policy import PolicyError
from .revocation import RevocationList
from .tokens import TokenError


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
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return {}

    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if urlparse(self.path).path == "/health":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_json()
        if body is None:
            return  # error already sent
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
                claims = _verify(
                    body["token"],
                    expected_resource=body["resource"],
                    base=self.base,
                )
                self._send(200, {"valid": True, "claims": claims})
            elif path == "/broker/redeem":
                rec = Broker(self.base).redeem(body["key"])
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
