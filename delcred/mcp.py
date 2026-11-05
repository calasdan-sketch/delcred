"""MCP / OAuth resource-server helpers (stdlib only).

Drop-in pieces for an MCP server (or any HTTP API) that accepts delcred
credentials, shaped after the MCP authorization spec (2025-11-25 revision):

* :func:`authorize` — one call per request: parse ``Authorization: Bearer``,
  verify signature/expiry/audience/scopes/revocation (JWT) or redeem a
  ``dk_…`` key pinned to this resource, and return an :class:`AuthDecision`
  carrying the HTTP status and a ready ``WWW-Authenticate`` header:

  - **401** + ``Bearer resource_metadata="…", scope="…"`` when the token is
    missing, invalid, expired, revoked, or for another audience;
  - **403** + ``Bearer error="insufficient_scope", scope="…"`` when the token
    is valid but lacks a scope this operation needs (the client can step up).

* :func:`protected_resource_metadata` / :func:`metadata_path` — the RFC 9728
  document MCP clients fetch from ``/.well-known/oauth-protected-resource``.

The MCP spec requires the server to accept only tokens whose audience is the
server itself (RFC 8707) and forbids passing client tokens through to
upstream APIs. Use the MCP server's own canonical URL as the delcred
``resource`` and mint a *separate* delegation for each upstream.

Example (any framework)::

    from delcred.mcp import authorize

    d = authorize(request.headers.get("Authorization"),
                  resource="https://mcp.example.com/mcp",
                  required_scopes="tools:call",
                  resource_metadata_url="https://mcp.example.com/.well-known/oauth-protected-resource/mcp")
    if not d.ok:
        return Response(status=d.status, headers=d.headers, json={"error": d.error})
    user, agent = d.user, d.agent
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ._common import KEY_PREFIX, home
from .broker import Broker, BrokerError
from .exchange import ExchangeError
from .exchange import verify as _verify
from .tokens import InsufficientScope, TokenError, normalize_scopes

# Bearer tokens are short; anything bigger is junk or an attack.
MAX_AUTHORIZATION_HEADER = 16 * 1024


def _quote(value: str) -> str:
    """RFC 7235 quoted-string, with CR/LF stripped (header-injection defense)."""
    value = value.replace("\r", " ").replace("\n", " ")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def www_authenticate(
    *,
    resource_metadata_url: str | None = None,
    scope: str | list[str] | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> str:
    """Build a ``WWW-Authenticate: Bearer …`` challenge value (RFC 6750 §3)."""
    params: list[str] = []
    if error:
        params.append(f"error={_quote(error)}")
    if scope:
        params.append(f"scope={_quote(' '.join(sorted(normalize_scopes(scope))))}")
    if resource_metadata_url:
        params.append(f"resource_metadata={_quote(resource_metadata_url)}")
    if error_description:
        params.append(f"error_description={_quote(error_description)}")
    return "Bearer " + ", ".join(params) if params else "Bearer"


def metadata_path(resource: str) -> str:
    """RFC 9728 §3.1 well-known path for ``resource``.

    ``https://mcp.example.com/mcp`` → ``/.well-known/oauth-protected-resource/mcp``
    """
    path = urlsplit(resource).path.rstrip("/")
    return "/.well-known/oauth-protected-resource" + path


def protected_resource_metadata(
    resource: str,
    authorization_servers: list[str],
    *,
    scopes_supported: list[str] | None = None,
    resource_name: str | None = None,
    jwks_uri: str | None = None,
) -> dict[str, Any]:
    """RFC 9728 Protected Resource Metadata document for an MCP server."""
    if not authorization_servers:
        raise ValueError("authorization_servers must list at least one issuer URL")
    doc: dict[str, Any] = {
        "resource": resource,
        "authorization_servers": list(authorization_servers),
        "bearer_methods_supported": ["header"],
    }
    if scopes_supported:
        doc["scopes_supported"] = sorted(normalize_scopes(scopes_supported))
    if resource_name:
        doc["resource_name"] = resource_name
    if jwks_uri:
        doc["jwks_uri"] = jwks_uri
    return doc


@dataclass
class AuthDecision:
    ok: bool
    status: int  # 200, 401 or 403
    claims: dict[str, Any] = field(default_factory=dict)
    error: str = ""  # OAuth error code: invalid_token / insufficient_scope
    description: str = ""
    www_authenticate: str = ""

    @property
    def headers(self) -> dict[str, str]:
        return {"WWW-Authenticate": self.www_authenticate} if self.www_authenticate else {}

    @property
    def user(self) -> str | None:
        return self.claims.get("sub")

    @property
    def agent(self) -> str | None:
        return (self.claims.get("act") or {}).get("sub")


def bearer_token(authorization: str | None) -> str | None:
    """Extract the token from an ``Authorization`` header (scheme is case-insensitive)."""
    if not authorization or len(authorization) > MAX_AUTHORIZATION_HEADER:
        return None
    scheme, _, rest = authorization.strip().partition(" ")
    if scheme.lower() != "bearer":
        return None
    token = rest.strip()
    if not token or any(c.isspace() for c in token):
        return None
    return token


def authorize(
    authorization: str | None,
    *,
    resource: str,
    required_scopes: str | list[str] | None = None,
    resource_metadata_url: str | None = None,
    base: Path | None = None,
) -> AuthDecision:
    """Authorize one request. Never raises for bad credentials — returns a decision.

    Error descriptions are deliberately generic (no oracle about *why* a
    token failed); the delcred audit log records the specific reason.
    """
    if not resource:
        raise ValueError("resource is required (audience pinning)")
    need = sorted(normalize_scopes(required_scopes))

    def deny(status: int, error: str, desc: str, scope=None) -> AuthDecision:
        return AuthDecision(
            ok=False,
            status=status,
            error=error,
            description=desc,
            www_authenticate=www_authenticate(
                resource_metadata_url=resource_metadata_url,
                scope=scope if scope is not None else (need or None),
                error=error,
                error_description=desc,
            ),
        )

    token = bearer_token(authorization)
    if token is None:
        # RFC 6750 §3.1: no error code when the request lacked credentials.
        return AuthDecision(
            ok=False,
            status=401,
            error="",
            description="missing bearer token",
            www_authenticate=www_authenticate(
                resource_metadata_url=resource_metadata_url, scope=need or None
            ),
        )
    home_ = base or home()
    if token.startswith(KEY_PREFIX):
        try:
            rec = Broker(home_).redeem(
                token, expected_resource=resource, required_scopes=need or None
            )
        except BrokerError:
            return deny(401, "invalid_token", "invalid or expired credential")
        claims = {
            "sub": rec["user"],
            "act": {"sub": rec["agent"]},
            "scope": rec["scope"],
            "aud": rec["resource"],
            "exp": rec["expires_at"],
        }
        return AuthDecision(ok=True, status=200, claims=claims)
    try:
        claims = _verify(token, expected_resource=resource, required_scopes=need or None, base=home_)
    except InsufficientScope as e:
        return deny(403, "insufficient_scope", "additional scope required", scope=e.required)
    except (TokenError, ExchangeError):
        return deny(401, "invalid_token", "invalid or expired credential")
    return AuthDecision(ok=True, status=200, claims=claims)
