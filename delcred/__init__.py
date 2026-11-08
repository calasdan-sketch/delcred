"""delcred — short-lived, per-task, per-user-scoped credentials for AI agents.

Five-line happy path::

    import delcred

    tok = delcred.delegate(
        user="u_123", agent="billing-agent",
        scope="invoices:read", resource="https://api.acme.test/v1",
        user_token=user_jwt, agent_token=agent_jwt,
    )
    claims = delcred.verify(tok, expected_resource="https://api.acme.test/v1")
"""

from __future__ import annotations

import sys

if sys.platform == "win32":
    raise ImportError(
        "delcred supports Linux and macOS only: it relies on fcntl file locks "
        "and POSIX 0600 permission checks for its keys and state files"
    )

from pathlib import Path  # noqa: E402
from typing import Any

from . import keys, policy, tokens
from ._common import DEFAULT_TTL
from .audit import AuditLog
from .broker import Broker
from .exchange import (
    TOKEN_TYPE_BROKER_KEY,
    TOKEN_TYPE_JWT,
    ExchangeError,
)
from .exchange import (
    exchange as _exchange,
)
from .exchange import (
    verify as _verify,
)
from .policy import PolicyError
from .revocation import RevocationList
from .tokens import ExpiredToken, InvalidToken, TokenError
from .trust import TrustConfigError, add_trusted_issuer, trusted_issuers

__version__ = "0.2.1"
__all__ = [
    "DEFAULT_TTL",
    "TOKEN_TYPE_BROKER_KEY",
    "TOKEN_TYPE_JWT",
    "ExchangeError",
    "ExpiredToken",
    "InvalidToken",
    "PolicyError",
    "TokenError",
    "TrustConfigError",
    "__version__",
    "agent_token",
    "delegate",
    "delegate_api_key",
    "init",
    "revoke_agent",
    "revoke_token",
    "revoke_user",
    "trust_add",
    "trusted_issuers",
    "user_token",
    "verify",
    "verify_broker_key",
]


def init(base: Path | None = None, force: bool = False) -> Path:
    """Create a delcred home: issuer keypair + default policy. Returns home path."""
    from ._common import home as _home
    from .keys import key_paths

    h = base or _home()
    priv, _ = key_paths(h)
    if priv.exists() and not force:
        raise FileExistsError(f"issuer key already exists at {priv} (use force=True)")
    keys.generate(h)
    policy.policy_path(h).write_text(policy.default_policy())
    AuditLog(h).record("init", home=str(h))
    return h


def delegate(
    *,
    user: str | None = None,
    agent: str | None = None,
    scope: str,
    resource: str,
    user_token: str,
    agent_token: str,
    ttl: int = DEFAULT_TTL,
    base: Path | None = None,
) -> str:
    """Mint a delegation JWT via RFC 8693 exchange. Returns the token.

    ``user``/``agent`` are optional assertions: if given, they must match the
    ``sub`` of ``user_token``/``agent_token`` or ExchangeError is raised.
    """
    for want, tok, role in ((user, user_token, "user"), (agent, agent_token, "agent")):
        if want is not None and tokens.decode_unverified(tok).get("sub") != want:
            raise ExchangeError(f"{role}={want!r} does not match the {role} token's sub")
    result = _exchange(
        subject_token=user_token,
        actor_token=agent_token,
        scope=scope,
        resource=resource,
        requested_token_type=TOKEN_TYPE_JWT,
        ttl=ttl,
        base=base,
    )
    return result.credential


def delegate_api_key(
    *,
    scope: str,
    resource: str,
    user_token: str,
    agent_token: str,
    ttl: int = DEFAULT_TTL,
    base: Path | None = None,
) -> str:
    """Mint an opaque ephemeral API key (``dk_…``) backed by a delegation."""
    result = _exchange(
        subject_token=user_token,
        actor_token=agent_token,
        scope=scope,
        resource=resource,
        requested_token_type=TOKEN_TYPE_BROKER_KEY,
        ttl=ttl,
        base=base,
    )
    return result.credential


def verify(
    token: str,
    *,
    expected_resource: str,
    base: Path | None = None,
) -> dict[str, Any]:
    """Verify a delegation JWT (signature → expiry → revocation → audience).

    ``expected_resource`` is required — audience pinning is the
    confused-deputy defense and must not be skippable.
    """
    return _verify(token, expected_resource=expected_resource, base=base)


def verify_broker_key(key: str, base: Path | None = None) -> dict[str, Any]:
    """Redeem an opaque broker key → capability record (burns single-use keys)."""
    from ._common import home as _home

    return Broker(base or _home()).redeem(key)


def revoke_token(jti: str, reason: str = "", base: Path | None = None) -> None:
    from ._common import home as _home

    RevocationList(base or _home()).revoke_jti(jti, reason=reason)


def revoke_agent(agent: str, reason: str = "", base: Path | None = None) -> None:
    """Kill switch: invalidate every credential for this agent, user untouched."""
    from ._common import home as _home

    h = base or _home()
    RevocationList(h).revoke_agent(agent, reason=reason)
    AuditLog(h).record("agent_revoked", agent=agent, reason=reason)


def revoke_user(user: str, reason: str = "", base: Path | None = None) -> None:
    """Kill switch: invalidate every delegation made by this user."""
    from ._common import home as _home

    h = base or _home()
    RevocationList(h).revoke_user(user, reason=reason)
    AuditLog(h).record("user_revoked", user=user, reason=reason)


def agent_token(agent_id: str, ttl: int = 86400, base: Path | None = None) -> str:
    from ._common import home as _home

    return tokens.mint_agent_token(agent_id, ttl=ttl, base=base or _home())


def trust_add(iss: str, key_file: str, base: Path | None = None) -> Path:
    """Trust an external IdP's subject tokens: register its Ed25519 public key."""
    from ._common import home as _home

    return add_trusted_issuer(iss, key_file, base=base or _home())


def user_token(user_id: str, ttl: int = 3600, base: Path | None = None) -> str:
    from ._common import home as _home

    return tokens.mint_user_token(user_id, ttl=ttl, base=base or _home())
