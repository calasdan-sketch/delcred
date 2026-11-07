"""delcred — short-lived, per-task, per-user-scoped credentials for AI agents.

Five-line happy path::

    import delcred

    tok = delcred.delegate(
        scope="invoices:read", resource="https://api.acme.test/v1",
        user_token=user_jwt, agent_token=agent_jwt,
    )
    claims = delcred.verify(tok, expected_resource="https://api.acme.test/v1",
                            required_scopes="invoices:read")
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import bulletin, keys, offline, policy, pop, tokens
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
from .tokens import ExpiredToken, InsufficientScope, InvalidToken, TokenError
from .trust import TrustConfigError, add_trusted_issuer, trusted_issuers

__version__ = "0.4.0"
__all__ = [
    "DEFAULT_TTL",
    "TOKEN_TYPE_BROKER_KEY",
    "TOKEN_TYPE_JWT",
    "AuditLog",
    "ExchangeError",
    "ExpiredToken",
    "InsufficientScope",
    "InvalidToken",
    "PolicyError",
    "TokenError",
    "TrustConfigError",
    "__version__",
    "agent_token",
    "attenuate",
    "bulletin",
    "delegate",
    "delegate_api_key",
    "init",
    "jwks",
    "offline",
    "pop",
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
    dpop_jkt: str | None = None,
    base: Path | None = None,
) -> str:
    """Mint a delegation JWT via RFC 8693 exchange. Returns the token.

    ``dpop_jkt`` (``delcred.pop.thumbprint(key)``) binds the token to a key:
    every use then needs a DPoP proof signed by it (RFC 9449), so a leaked
    token is worthless on its own.

    ``user`` / ``agent`` are optional assertions: when given, they must match
    the identities inside ``user_token`` / ``agent_token`` or the call fails
    before anything is minted (catches wiring mistakes such as swapped
    tokens). The identities themselves always come from the verified tokens.
    """
    _assert_identities(user, agent, user_token, agent_token)
    result = _exchange(
        subject_token=user_token,
        actor_token=agent_token,
        scope=scope,
        resource=resource,
        requested_token_type=TOKEN_TYPE_JWT,
        ttl=ttl,
        dpop_jkt=dpop_jkt,
        base=base,
    )
    return result.credential


def attenuate(
    parent_token: str,
    *,
    sub_agent_token: str,
    scope: str,
    resource: str,
    ttl: int = DEFAULT_TTL,
    dpop_jkt: str | None = None,
    dpop_proof: str | None = None,
    dpop_url: str | None = None,
    base: Path | None = None,
) -> str:
    """Hand a **narrower** copy of a delegation to a sub-agent.

    The result can never exceed the parent: scope ⊆ parent's, same resource,
    expires no later, and only for agents the grant lists in ``delegate_to``
    (``max_depth`` hops). Revoking the parent, any agent in the chain or the
    user kills it. ``sub_agent_token`` is the sub-agent's identity token
    (``delcred.agent_token(...)``). If the parent is DPoP-bound, pass the
    ``dpop_proof`` (signed by its key) and the token endpoint ``dpop_url``.
    """
    result = _exchange(
        subject_token=parent_token,
        actor_token=sub_agent_token,
        scope=scope,
        resource=resource,
        requested_token_type=TOKEN_TYPE_JWT,
        ttl=ttl,
        dpop_jkt=dpop_jkt,
        dpop_proof=dpop_proof,
        dpop_url=dpop_url,
        base=base,
    )
    return result.credential


def _assert_identities(
    user: str | None, agent: str | None, user_token: str, agent_token: str
) -> None:
    if user is None and agent is None:
        return
    for want, tok, role in ((user, user_token, "user"), (agent, agent_token, "agent")):
        if want is None:
            continue
        try:
            got = tokens.decode_unverified(tok).get("sub")
        except TokenError as e:
            raise ExchangeError(f"{role} token rejected: {e}") from e
        if got != want:
            raise ExchangeError(
                f"{role}={want!r} does not match the {role} token (sub={got!r})"
            )


def delegate_api_key(
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
    """Mint an opaque ephemeral API key (``dk_…``) backed by a delegation."""
    _assert_identities(user, agent, user_token, agent_token)
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
    required_scopes: str | list[str] | None = None,
    base: Path | None = None,
    dpop_proof: str | None = None,
    http_method: str | None = None,
    http_url: str | None = None,
) -> dict[str, Any]:
    """Verify a delegation JWT (signature → expiry → audience → scope → [DPoP] → revocation).

    ``expected_resource`` is required — audience pinning is the
    confused-deputy defense and must not be skippable. ``required_scopes``
    enforces least privilege per operation (raises ``InsufficientScope``).
    A DPoP-bound token also needs ``dpop_proof`` / ``http_method`` /
    ``http_url`` (see :mod:`delcred.pop`).
    """
    return _verify(
        token,
        expected_resource=expected_resource,
        required_scopes=required_scopes,
        base=base,
        dpop_proof=dpop_proof,
        http_method=http_method,
        http_url=http_url,
    )


def verify_broker_key(
    key: str,
    base: Path | None = None,
    *,
    expected_resource: str | None = None,
    required_scopes: str | list[str] | None = None,
) -> dict[str, Any]:
    """Redeem an opaque broker key → capability record (burns single-use keys).

    Pass ``expected_resource`` so a key minted for one API cannot be
    redeemed by another (strongly recommended; optional for 0.2 compat).
    """
    from ._common import home as _home

    return Broker(base or _home()).redeem(
        key, expected_resource=expected_resource, required_scopes=required_scopes
    )


def jwks(base: Path | None = None) -> dict[str, Any]:
    """Public JWK Set for the issuer key — lets any resource server verify
    delegation tokens with a stock JWT library (no delcred install needed)."""
    from ._common import home as _home

    return keys.jwks(base or _home())


def revoke_token(jti: str, reason: str = "", base: Path | None = None) -> None:
    from ._common import home as _home

    RevocationList(base or _home()).revoke_jti(jti, reason=reason)


def revoke_agent(agent: str, reason: str = "", base: Path | None = None) -> None:
    """Kill switch: invalidate every credential for this agent, user untouched."""
    from ._common import home as _home

    h = base or _home()
    RevocationList(h).revoke_agent(agent, reason=reason)
    AuditLog(h).record("agent_revoked", agent=agent, reason=reason)


def revoke_user(
    user: str, reason: str = "", base: Path | None = None, issuer: str | None = None
) -> None:
    """Kill switch: invalidate every delegation made by this user.

    ``issuer=None`` revokes the id under every issuer (fail-closed); pass an
    IdP issuer URL to revoke only that IdP's user.
    """
    from ._common import home as _home

    h = base or _home()
    RevocationList(h).revoke_user(user, reason=reason, issuer=issuer)
    AuditLog(h).record("user_revoked", user=user, issuer=issuer, reason=reason)


def agent_token(agent_id: str, ttl: int = 86400, base: Path | None = None) -> str:
    from ._common import home as _home

    return tokens.mint_agent_token(agent_id, ttl=ttl, base=base or _home())


def trust_add(
    iss: str, key_file: str, base: Path | None = None, audience: str | None = None
) -> Path:
    """Trust an external IdP's subject tokens: register its Ed25519 public key.

    Its tokens must carry ``aud`` = ``audience`` (default ``"delcred"``).
    """
    from ._common import home as _home

    return add_trusted_issuer(iss, key_file, base=base or _home(), audience=audience)


def user_token(user_id: str, ttl: int = 3600, base: Path | None = None) -> str:
    from ._common import home as _home

    return tokens.mint_user_token(user_id, ttl=ttl, base=base or _home())
