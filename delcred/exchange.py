"""RFC 8693-style token exchange: the heart of delcred.

Flow::

    subject_token (user: kind="user", or an external IdP JWT)
        + actor_token (agent: kind="agent", minted by `delcred agent-token`)
        + scope + resource (RFC 8707) + requested_token_type
        → policy check (deny by default, scope ⊆ grant, exact resource match)
        → mint short-lived delegation (JWT and/or opaque broker key)

The agent can never mint beyond its grant. TTL is clamped server-side.
``sub`` names the human, ``act.sub`` names the agent — one credential
naming both, revocable independently.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import tokens
from ._common import DEFAULT_TTL, home
from .audit import AuditLog
from .broker import Broker
from .policy import PolicyError
from .policy import load as load_policy
from .revocation import RevocationList
from .tokens import ExpiredToken, InvalidToken

TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"
TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_TYPE_BROKER_KEY = "urn:delcred:token-type:api-key"


class ExchangeError(Exception):
    pass


@dataclass
class ExchangeResult:
    token_type: str
    credential: str  # the JWT or opaque key (caller must handle carefully)
    claims: dict[str, Any]  # delegation claims (no secret material)
    ttl: int


def _require_kind(claims: dict[str, Any], kind: str, role: str) -> None:
    if claims.get("kind") != kind:
        raise ExchangeError(
            f"{role} token has kind={claims.get('kind')!r}; expected {kind!r}"
        )


def exchange(
    *,
    subject_token: str,
    actor_token: str,
    scope: str,
    resource: str,
    requested_token_type: str = TOKEN_TYPE_JWT,
    ttl: int = DEFAULT_TTL,
    base: Path | None = None,
) -> ExchangeResult:
    """Perform the delegation exchange. Raises ExchangeError / PolicyError."""
    home_ = base or home()
    audit = AuditLog(home_)
    revocations = RevocationList(home_)

    # 1. Validate both input tokens (signature → issuer → expiry).
    try:
        # Only the subject may come from a trusted external IdP.
        sub_claims = tokens.verify_signature(
            subject_token, base=home_, allow_external=True
        )
    except (InvalidToken, ExpiredToken) as e:
        audit.record("exchange_failed", reason="bad_subject_token", detail=str(e))
        raise ExchangeError(f"subject_token rejected: {e}") from e
    try:
        act_claims = tokens.verify_signature(actor_token, base=home_)
    except (InvalidToken, ExpiredToken) as e:
        audit.record("exchange_failed", reason="bad_actor_token", detail=str(e))
        raise ExchangeError(f"actor_token rejected: {e}") from e

    # 2. Role check: subject must be a user, actor must be an agent.
    #    Accept external IdP JWTs as subject tokens: any token whose kind is
    #    absent/"user" and which carries a sub is treated as the user —
    #    EXCEPT it must not be one of our own agent/delegation tokens
    #    (prevents an agent laundering its own token into a subject).
    if sub_claims.get("kind") in ("agent", "delegation"):
        audit.record("exchange_failed", reason="subject_is_agent_token")
        raise ExchangeError("subject_token must identify a user, not an agent")
    _require_kind(act_claims, "agent", "actor")
    user = sub_claims["sub"]
    user_iss = tokens.user_issuer(sub_claims)
    agent = act_claims["sub"]

    # 3. Neither party may be revoked.
    for claims, role in ((sub_claims, "user"), (act_claims, "agent")):
        revoked, why = revocations.is_revoked(claims)
        if revoked:
            audit.record(
                "exchange_failed", reason=f"{role}_revoked", user=user, agent=agent
            )
            raise ExchangeError(f"{role} is revoked: {why}")

    # 4. Policy check: deny by default, scope ⊆ grant, exact resource match.
    policy = load_policy(home_)
    try:
        grant = policy.check(user, agent, scope, resource, ttl, issuer=user_iss)
    except PolicyError as e:
        audit.record(
            "exchange_denied",
            user=user,
            agent=agent,
            scope=scope,
            resource=resource,
            reason=str(e),
        )
        raise
    effective_ttl = policy.effective_ttl(grant, ttl)
    single_use = grant.single_use

    # 5. Mint.
    delegation_jwt = tokens.mint_delegation_token(
        user=user,
        agent=agent,
        scope=scope,
        resource=resource,
        ttl=effective_ttl,
        single_use=single_use,
        user_iss=user_iss,
        base=home_,
    )
    claims = tokens.decode_unverified(delegation_jwt)

    if requested_token_type == TOKEN_TYPE_BROKER_KEY:
        broker = Broker(home_)
        key = broker.issue(
            user=user,
            agent=agent,
            scope=claims["scope"],
            resource=resource,
            ttl=effective_ttl,
            delegation_jwt=delegation_jwt,
            single_use=single_use,
            user_iss=user_iss,
        )
        audit.record(
            "broker_issued",
            user=user,
            agent=agent,
            scope=claims["scope"],
            resource=resource,
            ttl=effective_ttl,
            jti=claims["jti"],
        )
        return ExchangeResult(TOKEN_TYPE_BROKER_KEY, key, claims, effective_ttl)

    if requested_token_type in (TOKEN_TYPE_JWT, TOKEN_TYPE_ACCESS):
        audit.record(
            "token_issued",
            user=user,
            agent=agent,
            scope=claims["scope"],
            resource=resource,
            ttl=effective_ttl,
            jti=claims["jti"],
            single_use=single_use,
        )
        return ExchangeResult(
            requested_token_type, delegation_jwt, claims, effective_ttl
        )

    raise ExchangeError(f"unsupported requested_token_type: {requested_token_type}")


def verify(
    token: str,
    *,
    expected_resource: str,
    required_scopes: str | list[str] | set[str] | None = None,
    base: Path | None = None,
) -> dict[str, Any]:
    """Full verification: signature → expiry → audience → scope → revocation.

    ``expected_resource`` is REQUIRED (finding #2): verifying without an
    audience is a confused-deputy hole. Use ``tokens.decode_unverified``
    (or the ``inspect`` CLI command) for debug-only peeks.

    ``required_scopes`` (recommended): scopes this operation needs; a token
    lacking any of them raises :class:`delcred.InsufficientScope` (→ HTTP
    403 ``insufficient_scope``). Checked *before* the single-use burn, so a
    token presented for the wrong operation is not destroyed.

    Single-use tokens are burned atomically on first successful verify.
    Raises tokens.TokenError or ExchangeError.
    """
    home_ = base or home()
    audit = AuditLog(home_)
    revocations = RevocationList(home_)

    if not isinstance(expected_resource, str) or not expected_resource:
        raise ExchangeError("expected_resource is required (audience pinning)")
    try:
        claims = tokens.verify_delegation_token(
            token,
            expected_resource=expected_resource,
            required_scopes=required_scopes,
            base=home_,
        )
    except tokens.InsufficientScope as e:
        audit.record(
            "verify_insufficient_scope",
            resource=expected_resource,
            missing=e.missing,
        )
        raise
    revoked, why = revocations.is_revoked(claims)
    if revoked:
        audit.record(
            "verify_revoked",
            jti=claims.get("jti"),
            user=claims.get("sub"),
            agent=(claims.get("act") or {}).get("sub"),
        )
        raise ExchangeError(why)
    if claims.get("single_use"):
        # Burn atomically: exactly one concurrent verify wins; the losers are
        # rejected. +300s grace so the burn outlives the token's exp +
        # clock-skew leeway (finding #5).
        burned = revocations.burn_once(
            claims["jti"],
            reason="single-use token consumed",
            expires_at=claims["exp"] + 300,
        )
        if not burned:
            audit.record(
                "verify_replay",
                jti=claims.get("jti"),
                user=claims.get("sub"),
                agent=(claims.get("act") or {}).get("sub"),
            )
            raise ExchangeError("single-use token already consumed")
    audit.record(
        "verify_ok",
        jti=claims.get("jti"),
        user=claims.get("sub"),
        agent=(claims.get("act") or {}).get("sub"),
    )
    return claims
