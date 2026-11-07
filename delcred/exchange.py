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

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import _common as _c
from . import pop as _pop
from . import tokens
from ._common import (
    DEFAULT_TTL,
    MAX_TTL,
    check_identifier,
    check_ttl,
    home,
    parse_scope,
    safe_text,
)
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
    dpop_jkt: str | None = None,
    dpop_proof: str | None = None,
    dpop_url: str | None = None,
    base: Path | None = None,
) -> ExchangeResult:
    """Perform the delegation exchange. Raises ExchangeError / PolicyError.

    * ``dpop_jkt`` binds the new token to a DPoP key (thumbprint, RFC 7638);
      ``dpop_proof`` + ``dpop_url`` (the token endpoint URL) instead derives
      it from a proof of possession (RFC 9449 §5), which is what
      ``POST /token`` does with its ``DPoP`` header. Bound tokens are
      useless without the key.
    * If ``subject_token`` is itself a **delegation** token, this is a
      sub-delegation (agent → sub-agent): the new token can only be
      *narrower* than the parent. See :func:`_attenuate`.
    """
    home_ = base or home()
    audit = AuditLog(home_)
    revocations = RevocationList(home_)
    try:
        check_ttl(ttl)
    except ValueError as e:
        raise PolicyError(str(e)) from e
    if dpop_jkt is not None and dpop_proof is not None:
        raise ExchangeError("pass dpop_jkt or dpop_proof, not both")
    proof_jkt: str | None = None
    if dpop_proof is not None:
        try:
            proof_jkt = _pop.verify_proof(
                dpop_proof, method="POST", url=dpop_url or "", now=None
            )
        except _pop.PopError as e:
            audit.record("exchange_failed", reason="bad_dpop_proof", detail=str(e))
            raise ExchangeError(f"DPoP proof rejected: {e}") from e
    bind_jkt = dpop_jkt or proof_jkt
    if bind_jkt is not None and not (isinstance(bind_jkt, str) and 20 <= len(bind_jkt) <= 128):
        raise ExchangeError("dpop_jkt must be an RFC 7638 thumbprint")

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
    if sub_claims.get("kind") == "delegation":
        return _attenuate(
            parent_token=subject_token,
            parent_claims=sub_claims,
            child_claims=act_claims,
            scope=scope,
            resource=resource,
            requested_token_type=requested_token_type,
            ttl=ttl,
            bind_jkt=bind_jkt,
            proof_jkt=proof_jkt,
            home_=home_,
            audit=audit,
            revocations=revocations,
        )
    if sub_claims.get("kind") == "agent":
        audit.record("exchange_failed", reason="subject_is_agent_token")
        raise ExchangeError("subject_token must identify a user, not an agent")
    _require_kind(act_claims, "agent", "actor")
    user = sub_claims["sub"]
    user_iss = tokens.user_issuer(sub_claims)
    agent = act_claims["sub"]
    try:
        check_identifier(user, "user")
        check_identifier(agent, "agent")
    except (ValueError, TypeError) as e:
        audit.record("exchange_failed", reason="bad_identifier", detail=str(e)[:120])
        raise ExchangeError(str(e)) from e

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
        cnf_jkt=bind_jkt,
        base=home_,
    )
    claims = tokens.decode_unverified(delegation_jwt)

    if requested_token_type == TOKEN_TYPE_BROKER_KEY:
        if bind_jkt:
            raise ExchangeError("opaque API keys cannot be DPoP-bound; request a JWT")
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


def _attenuate(
    *,
    parent_token: str,
    parent_claims: dict[str, Any],
    child_claims: dict[str, Any],
    scope: str,
    resource: str,
    requested_token_type: str,
    ttl: int,
    bind_jkt: str | None,
    proof_jkt: str | None,
    home_: Path,
    audit: AuditLog,
    revocations: RevocationList,
) -> ExchangeResult:
    """Sub-delegation: mint a token for a sub-agent that is NEVER broader.

    Invariants (each one enforced here and fuzz-tested in ``bench/``):

    * scope(child) ⊆ scope(parent) ∩ scope(user's *current* grant);
    * aud(child) == aud(parent); exp(child) ≤ exp(parent);
    * the sub-agent must be named in the grant's ``delegate_to`` and the
      chain depth within ``max_depth`` (deny by default);
    * the child's identity is proven by an issuer-signed agent token, so a
      parent cannot name an agent it does not control;
    * single-use parents cannot delegate; a DPoP-bound parent requires
      proof of its key and the child stays bound to that key;
    * revoking any ancestor jti, any agent in the chain, or the user kills
      the child (see :meth:`RevocationList.is_revoked`).
    """
    def deny(reason: str, **kw: Any) -> None:
        audit.record("delegation_denied", reason=reason, **kw)

    if requested_token_type not in (TOKEN_TYPE_JWT, TOKEN_TYPE_ACCESS):
        raise ExchangeError("sub-delegation can only issue JWT access tokens")
    if child_claims.get("kind") != "agent":
        raise ExchangeError(f"actor token has kind={child_claims.get('kind')!r}; expected 'agent'")
    child = child_claims["sub"]
    try:
        check_identifier(child, "agent")
        parse_scope(scope)
    except (ValueError, TypeError) as e:
        raise PolicyError(str(e), code="scope") from e
    # The parent must be a valid delegation token for exactly this resource.
    try:
        parent = tokens.verify_delegation_token(parent_token, expected_resource=resource, base=home_)
    except tokens.TokenError as e:
        deny("bad_parent", detail=str(e)[:160])
        raise PolicyError(f"parent delegation rejected: {e}", code="resource") from e
    revoked, why = revocations.is_revoked(parent)
    if revoked:
        deny("parent_revoked", user=parent["sub"])
        raise ExchangeError(f"parent delegation is revoked: {why}")
    revoked, why = revocations.is_revoked(child_claims)
    if revoked:
        deny("child_revoked", user=parent["sub"], agent=child)
        raise ExchangeError(f"sub-agent is revoked: {why}")
    if parent.get("single_use"):
        deny("parent_single_use", user=parent["sub"])
        raise PolicyError("single-use credentials cannot be sub-delegated", code="delegation")
    actors = tokens.actor_chain(parent)  # leaf first
    if child in actors:
        deny("cycle", user=parent["sub"], agent=child)
        raise ExchangeError(
            f"subject_token must identify a user: agent {child!r} is already in this "
            "delegation chain (an agent cannot re-delegate to itself)"
        )
    parent_jkt = (parent.get("cnf") or {}).get("jkt")
    if parent_jkt and proof_jkt != parent_jkt:
        raise ExchangeError(
            "the parent token is DPoP-bound: present a DPoP proof signed by its key"
        )
    if bind_jkt and parent_jkt and bind_jkt != parent_jkt:
        raise ExchangeError("a sub-delegation cannot move a DPoP-bound token to another key")
    new_jkt = parent_jkt or bind_jkt
    user, user_iss, root = parent["sub"], tokens.user_issuer(parent), actors[-1]
    held = set(str(parent.get("scope", "")).split())
    policy = load_policy(home_)
    try:
        grant = policy.check_delegation(
            user, root, child, held, scope, resource, ttl, depth=len(actors), issuer=user_iss
        )
    except PolicyError as e:
        deny(e.code, user=user, agent=child, scope=scope, resource=resource, detail=str(e)[:160])
        raise
    now = int(time.time())
    remaining = int(parent["exp"]) - now
    effective = min(ttl, grant.max_ttl, MAX_TTL, remaining)
    if effective <= 0:
        raise ExchangeError("parent delegation has expired")
    jwt_ = tokens.mint_delegation_token(
        user=user,
        agent=child,
        scope=scope,
        resource=resource,
        ttl=effective,
        user_iss=user_iss,
        actors=[child, *actors],
        chain=[*parent.get("chain", []), parent["jti"]],
        cnf_jkt=new_jkt,
        base=home_,
    )
    claims = tokens.decode_unverified(jwt_)
    audit.record(
        "delegation_attenuated",
        user=user,
        agent=child,
        parent_agent=actors[0],
        scope=claims["scope"],
        resource=resource,
        ttl=effective,
        depth=len(actors),
        parent_jti=parent["jti"],
        jti=claims["jti"],
    )
    return ExchangeResult(requested_token_type, jwt_, claims, effective)


def _audit_rejected(audit: AuditLog, token: object, resource: str, err: Exception) -> None:
    """Record a rejected credential without storing it. Rate-limited so a
    flood of junk cannot grow the log without bound; identity hints come from
    the UNVERIFIED payload and are labelled as claims."""
    hints: dict[str, Any] = {}
    try:
        if not isinstance(token, str) or len(token) > _c.MAX_TOKEN_BYTES:
            raise ValueError("no hints from oversized input")
        c = tokens.decode_unverified(token)
        for k_out, k_in in (("claimed_jti", "jti"), ("claimed_sub", "sub")):
            if isinstance(c.get(k_in), str):
                hints[k_out] = safe_text(c[k_in], 80)
    except Exception:  # noqa: BLE001,S110 - garbage in, no hints out
        pass
    audit.record_throttled(
        "verify_rejected",
        reason=type(err).__name__,
        detail=safe_text(err, 160),
        resource=safe_text(resource, 200),
        **hints,
    )


def _grant_still_holds(claims: dict[str, Any], home_: Path) -> tuple[bool, str]:
    try:
        return load_policy(home_).still_granted(claims)
    except PolicyError as e:
        return False, f"policy unreadable: {e}"
    except Exception as e:  # noqa: BLE001 - fail closed on any loader problem
        return False, f"policy unreadable: {type(e).__name__}"


def revoke_presented(token: str, *, base: Path | None = None) -> bool:
    """RFC 7009-style self-revocation: whoever holds a valid delegation token
    can end it (an agent finishing a task burns its own credential). Junk,
    expired or foreign tokens are ignored silently. Returns True if a
    revocation was recorded."""
    home_ = base or home()
    audit = AuditLog(home_)
    try:
        claims = tokens.verify_delegation_token(token, base=home_)
    except tokens.TokenError:
        return False
    RevocationList(home_).revoke_jti(
        claims["jti"], reason="revoked by holder", expires_at=int(claims["exp"]) + 300
    )
    audit.record(
        "token_revoked_by_holder",
        jti=claims["jti"],
        user=claims.get("sub"),
        agent=(claims.get("act") or {}).get("sub"),
    )
    return True


def verify(
    token: str,
    *,
    expected_resource: str,
    required_scopes: str | list[str] | set[str] | None = None,
    base: Path | None = None,
    dpop_proof: str | None = None,
    http_method: str | None = None,
    http_url: str | None = None,
    check_policy: bool = False,
) -> dict[str, Any]:
    """Full verification: signature → expiry → audience → scope → revocation.

    ``expected_resource`` is REQUIRED (finding #2): verifying without an
    audience is a confused-deputy hole. Use ``tokens.decode_unverified``
    (or the ``inspect`` CLI command) for debug-only peeks.

    ``required_scopes`` (recommended): scopes this operation needs; a token
    lacking any of them raises :class:`delcred.InsufficientScope` (→ HTTP
    403 ``insufficient_scope``). Checked *before* the single-use burn, so a
    token presented for the wrong operation is not destroyed.

    Tokens bound to a key (``cnf.jkt``) additionally REQUIRE ``dpop_proof``,
    ``http_method`` and ``http_url`` (RFC 9449); the proof is checked before
    revocation and before a single-use burn, so a thief without the key
    cannot even consume the victim's single-use token.

    ``check_policy=True`` also re-reads ``policy.yaml`` and refuses a token
    whose user/agent grant has been removed or narrowed since it was minted
    (otherwise an already-minted token lives out its TTL, <= 60 min, after
    you delete the grant). Needs the delcred home, so it is for verifiers that
    run beside the issuer; offline verifiers rely on the signed bulletin.

    Single-use tokens are burned atomically on first successful verify.
    Rejected credentials are audited (``verify_rejected``, rate-limited).
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
    except tokens.TokenError as e:
        _audit_rejected(audit, token, expected_resource, e)
        raise
    if check_policy:
        ok, why = _grant_still_holds(claims, home_)
        if not ok:
            audit.record(
                "verify_policy_revoked",
                jti=claims.get("jti"),
                user=claims.get("sub"),
                agent=(claims.get("act") or {}).get("sub"),
                reason=safe_text(why, 200),
            )
            raise ExchangeError(f"grant no longer holds: {why}")
    jkt = (claims.get("cnf") or {}).get("jkt")
    if jkt:
        if not (dpop_proof and http_method and http_url):
            audit.record("verify_dpop_missing", jti=claims.get("jti"))
            raise tokens.InvalidToken(
                "token is sender-constrained (cnf.jkt): a DPoP proof, method and URL are required"
            )
        try:
            _pop.verify_proof(
                dpop_proof,
                method=http_method,
                url=http_url,
                access_token=token,
                expected_jkt=jkt,
            )
        except _pop.PopError as e:
            audit.record("verify_dpop_failed", jti=claims.get("jti"), detail=str(e)[:120])
            raise tokens.InvalidToken(f"DPoP proof rejected: {e}") from e
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
