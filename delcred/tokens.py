"""JWT minting and strict verification (EdDSA / Ed25519).

Local tokens are always EdDSA. Trusted external IdPs may be pinned to RS256
or ES256 for subject tokens only (see ``trust.py``).

Claim model (RFC 8693-flavoured)::

    iss:      "delcred"                      # this issuer
    sub:      "<user-id>"                    # the human on whose behalf we act
    act:      {"sub": "<agent-id>"}          # the acting agent (RFC 8693 §4.4)
    kind:     "delegation" | "agent" | "user"
    scope:    "invoices:read customers:read" # space-delimited, RFC 8693 §4.2
    aud:      "https://api.example.com"      # RFC 8707 resource indicator
    jti:      unique token id                # revocation handle
    iat/nbf/exp as usual; nbf == iat.

Verification order (panel-mandated): parse → signature → issuer trust →
expiry/nbf → revocation → scope/audience. ``verify_*`` does everything up to
expiry; revocation is checked by the caller (exchange/broker/verify command)
because it needs the RevocationList.
"""

from __future__ import annotations

import secrets
import time
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import keys as _keys
from ._common import CLOCK_SKEW_LEEWAY, DEFAULT_TTL, ISSUER_ID


class TokenError(Exception):
    """Base class for all token verification failures."""


class ExpiredToken(TokenError):
    pass


class InvalidToken(TokenError):
    pass


def _now() -> int:
    return int(time.time())


def _new_jti() -> str:
    return secrets.token_urlsafe(16)


def _signing_key_pem(priv: Ed25519PrivateKey) -> bytes:
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def mint_delegation_token(
    *,
    user: str,
    agent: str,
    scope: str,
    resource: str,
    ttl: int = DEFAULT_TTL,
    single_use: bool = False,
    base: Path | None = None,
) -> str:
    """Mint a delegation JWT: ``sub``=user, ``act``=agent, pinned to ``resource``."""
    if not user or not agent:
        raise ValueError("user and agent are required")
    if not resource:
        raise ValueError("resource (RFC 8707 indicator) is required")
    now = _now()
    claims: dict[str, Any] = {
        "iss": ISSUER_ID,
        "sub": user,
        "act": {"sub": agent},
        "kind": "delegation",
        "scope": " ".join(sorted(set(scope.split()))),
        "aud": resource,
        "jti": _new_jti(),
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
    }
    if single_use:
        claims["single_use"] = True
    priv = _keys.load_private(base)
    return jwt.encode(
        claims,
        _signing_key_pem(priv),
        algorithm="EdDSA",
        headers={"typ": "at+jwt"},
    )


def mint_agent_token(agent_id: str, ttl: int = 86400, base: Path | None = None) -> str:
    """Mint an agent identity token (the ``actor_token`` in an exchange)."""
    now = _now()
    claims = {
        "iss": ISSUER_ID,
        "sub": agent_id,
        "kind": "agent",
        "jti": _new_jti(),
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
    }
    priv = _keys.load_private(base)
    return jwt.encode(claims, _signing_key_pem(priv), algorithm="EdDSA")


def mint_user_token(user_id: str, ttl: int = 3600, base: Path | None = None) -> str:
    """Mint a local user assertion (the ``subject_token`` in dev / no-IdP setups)."""
    now = _now()
    claims = {
        "iss": ISSUER_ID,
        "sub": user_id,
        "kind": "user",
        "jti": _new_jti(),
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
    }
    priv = _keys.load_private(base)
    return jwt.encode(claims, _signing_key_pem(priv), algorithm="EdDSA")


def decode_unverified(token: str) -> dict[str, Any]:
    """Decode claims without verifying — for inspection only, never trust."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as e:
        raise InvalidToken(f"malformed token: {e}") from e


def _key_for_issuer(token: str, base: Path | None) -> tuple[bytes, list[str], str, str]:
    """Select the verification key, required claims and alg from the token's ``iss``.

    Returns ``(public_key_pem, required_claims, issuer, alg)``. The local issuer
    uses the delcred issuer key (EdDSA) with the full claim set; trusted external
    issuers (IdPs) use their registered key and pinned alg with a minimal claim
    set (external tokens rarely carry ``jti``/``nbf`` — revocation of users is by
    ``sub``, which is always required). The token's own ``alg`` header must equal
    the pinned alg; it never chooses the algorithm.
    """
    from . import trust as _trust

    try:
        headers = jwt.get_unverified_header(token)
    except jwt.PyJWTError as e:
        raise InvalidToken(f"malformed token header: {e}") from e
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as e:
        raise InvalidToken(f"malformed token: {e}") from e
    if not isinstance(unverified, dict):
        raise InvalidToken("malformed token: claims are not an object")
    iss = unverified.get("iss")

    def _pin(alg: str) -> None:
        if headers.get("alg") != alg:
            raise InvalidToken(
                f"unexpected alg {headers.get('alg')!r}; issuer {iss!r} accepts {alg} only"
            )

    if iss == ISSUER_ID:
        _pin("EdDSA")
        pub = _keys.load_public(base)
        pem = pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem, ["exp", "iat", "nbf", "iss", "sub", "jti"], iss, "EdDSA"
    try:
        trusted = _trust.trusted_issuer_algs(base)
    except _trust.TrustConfigError as e:
        raise InvalidToken(f"bad trusted_issuers config: {e}") from e
    entry = trusted.get(iss) if isinstance(iss, str) else None
    if entry is None:
        raise InvalidToken(
            f"untrusted issuer {iss!r} — local issuer is {ISSUER_ID!r}; "
            "register external IdPs with `delcred trust-add`"
        )
    key, alg = entry
    _pin(alg)
    pem = key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem, ["exp", "iss", "sub"], iss, alg


def verify_signature(
    token: str,
    *,
    leeway: int = CLOCK_SKEW_LEEWAY,
    base: Path | None = None,
) -> dict[str, Any]:
    """Strict verification: one alg per issuer, issuer pinned, expiry/nbf.

    The verification key is selected from the token's ``iss``: the local
    delcred issuer key, or a trusted external IdP registered via
    ``policy.yaml`` ``trusted_issuers`` / ``delcred trust-add``.

    Raises TokenError subclasses. Does NOT check revocation (caller does).
    """
    pub_pem, required, issuer, alg = _key_for_issuer(token, base)
    try:
        claims = jwt.decode(
            token,
            pub_pem,
            algorithms=[alg],
            issuer=issuer,
            leeway=leeway,
            options={
                "require": required,
                # Audience is enforced explicitly by verify_delegation_token
                # (confused-deputy defense with a clear error), not here, so
                # that non-delegation tokens carrying aud are unaffected.
                "verify_aud": False,
            },
        )
    except jwt.ExpiredSignatureError as e:
        raise ExpiredToken("token expired") from e
    except jwt.InvalidIssuerError as e:
        raise InvalidToken(f"untrusted issuer: {e}") from e
    except jwt.PyJWTError as e:
        raise InvalidToken(f"token rejected: {e}") from e
    return claims


def verify_delegation_token(
    token: str,
    *,
    expected_resource: str | None = None,
    leeway: int = CLOCK_SKEW_LEEWAY,
    base: Path | None = None,
) -> dict[str, Any]:
    """Verify a delegation token and enforce audience pinning (confused-deputy defense)."""
    claims = verify_signature(token, leeway=leeway, base=base)
    # Only this issuer mints delegations. A trusted external IdP may assert
    # *users*, never delegations — otherwise its tokens would bypass policy.
    if claims.get("iss") != ISSUER_ID:
        raise InvalidToken(
            f"delegation tokens must be issued by {ISSUER_ID!r}, "
            f"not {claims.get('iss')!r}"
        )
    if claims.get("kind") != "delegation":
        raise InvalidToken(f"not a delegation token (kind={claims.get('kind')!r})")
    if "act" not in claims or "sub" not in claims["act"]:
        raise InvalidToken("delegation token missing act.sub (agent identity)")
    if jwt.get_unverified_header(token).get("typ") != "at+jwt":
        raise InvalidToken("not a delegation token (typ must be 'at+jwt')")
    if expected_resource is not None and claims.get("aud") != expected_resource:
        raise InvalidToken(
            f"audience mismatch: token is for {claims.get('aud')!r}, "
            f"not {expected_resource!r}"
        )
    return claims


def scopes_of(claims: dict[str, Any]) -> set[str]:
    return set(str(claims.get("scope", "")).split())
