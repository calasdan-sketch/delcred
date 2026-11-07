"""JWT minting and strict verification (EdDSA / Ed25519).

Claim model (RFC 8693-flavoured)::

    iss:      "delcred"                      # this issuer
    sub:      "<user-id>"                    # the human on whose behalf we act
    act:      {"sub": "<agent-id>"}          # the acting agent (RFC 8693 §4.4)
    kind:     "delegation" | "agent" | "user"
    scope:    "invoices:read customers:read" # space-delimited, RFC 8693 §4.2
    aud:      "https://api.example.com"      # RFC 8707 resource indicator
    jti:      unique token id                # revocation handle
    iat/nbf/exp as usual; nbf == iat.

Issuer rule: delegation, agent and local user tokens MUST be signed by the
local issuer (``iss == "delcred"``). Trusted external IdPs are accepted only
for the ``subject_token`` of an exchange (``allow_external=True``), and their
tokens must carry the configured audience.

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
from ._common import (
    CLOCK_SKEW_LEEWAY,
    DEFAULT_TTL,
    ISSUER_ID,
    MAX_CHAIN_DEPTH,
    MAX_TOKEN_BYTES,
    check_identifier,
)
from ._jws import FORBIDDEN_HEADERS


class TokenError(Exception):
    """Base class for all token verification failures."""


class ExpiredToken(TokenError):
    pass


class InvalidToken(TokenError):
    pass


class InsufficientScope(TokenError):
    """The token is valid but lacks scopes the operation requires.

    Maps to HTTP 403 + ``WWW-Authenticate: Bearer error="insufficient_scope"``
    (RFC 6750 §3.1, MCP authorization spec). ``required``/``missing`` are
    sorted lists of scope strings.
    """

    def __init__(self, required: list[str], missing: list[str], granted: list[str]):
        self.required = required
        self.missing = missing
        self.granted = granted
        super().__init__(f"insufficient scope: missing {missing} (token grants {granted})")


def normalize_scopes(scopes: str | list[str] | set[str] | tuple[str, ...] | None) -> set[str]:
    """Accept ``"a b"`` or ``["a", "b"]`` → ``{"a", "b"}`` (whitespace-split)."""
    if scopes is None:
        return set()
    if isinstance(scopes, str):
        return set(scopes.split())
    out: set[str] = set()
    for s in scopes:
        if not isinstance(s, str):
            raise TypeError("scopes must be strings")
        out.update(s.split())
    return out


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


def _headers(priv: Ed25519PrivateKey, typ: str | None = None) -> dict[str, str]:
    h = {"kid": _keys.key_id(priv.public_key())}
    if typ:
        h["typ"] = typ
    return h


def mint_delegation_token(
    *,
    user: str,
    agent: str,
    scope: str,
    resource: str,
    ttl: int = DEFAULT_TTL,
    single_use: bool = False,
    user_iss: str = ISSUER_ID,
    actors: list[str] | None = None,
    chain: list[str] | None = None,
    cnf_jkt: str | None = None,
    exp_cap: int | None = None,
    base: Path | None = None,
) -> str:
    """Mint a delegation JWT: ``sub``=user, ``act``=agent, pinned to ``resource``.

    ``user_iss`` records which issuer vouched for the user, so users are
    identified by ``(user_iss, sub)`` — ``u_1`` from an IdP is not the local
    ``u_1``.

    ``actors`` (leaf first, ``actors[0] == agent``) mints a chained
    delegation: ``act`` nests per RFC 8693 §4.4 and ``chain`` lists the
    ancestor token ids so that revoking any ancestor kills this token.
    ``cnf_jkt`` binds the token to a DPoP key (RFC 9449 ``cnf.jkt``).
    ``exp_cap`` is an absolute ceiling for ``exp`` (a sub-delegation must never
    outlive its parent; computing ``now + remaining`` in the caller and again
    here let the clock tick between the two reads and overshoot by 1 s).
    """
    check_identifier(user, "user")
    check_identifier(agent, "agent")
    if not resource:
        raise ValueError("resource (RFC 8707 indicator) is required")
    actors = list(actors) if actors else [agent]
    if actors[0] != agent or len(actors) > MAX_CHAIN_DEPTH + 1:
        raise ValueError("actors must start with the agent and respect the depth cap")
    now = _now()
    act: dict[str, Any] = {"sub": actors[-1]}
    for a in reversed(actors[:-1]):
        act = {"sub": a, "act": act}
    claims: dict[str, Any] = {
        "iss": ISSUER_ID,
        "sub": user,
        "act": act,
        "kind": "delegation",
        "user_iss": user_iss,
        "scope": " ".join(sorted(set(scope.split()))),
        "aud": resource,
        "jti": _new_jti(),
        "iat": now,
        "nbf": now,
        "exp": now + ttl if exp_cap is None else min(now + ttl, exp_cap),
    }
    if single_use:
        claims["single_use"] = True
    if chain:
        claims["chain"] = list(chain)
    if cnf_jkt:
        claims["cnf"] = {"jkt": cnf_jkt}
    priv = _keys.load_private(base)
    return jwt.encode(
        claims,
        _signing_key_pem(priv),
        algorithm="EdDSA",
        headers=_headers(priv, "at+jwt"),
    )


def mint_agent_token(agent_id: str, ttl: int = 86400, base: Path | None = None) -> str:
    """Mint an agent identity token (the ``actor_token`` in an exchange)."""
    check_identifier(agent_id, "agent id")
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
    return jwt.encode(
        claims, _signing_key_pem(priv), algorithm="EdDSA", headers=_headers(priv)
    )


def mint_user_token(user_id: str, ttl: int = 3600, base: Path | None = None) -> str:
    """Mint a local user assertion (the ``subject_token`` in dev / no-IdP setups)."""
    check_identifier(user_id, "user id")
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
    return jwt.encode(
        claims, _signing_key_pem(priv), algorithm="EdDSA", headers=_headers(priv)
    )


def decode_unverified(token: str) -> dict[str, Any]:
    """Decode claims without verifying — for inspection only, never trust."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as e:
        raise InvalidToken(f"malformed token: {e}") from e


def _key_for_issuer(
    token: str, base: Path | None, allow_external: bool = False
) -> tuple[bytes, list[str], Any, Any]:
    """Select the verification key and required claims from the token's ``iss``.

    Returns ``(public_key_pem, required_claims, issuer)``. The local issuer
    uses the delcred issuer key with the full claim set; trusted external
    issuers (IdPs) use their registered Ed25519 key with a minimal claim set
    (external tokens rarely carry ``jti``/``nbf`` — revocation of users is by
    ``sub``, which is always required).
    """
    from . import trust as _trust

    if not isinstance(token, str) or len(token) > MAX_TOKEN_BYTES:
        raise InvalidToken(f"malformed token: not a string of at most {MAX_TOKEN_BYTES} bytes")
    try:
        headers = jwt.get_unverified_header(token)
    except jwt.PyJWTError as e:
        raise InvalidToken(f"malformed token header: {e}") from e
    if headers.get("alg") != "EdDSA":
        raise InvalidToken(
            f"unexpected alg {headers.get('alg')!r}; only EdDSA accepted"
        )
    for forbidden in FORBIDDEN_HEADERS:
        if forbidden in headers:
            raise InvalidToken(f"header parameter {forbidden!r} is not accepted")
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as e:
        raise InvalidToken(f"malformed token: {e}") from e
    if not isinstance(unverified, dict):
        raise InvalidToken("malformed token: claims are not an object")
    iss = unverified.get("iss")
    if iss == ISSUER_ID:
        pub = _keys.load_public(base)
        kid = headers.get("kid")
        if kid is not None and kid != _keys.key_id(pub):
            # Rotated with an overlap window? Retired keys still verify.
            old = _keys.retired_keys(base).get(kid) if isinstance(kid, str) else None
            if old is None:
                raise InvalidToken(
                    "token was signed by a different issuer key (kid mismatch) — "
                    "the key was rotated or the token comes from another delcred home"
                )
            pub = old
        pem = pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem, ["exp", "iat", "nbf", "iss", "sub", "jti"], iss, None
    if not allow_external:
        raise InvalidToken(
            f"untrusted issuer {iss!r} for this token — only the local issuer "
            f"{ISSUER_ID!r} may sign delegation/agent tokens; external IdP "
            "tokens are only accepted as an exchange subject_token"
        )
    try:
        trusted = _trust.trusted_issuer_configs(base)
    except _trust.TrustConfigError as e:
        raise InvalidToken(f"bad trusted_issuers config: {e}") from e
    cfg = trusted.get(iss) if isinstance(iss, str) else None
    if cfg is None:
        raise InvalidToken(
            f"untrusted issuer {iss!r} — local issuer is {ISSUER_ID!r}; "
            "register external IdPs with `delcred trust-add`"
        )
    key, audience = cfg
    pem = key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem, ["exp", "iss", "sub", "aud"], iss, audience


def verify_signature(
    token: str,
    *,
    leeway: int = CLOCK_SKEW_LEEWAY,
    base: Path | None = None,
    allow_external: bool = False,
) -> dict[str, Any]:
    """Strict verification: EdDSA only, issuer pinned, expiry/nbf.

    By default only the local delcred issuer is accepted. With
    ``allow_external=True`` (exchange subject tokens only) a trusted external
    IdP registered via ``policy.yaml`` ``trusted_issuers`` / ``delcred
    trust-add`` is also accepted, and its token's ``aud`` must contain the
    audience configured for that issuer (default ``"delcred"``).

    ``typ`` is checked by :func:`verify_delegation_token`, not here.
    Raises TokenError subclasses. Does NOT check revocation (caller does).
    """
    pub_pem, required, issuer, audience = _key_for_issuer(token, base, allow_external)
    try:
        claims = jwt.decode(
            token,
            pub_pem,
            algorithms=["EdDSA"],
            issuer=issuer,
            leeway=leeway,
            audience=audience,
            options={
                "require": required,
                # Local tokens: audience is enforced explicitly by
                # verify_delegation_token (clear confused-deputy error).
                # External subject tokens: PyJWT enforces the configured aud.
                "verify_aud": audience is not None,
            },
        )
    except jwt.ExpiredSignatureError as e:
        raise ExpiredToken("token expired") from e
    except jwt.InvalidIssuerError as e:
        raise InvalidToken(f"untrusted issuer: {e}") from e
    except jwt.InvalidAudienceError as e:
        raise InvalidToken(
            f"subject token audience rejected: {e} (expected {audience!r})"
        ) from e
    except jwt.PyJWTError as e:
        raise InvalidToken(f"token rejected: {e}") from e
    return claims


def verify_delegation_token(
    token: str,
    *,
    expected_resource: str | None = None,
    required_scopes: str | list[str] | set[str] | None = None,
    leeway: int = CLOCK_SKEW_LEEWAY,
    base: Path | None = None,
) -> dict[str, Any]:
    """Verify a delegation token, enforce audience pinning (confused-deputy
    defense) and, if given, that every ``required_scopes`` entry is granted
    (least privilege per operation; raises :class:`InsufficientScope`)."""
    claims = verify_signature(token, leeway=leeway, base=base)
    if claims.get("kind") != "delegation":
        raise InvalidToken(f"not a delegation token (kind={claims.get('kind')!r})")
    actors = actor_chain(claims)  # raises InvalidToken on a malformed act
    if not actors:
        raise InvalidToken("delegation token missing act.sub (agent identity)")
    chain = claims.get("chain", [])
    if (
        not isinstance(chain, list)
        or len(chain) != len(actors) - 1
        or not all(isinstance(j, str) and j for j in chain)
    ):
        raise InvalidToken("delegation token has an inconsistent actor chain")
    if "cnf" in claims:
        cnf = claims["cnf"]
        if not (
            isinstance(cnf, dict)
            and set(cnf) == {"jkt"}
            and isinstance(cnf["jkt"], str)
            and cnf["jkt"]
        ):
            # Unknown confirmation method: we cannot enforce it, so refuse.
            raise InvalidToken("unsupported cnf confirmation (only cnf.jkt is understood)")
    try:
        typ = str(jwt.get_unverified_header(token).get("typ", "")).lower()
    except jwt.PyJWTError as e:  # pragma: no cover - verify_signature parsed it
        raise InvalidToken(f"malformed token header: {e}") from e
    if typ not in ("at+jwt", "application/at+jwt"):
        raise InvalidToken(f"not an access token (typ={typ!r}; expected 'at+jwt')")
    if expected_resource is not None and claims.get("aud") != expected_resource:
        raise InvalidToken(
            f"audience mismatch: token is for {claims.get('aud')!r}, "
            f"not {expected_resource!r}"
        )
    need = normalize_scopes(required_scopes)
    if need:
        have = scopes_of(claims)
        missing = need - have
        if missing:
            raise InsufficientScope(sorted(need), sorted(missing), sorted(have))
    return claims


def actor_chain(claims: dict[str, Any]) -> list[str]:
    """Acting agents, leaf (current actor) first, root (first delegatee) last.

    ``act`` nests per RFC 8693 §4.4: ``{"sub": leaf, "act": {"sub": parent}}``.
    Raises :class:`InvalidToken` for a malformed or over-deep chain.
    """
    out: list[str] = []
    node: Any = claims.get("act")
    while node is not None:
        if not isinstance(node, dict) or not isinstance(node.get("sub"), str) or not node["sub"]:
            raise InvalidToken("malformed act claim")
        out.append(node["sub"])
        if len(out) > MAX_CHAIN_DEPTH + 1:
            raise InvalidToken("actor chain exceeds the depth cap")
        node = node.get("act")
    return out


def user_issuer(claims: dict[str, Any]) -> str:
    """Issuer that vouched for the human in ``claims`` (``(iss, sub)`` identity)."""
    if claims.get("kind") == "delegation":
        return str(claims.get("user_iss") or ISSUER_ID)
    return str(claims.get("iss") or ISSUER_ID)


def scopes_of(claims: dict[str, Any]) -> set[str]:
    return set(str(claims.get("scope", "")).split())
