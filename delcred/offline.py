"""Offline verification: check a delcred token with only the issuer's JWKS.

This is the *reference implementation of the verifier spec* in
``spec/VERIFICATION.md``. It touches no delcred home, no database, no
network and no clock except the one you pass in. The Node and Go verifiers in
``spec/verifiers/`` implement the same rules and are tested against the same
vectors, so a resource server in any language gets identical answers.

    from delcred.offline import verify_offline
    v = verify_offline(token, jwks=jwks_json, resource="https://api.acme.test/v1",
                       required_scopes="invoices:read", bulletin=signed_bulletin)
    if not v.ok: reject(v.code)        # v.claims on success

Result codes (stable, part of the spec): ``ok``, ``invalid_token``,
``expired``, ``not_yet_valid``, ``wrong_audience``, ``insufficient_scope``,
``dpop_required``, ``invalid_dpop_proof``, ``revoked``,
``revocation_data_invalid``.

Revocation: JWKS alone cannot tell a verifier that an agent was revoked. The
issuer publishes a short-lived *signed revocation bulletin*
(``delcred revocations export`` / ``GET /revocations.jwt``); pass it as
``bulletin=`` and revocations take effect at the verifier within the bulletin's
age limit instead of "when the token expires".
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, TypeGuard

from . import pop as _pop
from ._common import CLOCK_SKEW_LEEWAY, ISSUER_ID, MAX_CHAIN_DEPTH, parse_scope
from ._jws import JWSError, check_header, ed25519_verify, parse_compact

BULLETIN_TYP = "delcred-rev+jwt"
BULLETIN_MAX_AGE = 300


@dataclass
class Verdict:
    ok: bool
    code: str
    detail: str = ""
    claims: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.ok


def _fail(code: str, detail: str = "") -> Verdict:
    return Verdict(False, code, detail)


def _jwk_for(jwks: Any, kid: Any) -> str | None:
    if not isinstance(jwks, dict) or not isinstance(kid, str):
        return None
    for k in jwks.get("keys", []) or []:
        if (
            isinstance(k, dict)
            and k.get("kid") == kid
            and k.get("kty") == "OKP"
            and k.get("crv") == "Ed25519"
            and k.get("alg", "EdDSA") == "EdDSA"
            and k.get("use", "sig") == "sig"
            and isinstance(k.get("x"), str)
        ):
            return k["x"]
    return None


def _verify_jws(token: str, jwks: Any, typ: set[str]) -> tuple[dict, dict]:
    header, payload, signing_input, sig = parse_compact(token)
    check_header(header)
    if str(header.get("typ", "")).lower() not in typ:
        raise JWSError(f"typ {header.get('typ')!r} not accepted here")
    x = _jwk_for(jwks, header.get("kid"))
    if x is None:
        raise JWSError("kid not found in the JWKS")
    if not ed25519_verify(x, signing_input, sig):
        raise JWSError("signature invalid")
    return header, payload


def _int(v: Any) -> TypeGuard[int]:
    return isinstance(v, int) and not isinstance(v, bool)


def check_bulletin(
    bulletin: str, jwks: Any, *, now: int, max_age: int = BULLETIN_MAX_AGE, leeway: int = CLOCK_SKEW_LEEWAY
) -> dict[str, Any]:
    """Validate a signed revocation bulletin; returns its payload or raises JWSError."""
    _, p = _verify_jws(bulletin, jwks, {BULLETIN_TYP})
    if p.get("iss") != ISSUER_ID:
        raise JWSError("bulletin issuer mismatch")
    iat, exp = p.get("iat"), p.get("exp")
    if not (_int(iat) and _int(exp)):
        raise JWSError("bulletin lacks iat/exp")
    if iat > now + leeway or now - iat > max_age or now > exp + leeway:
        raise JWSError("bulletin is stale")
    for name in ("jtis", "agents"):
        if not (isinstance(p.get(name), list) and all(isinstance(i, str) for i in p[name])):
            raise JWSError(f"bulletin {name} malformed")
    if not (
        isinstance(p.get("users"), list)
        and all(
            isinstance(u, dict)
            and isinstance(u.get("sub"), str)
            and isinstance(u.get("iss", ""), str)
            for u in p["users"]
        )
    ):
        raise JWSError("bulletin users malformed")
    return p


def _actors(claims: dict[str, Any]) -> list[str] | None:
    out: list[str] = []
    node: Any = claims.get("act")
    while node is not None:
        if not isinstance(node, dict) or not isinstance(node.get("sub"), str) or not node["sub"]:
            return None
        out.append(node["sub"])
        if len(out) > MAX_CHAIN_DEPTH + 1:
            return None
        node = node.get("act")
    return out or None


def verify_offline(
    token: str,
    *,
    jwks: Any,
    resource: str,
    required_scopes: str | list[str] | None = None,
    now: int | None = None,
    leeway: int = CLOCK_SKEW_LEEWAY,
    issuer: str = ISSUER_ID,
    bulletin: str | None = None,
    bulletin_max_age: int = BULLETIN_MAX_AGE,
    require_bulletin: bool = False,
    dpop_proof: str | None = None,
    http_method: str | None = None,
    http_url: str | None = None,
    replay_cache: _pop.ReplayCache | None = None,
) -> Verdict:
    """Verify a delegation token without a delcred home. Never raises on bad input."""
    t = int(time.time()) if now is None else now
    try:
        header, claims, signing_input, sig = parse_compact(token)
        check_header(header)
    except JWSError as e:
        return _fail("invalid_token", str(e))
    if str(header.get("typ", "")).lower() not in ("at+jwt", "application/at+jwt"):
        return _fail("invalid_token", "typ must be at+jwt")
    x = _jwk_for(jwks, header.get("kid"))
    if x is None:
        return _fail("invalid_token", "kid not found in the JWKS")
    if not ed25519_verify(x, signing_input, sig):
        return _fail("invalid_token", "signature invalid")
    if claims.get("iss") != issuer:
        return _fail("invalid_token", "issuer mismatch")
    exp, nbf, iat = claims.get("exp"), claims.get("nbf"), claims.get("iat")
    if not (_int(exp) and _int(nbf) and _int(iat)):
        return _fail("invalid_token", "exp/nbf/iat must be integers")
    if t > exp + leeway:
        return _fail("expired", "token expired")
    if t < nbf - leeway:
        return _fail("not_yet_valid", "token not yet valid")
    if claims.get("kind") != "delegation":
        return _fail("invalid_token", "not a delegation token")
    actors = _actors(claims)
    sub, jti = claims.get("sub"), claims.get("jti")
    if actors is None or not (isinstance(sub, str) and sub) or not (isinstance(jti, str) and jti):
        return _fail("invalid_token", "missing sub/act/jti")
    chain = claims.get("chain", [])
    if not (
        isinstance(chain, list)
        and len(chain) == len(actors) - 1
        and all(isinstance(j, str) and j for j in chain)
    ):
        return _fail("invalid_token", "inconsistent actor chain")
    cnf = claims.get("cnf")
    if "cnf" in claims and not (
        isinstance(cnf, dict) and set(cnf) == {"jkt"} and isinstance(cnf["jkt"], str) and cnf["jkt"]
    ):
        return _fail("invalid_token", "unsupported cnf")
    aud = claims.get("aud")
    if not isinstance(aud, str):
        return _fail("invalid_token", "aud must be a string")
    if aud != resource:
        return _fail("wrong_audience", "token is for another resource")
    scope = claims.get("scope")
    if not isinstance(scope, str):
        return _fail("invalid_token", "scope must be a string")
    held = set(scope.split(" "))
    if required_scopes:
        try:
            need = set(parse_scope(required_scopes if isinstance(required_scopes, str) else " ".join(required_scopes)))
        except ValueError as e:
            return _fail("insufficient_scope", str(e))
        missing = need - held
        if missing:
            return _fail("insufficient_scope", "missing " + " ".join(sorted(missing)))
    if cnf is not None:
        if not dpop_proof or http_method is None or http_url is None:
            return _fail("dpop_required", "token is sender-constrained (cnf.jkt)")
        try:
            _pop.verify_proof(
                dpop_proof,
                method=http_method,
                url=http_url,
                access_token=token,
                expected_jkt=cnf["jkt"],
                now=t,
                cache=replay_cache,
            )
        except _pop.PopError as e:
            return _fail("invalid_dpop_proof", str(e))
    if bulletin is not None or require_bulletin:
        if bulletin is None:
            return _fail("revocation_data_invalid", "a fresh revocation bulletin is required")
        try:
            b = check_bulletin(bulletin, jwks, now=t, max_age=bulletin_max_age, leeway=leeway)
        except JWSError as e:
            return _fail("revocation_data_invalid", str(e))
        user_iss = str(claims.get("user_iss") or issuer)
        hit = (
            any(j in b["jtis"] for j in [jti, *chain])
            or any(a in b["agents"] for a in actors)
            or any(u["sub"] == sub and (not u.get("iss") or u["iss"] == user_iss) for u in b["users"])
        )
        if hit:
            return _fail("revoked", "token, agent or user is revoked")
    return Verdict(True, "ok", "", claims)
