"""Deterministic cross-language conformance vectors for the delcred verifier spec.

``delcred vectors --out spec/vectors`` writes ``vectors.json``: a public JWKS
plus ~70 cases (valid tokens, every classic JWT attack, boundary timing,
chained delegations, DPoP proofs, signed revocation bulletins), each with the
verdict a conforming verifier MUST return. Signatures are Ed25519 and
therefore deterministic, and the signing seeds are *derived from public
strings* below — these are test keys, they protect nothing — so regenerating
yields byte-identical output (a test enforces that).

A verifier in any language passes if, for every case, ``ok`` and ``code``
equal ``expect``. ``spec/verifiers/`` has Node and Go implementations.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import keys as _keys
from . import pop as _pop
from ._jws import b64url_encode, sign_compact
from .offline import BULLETIN_TYP, verify_offline

SPEC_VERSION = 1
NOW = 1_800_000_000
RES = "https://api.acme.test/v1"
LEEWAY = 60
BULLETIN_MAX_AGE = 300


def _key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"delcred conformance vectors v1 / {label} / public test key".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


ISSUER_KEY = _key("issuer")
OTHER_KEY = _key("attacker")
CLIENT_KEY = _key("dpop client")
KID = _keys.key_id(ISSUER_KEY.public_key())


def _claims(**over: Any) -> dict[str, Any]:
    c: dict[str, Any] = {
        "iss": "delcred",
        "sub": "u_alice",
        "act": {"sub": "billing-agent"},
        "kind": "delegation",
        "user_iss": "delcred",
        "scope": "customers:read invoices:read",
        "aud": RES,
        "jti": "jti-0001",
        "iat": NOW - 60,
        "nbf": NOW - 60,
        "exp": NOW + 840,
    }
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def _hdr(**over: Any) -> dict[str, Any]:
    h: dict[str, Any] = {"alg": "EdDSA", "kid": KID, "typ": "at+jwt"}
    h.update(over)
    return {k: v for k, v in h.items() if v is not None}


def _tok(claims: dict | None = None, header: dict | None = None, key: Ed25519PrivateKey = ISSUER_KEY) -> str:
    return sign_compact(header or _hdr(), claims or _claims(), key)


def _bulletin(*, jtis=(), agents=(), users=(), iat=NOW - 10, exp=NOW + 290, key=ISSUER_KEY, typ=BULLETIN_TYP, iss="delcred") -> str:
    payload = {
        "iss": iss, "iat": iat, "exp": exp, "seq": 1,
        "jtis": list(jtis), "agents": list(agents), "users": list(users),
    }
    return sign_compact({"alg": "EdDSA", "typ": typ, "kid": KID}, payload, key)


def _proof(token: str, *, method="GET", url=RES + "/invoices", jti="proof-0001", iat=NOW,
           key=CLIENT_KEY, ath: str | None = "auto", htu: str | None = None, typ="dpop+jwt") -> str:
    claims: dict[str, Any] = {"jti": jti, "htm": method, "htu": htu or url, "iat": iat}
    if ath == "auto":
        claims["ath"] = _pop.access_token_hash(token)
    elif ath is not None:
        claims["ath"] = ath
    return sign_compact({"typ": typ, "alg": "EdDSA", "jwk": _pop.public_jwk(key)}, claims, key)


def _forge(header: dict, payload: dict, sig: bytes = b"") -> str:
    h = b64url_encode(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    return f"{h}.{p}.{b64url_encode(sig)}"


def build() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []

    def case(name: str, token: str, expect: str | list[str], *, why: str, resource: str = RES,
             scopes: list[str] | None = None, now: int = NOW, bulletin: str | None = None,
             require_bulletin: bool = False, dpop: dict | None = None, repeat: int = 1) -> None:
        codes = [expect] * repeat if isinstance(expect, str) else expect
        cases.append({
            "name": name, "why": why, "token": token,
            "request": {
                "resource": resource, "required_scopes": scopes, "now": now,
                "bulletin": bulletin, "require_bulletin": require_bulletin, "dpop": dpop,
                "repeat": len(codes),
            },
            "expect": codes,
        })

    ok = "ok"
    base = _tok()
    case("valid_basic", base, ok, why="well-formed token, right audience")
    case("valid_required_scope", base, ok, scopes=["invoices:read"], why="token holds the required scope")
    case("valid_two_scopes", base, ok, scopes=["invoices:read", "customers:read"], why="all required scopes held")
    case("valid_chained_depth2", _tok(_claims(
        act={"sub": "summarizer", "act": {"sub": "billing-agent"}}, chain=["jti-parent"], jti="jti-0002")),
        ok, why="RFC 8693 nested act with matching chain")
    case("valid_chained_depth3", _tok(_claims(
        act={"sub": "c", "act": {"sub": "b", "act": {"sub": "a"}}}, chain=["j1", "j2"])),
        ok, why="three actors, two ancestor jtis")
    case("leeway_expired_boundary_ok", base, ok, now=NOW + 840 + LEEWAY, why="exp + 60s leeway is still valid")
    case("expired", base, "expired", now=NOW + 840 + LEEWAY + 1, why="one second past exp + leeway")
    case("leeway_nbf_boundary_ok", _tok(_claims(nbf=NOW + LEEWAY)), ok, why="nbf = now + 60s is within leeway")
    case("not_yet_valid", _tok(_claims(nbf=NOW + LEEWAY + 1)), "not_yet_valid", why="nbf one second beyond leeway")
    case("wrong_audience", base, "wrong_audience", resource="https://other.test/v1", why="confused-deputy: token for API A at API B")
    case("audience_prefix_not_equal", base, "wrong_audience", resource=RES + "/", why="audience compare is exact string equality")
    case("audience_array_rejected", _tok(_claims(aud=[RES])), "invalid_token", why="aud must be a single string")
    case("insufficient_scope", base, "insufficient_scope", scopes=["invoices:write"], why="step-up needed")
    case("insufficient_scope_partial", base, "insufficient_scope", scopes=["invoices:read", "invoices:write"], why="every required scope must be held")
    case("scope_nbsp_is_not_a_separator", _tok(_claims(scope="invoices:read\u00a0invoices:write")), "insufficient_scope",
         scopes=["invoices:write"], why="only ASCII space separates scopes; NBSP is part of the token")
    case("scope_prefix_not_substring", _tok(_claims(scope="invoices:readonly")), "insufficient_scope",
         scopes=["invoices:read"], why="scope compare is whole-token, not prefix")

    # --- classic JWT attacks -------------------------------------------------
    case("alg_none", _forge({"alg": "none", "kid": KID, "typ": "at+jwt"}, _claims()), "invalid_token", why="alg=none")
    h = b64url_encode(json.dumps({"alg": "HS256", "kid": KID, "typ": "at+jwt"}, sort_keys=True, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(_claims(), sort_keys=True, separators=(",", ":")).encode())
    pub_raw = ISSUER_KEY.public_key().public_bytes_raw()
    mac = hmac.new(pub_raw, f"{h}.{p}".encode(), hashlib.sha256).digest()
    signing_input = f"{h}.{p}.{b64url_encode(mac)}"
    case("alg_hs256_public_key_as_secret", signing_input, "invalid_token", why="HMAC keyed with the public key (alg confusion)")
    case("alg_rs256_header", _tok(header=_hdr(alg="RS256")), "invalid_token", why="only EdDSA is accepted")
    case("header_missing_typ", _tok(header=_hdr(typ=None)), "invalid_token", why="typ must be at+jwt (RFC 9068)")
    case("header_typ_jwt", _tok(header=_hdr(typ="JWT")), "invalid_token", why="a plain JWT is not an access token")
    case("header_typ_case_insensitive", _tok(header=_hdr(typ="AT+JWT")), ok, why="typ compares case-insensitively")
    case("header_application_at_jwt", _tok(header=_hdr(typ="application/at+jwt")), ok, why="full media type accepted")
    case("header_embedded_jwk", _tok(header=_hdr(jwk=_pop.public_jwk(OTHER_KEY)), key=OTHER_KEY), "invalid_token",
         why="attacker-supplied key in the header must never be used")
    case("header_jku", _tok(header=_hdr(jku="https://evil.test/jwks.json")), "invalid_token", why="jku is not accepted")
    case("header_x5u", _tok(header=_hdr(x5u="https://evil.test/cert")), "invalid_token", why="x5u is not accepted")
    case("header_crit", _tok(header=_hdr(crit=["exp"])), "invalid_token", why="crit extensions are not understood")
    case("kid_unknown", _tok(header=_hdr(kid="not-in-the-jwks")), "invalid_token", why="kid must resolve in the JWKS")
    case("kid_missing", _tok(header=_hdr(kid=None)), "invalid_token", why="offline verification requires kid")
    case("signature_wrong_key", _tok(key=OTHER_KEY), "invalid_token", why="correct kid, attacker's signature")
    tampered = base.split(".")
    tampered[1] = b64url_encode(json.dumps(_claims(scope="admin:all"), sort_keys=True, separators=(",", ":")).encode())
    case("payload_tampered", ".".join(tampered), "invalid_token", scopes=["admin:all"], why="payload edited after signing")
    case("signature_truncated", base[:-4], "invalid_token", why="signature shorter than 64 bytes")
    case("signature_padded_base64", base + "=", "invalid_token", why="base64url must be unpadded")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = base[-1]
    alt = alphabet[alphabet.index(last) ^ 1]  # same 4 data bits, different padding bits
    case("signature_noncanonical_base64", base[:-1] + alt, "invalid_token",
         why="trailing padding bits must be zero (same bytes, different text = malleable token)")
    case("token_four_segments", base + ".AAAA", "invalid_token", why="compact JWS has exactly three segments")
    case("token_empty_signature", ".".join(base.split(".")[:2]) + ".", "invalid_token", why="empty signature")
    case("token_not_json_payload", "eyJhbGciOiJFZERTQSJ9.bm90LWpzb24.AAAA", "invalid_token", why="payload is not JSON")
    case("token_oversized", _tok(_claims(pad="x" * 17000)), "invalid_token", why="tokens over 16 KiB are refused before parsing")
    case("order_signature_before_expiry", ".".join(tampered), "invalid_token", now=NOW + 99999, why="bad signature wins over expiry")
    case("order_expiry_before_audience", base, "expired", resource="https://other.test/v1", now=NOW + 99999, why="expired wins over audience")
    case("order_audience_before_scope", base, "wrong_audience", resource="https://other.test/v1", scopes=["x:y"], why="audience wins over scope")

    # --- claim hygiene -------------------------------------------------------
    case("issuer_wrong", _tok(_claims(iss="https://evil.test")), "invalid_token", why="iss must be exactly delcred")
    case("kind_user", _tok(_claims(kind="user")), "invalid_token", why="an identity assertion is not a delegation")
    case("kind_agent", _tok(_claims(kind="agent")), "invalid_token", why="an agent identity token is not a delegation")
    case("missing_sub", _tok(_claims(sub=None)), "invalid_token", why="sub required")
    case("missing_act", _tok(_claims(act=None)), "invalid_token", why="act required (who is acting)")
    case("act_not_object", _tok(_claims(act="billing-agent")), "invalid_token", why="act must be an object")
    case("missing_jti", _tok(_claims(jti=None)), "invalid_token", why="jti required (revocation handle)")
    case("exp_as_string", _tok(_claims(exp="1800000840")), "invalid_token", why="exp must be an integer")
    case("exp_as_float", _tok(_claims(exp=1800000840.5)), "invalid_token", why="NumericDate must be an integer in delcred")
    case("exp_missing", _tok(_claims(exp=None)), "invalid_token", why="exp required")
    case("chain_length_mismatch", _tok(_claims(act={"sub": "b", "act": {"sub": "a"}}, chain=[])), "invalid_token",
         why="chain must list one ancestor jti per extra actor")
    case("chain_without_nested_act", _tok(_claims(chain=["j1"])), "invalid_token", why="chain present but act not nested")
    case("act_too_deep", _tok(_claims(act={"sub": "e", "act": {"sub": "d", "act": {"sub": "c", "act": {"sub": "b", "act": {"sub": "a", "act": {"sub": "z"}}}}}},
                                  chain=["1", "2", "3", "4", "5"])), "invalid_token", why="more than 4 sub-delegation hops")
    case("cnf_unsupported_member", _tok(_claims(cnf={"x5t#S256": "abc"})), "invalid_token", why="unknown confirmation method fails closed")
    case("cnf_jkt_empty", _tok(_claims(cnf={"jkt": ""})), "invalid_token", why="empty jkt")

    # --- revocation bulletin -------------------------------------------------
    case("bulletin_clean", base, ok, bulletin=_bulletin(jtis=["unrelated"], agents=["other"]), why="fresh bulletin, nothing matching")
    case("revoked_jti", base, "revoked", bulletin=_bulletin(jtis=["jti-0001"]), why="token id on the bulletin")
    case("revoked_agent", base, "revoked", bulletin=_bulletin(agents=["billing-agent"]), why="agent kill switch")
    case("revoked_user_any_issuer", base, "revoked", bulletin=_bulletin(users=[{"sub": "u_alice"}]), why="user kill switch without issuer")
    case("revoked_user_matching_issuer", base, "revoked", bulletin=_bulletin(users=[{"sub": "u_alice", "iss": "delcred"}]), why="(issuer, sub) match")
    case("not_revoked_user_other_issuer", base, ok, bulletin=_bulletin(users=[{"sub": "u_alice", "iss": "https://idp.test"}]),
         why="same sub under another IdP is a different user")
    chained = _tok(_claims(act={"sub": "summarizer", "act": {"sub": "billing-agent"}}, chain=["jti-parent"], jti="jti-0002"))
    case("revoked_chain_ancestor_jti", chained, "revoked", bulletin=_bulletin(jtis=["jti-parent"]), why="revoking the parent delegation kills the child")
    case("revoked_chain_root_agent", chained, "revoked", bulletin=_bulletin(agents=["billing-agent"]), why="revoking any agent in the chain kills it")
    case("revoked_chain_leaf_agent", chained, "revoked", bulletin=_bulletin(agents=["summarizer"]), why="…including the leaf")
    case("bulletin_stale", base, "revocation_data_invalid", bulletin=_bulletin(iat=NOW - BULLETIN_MAX_AGE - 1, exp=NOW + 600),
         why="bulletin older than the verifier's max age (rollback defence)")
    case("bulletin_expired", base, "revocation_data_invalid", bulletin=_bulletin(iat=NOW - 200, exp=NOW - LEEWAY - 1), why="bulletin past its own exp")
    case("bulletin_future", base, "revocation_data_invalid", bulletin=_bulletin(iat=NOW + LEEWAY + 1, exp=NOW + 600), why="bulletin from the future")
    case("bulletin_wrong_key", base, "revocation_data_invalid", bulletin=_bulletin(key=OTHER_KEY), why="forged empty bulletin")
    case("bulletin_wrong_typ", base, "revocation_data_invalid", bulletin=_bulletin(typ="JWT"), why="bulletin typ must be delcred-rev+jwt")
    case("bulletin_wrong_issuer", base, "revocation_data_invalid", bulletin=_bulletin(iss="evil"), why="bulletin issuer must be delcred")
    case("bulletin_garbage", base, "revocation_data_invalid", bulletin="not.a.jws", why="unparseable bulletin fails closed")
    case("bulletin_required_but_absent", base, "revocation_data_invalid", require_bulletin=True, why="verifier policy: fresh bulletin mandatory")
    case("bulletin_not_checked_after_other_failure", base, "wrong_audience", resource="https://other.test/v1", bulletin=_bulletin(key=OTHER_KEY),
         why="an earlier failure code is reported first")

    # --- DPoP ---------------------------------------------------------------
    jkt = _pop.thumbprint(CLIENT_KEY)
    bound = _tok(_claims(cnf={"jkt": jkt}, jti="jti-bound"))
    dp = lambda proof, m="GET", u=RES + "/invoices": {"proof": proof, "method": m, "url": u}
    case("dpop_valid", bound, ok, dpop=dp(_proof(bound)), why="bound token + matching proof")
    case("dpop_valid_default_port_and_query", bound, ok,
         dpop=dp(_proof(bound, htu="HTTPS://API.ACME.TEST:443/v1/invoices"), u=RES + "/invoices?limit=5#x"),
         why="htu compared without query/fragment, case-insensitive host, default port dropped")
    case("dpop_missing", bound, "dpop_required", why="sender-constrained token without a proof")
    case("dpop_method_mismatch", bound, "invalid_dpop_proof", dpop=dp(_proof(bound, method="POST")), why="htm differs from request")
    case("dpop_url_mismatch", bound, "invalid_dpop_proof", dpop=dp(_proof(bound, url=RES + "/customers")), why="htu differs from request")
    case("dpop_wrong_ath", bound, "invalid_dpop_proof", dpop=dp(_proof(bound, ath=_pop.access_token_hash("another token"))), why="proof is for a different token")
    case("dpop_no_ath", bound, "invalid_dpop_proof", dpop=dp(_proof(bound, ath=None)), why="ath required with an access token")
    case("dpop_wrong_key", bound, "invalid_dpop_proof", dpop=dp(_proof(bound, key=OTHER_KEY)), why="proof key is not the one in cnf.jkt (stolen token)")
    case("dpop_stale", bound, "invalid_dpop_proof", dpop=dp(_proof(bound, iat=NOW - 121)), why="iat older than 120 s")
    case("dpop_future", bound, "invalid_dpop_proof", dpop=dp(_proof(bound, iat=NOW + 61)), why="iat more than 60 s ahead")
    case("dpop_window_edge_ok", bound, ok, dpop=dp(_proof(bound, iat=NOW - 120)), why="iat exactly 120 s old")
    case("dpop_wrong_typ", bound, "invalid_dpop_proof", dpop=dp(_proof(bound, typ="JWT")), why="proof typ must be dpop+jwt")
    case("dpop_replay", bound, [ok, "invalid_dpop_proof"], dpop=dp(_proof(bound, jti="replayed")), why="same proof twice")
    case("dpop_garbage", bound, "invalid_dpop_proof", dpop=dp("x.y.z"), why="unparseable proof")
    case("dpop_ignored_for_unbound_token", base, ok, dpop=dp(_proof(base)), why="a proof on an unbound token is ignored")

    return {
        "spec_version": SPEC_VERSION,
        "issuer": "delcred",
        "leeway_seconds": LEEWAY,
        "bulletin_max_age_seconds": BULLETIN_MAX_AGE,
        "resource": RES,
        "jwks": {"keys": [_keys.public_jwk(ISSUER_KEY.public_key())]},
        "dpop_client_thumbprint": jkt,
        "cases": cases,
    }


def write(path: Path) -> None:
    path.write_text(json.dumps(build(), indent=1, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def run(doc: dict[str, Any]) -> list[str]:
    """Run the Python reference verifier over the vectors; returns failure messages."""
    failures: list[str] = []
    for c in doc["cases"]:
        r = c["request"]
        cache = _pop.ReplayCache()
        got: list[str] = []
        for _ in range(r["repeat"]):
            d = r.get("dpop") or {}
            v = verify_offline(
                c["token"], jwks=doc["jwks"], resource=r["resource"],
                required_scopes=r["required_scopes"], now=r["now"], leeway=doc["leeway_seconds"],
                bulletin=r["bulletin"], bulletin_max_age=doc["bulletin_max_age_seconds"],
                require_bulletin=r["require_bulletin"], dpop_proof=d.get("proof"),
                http_method=d.get("method"), http_url=d.get("url"), replay_cache=cache,
            )
            got.append(v.code)
        if got != c["expect"]:
            failures.append(f"{c['name']}: expected {c['expect']}, got {got}")
    return failures
