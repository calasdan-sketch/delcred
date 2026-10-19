"""Token minting / strict verification."""

import time

import jwt
import pytest

import delcred
from delcred import keys, tokens
from delcred.tokens import (
    ExpiredToken,
    InvalidToken,
    decode_unverified,
    mint_delegation_token,
    verify_delegation_token,
    verify_signature,
)


def test_delegation_claims_shape(home):
    tok = mint_delegation_token(
        user="u_alice",
        agent="billing-agent",
        scope="invoices:read",
        resource="https://api.acme.test/v1",
        base=home,
    )
    c = decode_unverified(tok)
    assert c["iss"] == "delcred"
    assert c["sub"] == "u_alice"
    assert c["act"] == {"sub": "billing-agent"}
    assert c["kind"] == "delegation"
    assert c["scope"] == "invoices:read"
    assert c["aud"] == "https://api.acme.test/v1"
    assert c["nbf"] == c["iat"]
    assert c["exp"] - c["iat"] == 900
    assert c["jti"]


def test_typ_header_is_at_jwt(home):
    tok = mint_delegation_token(
        user="u", agent="a", scope="x", resource="https://r.test", base=home
    )
    assert jwt.get_unverified_header(tok)["typ"] == "at+jwt"
    assert jwt.get_unverified_header(tok)["alg"] == "EdDSA"


def test_verify_roundtrip(home):
    tok = mint_delegation_token(
        user="u_alice",
        agent="billing-agent",
        scope="invoices:read customers:read",
        resource="https://api.acme.test/v1",
        base=home,
    )
    claims = verify_delegation_token(tok, base=home)
    assert claims["sub"] == "u_alice"
    assert tokens.scopes_of(claims) == {"invoices:read", "customers:read"}


def test_scope_deduped_and_sorted(home):
    tok = mint_delegation_token(
        user="u", agent="a", scope="b a b", resource="https://r.test", base=home
    )
    assert decode_unverified(tok)["scope"] == "a b"


def test_expired_rejected(home):
    tok = mint_delegation_token(
        user="u", agent="a", scope="x", resource="https://r.test", ttl=-300, base=home
    )
    with pytest.raises(ExpiredToken):
        verify_signature(tok, base=home)


def test_tampered_signature_rejected(home):
    tok = mint_delegation_token(
        user="u", agent="a", scope="x", resource="https://r.test", base=home
    )
    # flip a char in the payload segment
    parts = tok.split(".")
    bad_payload = ("A" if parts[1][0] != "A" else "B") + parts[1][1:]
    with pytest.raises(InvalidToken):
        verify_signature(".".join([parts[0], bad_payload, parts[2]]), base=home)


def test_wrong_issuer_rejected(home):
    # same key, forged issuer claim — signature passes, issuer must not
    import time

    from cryptography.hazmat.primitives import serialization

    priv = keys.load_private(home)
    raw = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    now = int(time.time())
    tok = jwt.encode(
        {
            "iss": "evil-issuer",
            "sub": "u",
            "jti": "x",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
        },
        raw,
        algorithm="EdDSA",
    )
    with pytest.raises(InvalidToken, match="issuer"):
        verify_signature(tok, base=home)


def test_none_alg_rejected(home):
    # attacker crafts an unsigned token
    bad = jwt.encode(
        {
            "iss": "delcred",
            "sub": "u",
            "jti": "x",
            "iat": 1,
            "nbf": 1,
            "exp": 9999999999,
        },
        key="",
        algorithm="none",
    )
    with pytest.raises(InvalidToken):
        verify_signature(bad, base=home)


def test_hs256_confusion_rejected(home):
    # attacker signs with HS256 (any HMAC secret) hoping the verifier
    # accepts it — delcred only speaks EdDSA.
    import time

    now = int(time.time())
    bad = jwt.encode(
        {
            "iss": "delcred",
            "sub": "u",
            "jti": "x",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
        },
        key=b"attacker-hmac-secret",
        algorithm="HS256",
        headers={"typ": "at+jwt"},
    )
    with pytest.raises(InvalidToken):
        verify_signature(bad, base=home)


def test_audience_pinning_enforced(home):
    tok = mint_delegation_token(
        user="u", agent="a", scope="x", resource="https://api.acme.test/v1", base=home
    )
    with pytest.raises(InvalidToken, match="audience mismatch"):
        verify_delegation_token(tok, expected_resource="https://evil.test", base=home)
    # correct audience passes
    verify_delegation_token(
        tok, expected_resource="https://api.acme.test/v1", base=home
    )


def test_non_delegation_kind_rejected(home):
    agent_tok = delcred.agent_token("billing-agent", base=home)
    with pytest.raises(InvalidToken, match="not a delegation"):
        verify_delegation_token(agent_tok, base=home)


def test_missing_act_rejected(home):
    now = int(time.time())
    priv = keys.load_private(home)
    raw = priv.private_bytes(
        __import__(
            "cryptography.hazmat.primitives.serialization", fromlist=["x"]
        ).Encoding.PEM,
        __import__(
            "cryptography.hazmat.primitives.serialization", fromlist=["x"]
        ).PrivateFormat.PKCS8,
        __import__(
            "cryptography.hazmat.primitives.serialization", fromlist=["x"]
        ).NoEncryption(),
    )
    tok = jwt.encode(
        {
            "iss": "delcred",
            "sub": "u",
            "kind": "delegation",
            "jti": "x",
            "iat": now,
            "nbf": now,
            "exp": now + 60,
        },
        raw,
        algorithm="EdDSA",
    )
    with pytest.raises(InvalidToken, match="act"):
        verify_delegation_token(tok, base=home)


def test_clock_skew_leeway(home):
    # token with nbf 30s in the future passes with default 60s leeway
    now = int(time.time())
    priv = keys.load_private(home)
    from cryptography.hazmat.primitives import serialization

    raw = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    tok = jwt.encode(
        {
            "iss": "delcred",
            "sub": "u",
            "kind": "delegation",
            "act": {"sub": "a"},
            "scope": "x",
            "aud": "https://r.test",
            "jti": "skew1",
            "iat": now + 30,
            "nbf": now + 30,
            "exp": now + 930,
        },
        raw,
        algorithm="EdDSA",
        headers={"typ": "at+jwt"},
    )
    claims = verify_signature(tok, base=home)  # default leeway 60
    assert claims["jti"] == "skew1"
    with pytest.raises(InvalidToken):
        verify_signature(tok, leeway=0, base=home)


def test_agent_and_user_token_kinds(home):
    a = decode_unverified(delcred.agent_token("ag", base=home))
    u = decode_unverified(delcred.user_token("usr", base=home))
    assert a["kind"] == "agent" and a["sub"] == "ag"
    assert u["kind"] == "user" and u["sub"] == "usr"


def test_single_use_flag_present(home):
    tok = mint_delegation_token(
        user="u",
        agent="a",
        scope="x",
        resource="https://r.test",
        single_use=True,
        base=home,
    )
    assert decode_unverified(tok)["single_use"] is True
    tok2 = mint_delegation_token(
        user="u", agent="a", scope="x", resource="https://r.test", base=home
    )
    assert "single_use" not in decode_unverified(tok2)
