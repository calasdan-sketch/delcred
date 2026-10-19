"""Exchange: RFC 8693 happy path + every denial."""

import pytest

import delcred
from delcred.exchange import (
    ExchangeError,
    exchange,
    verify,
)
from delcred.policy import PolicyError
from delcred.tokens import decode_unverified

RES = "https://api.acme.test/v1"


def _x(home, subject, actor, **kw):
    kw.setdefault("scope", "invoices:read")
    kw.setdefault("resource", RES)
    return exchange(subject_token=subject, actor_token=actor, base=home, **kw)


def test_happy_path(home, subject, actor):
    r = _x(home, subject, actor)
    assert r.token_type == "urn:ietf:params:oauth:token-type:jwt"
    claims = decode_unverified(r.credential)
    assert claims["sub"] == "u_alice"
    assert claims["act"] == {"sub": "billing-agent"}
    assert claims["aud"] == RES
    assert r.ttl == 900
    # and it verifies
    v = verify(r.credential, expected_resource=RES, base=home)
    assert v["jti"] == claims["jti"]


def test_library_delegate(home, subject, actor):
    tok = delcred.delegate(
        scope="invoices:read",
        resource=RES,
        user_token=subject,
        agent_token=actor,
        base=home,
    )
    assert delcred.verify(tok, expected_resource=RES, base=home)["sub"] == "u_alice"


def test_no_grant_denied(home, subject, rogue_actor):
    with pytest.raises(PolicyError):
        _x(home, subject, rogue_actor)


def test_scope_escalation_denied(home, subject, actor):
    with pytest.raises(PolicyError):
        _x(home, subject, actor, scope="invoices:read invoices:write")


def test_resource_confused_deputy_denied(home, subject, actor):
    with pytest.raises(PolicyError):
        _x(home, subject, actor, resource="https://payments.evil.test")


def test_ttl_clamped_to_grant_max(home, bob_subject, actor):
    r = _x(home, bob_subject, actor, ttl=3600)
    assert r.ttl == 60  # u_bob's grant caps at 60s


def test_ttl_clamped_to_global_max(home, subject, actor):
    r = _x(home, subject, actor, ttl=10**6)
    assert r.ttl == 900  # grant max 900 wins here (< MAX_TTL)


def test_agent_token_cannot_be_subject(home, actor):
    # an agent trying to launder its own token as the "user"
    agent2 = delcred.agent_token("billing-agent", base=home)
    with pytest.raises(ExchangeError, match="must identify a user"):
        _x(home, agent2, actor)


def test_delegation_token_cannot_be_subject(home, subject, actor):
    legit = _x(home, subject, actor)
    with pytest.raises(ExchangeError, match="must identify a user"):
        _x(home, legit.credential, actor)


def test_bad_actor_token_rejected(home, subject):
    with pytest.raises(ExchangeError, match="actor_token rejected"):
        _x(home, subject, "not-a-token")


def test_bad_subject_token_rejected(home, actor):
    with pytest.raises(ExchangeError, match="subject_token rejected"):
        _x(home, "not-a-token", actor)


def test_expired_actor_rejected(home, subject):
    expired = delcred.agent_token("billing-agent", ttl=-300, base=home)
    with pytest.raises(ExchangeError, match="actor_token rejected"):
        _x(home, subject, expired)


def test_revoked_agent_denied(home, subject, actor):
    delcred.revoke_agent("billing-agent", reason="test", base=home)
    with pytest.raises(ExchangeError, match="revoked"):
        _x(home, subject, actor)


def test_revoked_user_denied(home, subject, actor):
    delcred.revoke_user("u_alice", reason="test", base=home)
    with pytest.raises(ExchangeError, match="revoked"):
        _x(home, subject, actor)


def test_external_idp_subject_token_accepted(home, actor):
    # subject tokens from an external IdP (no delcred "kind") are accepted
    # as the user — delcred is not an IdP.
    import time

    import jwt
    from cryptography.hazmat.primitives import serialization

    from delcred import keys

    priv = keys.load_private(home)
    raw = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    now = int(time.time())
    ext = jwt.encode(
        {
            "iss": "delcred",
            "sub": "u_alice",
            "jti": "ext1",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
        },
        raw,
        algorithm="EdDSA",
    )
    r = _x(home, ext, actor)
    assert decode_unverified(r.credential)["sub"] == "u_alice"


def test_single_use_grant_burns_on_verify(home, bob_subject, actor):
    r = _x(home, bob_subject, actor)  # u_bob grant is single_use
    assert decode_unverified(r.credential).get("single_use") is True
    verify(r.credential, expected_resource=RES, base=home)  # first OK
    with pytest.raises(ExchangeError, match="revoked"):
        verify(r.credential, expected_resource=RES, base=home)  # second dies


def test_verify_rejects_wrong_audience(home, subject, actor):
    r = _x(home, subject, actor)
    with pytest.raises(Exception, match="audience mismatch"):
        verify(r.credential, expected_resource="https://other.test", base=home)


def test_verify_rejects_revoked_jti(home, subject, actor):
    r = _x(home, subject, actor)
    jti = decode_unverified(r.credential)["jti"]
    delcred.revoke_token(jti, reason="test", base=home)
    with pytest.raises(ExchangeError, match="revoked"):
        verify(r.credential, expected_resource=RES, base=home)


def test_broker_key_type(home, subject, actor):
    key = delcred.delegate_api_key(
        scope="invoices:read",
        resource=RES,
        user_token=subject,
        agent_token=actor,
        base=home,
    )
    assert key.startswith("dk_")
    rec = delcred.verify_broker_key(key, base=home)
    assert rec["user"] == "u_alice" and rec["agent"] == "billing-agent"
    assert rec["resource"] == RES


def test_unsupported_token_type(home, subject, actor):
    with pytest.raises(ExchangeError, match="unsupported"):
        exchange(
            subject_token=subject,
            actor_token=actor,
            scope="invoices:read",
            resource=RES,
            requested_token_type="urn:x:weird",
            base=home,
        )


def test_audit_log_records_exchange(home, subject, actor):
    from delcred.audit import AuditLog

    _x(home, subject, actor)
    events = [e["event"] for e in AuditLog(home).tail(5)]
    assert "token_issued" in events


def test_audit_log_never_contains_token_values(home, subject, actor):
    from delcred.audit import AuditLog

    r = _x(home, subject, actor)
    raw = AuditLog(home).path.read_text()
    assert r.credential not in raw
    assert subject not in raw and actor not in raw


# --- scrutiny findings -----------------------------------------------------


def test_verify_requires_expected_resource(home, subject, actor):
    # Finding #2: audience pinning must not be skippable.
    tok = delcred.delegate(
        scope="invoices:read",
        resource=RES,
        user_token=subject,
        agent_token=actor,
        base=home,
    )
    with pytest.raises(TypeError):
        delcred.verify(tok, base=home)  # type: ignore[call-arg]


def test_exchange_rejects_empty_scope(home, subject, actor):
    # Finding #8 at the exchange layer.
    with pytest.raises(PolicyError, match="must not be empty"):
        _x(home, subject, actor, scope="   ")
