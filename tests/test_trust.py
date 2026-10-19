"""Trusted external issuers (IdPs) + trust-add CLI."""

import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import delcred
from delcred import trust
from delcred.exchange import ExchangeError, exchange
from delcred.tokens import InvalidToken, verify_signature
from delcred.trust import TrustConfigError

IDP_ISS = "https://idp.example.com"


@pytest.fixture
def idp_keypair(tmp_path):
    """A genuinely external IdP keypair (not delcred's issuer key)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_path = tmp_path / "idp-pub.pem"
    pub_path.write_bytes(
        pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return priv_pem, pub_path


def _idp_token(priv_pem, iss=IDP_ISS, sub="u_alice", **extra):
    now = int(time.time())
    claims = {"iss": iss, "sub": sub, "iat": now, "exp": now + 300}
    claims.update(extra)
    return jwt.encode(claims, priv_pem, algorithm="EdDSA")


def test_untrusted_issuer_rejected(home, idp_keypair):
    priv_pem, _ = idp_keypair
    tok = _idp_token(priv_pem)
    with pytest.raises(InvalidToken, match="untrusted issuer"):
        verify_signature(tok, base=home)


def test_trusted_issuer_accepted(home, idp_keypair):
    priv_pem, pub_path = idp_keypair
    delcred.trust_add(IDP_ISS, str(pub_path), base=home)
    tok = _idp_token(priv_pem)
    claims = verify_signature(tok, base=home)
    assert claims["iss"] == IDP_ISS
    assert claims["sub"] == "u_alice"


def test_trusted_issuer_wrong_key_rejected(home, idp_keypair):
    _, pub_path = idp_keypair
    delcred.trust_add(IDP_ISS, str(pub_path), base=home)
    # signed by a *different* key than the registered one
    other = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with pytest.raises(InvalidToken):
        verify_signature(_idp_token(other), base=home)


def test_trusted_issuer_tampered_rejected(home, idp_keypair):
    priv_pem, pub_path = idp_keypair
    delcred.trust_add(IDP_ISS, str(pub_path), base=home)
    tok = _idp_token(priv_pem)
    parts = tok.split(".")
    import base64
    import json

    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    payload["sub"] = "u_bob"
    bad_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    with pytest.raises(InvalidToken):
        verify_signature(".".join([parts[0], bad_payload, parts[2]]), base=home)


def test_trust_add_copies_key_and_updates_policy(home, idp_keypair):
    _, pub_path = idp_keypair
    dest = delcred.trust_add(IDP_ISS, str(pub_path), base=home)
    assert dest.exists()
    assert dest.parent == home / "trusted_issuers"
    text = (home / "policy.yaml").read_text()
    assert "trusted_issuers:" in text
    assert IDP_ISS in text
    assert len(trust.trusted_issuers(home)) == 1


def test_trust_add_rejects_non_ed25519(home, tmp_path):
    # RSA key must be refused — delcred is EdDSA-only, no algorithm confusion.
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub = tmp_path / "rsa.pem"
    rsa_pub.write_bytes(
        rsa_priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    with pytest.raises(TrustConfigError, match="Ed25519"):
        delcred.trust_add("https://rsa-idp.example.com", str(rsa_pub), base=home)


def test_trust_add_rejects_shadowing_local_issuer(home, idp_keypair):
    _, pub_path = idp_keypair
    with pytest.raises(TrustConfigError, match="local issuer"):
        delcred.trust_add("delcred", str(pub_path), base=home)


def test_exchange_with_external_subject_token(home, actor, idp_keypair):
    """Blueprint Decision 2: delcred accepts external subject tokens."""
    priv_pem, pub_path = idp_keypair
    delcred.trust_add(IDP_ISS, str(pub_path), base=home)
    ext_subject = _idp_token(priv_pem)  # no delcred "kind" — a real IdP token
    result = exchange(
        subject_token=ext_subject,
        actor_token=actor,
        scope="invoices:read",
        resource="https://api.acme.test/v1",
        base=home,
    )
    assert result.claims["sub"] == "u_alice"
    assert result.claims["act"] == {"sub": "billing-agent"}


def test_external_token_with_agent_kind_still_rejected(home, actor, idp_keypair):
    """Token laundering via a trusted IdP is still blocked: kind=agent."""
    priv_pem, pub_path = idp_keypair
    delcred.trust_add(IDP_ISS, str(pub_path), base=home)
    sneaky = _idp_token(priv_pem, kind="agent")
    with pytest.raises(ExchangeError, match="must identify a user"):
        exchange(
            subject_token=sneaky,
            actor_token=actor,
            scope="invoices:read",
            resource="https://api.acme.test/v1",
            base=home,
        )


def test_malformed_trusted_issuers_config_rejected(home, idp_keypair):
    (home / "policy.yaml").write_text("trusted_issuers: [not, a, mapping]\n")
    priv_pem, _ = idp_keypair
    # well-formed token, unknown issuer → config load blows up first
    with pytest.raises(InvalidToken, match="trusted_issuers"):
        verify_signature(_idp_token(priv_pem), base=home)


def test_trust_add_slug_collision_keeps_both_keys(home, idp_keypair, tmp_path):
    """Two issuers slugging to one filename must not overwrite each other."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    _, pub1 = idp_keypair
    pub2 = tmp_path / "idp2.pem"
    pub2.write_bytes(
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    # "https://a/b" and "https://a_b" both slug to "https___a_b"
    d1 = delcred.trust_add("https://a/b", str(pub1), base=home)
    d2 = delcred.trust_add("https://a_b", str(pub2), base=home)
    assert d1 != d2
    assert d1.read_bytes() != d2.read_bytes()
    assert len(trust.trusted_issuers(home)) == 2


def test_trust_add_rejects_malicious_issuer_string(home, idp_keypair):
    _, pub_path = idp_keypair
    with pytest.raises(TrustConfigError):
        delcred.trust_add('https://evil.example.com":\n  "x', str(pub_path), base=home)
