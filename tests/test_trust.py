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


def test_idp_bypass_regression_0_2_0(home, idp_keypair):
    """0.2.0 bypass: a trusted IdP could sign kind=delegation tokens that verified
    with no policy grant. A trusted IdP asserts users only."""
    priv_pem, pub_path = idp_keypair
    delcred.trust_add(IDP_ISS, str(pub_path), base=home)
    forged = jwt.encode(
        {
            "iss": IDP_ISS, "sub": "u_alice", "act": {"sub": "billing-agent"},
            "kind": "delegation", "aud": "https://api.acme.test/v1",
            "scope": "invoices:read", "iat": int(time.time()), "exp": int(time.time()) + 300,
        },
        priv_pem, algorithm="EdDSA", headers={"typ": "at+jwt"},
    )
    with pytest.raises(InvalidToken, match="must be issued by"):
        delcred.verify(forged, expected_resource="https://api.acme.test/v1", base=home)


def test_external_issuer_cannot_assert_agents(home, subject, idp_keypair):
    priv_pem, pub_path = idp_keypair
    delcred.trust_add(IDP_ISS, str(pub_path), base=home)
    ext_actor = _idp_token(priv_pem, sub="billing-agent", kind="agent")
    with pytest.raises(ExchangeError, match="actor_token must be issued by"):
        exchange(
            subject_token=subject,
            actor_token=ext_actor,
            scope="invoices:read",
            resource="https://api.acme.test/v1",
            base=home,
        )


def test_delegate_rejects_mismatched_user_assertion(home, subject, actor):
    with pytest.raises(ExchangeError, match="does not match"):
        delcred.delegate(
            user="u_bob", scope="invoices:read", resource="https://api.acme.test/v1",
            user_token=subject, agent_token=actor, base=home,
        )


# --- RS256 / ES256 trusted issuers: algorithm pinned per issuer -------------

from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402

RSA_ISS = "https://okta.example.com"


def _pem_pair(priv, tmp_path, name):
    pub_path = tmp_path / f"{name}.pem"
    pub_path.write_bytes(
        priv.public_key().public_bytes(
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


def _signed(priv_pem, alg, iss, **extra):
    now = int(time.time())
    claims = {"iss": iss, "sub": "u_alice", "iat": now, "exp": now + 300, **extra}
    return jwt.encode(claims, priv_pem, algorithm=alg)


@pytest.fixture
def rsa_idp(tmp_path):
    return _pem_pair(rsa.generate_private_key(public_exponent=65537, key_size=2048), tmp_path, "rsa")


def test_rs256_trusted_issuer_verifies(home, rsa_idp):
    priv_pem, pub_path = rsa_idp
    delcred.trust_add(RSA_ISS, str(pub_path), base=home, alg="RS256")
    claims = verify_signature(_signed(priv_pem, "RS256", RSA_ISS), base=home)
    assert claims["sub"] == "u_alice"


def test_es256_trusted_issuer_verifies(home, tmp_path):
    priv_pem, pub_path = _pem_pair(ec.generate_private_key(ec.SECP256R1()), tmp_path, "ec")
    delcred.trust_add("https://es.example.com", str(pub_path), base=home, alg="ES256")
    tok = _signed(priv_pem, "ES256", "https://es.example.com")
    assert verify_signature(tok, base=home)["sub"] == "u_alice"


def test_rs256_external_subject_exchanges(home, actor, rsa_idp):
    priv_pem, pub_path = rsa_idp
    delcred.trust_add(RSA_ISS, str(pub_path), base=home, alg="RS256")
    result = exchange(
        subject_token=_signed(priv_pem, "RS256", RSA_ISS),
        actor_token=actor, scope="invoices:read",
        resource="https://api.acme.test/v1", base=home,
    )
    assert result.claims["sub"] == "u_alice"


def test_rs256_token_under_eddsa_issuer_rejected(home, idp_keypair, rsa_idp):
    """The alg is pinned per issuer: an RS256 token for an EdDSA issuer fails."""
    _, ed_pub = idp_keypair
    delcred.trust_add(IDP_ISS, str(ed_pub), base=home)  # EdDSA
    rsa_priv, _ = rsa_idp
    with pytest.raises(InvalidToken, match="alg"):
        verify_signature(_signed(rsa_priv, "RS256", IDP_ISS), base=home)


def test_hs256_with_rsa_public_pem_as_secret_rejected(home, rsa_idp):
    """Classic confusion: HMAC-sign with the issuer's public PEM as the secret."""
    import base64
    import hashlib
    import hmac
    import json as _json

    _, pub_path = rsa_idp
    delcred.trust_add(RSA_ISS, str(pub_path), base=home, alg="RS256")

    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    now = int(time.time())
    head = b64(_json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(_json.dumps({"iss": RSA_ISS, "sub": "u_alice", "iat": now, "exp": now + 300}).encode())
    sig = hmac.new(pub_path.read_bytes(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    forged = f"{head}.{body}.{b64(sig)}"
    with pytest.raises(InvalidToken):
        verify_signature(forged, base=home)


def test_rsa_1024_key_refused_at_load(home, tmp_path):
    _, pub_path = _pem_pair(rsa.generate_private_key(public_exponent=65537, key_size=1024), tmp_path, "weak")
    with pytest.raises(TrustConfigError, match="2048"):
        delcred.trust_add(RSA_ISS, str(pub_path), base=home, alg="RS256")
    (home / "policy.yaml").write_text(
        f'trusted_issuers:\n  "{RSA_ISS}": {{key: "{pub_path.as_posix()}", alg: RS256}}\n'
    )
    with pytest.raises(TrustConfigError, match="2048"):
        trust.trusted_issuers(home)


def test_key_type_must_match_alg(home, idp_keypair, tmp_path):
    _, ed_pub = idp_keypair
    with pytest.raises(TrustConfigError, match="RS256"):
        delcred.trust_add(RSA_ISS, str(ed_pub), base=home, alg="RS256")
    _, p384 = _pem_pair(ec.generate_private_key(ec.SECP384R1()), tmp_path, "p384")
    with pytest.raises(TrustConfigError, match="P-256"):
        delcred.trust_add(RSA_ISS, str(p384), base=home, alg="ES256")
    with pytest.raises(TrustConfigError, match="alg"):
        delcred.trust_add(RSA_ISS, str(ed_pub), base=home, alg="HS256")


def test_rs256_issuer_cannot_assert_agents(home, subject, rsa_idp):
    priv_pem, pub_path = rsa_idp
    delcred.trust_add(RSA_ISS, str(pub_path), base=home, alg="RS256")
    ext_actor = _signed(priv_pem, "RS256", RSA_ISS, kind="agent")
    with pytest.raises(ExchangeError, match="actor_token must be issued by"):
        exchange(
            subject_token=subject, actor_token=ext_actor, scope="invoices:read",
            resource="https://api.acme.test/v1", base=home,
        )


def test_string_form_stays_eddsa(home, idp_keypair, rsa_idp):
    """Back-compat: the plain string form registers an EdDSA issuer."""
    priv_pem, pub_path = idp_keypair
    delcred.trust_add(IDP_ISS, str(pub_path), base=home)
    assert "alg" not in (home / "policy.yaml").read_text()
    assert verify_signature(_idp_token(priv_pem), base=home)["iss"] == IDP_ISS


def test_cli_trust_add_alg(home, rsa_idp):
    from delcred.cli import main

    priv_pem, pub_path = rsa_idp
    main(["--home", str(home), "trust-add", "--iss", RSA_ISS,
          "--key-file", str(pub_path), "--alg", "RS256"])
    assert verify_signature(_signed(priv_pem, "RS256", RSA_ISS), base=home)["iss"] == RSA_ISS
