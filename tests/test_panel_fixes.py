"""Regression tests for the synapse-1 panel review findings (one block each)."""

import json
import socket
import stat
import threading
import time
import urllib.error
import urllib.request

import jwt
import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import delcred
from delcred import exchange as ex
from delcred.audit import AuditLog
from delcred.exchange import ExchangeError
from delcred.mcp import authorize, protected_resource_metadata
from delcred.revocation import RevocationList
from delcred.tokens import InvalidToken, verify_signature

RES = "https://api.acme.test/v1"
IDP = "https://idp.test"


@pytest.fixture
def idp(home, tmp_path):
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "idp.pem"
    pub.write_bytes(
        priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    delcred.trust_add(IDP, str(pub), base=home)
    pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )

    def mint(**claims):
        now = int(time.time())
        body = {"iss": IDP, "sub": "u_alice", "aud": "delcred", "exp": now + 300}
        body.update(claims)
        return jwt.encode({k: v for k, v in body.items() if v is not None}, pem, algorithm="EdDSA")

    return mint


def _add_grant(home, **g):
    pol = yaml.safe_load((home / "policy.yaml").read_text())
    pol["grants"].append(g)
    (home / "policy.yaml").write_text(yaml.safe_dump(pol))


# --- (1) CRITICAL: only the local issuer may sign delegation / agent tokens ---


def test_idp_signed_delegation_rejected(home, idp):
    forged = idp(kind="delegation", act={"sub": "x"}, aud="https://bank.test", scope="admin:*")
    with pytest.raises(InvalidToken, match="untrusted issuer"):
        ex.verify(forged, expected_resource="https://bank.test", required_scopes="admin:*", base=home)
    # Also via the MCP helper: never 200.
    assert authorize(f"Bearer {forged}", resource="https://bank.test", base=home).status == 401


def test_idp_signed_agent_token_rejected_as_actor(home, idp, subject):
    act = idp(sub="billing-agent", kind="agent")
    with pytest.raises(ExchangeError, match="actor_token rejected"):
        ex.exchange(subject_token=subject, actor_token=act, scope="invoices:read",
                    resource=RES, base=home)


def test_verify_signature_is_local_only_by_default(home, idp):
    tok = idp()
    with pytest.raises(InvalidToken, match="untrusted issuer"):
        verify_signature(tok, base=home)
    assert verify_signature(tok, base=home, allow_external=True)["iss"] == IDP


# --- (2) HIGH: users are (iss, sub); external subject tokens need aud ---------


@pytest.mark.parametrize("aud", ["some-other-app", None])
def test_external_subject_wrong_or_missing_aud_rejected(home, idp, actor, aud):
    _add_grant(home, user="u_alice", issuer=IDP, agent="billing-agent",
               scopes=["invoices:read"], resources=[RES])
    with pytest.raises(ExchangeError, match="subject_token rejected"):
        ex.exchange(subject_token=idp(aud=aud), actor_token=actor,
                    scope="invoices:read", resource=RES, base=home)


def test_idp_user_does_not_inherit_local_users_grant(home, idp, actor):
    # conftest grants local u_alice; the IdP's u_alice is a different person.
    with pytest.raises(delcred.PolicyError, match="no delegation grant"):
        ex.exchange(subject_token=idp(), actor_token=actor, scope="invoices:read",
                    resource=RES, base=home)


def test_custom_audience_for_trusted_issuer(home, tmp_path, actor):
    priv = Ed25519PrivateKey.generate()
    (tmp_path / "k.pem").write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    delcred.trust_add("https://idp2.test", str(tmp_path / "k.pem"), base=home,
                      audience="https://delcred.acme.internal")
    _add_grant(home, user="u_alice", issuer="https://idp2.test", agent="billing-agent",
               scopes=["invoices:read"], resources=[RES])
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())

    def tok(aud):
        return jwt.encode({"iss": "https://idp2.test", "sub": "u_alice", "aud": aud,
                           "exp": int(time.time()) + 60}, pem, algorithm="EdDSA")

    r = ex.exchange(subject_token=tok("https://delcred.acme.internal"), actor_token=actor,
                    scope="invoices:read", resource=RES, base=home)
    assert r.claims["user_iss"] == "https://idp2.test"
    with pytest.raises(ExchangeError):
        ex.exchange(subject_token=tok("delcred"), actor_token=actor,
                    scope="invoices:read", resource=RES, base=home)


def test_user_revocation_is_issuer_scoped(home, idp, actor, subject):
    _add_grant(home, user="u_alice", issuer=IDP, agent="billing-agent",
               scopes=["invoices:read"], resources=[RES])
    local = delcred.delegate(scope="invoices:read", resource=RES, user_token=subject,
                             agent_token=actor, base=home)
    ext = delcred.delegate(scope="invoices:read", resource=RES, user_token=idp(),
                           agent_token=actor, base=home)
    delcred.revoke_user("u_alice", base=home, issuer=IDP)
    assert delcred.verify(local, expected_resource=RES, base=home)  # local user untouched
    with pytest.raises(ExchangeError, match="revoked"):
        delcred.verify(ext, expected_resource=RES, base=home)
    # No issuer → fail-closed: the id under every issuer.
    delcred.revoke_user("u_alice", base=home)
    with pytest.raises(ExchangeError, match="revoked"):
        delcred.verify(local, expected_resource=RES, base=home)


def test_user_kill_switch_does_not_hit_agent_named_like_user(home, actor, subject):
    RevocationList(home).revoke_user("billing-agent")
    assert delcred.delegate(scope="invoices:read", resource=RES, user_token=subject,
                            agent_token=actor, base=home)


# --- (3) HIGH: threaded server, timeout, rate limit ---------------------------


@pytest.fixture
def srv(home):
    from delcred.server import make_server

    httpd = make_server(0, base=home, rate=5)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd, f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def test_slow_client_does_not_block_server(srv):
    httpd, url = srv
    s = socket.create_connection(("127.0.0.1", httpd.server_address[1]))
    s.sendall(b"POST /verify HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\nab")
    try:
        with urllib.request.urlopen(url + "/health", timeout=3) as r:
            assert r.status == 200
    finally:
        s.close()
    assert httpd.RequestHandlerClass.timeout == 10


def test_token_endpoint_rate_limited(srv):
    _, url = srv
    codes = []
    for _ in range(7):
        req = urllib.request.Request(url + "/token", data=b"grant_type=x", method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            codes.append(e.code)
            if e.code == 429:
                assert int(e.headers["Retry-After"]) >= 1
    assert codes[:5] == [400] * 5 and codes[5:] == [429, 429]
    with urllib.request.urlopen(url + "/health") as r:  # unlimited paths unaffected
        assert r.status == 200


def test_rate_limiter_refills_and_bounds_memory():
    from delcred.server import RateLimiter

    rl = RateLimiter(rate=2, per=0.2, max_keys=3)
    assert rl.allow("a")[0] and rl.allow("a")[0] and not rl.allow("a")[0]
    time.sleep(0.25)
    assert rl.allow("a")[0]
    for k in "bcdef":
        rl.allow(k)
    assert len(rl._buckets) == 3


# --- (4) MEDIUM: audit genesis anchor ----------------------------------------


@pytest.mark.parametrize("pad", ["{}", '{"ts": 1, "event": "old"}', ""])
def test_audit_head_deletion_with_fake_legacy_detected(tmp_path, pad):
    log = AuditLog(tmp_path)
    for i in range(5):
        log.record("e", i=i)
    lines = log.path.read_text().splitlines()
    log.path.write_text(((pad + "\n") if pad else "") + "\n".join(lines[4:]) + "\n")
    res = log.verify()
    assert not res.ok and any("chain broken" in p for p in res.problems)


def test_audit_genuine_legacy_upgrade_still_ok(tmp_path):
    (tmp_path / "audit.jsonl").write_text('{"ts": 1, "event": "a"}\n{}\n')
    log = AuditLog(tmp_path)
    log.record("new")
    assert log.verify().ok


# --- (5) MEDIUM: broker key missing scope → 403 insufficient_scope ----------


def test_broker_key_missing_scope_is_403(home, subject, actor):
    key = delcred.delegate_api_key(scope="invoices:read", resource=RES,
                                   user_token=subject, agent_token=actor, base=home)
    d = authorize(f"Bearer {key}", resource=RES, required_scopes="invoices:write", base=home)
    assert d.status == 403 and d.error == "insufficient_scope"
    assert 'scope="invoices:write"' in d.www_authenticate


def test_server_broker_redeem_missing_scope_is_403(srv, home, subject, actor):
    _, url = srv
    key = delcred.delegate_api_key(scope="invoices:read", resource=RES,
                                   user_token=subject, agent_token=actor, base=home)
    req = urllib.request.Request(url + "/broker/redeem", method="POST",
                                 data=json.dumps({"key": key, "resource": RES,
                                                  "scope": "invoices:write"}).encode(),
                                 headers={"Content-Type": "application/json"})
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 403 and "insufficient_scope" in e.value.headers["WWW-Authenticate"]


# --- (6) MCP: resource_metadata always, RFC 8414, no issuer key as jwks_uri ---


def test_authorize_always_emits_resource_metadata(home):
    d = authorize(None, resource="https://mcp.example.com/mcp", base=home)
    assert d.www_authenticate == (
        'Bearer resource_metadata="https://mcp.example.com/.well-known/'
        'oauth-protected-resource/mcp"'
    )
    d = authorize("Bearer junk", resource="https://mcp.example.com/mcp", base=home)
    assert "resource_metadata=" in d.www_authenticate


def test_authorization_server_metadata(srv):
    _, url = srv
    with urllib.request.urlopen(url + "/.well-known/oauth-authorization-server") as r:
        doc = json.loads(r.read())
    assert doc["issuer"] == url and doc["token_endpoint"] == url + "/token"
    assert doc["jwks_uri"] == url + "/.well-known/jwks.json"
    assert doc["grant_types_supported"] == ["urn:ietf:params:oauth:grant-type:token-exchange"]


def test_prm_has_no_issuer_jwks_uri():
    doc = protected_resource_metadata("https://m.test/mcp", ["https://as.test"])
    assert "jwks_uri" not in doc
    with pytest.raises(TypeError):
        protected_resource_metadata("https://m.test/mcp", ["https://as.test"], jwks_uri="x")


# --- (7) LOW: /revoke guard + caps, write_private, typ ------------------------


def _revoke(url, body, token=None):
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url + "/revoke", data=json.dumps(body).encode(),
                                 headers=h, method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_revoke_requires_admin_token_when_configured(home):
    from delcred.server import make_server

    httpd = make_server(0, base=home, admin_token="s3cret-admin")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        assert _revoke(url, {"agent": "billing-agent"}) == 401
        assert _revoke(url, {"agent": "billing-agent"}, token="wrong") == 401
        assert _revoke(url, {"agent": "billing-agent"}, token="s3cret-admin") == 200
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_revoke_non_loopback_rejected_without_admin(srv, monkeypatch):
    from delcred import server

    _, url = srv
    monkeypatch.setattr(server, "_is_loopback", lambda addr: False)
    assert _revoke(url, {"agent": "billing-agent"}) == 403


def test_is_loopback():
    from delcred.server import _is_loopback

    assert _is_loopback("127.0.0.1") and _is_loopback("::1")
    assert not _is_loopback("10.0.0.5") and not _is_loopback("garbage")


@pytest.mark.parametrize("body", [{"agent": "a" * 300}, {"jti": 5}, {"agent": "a", "reason": "r" * 600}])
def test_revoke_field_caps(srv, body):
    _, url = srv
    assert _revoke(url, body) == 400


def test_write_private_replaces_world_readable_file(tmp_path):
    from delcred._common import write_private

    p = tmp_path / "issuer.key"
    p.write_text("old")
    p.chmod(0o644)
    write_private(p, b"secret")
    assert p.read_bytes() == b"secret"
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert [x.name for x in tmp_path.iterdir()] == ["issuer.key"]  # no temp left


def test_delegation_without_at_jwt_typ_rejected(home):
    from delcred import keys

    priv = keys.load_private(home)
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    now = int(time.time())
    tok = jwt.encode({"iss": "delcred", "sub": "u", "kind": "delegation", "act": {"sub": "a"},
                      "aud": RES, "scope": "x", "jti": "j", "iat": now, "nbf": now,
                      "exp": now + 60}, pem, algorithm="EdDSA")
    with pytest.raises(InvalidToken, match="typ"):
        delcred.verify(tok, expected_resource=RES, base=home)
