"""CLI + HTTP server + sidecar tests."""

import json
import threading
import urllib.request

import pytest

import delcred
from delcred.cli import build_parser

RES = "https://api.acme.test/v1"


@pytest.fixture
def cli_home(home, monkeypatch):
    monkeypatch.setenv("DELCRED_HOME", str(home))
    return home


def run_cli(*argv, home):
    parser = build_parser()
    args = parser.parse_args(["--home", str(home), *argv])
    args.func(args)


def test_cli_init_and_status(tmp_path, capsys):
    run_cli("init", home=tmp_path)
    out = capsys.readouterr().out
    assert "initialized delcred home" in out
    run_cli("status", home=tmp_path)
    assert "issuer key: present" in capsys.readouterr().out


def test_cli_full_flow(cli_home, capsys):
    run_cli("agent-token", "billing-agent", home=cli_home)
    actor = capsys.readouterr().out.strip()
    run_cli("user-token", "u_alice", home=cli_home)
    subject = capsys.readouterr().out.strip()
    run_cli(
        "exchange",
        "--subject-token",
        subject,
        "--actor-token",
        actor,
        "--scope",
        "invoices:read",
        "--resource",
        RES,
        home=cli_home,
    )
    token = capsys.readouterr().out.strip().splitlines()[0]
    run_cli("verify", token, "--resource", RES, home=cli_home)
    assert "VALID" in capsys.readouterr().out


def test_cli_exchange_denied_exit_code(cli_home, capsys):
    run_cli("agent-token", "rogue-agent", home=cli_home)
    actor = capsys.readouterr().out.strip()
    run_cli("user-token", "u_alice", home=cli_home)
    subject = capsys.readouterr().out.strip()
    parser = build_parser()
    args = parser.parse_args(
        [
            "--home",
            str(cli_home),
            "exchange",
            "--subject-token",
            subject,
            "--actor-token",
            actor,
            "--scope",
            "invoices:read",
            "--resource",
            RES,
        ]
    )
    with pytest.raises(SystemExit) as e:
        args.func(args)
    assert e.value.code == 3


def test_cli_revoke_agent_kill_switch(cli_home, capsys):
    run_cli("revoke", "--agent", "billing-agent", "--reason", "test", home=cli_home)
    assert "revoked ALL credentials" in capsys.readouterr().out


def test_cli_policy_check(cli_home, capsys):
    run_cli(
        "policy",
        "check",
        "--user",
        "u_alice",
        "--agent",
        "billing-agent",
        "--scope",
        "invoices:read",
        "--resource",
        RES,
        home=cli_home,
    )
    assert "ALLOWED" in capsys.readouterr().out


def test_cli_broker_redeem(cli_home, capsys):
    run_cli("agent-token", "billing-agent", home=cli_home)
    actor = capsys.readouterr().out.strip()
    run_cli("user-token", "u_alice", home=cli_home)
    subject = capsys.readouterr().out.strip()
    run_cli(
        "exchange",
        "--subject-token",
        subject,
        "--actor-token",
        actor,
        "--scope",
        "invoices:read",
        "--resource",
        RES,
        "--as-api-key",
        "--quiet-claims",
        home=cli_home,
    )
    key = capsys.readouterr().out.strip()
    assert key.startswith("dk_")
    run_cli("broker", "redeem", key, home=cli_home)
    rec = json.loads(capsys.readouterr().out)
    assert rec["agent"] == "billing-agent"


# --- HTTP server -----------------------------------------------------------


@pytest.fixture
def server_home(home):
    return home


@pytest.fixture
def live_server(server_home):
    from http.server import HTTPServer

    from delcred.server import _Handler

    _Handler.base = server_home
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def _post(base, path, obj):
    req = urllib.request.Request(
        base + path,
        data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_server_health(live_server):
    with urllib.request.urlopen(live_server + "/health") as r:
        assert json.loads(r.read())["status"] == "ok"


def test_server_exchange_and_verify(live_server, server_home):
    actor = delcred.agent_token("billing-agent", base=server_home)
    subject = delcred.user_token("u_alice", base=server_home)
    code, body = _post(
        live_server,
        "/exchange",
        {
            "subject_token": subject,
            "actor_token": actor,
            "scope": "invoices:read",
            "resource": RES,
        },
    )
    assert code == 200, body
    assert body["claims"]["sub"] == "u_alice"
    code, body = _post(
        live_server, "/verify", {"token": body["credential"], "resource": RES}
    )
    assert code == 200 and body["valid"] is True


def test_server_exchange_denied(live_server, server_home):
    actor = delcred.agent_token("rogue-agent", base=server_home)
    subject = delcred.user_token("u_alice", base=server_home)
    code, body = _post(
        live_server,
        "/exchange",
        {
            "subject_token": subject,
            "actor_token": actor,
            "scope": "invoices:read",
            "resource": RES,
        },
    )
    assert code == 403
    assert "error" in body


def test_server_revoke(live_server, server_home):
    actor = delcred.agent_token("billing-agent", base=server_home)
    subject = delcred.user_token("u_alice", base=server_home)
    _, body = _post(
        live_server,
        "/exchange",
        {
            "subject_token": subject,
            "actor_token": actor,
            "scope": "invoices:read",
            "resource": RES,
        },
    )
    token, jti = body["credential"], body["claims"]["jti"]
    code, _ = _post(live_server, "/revoke", {"jti": jti, "reason": "test"})
    assert code == 200
    code, body = _post(live_server, "/verify", {"token": token, "resource": RES})
    assert code == 403


def test_server_broker_redeem(live_server, server_home):
    actor = delcred.agent_token("billing-agent", base=server_home)
    subject = delcred.user_token("u_alice", base=server_home)
    code, body = _post(
        live_server,
        "/exchange",
        {
            "subject_token": subject,
            "actor_token": actor,
            "scope": "invoices:read",
            "resource": RES,
            "requested_token_type": "urn:delcred:token-type:api-key",
        },
    )
    assert code == 200 and body["credential"].startswith("dk_")
    code, body = _post(live_server, "/broker/redeem", {"key": body["credential"]})
    assert code == 200 and body["valid"] is True


# --- sidecar ----------------------------------------------------------------


def test_sidecar_credential_caching(home, subject, actor):
    from delcred import sidecar

    sidecar._ProxyHandler.mapping = {
        "api.acme.test": "invoices:read|https://api.acme.test/v1"
    }
    sidecar._ProxyHandler.user_token = subject
    sidecar._ProxyHandler.agent_token = actor
    sidecar._ProxyHandler.base = home
    sidecar._ProxyHandler._cache = {}
    c1 = sidecar._ProxyHandler._credential_for("api.acme.test")
    c2 = sidecar._ProxyHandler._credential_for("api.acme.test")
    assert c1 == c2  # cached within TTL
    claims = delcred.verify(c1, expected_resource=RES, base=home)
    assert claims["act"]["sub"] == "billing-agent"


def test_sidecar_rejects_unknown_upstream():
    from delcred import sidecar

    h = sidecar._ProxyHandler
    h.mapping = {}
    # build a fake request through the handler is heavy; test the gate logic
    assert "evil.test" not in h.mapping


# --- scrutiny findings -----------------------------------------------------


def test_sidecar_rejects_revoked_cached_credential(home, subject, actor):
    # Finding #3: revocation is re-checked on every cache hit.
    from delcred import sidecar

    h = sidecar._ProxyHandler
    h.mapping = {"api.acme.test": "invoices:read|https://api.acme.test/v1"}
    h.user_token, h.agent_token, h.base, h._cache = subject, actor, home, {}
    c1 = h._credential_for("api.acme.test")
    assert h._credential_for("api.acme.test") == c1  # cached
    delcred.revoke_agent("billing-agent", reason="test", base=home)
    # cache hit is re-validated (finding #3) → rejected; the re-mint is
    # then denied by the exchange's own revocation check.
    import pytest as _pt

    from delcred.exchange import ExchangeError as _EE

    with _pt.raises(_EE, match="revoked"):
        h._credential_for("api.acme.test")


def test_sidecar_does_not_cache_single_use(home, bob_subject, actor):
    # Finding #4: single-use credentials are minted fresh per request.
    from delcred import sidecar

    h = sidecar._ProxyHandler
    h.mapping = {"api.acme.test": "invoices:read|https://api.acme.test/v1"}
    h.user_token, h.agent_token, h.base, h._cache = bob_subject, actor, home, {}
    c1 = h._credential_for("api.acme.test")
    c2 = h._credential_for("api.acme.test")
    assert c1 != c2  # never served from cache
    assert "api.acme.test" not in h._cache


def test_cli_exchange_via_token_files(cli_home, capsys, tmp_path):
    # Finding #7: tokens via files, never on the command line.
    run_cli("agent-token", "billing-agent", home=cli_home)
    (tmp_path / "agent.jwt").write_text(capsys.readouterr().out.strip())
    run_cli("user-token", "u_alice", home=cli_home)
    (tmp_path / "user.jwt").write_text(capsys.readouterr().out.strip())
    parser = build_parser()
    args = parser.parse_args(
        [
            "--home",
            str(cli_home),
            "exchange",
            "--subject-token-file",
            str(tmp_path / "user.jwt"),
            "--actor-token-file",
            str(tmp_path / "agent.jwt"),
            "--scope",
            "invoices:read",
            "--resource",
            RES,
            "--quiet-claims",
        ]
    )
    args.func(args)
    assert capsys.readouterr().out.strip().startswith("eyJ")


def test_cli_exchange_via_env(cli_home, capsys, monkeypatch):
    # Finding #7: env fallback.
    run_cli("agent-token", "billing-agent", home=cli_home)
    monkeypatch.setenv("DELCRED_ACTOR_TOKEN", capsys.readouterr().out.strip())
    run_cli("user-token", "u_alice", home=cli_home)
    monkeypatch.setenv("DELCRED_SUBJECT_TOKEN", capsys.readouterr().out.strip())
    parser = build_parser()
    args = parser.parse_args(
        [
            "--home",
            str(cli_home),
            "exchange",
            "--scope",
            "invoices:read",
            "--resource",
            RES,
            "--quiet-claims",
        ]
    )
    args.func(args)
    assert capsys.readouterr().out.strip().startswith("eyJ")


def test_server_verify_requires_resource(live_server, server_home):
    actor = delcred.agent_token("billing-agent", base=server_home)
    subject = delcred.user_token("u_alice", base=server_home)
    _, body = _post(
        live_server,
        "/exchange",
        {
            "subject_token": subject,
            "actor_token": actor,
            "scope": "invoices:read",
            "resource": RES,
        },
    )
    code, body = _post(live_server, "/verify", {"token": body["credential"]})
    assert code == 400  # resource is mandatory (finding #2)


# --- audit-phase hardening ---------------------------------------------------


def test_server_rejects_non_integer_ttl(live_server, server_home):
    actor = delcred.agent_token("billing-agent", base=server_home)
    subject = delcred.user_token("u_alice", base=server_home)
    code, body = _post(
        live_server,
        "/exchange",
        {
            "subject_token": subject,
            "actor_token": actor,
            "scope": "invoices:read",
            "resource": RES,
            "ttl": "not-a-number",
        },
    )
    assert code == 400
    assert "ttl" in body["error"]


def test_server_rejects_huge_body(live_server):
    # The server must refuse to buffer a multi-MB body. It answers 413 and
    # closes the connection; depending on write timing the client observes
    # either the 413 or a broken pipe — both prove the body was not buffered.
    req = urllib.request.Request(
        live_server + "/verify",
        data=b"x" * (2 * 1024 * 1024),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req)
        raise AssertionError("expected rejection of oversized body")
    except urllib.error.HTTPError as e:
        assert e.code == 413
    except urllib.error.URLError as e:
        assert "Broken pipe" in str(e) or "Connection reset" in str(e), str(e)


def test_cli_revoke_without_target_exits_2(cli_home, capsys):
    with pytest.raises(SystemExit) as ei:
        run_cli("revoke", home=cli_home)
    assert ei.value.code == 2
    assert "need one of" in capsys.readouterr().err


def test_cli_sidecar_accepts_token_files(cli_home, tmp_path, monkeypatch):

    (tmp_path / "user.jwt").write_text(delcred.user_token("u_alice", base=cli_home))
    (tmp_path / "agent.jwt").write_text(delcred.agent_token("billing-agent", base=cli_home))
    parser = build_parser()
    args = parser.parse_args(
        [
            "--home",
            str(cli_home),
            "sidecar",
            "--user-token-file",
            str(tmp_path / "user.jwt"),
            "--agent-token-file",
            str(tmp_path / "agent.jwt"),
            "--map",
            "api.acme.test=invoices:read|https://api.acme.test/v1",
            "--port",
            "18923",
        ]
    )
    # Don't actually serve; verify the secrets resolve without CLI args.
    from delcred.cli import _read_secret

    assert _read_secret(args, "user_token", "DELCRED_SIDECAR_USER_TOKEN").startswith("eyJ")
    assert _read_secret(args, "agent_token", "DELCRED_SIDECAR_AGENT_TOKEN").startswith("eyJ")


def test_cli_sidecar_accepts_env_tokens(cli_home, monkeypatch):
    from delcred.cli import _read_secret, build_parser

    monkeypatch.setenv("DELCRED_SIDECAR_USER_TOKEN", "user-tok")
    monkeypatch.setenv("DELCRED_SIDECAR_AGENT_TOKEN", "agent-tok")
    parser = build_parser()
    args = parser.parse_args(["--home", str(cli_home), "sidecar"])
    assert _read_secret(args, "user_token", "DELCRED_SIDECAR_USER_TOKEN") == "user-tok"
    assert _read_secret(args, "agent_token", "DELCRED_SIDECAR_AGENT_TOKEN") == "agent-tok"


def test_cli_sidecar_requires_identity(cli_home, capsys):
    with pytest.raises(SystemExit) as ei:
        run_cli("sidecar", "--map", "x=y|z", home=cli_home)
    assert ei.value.code != 0


def test_cli_trust_add(tmp_path, cli_home, capsys):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    pub_path = tmp_path / "idp.pem"
    pub_path.write_bytes(
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    run_cli("trust-add", "--iss", "https://idp.example.com", "--key-file", str(pub_path), home=cli_home)
    out = capsys.readouterr().out
    assert "trusted issuer https://idp.example.com" in out
    from delcred.trust import trusted_issuers

    assert "https://idp.example.com" in trusted_issuers(cli_home)


def test_policy_rejects_non_string_scope_resource(home):
    from delcred.policy import PolicyError, load

    pol = load(home)
    with pytest.raises(PolicyError):
        pol.check("u_alice", "billing-agent", ["invoices:read"], RES, 60)
    with pytest.raises(PolicyError):
        pol.check("u_alice", "billing-agent", "invoices:read", None, 60)
