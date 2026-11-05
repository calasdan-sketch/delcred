"""0.3 features: scope enforcement, MCP helpers, RFC 8693 /token, JWKS/kid,
tamper-evident audit, Claude Code headersHelper, demo, portable locking."""

import json
import multiprocessing
import threading
import urllib.error
import urllib.parse
import urllib.request

import jwt
import pytest

import delcred
from delcred.audit import AuditLog
from delcred.broker import BrokerError
from delcred.cli import build_parser
from delcred.exchange import ExchangeError
from delcred.mcp import (
    authorize,
    bearer_token,
    metadata_path,
    protected_resource_metadata,
    www_authenticate,
)

RES = "https://api.acme.test/v1"


def _tok(home, subject, actor, scope="invoices:read"):
    return delcred.delegate(
        scope=scope, resource=RES, user_token=subject, agent_token=actor, base=home
    )


def run_cli(home, *argv):
    args = build_parser().parse_args(["--home", str(home), *argv])
    args.func(args)


# --- least-privilege verification ------------------------------------------


def test_verify_required_scopes_ok_and_missing(home, subject, actor):
    tok = _tok(home, subject, actor, "invoices:read customers:read")
    c = delcred.verify(tok, expected_resource=RES, required_scopes=["invoices:read"], base=home)
    assert c["sub"] == "u_alice"
    with pytest.raises(delcred.InsufficientScope) as e:
        delcred.verify(
            tok, expected_resource=RES, required_scopes="invoices:read invoices:write", base=home
        )
    assert e.value.missing == ["invoices:write"]
    assert e.value.required == ["invoices:read", "invoices:write"]


def test_scope_failure_does_not_burn_single_use(home, bob_subject, actor):
    tok = _tok(home, bob_subject, actor)
    with pytest.raises(delcred.InsufficientScope):
        delcred.verify(tok, expected_resource=RES, required_scopes="invoices:write", base=home)
    with pytest.raises(delcred.InvalidToken):
        delcred.verify(tok, expected_resource="https://other.test", base=home)
    # Still usable once, by the right API for the right operation.
    delcred.verify(tok, expected_resource=RES, required_scopes="invoices:read", base=home)
    with pytest.raises(ExchangeError, match="consumed"):
        delcred.verify(tok, expected_resource=RES, base=home)


def test_verify_rejects_empty_resource(home, subject, actor):
    tok = _tok(home, subject, actor)
    with pytest.raises(ExchangeError, match="required"):
        delcred.verify(tok, expected_resource="", base=home)


def test_broker_resource_pinning_and_scope(home, bob_subject, actor):
    key = delcred.delegate_api_key(
        scope="invoices:read", resource=RES, user_token=bob_subject, agent_token=actor, base=home
    )
    with pytest.raises(BrokerError, match="invalid API key"):
        delcred.verify_broker_key(key, base=home, expected_resource="https://evil.test")
    with pytest.raises(BrokerError, match="invalid API key"):
        delcred.verify_broker_key(key, base=home, expected_resource=RES, required_scopes="x:y")
    # Single-use key was not burned by the failed attempts.
    cap = delcred.verify_broker_key(key, base=home, expected_resource=RES)
    assert cap["scope"] == "invoices:read"
    with pytest.raises(BrokerError):
        delcred.verify_broker_key(key, base=home, expected_resource=RES)
    reasons = [e.get("reason") for e in AuditLog(home).tail(50)]
    assert "wrong_resource" in reasons and "insufficient_scope" in reasons


def test_broker_rejects_non_string_key(home):
    with pytest.raises(BrokerError):
        delcred.verify_broker_key(None, base=home)  # type: ignore[arg-type]


# --- delegate() identity assertions ----------------------------------------


def test_delegate_user_agent_assertions(home, subject, actor):
    assert _tok(home, subject, actor)
    delcred.delegate(
        user="u_alice", agent="billing-agent", scope="invoices:read", resource=RES,
        user_token=subject, agent_token=actor, base=home,
    )
    with pytest.raises(ExchangeError, match="does not match"):
        delcred.delegate(
            user="u_bob", scope="invoices:read", resource=RES,
            user_token=subject, agent_token=actor, base=home,
        )
    with pytest.raises(ExchangeError, match="does not match"):
        delcred.delegate_api_key(
            agent="rogue-agent", scope="invoices:read", resource=RES,
            user_token=subject, agent_token=actor, base=home,
        )


# --- JWKS / kid --------------------------------------------------------------


def test_tokens_carry_kid_and_verify_with_stock_pyjwt(home, subject, actor):
    tok = _tok(home, subject, actor)
    jwks = delcred.jwks(base=home)
    assert len(jwks["keys"]) == 1 and "d" not in jwks["keys"][0]  # public only
    hdr = jwt.get_unverified_header(tok)
    assert hdr["kid"] == jwks["keys"][0]["kid"] and hdr["typ"] == "at+jwt"
    # A third-party resource server with only the JWKS can verify.
    key = jwt.PyJWK(jwks["keys"][0])
    claims = jwt.decode(tok, key, algorithms=["EdDSA"], audience=RES, issuer="delcred")
    assert claims["act"]["sub"] == "billing-agent"


def test_kid_mismatch_after_rotation_is_explicit(home, subject, actor):
    tok = _tok(home, subject, actor)
    run_cli(home, "key", "rotate")
    with pytest.raises(delcred.InvalidToken, match="kid mismatch"):
        delcred.verify(tok, expected_resource=RES, base=home)


def test_kid_rfc7638_known_vector():
    # RFC 8037 Appendix A.3 test vector: Ed25519 public key thumbprint.
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from delcred.keys import key_id

    x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    raw = base64.urlsafe_b64decode(x + "=")
    assert key_id(Ed25519PublicKey.from_public_bytes(raw)) == (
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    )


# --- tamper-evident audit ----------------------------------------------------


def test_audit_chain_ok_and_head(home, subject, actor):
    _tok(home, subject, actor)
    log = AuditLog(home)
    res = log.verify()
    assert res.ok and res.chained >= 2 and res.legacy == 0
    assert res.head == log.head()
    assert all("hash" in e and "prev" in e for e in log.entries())


@pytest.mark.parametrize("attack", ["edit", "delete", "reorder", "insert"])
def test_audit_tamper_detected(home, subject, actor, attack):
    for _ in range(3):
        _tok(home, subject, actor)
    log = AuditLog(home)
    lines = log.path.read_text().splitlines()
    if attack == "edit":
        lines[2] = lines[2].replace("u_alice", "u_mallory")
    elif attack == "delete":
        del lines[2]
    elif attack == "reorder":
        lines[1], lines[2] = lines[2], lines[1]
    else:
        lines.insert(2, json.dumps({"ts": 1, "event": "token_issued", "user": "x"}))
    log.path.write_text("\n".join(lines) + "\n")
    res = log.verify()
    assert not res.ok and res.problems


def test_audit_legacy_entries_then_chain(tmp_path):
    p = tmp_path / "audit.jsonl"
    p.write_text('{"ts": 1, "event": "old"}\n{"ts": 2, "event": "old2"}\n')
    log = AuditLog(tmp_path)
    log.record("new", agent="a")
    log.record("new2")
    res = log.verify()
    assert res.ok and res.legacy == 2 and res.chained == 2


def test_audit_never_logs_secrets_or_forges_chain(tmp_path):
    log = AuditLog(tmp_path)
    log.record("x", token="SECRET", credential="SECRET", api_key="SECRET",
               hash="f" * 64, prev="0" * 64, user="u")
    text = log.path.read_text()
    assert "SECRET" not in text
    assert log.verify().ok


def test_audit_filters(home, subject, actor):
    _tok(home, subject, actor)
    delcred.revoke_agent("billing-agent", base=home)
    log = AuditLog(home)
    assert {e["event"] for e in log.tail(50, event="agent_revoked")} == {"agent_revoked"}
    assert all(e.get("agent") == "billing-agent" for e in log.tail(50, agent="billing-agent"))
    assert log.tail(50, since=10**12) == []
    assert log.tail(0) == []


def test_audit_chain_survives_concurrent_threads(tmp_path):
    log = AuditLog(tmp_path)

    def worker(n):
        for i in range(25):
            AuditLog(tmp_path).record("t", n=n, i=i)

    ts = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    res = log.verify()
    assert res.ok and res.chained == 200


def _proc_writer(path, n):
    from pathlib import Path

    from delcred.audit import AuditLog as _A

    for i in range(20):
        _A(Path(path)).record("p", n=n, i=i)


def test_audit_chain_survives_concurrent_processes(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    ps = [ctx.Process(target=_proc_writer, args=(str(tmp_path), n)) for n in range(4)]
    for p in ps:
        p.start()
    for p in ps:
        p.join(60)
        assert p.exitcode == 0
    res = AuditLog(tmp_path).verify()
    assert res.ok and res.chained == 80


def test_prune_keeps_live_entries_and_lockfile(home):
    from delcred.revocation import RevocationList

    rl = RevocationList(home)
    rl.revoke_jti("dead", expires_at=1)
    rl.revoke_jti("live", expires_at=None)
    rl.revoke_agent("a")
    assert rl.prune() == 1
    assert rl.is_revoked({"jti": "live"})[0]
    assert (home / "revocations.jsonl.lock").exists()
    rl.revoke_jti("after-prune")
    assert rl.is_revoked({"jti": "after-prune"})[0]


# --- MCP resource-server helpers -------------------------------------------

PRM = "https://api.acme.test/.well-known/oauth-protected-resource/v1"


def test_authorize_decisions(home, subject, actor):
    tok = _tok(home, subject, actor)
    d = authorize(None, resource=RES, required_scopes="invoices:read",
                  resource_metadata_url=PRM, base=home)
    assert d.status == 401 and d.error == ""
    assert d.www_authenticate == f'Bearer scope="invoices:read", resource_metadata="{PRM}"'

    d = authorize("Bearer garbage", resource=RES, base=home, resource_metadata_url=PRM)
    assert d.status == 401 and d.error == "invalid_token"
    assert 'error="invalid_token"' in d.headers["WWW-Authenticate"]

    d = authorize(f"Bearer {tok}", resource="https://other.test", base=home)
    assert d.status == 401  # wrong audience is never accepted

    d = authorize(f"Bearer {tok}", resource=RES, required_scopes="invoices:write", base=home,
                  resource_metadata_url=PRM)
    assert d.status == 403 and d.error == "insufficient_scope"
    assert 'scope="invoices:write"' in d.www_authenticate

    d = authorize(f"bearer   {tok}", resource=RES, required_scopes="invoices:read", base=home)
    assert d.ok and d.status == 200 and d.user == "u_alice" and d.agent == "billing-agent"


def test_authorize_broker_key(home, subject, actor):
    key = delcred.delegate_api_key(
        scope="invoices:read", resource=RES, user_token=subject, agent_token=actor, base=home
    )
    assert authorize(f"Bearer {key}", resource=RES, base=home).ok
    assert authorize(f"Bearer {key}", resource="https://evil.test", base=home).status == 401


def test_authorize_revoked(home, subject, actor):
    tok = _tok(home, subject, actor)
    delcred.revoke_agent("billing-agent", base=home)
    assert authorize(f"Bearer {tok}", resource=RES, base=home).status == 401


def test_bearer_parsing_edge_cases():
    assert bearer_token(None) is None
    assert bearer_token("Basic abc") is None
    assert bearer_token("Bearer") is None
    assert bearer_token("Bearer a b") is None
    assert bearer_token("Bearer " + "a" * 20000) is None
    assert bearer_token("BEARER abc") == "abc"


def test_challenge_header_injection_safe():
    h = www_authenticate(resource_metadata_url='https://x/"\r\nSet-Cookie: a=b',
                         error_description='say "hi"\\')
    assert "\r" not in h and "\n" not in h
    assert '\\"' in h


def test_protected_resource_metadata():
    doc = protected_resource_metadata(
        "https://mcp.example.com/mcp", ["https://auth.example.com"],
        scopes_supported=["tools:call", "tools:list"], resource_name="Demo",
    )
    assert doc["resource"] == "https://mcp.example.com/mcp"
    assert doc["authorization_servers"] == ["https://auth.example.com"]
    assert doc["bearer_methods_supported"] == ["header"]
    assert metadata_path("https://mcp.example.com/mcp") == "/.well-known/oauth-protected-resource/mcp"
    assert metadata_path("https://mcp.example.com/") == "/.well-known/oauth-protected-resource"
    with pytest.raises(ValueError):
        protected_resource_metadata("https://x", [])


# --- HTTP server: RFC 8693 /token, JWKS --------------------------------------


@pytest.fixture
def server(home):
    from http.server import HTTPServer

    from delcred.server import _Handler

    _Handler.base = home
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _form(url, fields, raw=None):
    data = raw if raw is not None else urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url + "/token", data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read()), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), dict(e.headers)


JWT_T = "urn:ietf:params:oauth:token-type:jwt"
GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"


def _fields(subject, actor, **over):
    f = {
        "grant_type": GRANT, "subject_token": subject, "subject_token_type": JWT_T,
        "actor_token": actor, "actor_token_type": JWT_T,
        "scope": "invoices:read", "resource": RES,
    }
    f.update(over)
    return f


def test_token_endpoint_success(server, home, subject, actor):
    code, body, headers = _form(server, _fields(subject, actor))
    assert code == 200, body
    assert body["token_type"] == "Bearer" and body["expires_in"] == 900
    assert body["issued_token_type"] == "urn:ietf:params:oauth:token-type:access_token"
    assert body["scope"] == "invoices:read"
    assert headers.get("Cache-Control") == "no-store"
    assert delcred.verify(body["access_token"], expected_resource=RES, base=home)


@pytest.mark.parametrize(
    "over,expected",
    [
        ({"grant_type": "password"}, "unsupported_grant_type"),
        ({"scope": ""}, "invalid_request"),
        ({"subject_token_type": "urn:x"}, "invalid_request"),
        ({"requested_token_type": "urn:x"}, "invalid_request"),
        ({"scope": "admin:all"}, "invalid_scope"),
        ({"resource": "https://evil.test"}, "invalid_target"),
        ({"subject_token": "garbage"}, "invalid_grant"),
        ({"ttl": "abc"}, "invalid_request"),
    ],
)
def test_token_endpoint_errors(server, subject, actor, over, expected):
    code, body, _ = _form(server, _fields(subject, actor, **over))
    assert code == 400 and body["error"] == expected


def test_token_endpoint_no_grant(server, home, actor):
    stranger = delcred.user_token("u_nobody", base=home)
    code, body, _ = _form(server, _fields(stranger, actor))
    assert code == 400 and body["error"] == "invalid_grant"


def test_token_endpoint_repeated_param(server, subject, actor):
    raw = urllib.parse.urlencode(_fields(subject, actor)) + "&scope=customers:read"
    code, body, _ = _form(server, None, raw=raw.encode())
    assert code == 400 and "repeated" in body["error_description"]


def test_server_jwks_and_scoped_verify(server, home, subject, actor):
    with urllib.request.urlopen(server + "/.well-known/jwks.json") as r:
        keys = json.loads(r.read())["keys"]
    assert keys[0]["kty"] == "OKP" and "d" not in keys[0]
    tok = _tok(home, subject, actor)
    req = urllib.request.Request(
        server + "/verify",
        data=json.dumps({"token": tok, "resource": RES, "scope": "invoices:write"}).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 403
    assert "insufficient_scope" in e.value.headers["WWW-Authenticate"]


def test_server_rejects_non_object_json(server):
    req = urllib.request.Request(
        server + "/verify", data=b"[1,2]", headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 400


# --- CLI: Claude Code headersHelper, audit verify, demo -----------------------


def test_mcp_headers_for_claude_code(home, subject, actor, tmp_path, monkeypatch, capsys):
    (tmp_path / "u.jwt").write_text(subject)
    (tmp_path / "a.jwt").write_text(actor)
    monkeypatch.setenv("CLAUDE_CODE_MCP_SERVER_URL", RES)
    monkeypatch.setenv("DELCRED_SUBJECT_TOKEN_FILE", str(tmp_path / "u.jwt"))
    monkeypatch.delenv("DELCRED_SUBJECT_TOKEN", raising=False)
    monkeypatch.delenv("DELCRED_ACTOR_TOKEN", raising=False)
    run_cli(home, "mcp-headers", "--scope", "invoices:read",
            "--actor-token-file", str(tmp_path / "a.jwt"))
    out = capsys.readouterr().out
    hdrs = json.loads(out)  # stdout is exactly one JSON object
    assert list(hdrs) == ["Authorization"]
    tok = hdrs["Authorization"].removeprefix("Bearer ")
    assert delcred.verify(tok, expected_resource=RES, base=home)["aud"] == RES


def test_mcp_headers_denied_exit_3(home, subject, actor, monkeypatch, capsys):
    monkeypatch.setenv("DELCRED_SUBJECT_TOKEN", subject)
    monkeypatch.setenv("DELCRED_ACTOR_TOKEN", actor)
    with pytest.raises(SystemExit) as e:
        run_cli(home, "mcp-headers", "--scope", "invoices:read", "--resource", "https://evil.test")
    assert e.value.code == 3
    assert capsys.readouterr().out == ""


def test_cli_missing_token_file_is_clean_error(home, tmp_path):
    with pytest.raises(SystemExit) as e:
        run_cli(home, "exchange", "--subject-token-file", str(tmp_path / "nope"),
                "--actor-token", "x", "--scope", "a", "--resource", RES)
    assert "cannot read token file" in str(e.value.code)


def test_cli_verify_require_scope_exit_5(home, subject, actor):
    tok = _tok(home, subject, actor)
    with pytest.raises(SystemExit) as e:
        run_cli(home, "verify", tok, "--resource", RES, "--require-scope", "invoices:write")
    assert e.value.code == 5


def test_cli_audit_verify_and_tamper(home, subject, actor, capsys):
    _tok(home, subject, actor)
    run_cli(home, "audit", "verify")
    assert capsys.readouterr().out.startswith("OK")
    p = home / "audit.jsonl"
    p.write_text(p.read_text().replace("u_alice", "u_eve"))
    with pytest.raises(SystemExit) as e:
        run_cli(home, "audit", "verify")
    assert e.value.code == 6
    run_cli(home, "audit", "--event", "token_issued", "--since", "1h")
    assert "token_issued" in capsys.readouterr().out


def test_cli_jwks_prune_demo(home, capsys):
    run_cli(home, "jwks")
    assert json.loads(capsys.readouterr().out)["keys"][0]["alg"] == "EdDSA"
    run_cli(home, "prune")
    assert "pruned" in capsys.readouterr().out
    run_cli(home, "demo")
    out = capsys.readouterr().out
    assert "guarantees held" in out and "FAIL" not in out


def test_audit_torn_last_line_is_not_glued(tmp_path):
    log = AuditLog(tmp_path)
    log.record("a")
    with open(log.path, "a") as f:
        f.write('{"ts": 1, "event": "torn')  # simulated crash mid-write
    log.record("b")
    lines = log.path.read_text().splitlines()
    assert json.loads(lines[-1])["event"] == "b"
    res = log.verify()
    assert not res.ok and any("not valid JSON" in p for p in res.problems)


def test_token_endpoint_json_ttl_type_error(server, subject, actor):
    req = urllib.request.Request(
        server + "/token",
        data=json.dumps(_fields(subject, actor, ttl=[1])).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 400


def test_server_negative_content_length(server):
    import http.client

    host, port = server.removeprefix("http://").split(":")
    c = http.client.HTTPConnection(host, int(port), timeout=5)
    c.putrequest("POST", "/verify")
    c.putheader("Content-Length", "-1")
    c.endheaders()
    assert c.getresponse().status == 400
