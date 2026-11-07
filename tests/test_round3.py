"""Round 3 (expert-2): sidecar exfiltration, local-server CSRF/rebinding,
audit of rejected credentials, audit scale + signed checkpoints, strict policy,
policy-aware verify, holder-side revocation, terminal-escape hygiene."""

import http.client
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import delcred
from delcred import sidecar
from delcred._common import safe_text
from delcred.audit import AuditLog
from delcred.exchange import revoke_presented
from delcred.policy import PolicyError, validate
from delcred.policy import load as load_policy

RES = "https://api.acme.test/v1"


# --- helpers ---------------------------------------------------------------


class _Upstream:
    """Tiny local HTTP server recording what it receives."""

    def __init__(self, behaviour=None):
        self.seen = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _go(self):
                outer.seen.append((self.command, self.path, self.headers.get("Authorization")))
                code, headers, body = (behaviour or (lambda h: (200, {}, b"ok")))(self)
                self.send_response(code)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = do_POST = do_HEAD = _go

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        self.host = f"127.0.0.1:{self.port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture(autouse=True)
def _no_env_proxy(monkeypatch):
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("NO_PROXY", "*")


@pytest.fixture
def proxy(home, subject, actor):
    """A sidecar mapped to one local upstream; returns (sidecar_port, upstream)."""
    up = _Upstream()
    local_res = f"http://{up.host}"
    (home / "policy.yaml").write_text(
        f"""grants:
  - user: u_alice
    agent: billing-agent
    scopes: ["invoices:read"]
    resources: ["{local_res}"]
"""
    )
    H = sidecar._ProxyHandler
    H.mapping = {up.host: f"invoices:read|{local_res}"}
    H.user_token, H.agent_token, H.base, H._cache = subject, actor, home, {}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], up
    srv.shutdown()
    srv.server_close()
    up.close()


def _req(port, method, path, headers=None, body=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read()


# --- sidecar ---------------------------------------------------------------


def test_sidecar_injects_token_for_allowlisted_upstream(proxy):
    port, up = proxy
    st, _, body = _req(port, "GET", f"http://{up.host}/x?a=1")
    assert st == 200 and body == b"ok"
    assert up.seen[0][1] == "/x?a=1" and up.seen[0][2].startswith("Bearer ")


def test_sidecar_refuses_absolute_url_to_another_host(proxy):
    """An agent must not be able to point the injected token at a host of its choosing."""
    port, up = proxy
    thief = _Upstream()
    try:
        st, _, _ = _req(
            port, "GET", f"http://{thief.host}/steal", {"X-Delcred-Upstream": up.host}
        )
        assert st == 400
        assert thief.seen == []  # the token never left
    finally:
        thief.close()


@pytest.mark.parametrize("url", ["file:///etc/hostname", "ftp://x/y", "gopher://x/"])
def test_sidecar_refuses_non_http_schemes(proxy, url):
    port, up = proxy
    st, _, _ = _req(port, "GET", url, {"X-Delcred-Upstream": up.host})
    assert st == 400


def test_sidecar_does_not_follow_redirects(home, subject, actor):
    thief = _Upstream()
    up = _Upstream(lambda h: (302, {"Location": f"http://{thief.host}/leak"}, b""))
    res = f"http://{up.host}"
    (home / "policy.yaml").write_text(
        f'grants:\n  - {{user: u_alice, agent: billing-agent, scopes: ["invoices:read"], resources: ["{res}"]}}\n'
    )
    H = sidecar._ProxyHandler
    H.mapping = {up.host: f"invoices:read|{res}"}
    H.user_token, H.agent_token, H.base, H._cache = subject, actor, home, {}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        st, _, _ = _req(srv.server_address[1], "GET", f"http://{up.host}/")
        assert st == 302 and thief.seen == []
    finally:
        srv.shutdown(); srv.server_close(); up.close(); thief.close()


def test_sidecar_passes_upstream_errors_through_and_drops_caller_authorization(home, subject, actor):
    up = _Upstream(lambda h: (403, {"WWW-Authenticate": 'Bearer error="insufficient_scope"'}, b"no"))
    res = f"http://{up.host}"
    (home / "policy.yaml").write_text(
        f'grants:\n  - {{user: u_alice, agent: billing-agent, scopes: ["invoices:read"], resources: ["{res}"]}}\n'
    )
    H = sidecar._ProxyHandler
    H.mapping = {up.host: f"invoices:read|{res}"}
    H.user_token, H.agent_token, H.base, H._cache = subject, actor, home, {}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        st, hdrs, body = _req(
            srv.server_address[1], "GET", f"http://{up.host}/", {"authorization": "Bearer mine"}
        )
        assert st == 403 and body == b"no"  # was a blanket 502 before
        assert "insufficient_scope" in hdrs.get("WWW-Authenticate", "")
        assert up.seen[0][2] != "Bearer mine" and up.seen[0][2].startswith("Bearer ey")
    finally:
        srv.shutdown(); srv.server_close(); up.close()


def test_sidecar_rejects_bad_and_oversized_content_length(proxy):
    port, up = proxy
    st, _, _ = _req(port, "POST", "/", {"X-Delcred-Upstream": up.host, "Content-Length": "abc"})
    assert st == 400
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.putrequest("POST", "/")
    c.putheader("X-Delcred-Upstream", up.host)
    c.putheader("Content-Length", str(10**10))
    c.endheaders()
    assert c.getresponse().status == 413
    assert up.seen == []


def test_sidecar_plain_http_only_for_loopback():
    assert sidecar._is_loopback_host("127.0.0.1:8080") and sidecar._is_loopback_host("localhost")
    assert not sidecar._is_loopback_host("evil.test") and not sidecar._is_loopback_host("127.0.0.1.evil.test")


def test_sidecar_head_supported(proxy):
    port, up = proxy
    st, _, body = _req(port, "HEAD", f"http://{up.host}/h")
    assert st == 200 and body == b""


# --- server: CSRF + DNS rebinding + RFC 7009 --------------------------------


@pytest.fixture
def api(home):
    from delcred.server import make_server

    srv = make_server(port=0, base=home, rate=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], home
    srv.shutdown()
    srv.server_close()


def _post(port, path, obj, headers=None):
    h = {"Content-Type": "application/json", **(headers or {})}
    return _req(port, "POST", path, h, json.dumps(obj))


def test_revoke_refuses_cross_site_browser_requests(api):
    port, home = api
    # what a hostile web page can send: a "simple" POST with Origin/Sec-Fetch-Site set
    for hdr in ({"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"}):
        st, _, _ = _post(port, "/revoke", {"agent": "billing-agent"}, {**hdr, "Content-Type": "text/plain"})
        assert st == 403
    assert delcred.RevocationList(home).is_revoked({"act": {"sub": "billing-agent"}, "sub": "x"})[0] is False
    st, _, _ = _post(port, "/revoke", {"agent": "billing-agent"})  # non-browser client still works
    assert st == 200


def test_dns_rebinding_host_header_refused(api):
    port, _ = api
    assert _req(port, "GET", "/health", {"Host": "evil.example"})[0] == 421
    assert _req(port, "GET", "/health", {"Host": f"localhost:{port}"})[0] == 200
    assert _req(port, "GET", "/health", {"Host": f"[::1]:{port}"})[0] == 200
    assert _post(port, "/revoke", {"agent": "a"}, {"Host": "evil.example"})[0] == 421


def test_oauth_revoke_endpoint_rfc7009(api, home, subject, actor):
    port, _ = api
    tok = delcred.delegate(scope="invoices:read", resource=RES, user_token=subject, agent_token=actor, base=home)
    delcred.verify(tok, expected_resource=RES, base=home)
    assert _post(port, "/oauth/revoke", {"token": tok})[0] == 200
    with pytest.raises(delcred.ExchangeError, match="revoked"):
        delcred.verify(tok, expected_resource=RES, base=home)
    assert _post(port, "/oauth/revoke", {"token": "junk"})[0] == 200  # no oracle
    assert _post(port, "/oauth/revoke", {})[0] == 400
    _, _, body = _req(port, "GET", "/.well-known/oauth-authorization-server")
    assert json.loads(body)["revocation_endpoint"].endswith("/oauth/revoke")
    events = [e["event"] for e in AuditLog(home).entries()]
    assert "token_revoked_by_holder" in events


def test_revoke_presented_ignores_agent_tokens_and_garbage(home, actor):
    assert revoke_presented(actor, base=home) is False
    assert revoke_presented("x.y.z", base=home) is False
    assert delcred.revoke_presented("nope", base=home) is False


# --- audit -----------------------------------------------------------------


def test_rejected_credentials_are_audited_without_the_token(home, subject, actor):
    tok = delcred.delegate(scope="invoices:read", resource=RES, user_token=subject, agent_token=actor, base=home)
    for bad, res in ((tok[:-3] + "AAA", RES), (tok, "https://other.test"), ("garbage", RES)):
        with pytest.raises(delcred.TokenError):
            delcred.verify(bad, expected_resource=res, base=home)
    rows = [e for e in AuditLog(home).entries() if e["event"] == "verify_rejected"]
    assert len(rows) == 3
    assert {r["reason"] for r in rows} == {"InvalidToken"}
    raw = (home / "audit.jsonl").read_text()
    assert tok not in raw and "garbage" not in raw.replace("verify_rejected", "")
    assert AuditLog(home).verify().ok


def test_rejected_audit_is_rate_limited_and_reports_suppressed(home):
    from delcred import audit as au

    au._THROTTLE.clear()
    for i in range(300):
        with pytest.raises(delcred.TokenError):
            delcred.verify(f"junk{i}", expected_resource=RES, base=home)
    rows = [e for e in AuditLog(home).entries() if e["event"] == "verify_rejected"]
    assert 40 <= len(rows) < 120  # burst of 50 plus a trickle, not 300
    # the next one through says how many were dropped
    au._THROTTLE[str(AuditLog(home).path)] = [5.0, __import__("time").monotonic(), 7.0]
    with pytest.raises(delcred.TokenError):
        delcred.verify("again", expected_resource=RES, base=home)
    assert AuditLog(home).entries()[-1].get("suppressed") == 7


def test_audit_tail_matches_full_scan_and_handles_torn_tail(home):
    log = AuditLog(home)
    for i in range(400):
        log.record("verify_ok", jti=f"j{i}")
    full = log.entries()
    assert log.tail(5) == full[-5:]
    assert log.tail(1000) == full
    with open(log.path, "ab") as f:
        f.write(b'{"torn":')  # crash mid-write
    assert log.tail(3) == full[-3:]
    assert log.tail(0) == []
    assert log.tail(2, event="verify_ok")[-1]["jti"] == "j399"


def test_audit_checkpoint_detects_truncation_and_rewrite(home):
    log = AuditLog(home)
    for i in range(10):
        log.record("token_issued", jti=f"j{i}")
    cp = log.checkpoint()
    assert log.verify(checkpoint=cp).ok
    log.record("token_issued", jti="later")  # growth after the checkpoint is fine
    assert log.verify(checkpoint=cp).ok
    path = log.path
    lines = path.read_text().splitlines()
    # 1) truncation of the newest entries: the bare chain still verifies...
    path.write_text("\n".join(lines[:6]) + "\n")
    assert log.verify().ok
    res = log.verify(checkpoint=cp)
    assert not res.ok and "removed" in " ".join(res.problems)
    # 2) wholesale rewrite with a self-consistent chain
    path.write_text("")
    forged = AuditLog(home)
    for i in range(12):
        forged.record("token_issued", jti=f"forged{i}")
    assert forged.verify().ok
    res = forged.verify(checkpoint=cp)
    assert not res.ok and "rewritten" in " ".join(res.problems)


def test_audit_checkpoint_forgery_and_junk_rejected(home):
    log = AuditLog(home)
    log.record("x")
    cp = log.checkpoint()
    h, p, s = cp.split(".")
    for bad in (f"{h}.{p}.{s[:-2]}AA", "a.b.c", "", cp.replace(h, h[:-1] + "A")):
        with pytest.raises(ValueError):
            log.verify(checkpoint=bad)


def test_audit_fsync_routine_off(home, monkeypatch):
    import os as _os

    calls = []
    real = _os.fsync
    monkeypatch.setattr(_os, "fsync", lambda fd: (calls.append(1), real(fd))[1])
    log = AuditLog(home)
    monkeypatch.setenv("DELCRED_AUDIT_FSYNC", "routine-off")
    log.record("verify_ok")
    assert calls == []
    log.record("token_issued")  # important events always sync
    assert len(calls) == 1
    monkeypatch.delenv("DELCRED_AUDIT_FSYNC")
    log.record("verify_ok")
    assert len(calls) == 2


# --- policy ---------------------------------------------------------------


@pytest.mark.parametrize(
    "grant",
    [
        '{user: u, agent: a, scopes: "invoices:read", resources: [r]}',  # bare string
        "{user: u, agent: a, scopes: [x], resources: https://x.test}",
        "{user: u, agent: a, scopes: [x], resources: [r], max_ttl: 0}",
        "{user: u, agent: a, scopes: [x], resources: [r], max_ttl: abc}",
        '{user: u, agent: a, scopes: [x], resources: [r], single_use: "false"}',
        '{user: u, agent: a, scopes: ["a b"], resources: [r]}',
        "{agent: a, scopes: [x], resources: [r]}",
        "{user: u, agent: a, scopes: [x], resources: [r], delegate_to: child}",
    ],
)
def test_policy_rejects_wrong_types_instead_of_misreading_them(home, grant):
    (home / "policy.yaml").write_text(f"grants:\n  - {grant}\n")
    with pytest.raises(PolicyError):
        load_policy(home)


@pytest.mark.parametrize("text", ["- a\n- b\n", "grants: {a: b}\n", "grants: [1, 2]\n", "grants: [", "\x00\x01"])
def test_policy_rejects_wrong_shapes(home, text):
    (home / "policy.yaml").write_text(text)
    with pytest.raises(PolicyError):
        load_policy(home)


def test_malformed_policy_denies_exchange_cleanly(home, subject, actor):
    (home / "policy.yaml").write_text("grants: nope\n")
    with pytest.raises(PolicyError):
        delcred.delegate(scope="s", resource=RES, user_token=subject, agent_token=actor, base=home)


def test_policy_validate_warnings(home):
    (home / "policy.yaml").write_text(
        """agents:
  a: {}
grants:
  - {user: u, agent: a, scope: [x], resources: ["http://api.test/v1/"]}
  - {user: u, agent: a, scopes: ["inv:*"], resources: ["https://api.test/v1/#f"], delegate_to: [b], max_depth: 0}
  - {user: u, agent: ghost, scopes: [x], resources: ["https://api.test"], max_ttl: 99999}
"""
    )
    errors, warnings = validate(home)
    text = "\n".join(warnings)
    assert not errors
    for needle in ("unknown key 'scope'", "no scopes", "plain http", "ends with '/'", "duplicates grant #1",
                   "wildcard", "fragment", "max_depth", "not listed under 'agents:'", "exceeds the hard cap"):
        assert needle in text, needle
    (home / "policy.yaml").write_text("grants: nope")
    assert validate(home)[0]


def test_good_policy_validates_clean(home):
    assert validate(home) == ([], [])


# --- verify(check_policy) ---------------------------------------------------


def test_check_policy_kills_token_when_grant_removed_or_narrowed(home, subject, actor):
    tok = delcred.delegate(scope="invoices:read", resource=RES, user_token=subject, agent_token=actor, base=home)
    assert delcred.verify(tok, expected_resource=RES, base=home, check_policy=True)["sub"] == "u_alice"
    pol = (home / "policy.yaml").read_text()
    (home / "policy.yaml").write_text(pol.replace('"invoices:read", "customers:read"', '"customers:read"'))
    assert delcred.verify(tok, expected_resource=RES, base=home)  # default behaviour unchanged
    with pytest.raises(delcred.ExchangeError, match="no longer granted"):
        delcred.verify(tok, expected_resource=RES, base=home, check_policy=True)
    (home / "policy.yaml").write_text("grants: []\n")
    with pytest.raises(delcred.ExchangeError, match="no grant"):
        delcred.verify(tok, expected_resource=RES, base=home, check_policy=True)
    (home / "policy.yaml").write_text("grants: oops\n")  # unreadable policy fails closed
    with pytest.raises(delcred.ExchangeError, match="unreadable"):
        delcred.verify(tok, expected_resource=RES, base=home, check_policy=True)
    assert any(e["event"] == "verify_policy_revoked" for e in AuditLog(home).entries())


def test_check_policy_on_chained_token(home):
    (home / "policy.yaml").write_text(
        f'''grants:
  - user: u_alice
    agent: orch
    scopes: ["a", "b"]
    resources: ["{RES}"]
    delegate_to: [sub]
    max_depth: 1
'''
    )
    u = delcred.user_token("u_alice", base=home)
    parent = delcred.delegate(scope="a b", resource=RES, user_token=u, agent_token=delcred.agent_token("orch", base=home), base=home)
    child = delcred.attenuate(parent, sub_agent_token=delcred.agent_token("sub", base=home), scope="a", resource=RES, base=home)
    assert delcred.verify(child, expected_resource=RES, base=home, check_policy=True)
    (home / "policy.yaml").write_text((home / "policy.yaml").read_text().replace("delegate_to: [sub]", "delegate_to: []"))
    with pytest.raises(delcred.ExchangeError, match="delegate_to"):
        delcred.verify(child, expected_resource=RES, base=home, check_policy=True)


def test_mcp_authorize_check_policy(home, subject, actor):
    from delcred.mcp import authorize

    tok = delcred.delegate(scope="invoices:read", resource=RES, user_token=subject, agent_token=actor, base=home)
    hdr = f"Bearer {tok}"
    assert authorize(hdr, resource=RES, base=home, check_policy=True).ok
    (home / "policy.yaml").write_text("grants: []\n")
    assert authorize(hdr, resource=RES, base=home).ok
    d = authorize(hdr, resource=RES, base=home, check_policy=True)
    assert d.status == 401 and "no grant" not in d.description  # no oracle


# --- terminal hygiene -------------------------------------------------------


def test_safe_text_escapes_controls_bidi_and_truncates():
    out = safe_text("a\x1b]0;pwn\x07\u202e\u200bb\nc")
    assert "\x1b" not in out and "\x07" not in out and "\u202e" not in out and "\n" not in out
    assert "\\u001b" in out and "\\u202e" in out
    assert safe_text("é日本 ok") == "é日本 ok"
    assert safe_text("x" * 1000, 10) == "x" * 10 + "..."
    assert safe_text(Exception("\x1b[31m")) == "\\u001b[31m"


def test_revocation_reason_is_sanitised_at_rest_and_in_cli(home, subject, actor, capsys):
    from delcred.cli import build_parser

    tok = delcred.delegate(scope="invoices:read", resource=RES, user_token=subject, agent_token=actor, base=home)
    delcred.revoke_agent("billing-agent", reason="\x1b]0;PWNED\x07\x1b[31m", base=home)
    assert b"\x1b" not in (home / "revocations.jsonl").read_bytes()
    assert b"\x1b" not in (home / "audit.jsonl").read_bytes()
    args = build_parser().parse_args(["--home", str(home), "verify", tok, "--resource", RES])
    with pytest.raises(SystemExit):
        args.func(args)
    err = capsys.readouterr().err
    assert "\x1b" not in err and "\x07" not in err


def test_cli_policy_validate_audit_checkpoint_and_revoke_token(home, subject, actor, capsys, tmp_path):
    from delcred.cli import main

    def run(*argv):
        main(["--home", str(home), *argv])

    run("policy", "validate")
    assert "policy OK" in capsys.readouterr().out
    tok = delcred.delegate(scope="invoices:read", resource=RES, user_token=subject, agent_token=actor, base=home)
    run("audit", "checkpoint")
    cp = capsys.readouterr().out.strip().splitlines()[0]
    f = tmp_path / "cp.txt"
    f.write_text(cp)
    run("audit", "verify", "--checkpoint-file", str(f))
    assert "matches the signed checkpoint" in capsys.readouterr().out
    tf = tmp_path / "t.jwt"
    tf.write_text(tok)
    run("revoke", "--token-file", str(tf))
    with pytest.raises(SystemExit) as e:
        run("verify", tok, "--resource", RES)
    assert e.value.code == 4
    capsys.readouterr()
    (home / "policy.yaml").write_text("grants: nope\n")
    with pytest.raises(SystemExit) as e:
        run("status")
    assert e.value.code == 3 and "policy error" in capsys.readouterr().err
    (home / "policy.yaml").write_text("grants: []\n")
    t2 = delcred.delegate  # silence linters about unused
    del t2
    with pytest.raises(SystemExit) as e:
        run("verify", tok, "--resource", RES, "--check-policy")
    assert e.value.code == 4


# --- dpop ------------------------------------------------------------------


def test_dpop_non_ascii_access_token_is_a_clean_error():
    from delcred import pop

    key = pop.generate_key()
    with pytest.raises(pop.PopError):
        pop.make_proof(key, "GET", "https://a.test/x", access_token="tök")


def test_init_creates_a_missing_home_directory(tmp_path):
    target = tmp_path / "does" / "not" / "exist yet"
    delcred.init(base=target)
    assert (target / "policy.yaml").exists()
    import os
    if os.name != "nt":
        assert oct(target.stat().st_mode & 0o777) == "0o700"


def test_sidecar_refuses_userinfo_smuggling_in_request_path(proxy):
    """`GET @evil.test/x` must not become https://<allowlisted>@evil.test/x."""
    port, up = proxy
    thief = _Upstream()
    try:
        for path in (f"@{thief.host}/x", f"//{thief.host}/x", f"x@{thief.host}/", f"{thief.host}/x"):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.putrequest("GET", path, skip_host=False)
            c.putheader("X-Delcred-Upstream", up.host)
            c.endheaders()
            assert c.getresponse().status in (400, 403, 502)  # 502: stdlib rewrote "//h/x" to "/h/x" on the allowlisted host (https to a plain-http test server)
        assert thief.seen == [] and up.seen == []
    finally:
        thief.close()


def test_oauth_revoke_accepts_form_encoding_and_is_idempotent(api, home, subject, actor):
    port, _ = api
    tok = delcred.delegate(scope="invoices:read", resource=RES, user_token=subject, agent_token=actor, base=home)
    body = urllib.parse.urlencode({"token": tok, "token_type_hint": "access_token"})
    for _ in range(3):
        st, _, _ = _req(port, "POST", "/oauth/revoke", {"Content-Type": "application/x-www-form-urlencoded"}, body)
        assert st == 200
    rows = [e for e in AuditLog(home).entries() if e["event"] == "token_revoked_by_holder"]
    assert len(rows) == 1


def test_audit_tail_large_n_falls_back_to_stream(home):
    log = AuditLog(home)
    for i in range(30):
        log.record("verify_ok", jti=f"j{i}")
    assert log.tail(5000) == log.entries()


def test_child_never_outlives_parent_even_if_the_clock_ticks_mid_call(home, monkeypatch):
    """Regression: the bench fuzz found exp(child) = exp(parent) + 1 on a slow disk,
    because 'remaining' and the child's iat were read from two different clock reads."""

    from delcred import tokens as T

    (home / "policy.yaml").write_text(
        f"""grants:
  - user: u_alice
    agent: orch
    scopes: ["a"]
    resources: ["{RES}"]
    delegate_to: [sub]
    max_depth: 1
"""
    )
    parent = delcred.delegate(
        scope="a", resource=RES, ttl=30, base=home,
        user_token=delcred.user_token("u_alice", base=home),
        agent_token=delcred.agent_token("orch", base=home),
    )
    pexp = T.decode_unverified(parent)["exp"]
    sub = delcred.agent_token("sub", base=home)
    real = T._now
    calls = {"n": 0}

    def ticking():  # second read lands one second later than the first
        calls["n"] += 1
        return real() + (1 if calls["n"] >= 1 else 0)

    monkeypatch.setattr(T, "_now", ticking)
    child = delcred.attenuate(parent, sub_agent_token=sub, scope="a", resource=RES, base=home)
    assert T.decode_unverified(child)["exp"] <= pexp
