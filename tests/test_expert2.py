"""expert-2: sub-delegation, DPoP, key overlap, bulletins, hygiene, speed."""

import json
import random
import shutil
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

import delcred
from delcred import bulletin, keys, pop, tokens, vectors
from delcred._common import check_identifier, parse_scope
from delcred.exchange import ExchangeError
from delcred.mcp import authorize
from delcred.offline import verify_offline
from delcred.policy import PolicyError
from delcred.revocation import RevocationList
from delcred.tokens import InvalidToken

RES = "https://api.acme.test/v1"
REPO = Path(__file__).resolve().parent.parent

POLICY = f"""grants:
  - user: u_alice
    agent: orchestrator
    scopes: ["invoices:read", "invoices:write", "customers:read"]
    resources: ["{RES}"]
    max_ttl: 900
    delegate_to: [summarizer, mailer, archiver]
    max_depth: 2
  - user: u_alice
    agent: worker
    scopes: ["invoices:read"]
    resources: ["{RES}"]
  - user: u_alice
    agent: oneshot
    scopes: ["invoices:read"]
    resources: ["{RES}"]
    single_use: true
    delegate_to: [summarizer]
"""


@pytest.fixture
def h(home):
    (home / "policy.yaml").write_text(POLICY)
    return home


def _root(h, agent="orchestrator", scope="invoices:read invoices:write", **kw):
    u = delcred.user_token("u_alice", base=h)
    a = delcred.agent_token(agent, base=h)
    return delcred.delegate(scope=scope, resource=RES, user_token=u, agent_token=a, base=h, **kw)


def _sub(h, parent, child="summarizer", scope="invoices:read", **kw):
    return delcred.attenuate(
        parent, sub_agent_token=delcred.agent_token(child, base=h),
        scope=scope, resource=RES, base=h, **kw,
    )


# ---------------------------------------------------------------- sub-delegation


def test_attenuation_narrows_and_chains(h):
    parent = _root(h)
    child = _sub(h, parent)
    c = delcred.verify(child, expected_resource=RES, required_scopes="invoices:read", base=h)
    assert c["sub"] == "u_alice" and c["act"] == {"sub": "summarizer", "act": {"sub": "orchestrator"}}
    assert c["scope"] == "invoices:read" and c["aud"] == RES
    pc = tokens.decode_unverified(parent)
    assert c["chain"] == [pc["jti"]] and c["exp"] <= pc["exp"]
    with pytest.raises(delcred.InsufficientScope):
        delcred.verify(child, expected_resource=RES, required_scopes="invoices:write", base=h)
    assert authorize(f"Bearer {child}", resource=RES, base=h).agents == ["summarizer", "orchestrator"]


def test_cannot_widen_scope(h):
    parent = _root(h, scope="invoices:read")
    with pytest.raises(PolicyError, match="only narrow"):
        _sub(h, parent, scope="invoices:read invoices:write")  # write is in the grant, not the parent


def test_deny_by_default_for_unlisted_sub_agent_and_no_delegate_grant(h):
    parent = _root(h)
    with pytest.raises(PolicyError, match="not allowed to sub-delegate"):
        _sub(h, parent, child="stranger")
    w = _root(h, agent="worker", scope="invoices:read")
    with pytest.raises(PolicyError, match="not allowed to sub-delegate"):
        _sub(h, w)  # worker's grant has no delegate_to


def test_depth_limit_and_cycle(h):
    p = _root(h)
    c1 = _sub(h, p)  # depth 1
    c2 = _sub(h, c1, child="mailer")  # depth 2 == max_depth
    assert len(tokens.actor_chain(tokens.decode_unverified(c2))) == 3
    with pytest.raises(PolicyError, match="depth"):
        _sub(h, c2, child="archiver")  # would be hop 3
    with pytest.raises(ExchangeError, match="already in this"):
        _sub(h, c1, child="summarizer")


def test_resource_and_ttl_cannot_escape_parent(h):
    parent = _root(h, ttl=120)
    with pytest.raises(PolicyError):
        delcred.attenuate(
            parent, sub_agent_token=delcred.agent_token("summarizer", base=h),
            scope="invoices:read", resource="https://evil.test/v1", base=h)
    child = _sub(h, parent, ttl=3600)
    assert tokens.decode_unverified(child)["exp"] <= tokens.decode_unverified(parent)["exp"]


def test_single_use_parent_cannot_delegate(h):
    p = _root(h, agent="oneshot", scope="invoices:read")
    with pytest.raises(PolicyError, match="single-use"):
        _sub(h, p)


def test_revoking_ancestor_agent_or_user_kills_children(h):
    p = _root(h)
    c = _sub(h, p)
    g = _sub(h, c, child="mailer")
    for tok in (c, g):
        delcred.verify(tok, expected_resource=RES, base=h)
    delcred.revoke_token(tokens.decode_unverified(p)["jti"], reason="parent", base=h)
    for tok in (c, g):
        with pytest.raises(ExchangeError, match="parent delegation revoked"):
            delcred.verify(tok, expected_resource=RES, base=h)
    with pytest.raises(ExchangeError):
        _sub(h, p)  # revoked parent cannot mint more children


def test_revoking_middle_agent_kills_grandchild_only(h):
    p = _root(h)
    c = _sub(h, p)
    g = _sub(h, c, child="mailer")
    delcred.revoke_agent("summarizer", base=h)
    with pytest.raises(ExchangeError, match="summarizer"):
        delcred.verify(g, expected_resource=RES, base=h)
    delcred.verify(p, expected_resource=RES, base=h)  # root unaffected


def test_policy_shrink_blocks_new_children(h):
    p = _root(h)
    (h / "policy.yaml").write_text(POLICY.replace('"invoices:read", "invoices:write", "customers:read"', '"customers:read"', 1))
    with pytest.raises(PolicyError, match="no longer granted"):
        _sub(h, p)


def test_child_token_cannot_be_hand_edited(h):
    c = _sub(h, _root(h))
    head, payload, sig = c.split(".")
    import base64
    cl = json.loads(base64.urlsafe_b64decode(payload + "=="))
    cl["scope"] = "invoices:read invoices:write"
    forged = ".".join([head, base64.urlsafe_b64encode(json.dumps(cl).encode()).decode().rstrip("="), sig])
    with pytest.raises(InvalidToken):
        delcred.verify(forged, expected_resource=RES, base=h)


def test_escalation_fuzz_never_mints_more_than_parent(h):
    """Randomised attenuation attempts: every minted child must satisfy the invariants."""
    rng = random.Random(7)
    pool = ["invoices:read", "invoices:write", "customers:read", "admin:all", "x:y"]
    parent = _root(h, scope="invoices:read invoices:write")
    pc = tokens.decode_unverified(parent)
    minted = 0
    for _ in range(300):
        want = " ".join(rng.sample(pool, rng.randint(1, 3)))
        child = rng.choice(["summarizer", "mailer", "stranger", "orchestrator"])
        res = rng.choice([RES, RES, "https://evil.test/v1"])
        ttl = rng.choice([1, 60, 900, 99999])
        try:
            c = delcred.attenuate(
                parent, sub_agent_token=delcred.agent_token(child, base=h),
                scope=want, resource=res, ttl=ttl, base=h)
        except (PolicyError, ExchangeError):
            continue
        minted += 1
        cc = tokens.decode_unverified(c)
        assert set(cc["scope"].split()) <= set(pc["scope"].split())
        assert cc["aud"] == pc["aud"] and cc["exp"] <= pc["exp"]
        assert cc["act"]["sub"] in ("summarizer", "mailer")
    assert minted > 5


# --------------------------------------------------------------------------- DPoP


def test_dpop_bound_token_roundtrip_and_theft(h):
    key = pop.generate_key()
    tok = _root(h, dpop_jkt=pop.thumbprint(key))
    url = RES + "/invoices?limit=1"
    proof = pop.make_proof(key, "GET", url, access_token=tok)
    c = delcred.verify(tok, expected_resource=RES, base=h, dpop_proof=proof, http_method="GET", http_url=url)
    assert c["cnf"]["jkt"] == pop.thumbprint(key)
    with pytest.raises(InvalidToken, match="sender-constrained"):
        delcred.verify(tok, expected_resource=RES, base=h)  # stolen bearer use
    thief = pop.generate_key()
    with pytest.raises(InvalidToken, match="DPoP"):
        delcred.verify(tok, expected_resource=RES, base=h, http_method="GET", http_url=url,
                       dpop_proof=pop.make_proof(thief, "GET", url, access_token=tok))
    with pytest.raises(InvalidToken, match="replayed"):
        delcred.verify(tok, expected_resource=RES, base=h, dpop_proof=proof, http_method="GET", http_url=url)


def test_thief_cannot_burn_single_use_token(h):
    key = pop.generate_key()
    tok = _root(h, agent="oneshot", scope="invoices:read", dpop_jkt=pop.thumbprint(key))
    for _ in range(3):
        with pytest.raises(InvalidToken):
            delcred.verify(tok, expected_resource=RES, base=h)
    url = RES + "/x"
    delcred.verify(tok, expected_resource=RES, base=h, http_method="GET", http_url=url,
                   dpop_proof=pop.make_proof(key, "GET", url, access_token=tok))


def test_dpop_proof_rules(h):
    key = pop.generate_key()
    tok = "tok"
    jkt = pop.thumbprint(key)
    url = "https://api.acme.test/v1/a"
    now = int(time.time())
    ok = pop.make_proof(key, "GET", url, access_token=tok, now=now)
    assert pop.verify_proof(ok, method="GET", url=url, access_token=tok, expected_jkt=jkt, cache=pop.ReplayCache()) == jkt
    cases = [
        {"method": "POST", "url": url},
        {"method": "GET", "url": url + "x"},
        {"method": "GET", "url": url, "access_token": "other"},
    ]
    for kw in cases:
        kw.setdefault("access_token", tok)
        with pytest.raises(pop.PopError):
            pop.verify_proof(ok, expected_jkt=jkt, cache=pop.ReplayCache(), **kw)
    for iat in (now - 500, now + 500):
        with pytest.raises(pop.PopError, match="window"):
            pop.verify_proof(pop.make_proof(key, "GET", url, access_token=tok, now=iat),
                             method="GET", url=url, access_token=tok, cache=pop.ReplayCache())
    with pytest.raises(pop.PopError):
        pop.verify_proof("a.b.c", method="GET", url=url, cache=pop.ReplayCache())
    with pytest.raises(pop.PopError):
        pop.verify_proof("x" * 5000, method="GET", url=url, cache=pop.ReplayCache())


def test_replay_cache_is_bounded_and_fails_closed():
    c = pop.ReplayCache(per_key=3, max_total=100)
    now = int(time.time())
    for i in range(3):
        c.add("k", f"j{i}", now + 100, now)
    with pytest.raises(pop.PopError, match="full"):
        c.add("k", "j4", now + 100, now)
    c.add("other-key", "j", now + 100, now)  # another key is unaffected
    with pytest.raises(pop.PopError, match="replayed"):
        c.add("other-key", "j", now + 100, now)


def test_attenuation_of_bound_parent_needs_proof_and_stays_bound(h):
    key = pop.generate_key()
    jkt = pop.thumbprint(key)
    parent = _root(h, dpop_jkt=jkt)
    child_tok = delcred.agent_token("summarizer", base=h)
    endpoint = "https://auth.acme.test/token"
    with pytest.raises(ExchangeError, match="DPoP-bound"):
        delcred.attenuate(parent, sub_agent_token=child_tok, scope="invoices:read", resource=RES, base=h)
    with pytest.raises(ExchangeError, match="DPoP-bound"):
        delcred.attenuate(parent, sub_agent_token=child_tok, scope="invoices:read", resource=RES, base=h,
                          dpop_jkt=pop.thumbprint(pop.generate_key()))
    from delcred.exchange import exchange
    proof = pop.make_proof(key, "POST", endpoint)
    res = exchange(subject_token=parent, actor_token=child_tok, scope="invoices:read", resource=RES,
                   dpop_proof=proof, dpop_url=endpoint, base=h)
    assert res.claims["cnf"] == {"jkt": jkt}  # cannot be stripped


def test_mcp_authorize_dpop(h):
    key = pop.generate_key()
    tok = _root(h, dpop_jkt=pop.thumbprint(key))
    url = RES + "/tools"
    kw = {"resource": RES, "base": h, "http_method": "POST", "http_url": url}
    d = authorize(f"Bearer {tok}", **kw)
    assert d.status == 401 and d.error == "invalid_dpop_proof" and d.www_authenticate.startswith("DPoP ")
    proof = pop.make_proof(key, "POST", url, access_token=tok)
    d = authorize(f"DPoP {tok}", dpop_proof=proof, **kw)
    assert d.ok and d.agent == "orchestrator"
    plain = _root(h)
    assert authorize(f"DPoP {plain}", dpop_proof=proof, **kw).status == 401


# ------------------------------------------------------------------ key rotation


def test_rotation_overlap_keeps_old_tokens_and_jwks(h):
    old_tok = _root(h)
    old_kid = keys.key_id(keys.load_public(h))
    keys.rotate(h, keep_old=3600)
    new_tok = _root(h)
    for t in (old_tok, new_tok):
        delcred.verify(t, expected_resource=RES, base=h)
    assert {k["kid"] for k in delcred.jwks(base=h)["keys"]} >= {old_kid, keys.key_id(keys.load_public(h))}
    assert len(delcred.jwks(base=h)["keys"]) == 2
    # a retired key never signs
    assert tokens.decode_unverified(new_tok) and jwt_kid(new_tok) != old_kid
    # offline verifiers with the new JWKS accept both generations
    for t in (old_tok, new_tok):
        assert verify_offline(t, jwks=delcred.jwks(base=h), resource=RES).ok
    assert keys.retire(old_kid, h)
    with pytest.raises(InvalidToken, match="kid mismatch"):
        delcred.verify(old_tok, expected_resource=RES, base=h)


def jwt_kid(t):
    import jwt
    return jwt.get_unverified_header(t)["kid"]


def test_hard_cut_forgets_overlaps_and_expiry_ends_overlap(h):
    t1 = _root(h)
    keys.rotate(h, keep_old=3600)
    keys.rotate(h, keep_old=0)  # compromise response: everything old dies
    with pytest.raises(InvalidToken):
        delcred.verify(t1, expected_resource=RES, base=h)
    assert len(delcred.jwks(base=h)["keys"]) == 1
    t2 = _root(h)
    keys.rotate(h, keep_old=1)
    assert keys.retired_keys(h, now=int(time.time()) + 5) == {}
    assert t2


def test_damaged_retired_record_does_not_widen_trust(h):
    keys.rotate(h, keep_old=3600)
    f = next((h / "retired").glob("*.json"))
    f.write_text(f.read_text().replace('"retire_after"', '"x"'))
    assert keys.retired_keys(h) == {}
    f.write_text("{not json")
    assert keys.retired_keys(h) == {}


# --------------------------------------------------- bulletin & offline verifier


def test_bulletin_makes_revocation_visible_to_third_parties(h):
    tok = _root(h)
    jwks = delcred.jwks(base=h)
    assert verify_offline(tok, jwks=jwks, resource=RES, bulletin=bulletin.export(h)).ok
    delcred.revoke_agent("orchestrator", reason="injection", base=h)
    v = verify_offline(tok, jwks=jwks, resource=RES, bulletin=bulletin.export(h))
    assert not v.ok and v.code == "revoked"
    assert verify_offline(tok, jwks=jwks, resource=RES).ok  # without a bulletin: only expiry protects
    v = verify_offline(tok, jwks=jwks, resource=RES, require_bulletin=True)
    assert v.code == "revocation_data_invalid"


def test_bulletin_old_copy_is_stale(h):
    old = bulletin.export(h)
    v = verify_offline(_root(h), jwks=delcred.jwks(base=h), resource=RES, bulletin=old,
                       now=int(time.time()) + 400)
    assert v.code == "revocation_data_invalid"


def test_offline_agrees_with_online_on_random_mutations(h):
    """Differential test: the standalone verifier and the full verifier accept the same tokens."""
    rng = random.Random(int(__import__("os").environ.get("DELCRED_FUZZ_SEED", "3")))
    jwks = delcred.jwks(base=h)
    good = [_root(h), _sub(h, _root(h))]
    revoked_one = _root(h, agent="worker", scope="invoices:read")
    delcred.revoke_agent("worker", base=h)
    for _ in range(300):
        t = rng.choice(good + [revoked_one])
        if rng.random() < 0.6:
            i = rng.randrange(len(t))
            t = t[:i] + rng.choice("AbZ-_.9") + t[i + 1:]
        online = True
        try:
            delcred.verify(t, expected_resource=RES, base=h)
        except Exception:  # noqa: BLE001
            online = False
        off = verify_offline(t, jwks=jwks, resource=RES, bulletin=bulletin.export(h)).ok
        assert online == off, t


def test_server_serves_bulletin_and_retired_keys(h):
    from delcred.server import make_server

    httpd = make_server(0, base=h, rate=0)
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        b = urllib.request.urlopen(base + "/revocations.jwt").read().decode()
        jwks = json.loads(urllib.request.urlopen(base + "/.well-known/jwks.json").read())
        assert verify_offline(_root(h), jwks=jwks, resource=RES, bulletin=b).ok
        meta = json.loads(urllib.request.urlopen(base + "/.well-known/oauth-authorization-server").read())
        assert meta["delcred_revocations_uri"].endswith("/revocations.jwt")
        # RFC 8693 /token: sub-delegation + DPoP header binding
        key = pop.generate_key()
        proof = pop.make_proof(key, "POST", base + "/token")
        parent = _root(h)
        form = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": parent, "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "actor_token": delcred.agent_token("summarizer", base=h),
            "actor_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "invoices:read", "resource": RES,
        }).encode()
        req = urllib.request.Request(base + "/token", data=form, headers={
            "Content-Type": "application/x-www-form-urlencoded", "DPoP": proof})
        r = json.loads(urllib.request.urlopen(req).read())
        assert r["token_type"] == "DPoP"
        c = tokens.decode_unverified(r["access_token"])
        assert c["cnf"]["jkt"] == pop.thumbprint(key) and c["act"]["act"]["sub"] == "orchestrator"
        bad = urllib.request.Request(base + "/token", data=form, headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "DPoP": pop.make_proof(key, "POST", base + "/other")})
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(bad)
        assert json.loads(e.value.read())["error"] == "invalid_dpop_proof"
    finally:
        httpd.shutdown()


# ------------------------------------------------------------------- hygiene


@pytest.mark.parametrize("bad", ["", "a b", "a\u00a0b", "ab\x1b[31m", "a\u202eb", "a\u200bb", "a\nb", "x" * 300, 5, None])
def test_identifier_rejects_terminal_bidi_zero_width_and_space(bad):
    with pytest.raises((ValueError, TypeError)):
        check_identifier(bad)


@pytest.mark.parametrize("bad", ["a\u00a0b\u00a0", "a\tb", "a\u2003b", "", "  ", "café", 'a"b', "a\\b", 5])
def test_scope_parser_is_rfc6749_strict(bad):
    with pytest.raises((ValueError, TypeError)):
        parse_scope(bad)
    assert parse_scope(" b  a a ") == ["a", "b"]


def test_exchange_rejects_bad_scope_ttl_and_ids(h):
    u = delcred.user_token("u_alice", base=h)
    a = delcred.agent_token("worker", base=h)
    for scope in ("invoices:read\u00a0x", "invoices:read\tx"):
        with pytest.raises(PolicyError):
            delcred.delegate(scope=scope, resource=RES, user_token=u, agent_token=a, base=h)
    for ttl in (True, 1.5, "900", 0, -1):
        with pytest.raises(PolicyError, match="ttl"):
            delcred.delegate(scope="invoices:read", resource=RES, user_token=u, agent_token=a, ttl=ttl, base=h)
    with pytest.raises(ValueError):
        delcred.agent_token("evil\x1b[2J", base=h)
    with pytest.raises(ValueError):
        delcred.user_token("u\u202ealice", base=h)


def test_oversized_token_rejected_fast(h):
    t0 = time.perf_counter()
    with pytest.raises(InvalidToken):
        delcred.verify(_root(h) + "A" * 3_000_000, expected_resource=RES, base=h)
    assert time.perf_counter() - t0 < 0.1


@pytest.mark.parametrize("hdr", [{"jwk": {"kty": "OKP"}}, {"jku": "https://x"}, {"x5c": ["a"]}, {"crit": ["exp"]}])
def test_key_injection_and_crit_headers_rejected(h, hdr):
    import jwt
    priv = keys.load_private(h)
    cl = tokens.decode_unverified(_root(h))
    from cryptography.hazmat.primitives import serialization
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    t = jwt.encode(cl, pem, algorithm="EdDSA", headers={"typ": "at+jwt", "kid": keys.key_id(priv.public_key()), **hdr})
    with pytest.raises(InvalidToken):
        delcred.verify(t, expected_resource=RES, base=h)


def test_unknown_cnf_and_inconsistent_chain_rejected(h):
    import jwt
    priv = keys.load_private(h)
    from cryptography.hazmat.primitives import serialization
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    base_claims = tokens.decode_unverified(_root(h))
    hdr = {"typ": "at+jwt", "kid": keys.key_id(priv.public_key())}
    for extra in ({"cnf": {"x5t#S256": "abc"}}, {"chain": ["x"]}, {"act": {"sub": "a", "act": "b"}}):
        t = jwt.encode({**base_claims, **extra}, pem, algorithm="EdDSA", headers=hdr)
        with pytest.raises(InvalidToken):
            delcred.verify(t, expected_resource=RES, base=h)


# ----------------------------------------------------------- revocation index


def test_revocation_index_sees_appends_prunes_and_other_writers(h):
    rl = RevocationList(h)
    claims = {"jti": "J1", "sub": "u", "act": {"sub": "a"}, "kind": "delegation"}
    assert rl.is_revoked(claims)[0] is False
    RevocationList(h).revoke_jti("J1", reason="x")  # a different instance (like another process)
    assert rl.is_revoked(claims)[0] is True
    RevocationList(h).revoke_jti("J2", expires_at=1)
    assert rl.prune() == 1
    assert rl.is_revoked(claims)[0] is True
    assert rl.is_revoked({**claims, "jti": "J2"})[0] is False


def test_revocation_check_is_fast_at_scale(h):
    rl = RevocationList(h)
    with open(rl.path, "a") as f:
        f.writelines(
            json.dumps({"type": "jti", "jti": f"x{i}", "revoked_at": 1, "reason": "", "expires_at": None}) + "\n"
            for i in range(20_000)
        )
    claims = {"jti": "none", "sub": "u", "act": {"sub": "a"}, "kind": "delegation"}
    rl.is_revoked(claims)  # build the index once
    t0 = time.perf_counter()
    for _ in range(200):
        rl.is_revoked(claims)
    assert (time.perf_counter() - t0) / 200 < 0.002  # was ~35 ms at 20k entries before the index


# --------------------------------------------------- cross-language vectors


def test_committed_vectors_are_current_and_python_passes():
    doc = vectors.build()
    committed = json.loads((REPO / "spec/vectors/vectors.json").read_text())
    assert committed == doc, "run `delcred vectors --out spec/vectors`"
    assert len(doc["cases"]) >= 80
    assert vectors.run(doc) == []


def test_vectors_cover_every_result_code():
    codes = {c for case in vectors.build()["cases"] for c in case["expect"]}
    assert codes == {"ok", "invalid_token", "expired", "not_yet_valid", "wrong_audience",
                     "insufficient_scope", "revoked", "revocation_data_invalid",
                     "dpop_required", "invalid_dpop_proof"}


def test_conformance_runner_detects_a_wrong_verifier():
    doc = vectors.build()
    doc["cases"][0]["expect"] = ["expired"]
    assert vectors.run(doc)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_node_verifier_passes_all_vectors():
    r = subprocess.run(["node", str(REPO / "spec/verifiers/node/verify.mjs"), str(REPO / "spec/vectors/vectors.json")],
                       check=False, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.skipif(shutil.which("go") is None, reason="go not installed")
def test_go_verifier_passes_all_vectors():
    r = subprocess.run(["go", "run", ".", str(REPO / "spec/vectors/vectors.json")],
                       cwd=REPO / "spec/verifiers/go", check=False, capture_output=True, text=True, timeout=240)
    assert r.returncode == 0, r.stdout + r.stderr


def test_torn_revocation_line_does_not_swallow_the_next_entry(h):
    rl = RevocationList(h)
    rl.revoke_jti("A")
    with open(rl.path, "ab") as f:
        f.write(b'{"type": "jti", "jti": "TORN')  # crash mid-write, no newline
    rl.revoke_agent("rogue", reason="after the crash")
    c = {"jti": "none", "sub": "u", "act": {"sub": "rogue"}, "kind": "delegation"}
    assert rl.is_revoked(c)[0] is True
    assert rl.burn_once("B") is True
    assert rl.burn_once("B") is False
    assert rl.is_revoked({**c, "act": {"sub": "x"}, "jti": "B"})[0] is True


def test_index_grows_incrementally_across_many_single_use_burns(h):
    rl = RevocationList(h)
    for i in range(500):
        assert rl.burn_once(f"j{i}") is True
    assert rl.burn_once("j7") is False
    t0 = time.perf_counter()
    for i in range(500, 1500):
        rl.burn_once(f"j{i}")
    assert time.perf_counter() - t0 < 5.0  # generous: CI disks vary (see bench/ for the real measurement)


def test_demo_and_agent_loop_example_run_clean(capsys):
    from delcred.demo import run_demo

    assert run_demo(out=lambda *_: None) is True
    import importlib.util

    spec = importlib.util.spec_from_file_location("agent_loop", REPO / "examples/agent_loop.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.main() is True
    assert "all guarantees held" in capsys.readouterr().out


def test_concurrent_single_use_burn_has_exactly_one_winner(h):
    rl = RevocationList(h)
    wins = []

    def go():
        wins.append(RevocationList(h).burn_once("same-jti"))

    ts = [threading.Thread(target=go) for _ in range(16)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert wins.count(True) == 1 and rl.burn_once("same-jti") is False


@pytest.mark.parametrize("kid", ["../issuer", "a/b", "..", "", "x" * 400])
def test_retire_cannot_escape_the_retired_directory(h, kid):
    (h / "victim.json").write_text("{}")
    keys.rotate(h, keep_old=100)
    assert keys.retire(kid, h) is False
    assert (h / "victim.json").exists()
