"""Round 5: upgrade path from 0.2.0, strict-JSON agreement across languages,
property tests, mutation-style sanity checks, golden output shapes, author pin."""

from __future__ import annotations

import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

import delcred
from delcred import _jws, keys, offline, vectors
from delcred._common import parse_scope
from delcred.policy import PolicyError

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = Path(__file__).resolve().parent / "golden"
RES = "https://api.acme.test/v1"
AUTHOR = "Calas Automations Inc."


def cli(*argv, home=None):
    cmd = [sys.executable, "-m", "delcred.cli"] + (["--home", str(home)] if home is not None else []) + list(argv)
    e = dict(os.environ, PYTHONPATH=str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    e.pop("DELCRED_DEBUG", None)
    p = subprocess.run(cmd, capture_output=True, env=e, timeout=60, check=False)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


# ---------------------------------------------------------------- author line

def test_author_string_is_pinned_everywhere():
    py = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'authors = [{{ name = "{AUTHOR}" }}]' in py
    assert f"Copyright (c) 2026 {AUTHOR}" in (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert f"MIT — {AUTHOR}" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert not re.search(r"Dan Calas|DC Enterprises", py)
    assert delcred.__author__ == AUTHOR
    rc, out, _ = cli("--version")
    assert rc == 0 and out.startswith("delcred ")


# ------------------------------------------- upgrade path: 0.2.0 tokens (no kid)

def _kidless_token(home: Path, **over) -> str:
    """What delcred 0.2.0 minted: same claims, header without ``kid`` (and no typ)."""
    sub = delcred.user_token("u_alice", base=home)
    act = delcred.agent_token("billing-agent", base=home)
    tok = delcred.delegate(user="u_alice", agent="billing-agent", scope="invoices:read", resource=RES,
                           user_token=sub, agent_token=act, base=home)
    import jwt
    claims = jwt.decode(tok, options={"verify_signature": False})
    claims.update(over)
    return _jws.sign_compact({"alg": "EdDSA", "typ": "at+jwt"}, claims, keys.load_private(home))


def test_kidless_0_2_token_survives_rotation_with_overlap(home):
    old = _kidless_token(home)
    assert delcred.verify(old, expected_resource=RES, base=home)
    keys.rotate(home, keep_old=3600)
    assert delcred.verify(old, expected_resource=RES, base=home)["sub"] == "u_alice"


def test_kidless_token_dies_on_hard_cut_rotation(home):
    old = _kidless_token(home)
    keys.rotate(home, keep_old=0)
    with pytest.raises(delcred.TokenError):
        delcred.verify(old, expected_resource=RES, base=home)


def test_kidless_token_from_another_key_is_still_rejected_after_overlap_rotation(home):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    forged = _jws.sign_compact({"alg": "EdDSA", "typ": "at+jwt"},
                               {"iss": "delcred", "sub": "u_alice", "act": {"sub": "billing-agent"}, "kind": "delegation",
                                "scope": "invoices:read", "aud": RES, "jti": "x", "iat": 1, "nbf": 1, "exp": 4102444800},
                               Ed25519PrivateKey.generate())
    keys.rotate(home, keep_old=3600)
    with pytest.raises(delcred.TokenError):
        delcred.verify(forged, expected_resource=RES, base=home)


def test_legacy_audit_lines_after_chain_explain_themselves(home):
    delcred.agent_token("billing-agent", base=home)
    with (home / "audit.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": 1, "event": "exchange_denied"}) + "\n")  # an old process still writing
    rc, out, err = cli("audit", "verify", home=home)
    assert rc == 6 and "older than 0.3" in out + err


# ---------------------------------------------- strict JSON: reference verifier

def _raw(payload_text: str) -> str:
    return vectors._raw_signed(payload_text)


GOOD = json.dumps(vectors._claims(), sort_keys=True, separators=(",", ":"))


@pytest.mark.parametrize("text,why", [
    (GOOD.replace('"exp":1800000840', '"exp":1800000840.0'), "whole-valued float"),
    (GOOD.replace('"exp":1800000840', '"exp":1.800000840e9'), "exponent"),
    (GOOD.replace('"exp":1800000840', '"exp":9007199254740992'), "2**53"),
    (GOOD.replace('"exp":1800000840', '"exp":1,"exp":1800000840'), "duplicate"),
    (GOOD.replace('"exp":1800000840', '"exp":Infinity'), "Infinity"),
    (GOOD.replace('"exp":1800000840', '"exp":-Infinity'), "-Infinity"),
    (GOOD[:-1] + ',"x":' + "[" * 33 + "]" * 33 + "}", "depth 34"),
    (GOOD[:-1] + ',"chain":null}', "null chain"),
])
def test_reference_verifier_rejects_ambiguous_json(text, why):
    v = offline.verify_offline(_raw(text), jwks=vectors.build()["jwks"], resource=RES, now=vectors.NOW)
    assert v.code == "invalid_token", why


def test_safe_int_boundary():
    assert _jws.is_safe_int(2**53 - 1) and _jws.is_safe_int(-(2**53 - 1))
    assert not _jws.is_safe_int(2**53) and not _jws.is_safe_int(True) and not _jws.is_safe_int(1.0)


def test_depth_32_is_still_accepted():
    ok = GOOD[:-1] + ',"x":' + "[" * 30 + "]" * 30 + "}"  # root object + 30 lists = 31 levels
    v = offline.verify_offline(_raw(ok), jwks=vectors.build()["jwks"], resource=RES, now=vectors.NOW)
    assert v.code == "ok"


# ------------------------------------- cross-language differential (seeded fuzz)

VALS = [None, True, False, 0, 1, -1, 1.5, 1.0, 1e3, 2**53, 2**63, 10**30, "", " ", "a", "é", "x" * 300, [], ["a"], {},
        {"sub": "x"}, "customers:read", "customers:read ", "a  b", "a\tb", "a b", RES, RES + "/", 1_800_000_100, 1_799_999_900]


def _mutants(seed: int, n: int) -> dict:
    rnd = random.Random(seed)
    base = vectors.build()
    cases = []
    for i in range(n):
        c = vectors._claims()
        for _ in range(rnd.randint(1, 3)):
            k = rnd.choice(["iss", "sub", "act", "kind", "scope", "aud", "jti", "iat", "nbf", "exp", "chain", "cnf", "x"])
            if rnd.random() < 0.25:
                c.pop(k, None)
            else:
                c[k] = rnd.choice(VALS)
        if rnd.random() < 0.2:
            c["act"] = {"sub": "a", "act": rnd.choice([{"sub": "b"}, "z", {}])}
            c["chain"] = [rnd.choice("ab") for _ in range(rnd.randint(0, 2))]
        h = vectors._hdr()
        if rnd.random() < 0.4:
            h[rnd.choice(["alg", "kid", "typ", "jwk", "crit", "x"])] = rnd.choice(VALS + ["EdDSA", "none", "AT+JWT"])
        text = json.dumps(c, sort_keys=True, separators=(",", ":"))
        if rnd.random() < 0.1:  # lexemes json.dumps cannot emit
            text = text.replace('"exp":', rnd.choice(['"exp":1,"exp":', '"exp":NaN,"y":']), 1)
        tok = vectors._raw_signed(text, h)
        if rnd.random() < 0.1:
            a, b, s = tok.split(".")
            i2 = rnd.randrange(len(s))
            tok = f"{a}.{b}.{s[:i2]}{rnd.choice('AQgw_-')}{s[i2 + 1:]}"
        now = vectors.NOW + rnd.choice([0, 0, -61, 61, 1000])
        sc = rnd.choice([None, ["customers:read"], ["x"]])
        res = rnd.choice([RES, RES, RES + "/"])
        v = offline.verify_offline(tok, jwks=base["jwks"], resource=res, required_scopes=sc, now=now, leeway=60)
        cases.append({"name": f"m{i}", "token": tok, "expect": [v.code],
                      "request": {"bulletin": None, "dpop": None, "now": now, "repeat": 1, "require_bulletin": False,
                                  "required_scopes": sc, "resource": res}})
    return {**base, "cases": cases}


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_node_agrees_with_python_on_mutated_tokens(tmp_path):
    f = tmp_path / "fuzz.json"
    f.write_text(json.dumps(_mutants(2026, 600)))
    r = subprocess.run(["node", str(ROOT / "spec/verifiers/node/verify.mjs"), str(f)], capture_output=True, timeout=120, check=False)
    assert r.returncode == 0, r.stdout.decode()[-800:] + r.stderr.decode()[-800:]


@pytest.mark.skipif(shutil.which("go") is None, reason="go not installed")
def test_go_agrees_with_python_on_mutated_tokens(tmp_path):
    f = tmp_path / "fuzz.json"
    f.write_text(json.dumps(_mutants(2027, 600)))
    r = subprocess.run(["go", "run", ".", str(f)], cwd=ROOT / "spec/verifiers/go", capture_output=True, timeout=240, check=False)
    assert r.returncode == 0, r.stdout.decode()[-800:] + r.stderr.decode()[-800:]


# --------------------------------------------------- mutation-style sanity

def test_reference_run_is_clean():
    assert vectors.run(vectors.build()) == []


@pytest.mark.parametrize("target,replacement", [
    ("ed25519_verify", lambda *a, **k: True),            # signatures not checked
    ("is_safe_int", lambda v: isinstance(v, int)),        # loose integer rule (bool and huge ints pass)
])
def test_vectors_catch_broken_verifier(monkeypatch, target, replacement):
    monkeypatch.setattr(offline, target, replacement)
    assert vectors.run(vectors.build()), f"vectors did not notice a broken {target}"


def test_vectors_catch_unicode_space_scope_splitting(monkeypatch):
    real = offline.verify_offline

    def sloppy(token, **kw):
        sc = kw.get("required_scopes")
        return real(token, **kw) if sc is None else real(token, **{**kw, "required_scopes": None})

    monkeypatch.setattr(vectors, "verify_offline", sloppy)
    assert vectors.run(vectors.build())


def test_parse_scope_mutation_is_caught(monkeypatch):
    import delcred._common as c
    with pytest.raises(ValueError):
        c.parse_scope("a\u00a0b")           # real code: NBSP is not a separator
    monkeypatch.setattr(c, "_SCOPE_TOKEN", re.compile(r".+\Z"))
    assert c.parse_scope("a\u00a0b") == ["a\u00a0b"]  # mutant lets it through, so the check above would fail


# ------------------------------------------------------------ property tests

hyp = pytest.importorskip("hypothesis", reason="pip install hypothesis to run property tests")
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

SCOPE_TOKENS = st.text(alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E, exclude_characters='"\\'), min_size=1, max_size=8)


@given(st.lists(SCOPE_TOKENS, min_size=1, max_size=6))
def test_parse_scope_is_idempotent_sorted_and_order_free(toks):
    a = parse_scope(" ".join(toks))
    assert a == parse_scope(" ".join(reversed(toks))) == sorted(set(toks))
    assert parse_scope(" ".join(a)) == a


@given(st.text(max_size=30))
def test_parse_scope_never_leaks_odd_whitespace(s):
    try:
        out = parse_scope(s)
    except (ValueError, TypeError):
        return
    assert all(re.fullmatch(r"[\x21\x23-\x5b\x5d-\x7e]+", t) for t in out)


@given(st.recursive(st.none() | st.booleans() | st.integers(-2**70, 2**70) | st.text(max_size=5),
                    lambda c: st.lists(c, max_size=3) | st.dictionaries(st.text(max_size=3), c, max_size=3), max_leaves=12))
def test_jws_json_parser_never_raises_unexpected(value):
    import base64
    raw = json.dumps(value).encode()
    try:
        obj = _jws._json_object(raw, "payload")
        assert isinstance(obj, dict)
    except _jws.JWSError:
        pass
    assert base64.urlsafe_b64encode(raw)  # smoke: input was representable


@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(parent=st.sets(st.sampled_from(["a:r", "b:r", "c:r", "d:r"]), min_size=1),
       child=st.sets(st.sampled_from(["a:r", "b:r", "c:r", "d:r", "e:r"]), min_size=1))
def test_attenuation_never_widens_scope(parent, child):
    """Property: a child token is minted iff its scopes are a subset of the parent's."""
    with tempfile.TemporaryDirectory() as td:
        h = Path(td)
        delcred.init(base=h)
        (h / "policy.yaml").write_text(
            "grants:\n  - user: u\n    agent: boss\n"
            f"    scopes: {json.dumps(sorted(parent))}\n    resources: [\"{RES}\"]\n"
            "    max_ttl: 900\n    delegate_to: [kid]\n    max_depth: 2\n",
            encoding="utf-8")
        tok = delcred.delegate(user="u", agent="boss", scope=" ".join(sorted(parent)), resource=RES,
                               user_token=delcred.user_token("u", base=h), agent_token=delcred.agent_token("boss", base=h), base=h)
        kid = delcred.agent_token("kid", base=h)
        try:
            c = delcred.attenuate(tok, sub_agent_token=kid, scope=" ".join(sorted(child)), resource=RES, base=h)
        except (delcred.TokenError, PolicyError):
            c = None
        if child <= parent:
            assert c is not None
            assert set(delcred.verify(c, expected_resource=RES, base=h)["scope"].split()) == child
        else:
            assert c is None, "attenuation minted a token wider than its parent"


# ------------------------------------------------------------- golden shapes

def _shape(v):
    if isinstance(v, dict):
        return {k: _shape(v[k]) for k in sorted(v)}
    if isinstance(v, list):
        return [_shape(v[0])] if v else []
    return type(v).__name__


def test_cli_json_output_shapes_match_golden(home):
    out = {}
    sub = delcred.user_token("u_alice", base=home)
    act = delcred.agent_token("billing-agent", base=home)
    tok = delcred.delegate(user="u_alice", agent="billing-agent", scope="invoices:read", resource=RES,
                           user_token=sub, agent_token=act, base=home)
    for name, argv in {
        "status": ["status", "--json"],
        "audit_verify": ["audit", "verify", "--json"],
        "verify_ok": ["verify", tok, "--resource", RES, "--json"],
        "doctor": ["doctor", "--json"],
    }.items():
        rc, so, _ = cli(*argv, home=home)
        assert rc in (0,), (name, rc)
        out[name] = _shape(json.loads(so))
    rc, so, _ = cli("verify", tok, "--resource", "https://wrong.test", "--json", home=home)
    assert rc != 0
    out["verify_denied"] = _shape(json.loads(so)) if so.strip() else "no-stdout"
    g = GOLDEN / "cli_json_shapes.json"
    if os.environ.get("DELCRED_UPDATE_GOLDEN"):
        g.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert out == json.loads(g.read_text(encoding="utf-8")), "CLI --json shape changed: update tests/golden deliberately"


def test_vectors_file_is_byte_stable():
    assert vectors.build() == vectors.build()
    committed = (ROOT / "spec/vectors/vectors.json").read_text(encoding="utf-8")
    assert json.loads(committed) == vectors.build()
    assert len(vectors.build()["cases"]) >= 96
