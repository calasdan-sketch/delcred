"""Re-runnable benchmark: delcred vs. the closest things you can `pip install`.

    pip install -e ".[dev]" biscuit-python pymacaroons
    python bench/run_bench.py            # prints a markdown report, writes bench/results.json

Everything is measured on THIS machine in ONE process; absolute numbers vary,
ratios are what matter. Nothing here is network I/O. Libraries that are not
installed are skipped and reported as such. Run it against an older checkout
with ``PYTHONPATH=/path/to/old python bench/run_bench.py`` to get a baseline
(features that did not exist then are reported as n/a).
"""

from __future__ import annotations

import json
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import delcred
from delcred import tokens
from delcred.revocation import RevocationList

ROOT = Path(__file__).resolve().parent.parent
RES = "https://api.acme.test/v1"
POLICY = f"""grants:
  - user: u_alice
    agent: orchestrator
    scopes: ["invoices:read", "invoices:write", "customers:read"]
    resources: ["{RES}"]
    delegate_to: [summarizer, mailer, archiver]
    max_depth: 3
"""


def rate(fn, n: int, repeat: int = 3) -> float:
    """Best-of-``repeat`` operations per second."""
    best = 0.0
    for _ in range(repeat):
        t0 = time.perf_counter()
        for _ in range(n):
            fn()
        best = max(best, n / (time.perf_counter() - t0))
    return best


def bench_delcred(out: dict) -> None:
    h = Path(tempfile.mkdtemp(prefix="delcred-bench-"))
    delcred.init(base=h, force=True)
    (h / "policy.yaml").write_text(POLICY)
    u = delcred.user_token("u_alice", base=h)
    a = delcred.agent_token("orchestrator", base=h)
    tok = delcred.delegate(scope="invoices:read invoices:write", resource=RES, user_token=u, agent_token=a, base=h)
    d: dict = {"version": getattr(delcred, "__version__", "?")}
    d["mint_per_s"] = rate(
        lambda: delcred.delegate(scope="invoices:read", resource=RES, user_token=u, agent_token=a, base=h), 100)
    d["verify_full_per_s"] = rate(lambda: delcred.verify(tok, expected_resource=RES, base=h), 300)
    d["verify_signature_only_per_s"] = rate(
        lambda: tokens.verify_delegation_token(tok, expected_resource=RES, base=h), 800)
    d["token_bytes"] = len(tok)

    # revocation check latency vs. list size
    rl = RevocationList(h)
    claims = tokens.decode_unverified(tok)
    d["revocation_check_ms"] = {}
    have = 0
    for size in (1_000, 10_000, 100_000):
        with open(rl.path, "a", encoding="utf-8") as f:
            f.writelines(
                json.dumps({"type": "jti", "jti": f"x{i}", "revoked_at": 1, "reason": "", "expires_at": None}) + "\n"
                for i in range(have, size))
        have = size
        samples = []
        for _ in range(30):
            t0 = time.perf_counter()
            rl.is_revoked(claims)
            samples.append((time.perf_counter() - t0) * 1000)
        d["revocation_check_ms"][str(size)] = round(statistics.median(samples), 3)

    # single-use burns (each one appends to a 100k-entry list)
    counter = iter(range(10**9))
    d["single_use_burn_per_s_at_100k"] = rate(lambda: rl.burn_once(f"b{next(counter)}"), 150, repeat=2)

    if hasattr(delcred, "attenuate"):
        from delcred import bulletin, offline, pop

        (h / "revocations.jsonl").write_text("")
        parent = tok
        child_agent = delcred.agent_token("summarizer", base=h)
        d["attenuate_per_s"] = rate(
            lambda: delcred.attenuate(parent, sub_agent_token=child_agent, scope="invoices:read", resource=RES, base=h), 100)
        child = delcred.attenuate(parent, sub_agent_token=child_agent, scope="invoices:read", resource=RES, base=h)
        d["chained_token_bytes"] = len(child)
        jwks = delcred.jwks(base=h)
        d["offline_verify_per_s"] = rate(lambda: offline.verify_offline(tok, jwks=jwks, resource=RES), 1500)
        b = bulletin.export(h)
        d["offline_verify_with_bulletin_per_s"] = rate(
            lambda: offline.verify_offline(tok, jwks=jwks, resource=RES, bulletin=b), 1000)
        key = pop.generate_key()
        bound = delcred.delegate(scope="invoices:read", resource=RES, user_token=u, agent_token=a,
                                 dpop_jkt=pop.thumbprint(key), base=h)
        url = RES + "/invoices"
        d["dpop_make_proof_per_s"] = rate(lambda: pop.make_proof(key, "GET", url, access_token=bound), 1500)
        proofs = [pop.make_proof(key, "GET", url, access_token=bound) for _ in range(1500)]
        it = iter(proofs)
        cache = pop.ReplayCache()
        t0 = time.perf_counter()
        for p in proofs:
            pop.verify_proof(p, method="GET", url=url, access_token=bound, cache=cache)
        d["dpop_verify_per_s"] = len(proofs) / (time.perf_counter() - t0)
        del it
        d["escalation_fuzz"] = escalation_fuzz(h, 3000)
    out["delcred"] = d
    shutil.rmtree(h, ignore_errors=True)


def escalation_fuzz(h: Path, attempts: int) -> dict:
    """Try to widen authority through sub-delegation; count what gets minted and what breaks the invariants."""
    rng = random.Random(1)
    pool = ["invoices:read", "invoices:write", "customers:read", "admin:all", "payments:create", "x:y"]
    u = delcred.user_token("u_alice", base=h)
    root_agent = delcred.agent_token("orchestrator", base=h)
    agents = {n: delcred.agent_token(n, base=h) for n in ("summarizer", "mailer", "archiver", "orchestrator", "stranger")}
    parents = [
        delcred.delegate(scope=" ".join(sorted(rng.sample(pool[:3], rng.randint(1, 3)))), resource=RES,
                         user_token=u, agent_token=root_agent, ttl=rng.choice([30, 300, 900]), base=h)
        for _ in range(20)
    ]
    minted = violations = denied = 0
    frontier = list(parents)
    for _ in range(attempts):
        parent = rng.choice(frontier)
        pc = tokens.decode_unverified(parent)
        want = " ".join(rng.sample(pool, rng.randint(1, 4)))
        who = rng.choice(list(agents))
        res = rng.choice([RES, RES, RES, "https://evil.test/v1", RES + "/"])
        ttl = rng.choice([1, 60, 900, 3600, 10**9])
        try:
            tok = delcred.attenuate(parent, sub_agent_token=agents[who], scope=want, resource=res, ttl=ttl, base=h)
        except Exception:  # noqa: BLE001 - any refusal is the correct outcome here
            denied += 1
            continue
        minted += 1
        c = tokens.decode_unverified(tok)
        if not (
            set(c["scope"].split()) <= set(pc["scope"].split())
            and c["aud"] == pc["aud"] and c["exp"] <= pc["exp"]
            and len(tokens.actor_chain(c)) == len(tokens.actor_chain(pc)) + 1
            and c["chain"][-1] == pc["jti"]
        ):
            violations += 1
        if len(frontier) < 200:
            frontier.append(tok)
    return {"attempts": attempts, "minted": minted, "refused": denied, "invariant_violations": violations}


def bench_competitors(out: dict) -> None:
    c: dict = {}
    try:
        import jwt
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        k = Ed25519PrivateKey.generate()
        pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        pub = k.public_key()
        now = int(time.time())
        claims = {"iss": "x", "sub": "u", "aud": RES, "exp": now + 900, "iat": now, "scope": "a b"}
        t = jwt.encode(claims, pem, algorithm="EdDSA")
        c["pyjwt_eddsa"] = {
            "sign_per_s": rate(lambda: jwt.encode(claims, pem, algorithm="EdDSA"), 1500),
            "verify_per_s": rate(lambda: jwt.decode(t, pub, algorithms=["EdDSA"], audience=RES), 1500),
            "note": "plain signed JWT: no agent identity, no delegation, no revocation, no audit",
        }
    except ImportError:
        c["pyjwt_eddsa"] = "not installed"
    try:
        from pymacaroons import Macaroon, Verifier

        key = "k" * 32
        def mk():
            m = Macaroon(location="acme", identifier="id", key=key)
            for cav in ("user = u_alice", "agent = orchestrator", "scope = invoices:read"):
                m.add_first_party_caveat(cav)
            return m
        m = mk()
        ser = m.serialize()
        ver = Verifier()
        ver.satisfy_exact("user = u_alice"); ver.satisfy_exact("agent = orchestrator"); ver.satisfy_exact("scope = invoices:read")

        def attenuate():
            x = Macaroon.deserialize(ser)
            x.add_first_party_caveat("ttl = 60")
            return x.serialize()
        c["pymacaroons"] = {
            "mint_with_3_caveats_per_s": rate(mk, 800),
            "attenuate_1_caveat_per_s": rate(attenuate, 800),
            "verify_per_s": rate(lambda: ver.verify(m, key), 800),
            "token_bytes": len(ser),
            "note": "HMAC: only the issuer (secret holder) can verify; no third-party/offline verification",
        }
    except ImportError:
        c["pymacaroons"] = "not installed"
    try:
        import biscuit_auth as ba

        kp = ba.KeyPair()
        def mk():
            return ba.BiscuitBuilder('user({u}); agent({a}); right({r});', {"u": "alice", "a": "orch", "r": "invoices:read"}).build(kp.private_key)
        root = mk()
        blk = ba.BlockBuilder('check if right("invoices:read");')
        att = root.append(blk)
        s = att.to_base64()
        def authz():
            tok = ba.Biscuit.from_base64(s, kp.public_key)
            ba.AuthorizerBuilder('allow if right("invoices:read");').build(tok).authorize()
        c["biscuit_python"] = {
            "mint_per_s": rate(mk, 800),
            "attenuate_offline_per_s": rate(lambda: root.append(ba.BlockBuilder('check if right("invoices:read");')), 800),
            "parse_and_authorize_per_s": rate(authz, 800),
            "token_bytes_root": len(root.to_base64()),
            "token_bytes_attenuated": len(s),
            "note": "datalog policies, offline attenuation by the holder; no built-in agent/user identity model, "
                    "revocation ids only, no audit log, no policy file",
        }
    except ImportError:
        c["biscuit_python"] = "not installed"
    out["competitors"] = c


def bench_cross_language(out: dict) -> None:
    r: dict = {}
    vec = ROOT / "spec/vectors/vectors.json"
    if not vec.exists():
        out["cross_language"] = "no vectors in this checkout"
        return
    n = len(json.loads(vec.read_text())["cases"])
    r["cases"] = n
    from delcred import vectors

    t0 = time.perf_counter()
    fails = vectors.run(json.loads(vec.read_text()))
    r["python"] = {"pass": n - len(fails), "ms": round((time.perf_counter() - t0) * 1000, 1)}
    if shutil.which("node"):
        p = subprocess.run(["node", str(ROOT / "spec/verifiers/node/verify.mjs"), str(vec)], capture_output=True, text=True, check=False)
        r["node"] = p.stdout.strip() or p.stderr.strip()[:200]
    if shutil.which("go"):
        p = subprocess.run(["go", "run", ".", str(vec)], cwd=ROOT / "spec/verifiers/go", capture_output=True, text=True, check=False)
        r["go"] = p.stdout.strip() or p.stderr.strip()[:200]
    out["cross_language"] = r


def main() -> None:
    out: dict = {
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
    }
    bench_delcred(out)
    if "--no-competitors" not in sys.argv:
        bench_competitors(out)
    if hasattr(delcred, "attenuate"):
        bench_cross_language(out)
    (ROOT / "bench" / "results.json").write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
