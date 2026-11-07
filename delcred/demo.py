"""`delcred demo` — a zero-config, self-checking tour in a throwaway home.

Runs every core guarantee end to end against a temporary directory (your
real ~/.delcred is never touched) and exits non-zero if any guarantee does
not hold. Doubles as a post-install smoke test.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from pathlib import Path

RES = "https://api.acme.test/v1"
OTHER = "https://evil.example/v1"

_POLICY = f"""grants:
  - user: u_alice
    agent: billing-agent
    scopes: ["invoices:read", "invoices:write"]
    resources: ["{RES}"]
    max_ttl: 900
    delegate_to: [summarizer, mailer]
    max_depth: 2
  - user: u_alice
    agent: one-shot-agent
    scopes: ["payments:create"]
    resources: ["{RES}"]
    max_ttl: 60
    single_use: true
"""


def run_demo(out: Callable[[str], None] = print) -> bool:
    import delcred
    from delcred.mcp import authorize

    results: list[bool] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        results.append(ok)
        out(f"  [{'ok' if ok else 'FAIL'}] {label}" + (f"  ({detail})" if detail else ""))

    def denied(fn) -> tuple[bool, str]:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - we want any rejection
            return True, f"{type(e).__name__}: {str(e)[:70]}"
        return False, "was NOT rejected"

    with tempfile.TemporaryDirectory(prefix="delcred-demo-") as tmp:
        h = Path(tmp)
        out(f"delcred demo — throwaway home {h}\n")
        delcred.init(base=h, force=True)
        (h / "policy.yaml").write_text(_POLICY, encoding="utf-8")

        out("1. identities")
        user = delcred.user_token("u_alice", base=h)
        agent = delcred.agent_token("billing-agent", base=h)
        check("minted user (subject) + agent (actor) tokens", bool(user and agent))

        out("2. delegation (RFC 8693 exchange)")
        tok = delcred.delegate(
            scope="invoices:read", resource=RES, user_token=user, agent_token=agent, base=h
        )
        c = delcred.verify(tok, expected_resource=RES, required_scopes="invoices:read", base=h)
        check(
            "15-min token names human AND agent",
            c["sub"] == "u_alice" and c["act"]["sub"] == "billing-agent",
            f"sub={c['sub']} act={c['act']['sub']} exp_in={c['exp'] - c['iat']}s",
        )

        out("3. least privilege")
        ok, d = denied(
            lambda: delcred.delegate(
                scope="admin:all", resource=RES, user_token=user, agent_token=agent, base=h
            )
        )
        check("agent cannot mint beyond its grant", ok, d)
        ok, d = denied(
            lambda: delcred.verify(
                tok, expected_resource=RES, required_scopes="invoices:write", base=h
            )
        )
        check("read token refused for a write operation", ok, d)

        out("4. confused-deputy defense")
        ok, d = denied(lambda: delcred.verify(tok, expected_resource=OTHER, base=h))
        check("token for API A rejected by API B", ok, d)

        out("5. MCP resource server (spec-shaped 401/403)")
        dec = authorize(
            f"Bearer {tok}", resource=RES, required_scopes="invoices:write", base=h,
            resource_metadata_url=RES + "/.well-known/oauth-protected-resource",
        )
        check("403 insufficient_scope with step-up challenge", dec.status == 403,
              dec.www_authenticate[:60] + "…")
        dec = authorize(None, resource=RES, base=h)
        check("401 when no credential is sent", dec.status == 401)

        out("6. opaque API key (agent never sees a real secret)")
        apikey = delcred.delegate_api_key(
            scope="invoices:read", resource=RES, user_token=user, agent_token=agent, base=h
        )
        cap = delcred.verify_broker_key(apikey, base=h, expected_resource=RES)
        check("dk_ key redeems to a scoped capability", cap["scope"] == "invoices:read",
              f"{apikey[:7]}… → {cap['scope']}")

        out("7. single-use credentials")
        one = delcred.agent_token("one-shot-agent", base=h)
        st = delcred.delegate(
            scope="payments:create", resource=RES, user_token=user, agent_token=one, base=h
        )
        delcred.verify(st, expected_resource=RES, base=h)
        ok, d = denied(lambda: delcred.verify(st, expected_resource=RES, base=h))
        check("replay of a single-use token blocked", ok, d)

        out("8. sub-delegation can only narrow")
        parent = delcred.delegate(
            scope="invoices:read invoices:write", resource=RES, user_token=user, agent_token=agent, base=h
        )
        sub_id = delcred.agent_token("summarizer", base=h)
        child = delcred.attenuate(parent, sub_agent_token=sub_id, scope="invoices:read", resource=RES, base=h)
        cc = delcred.verify(child, expected_resource=RES, base=h)
        check("sub-agent gets a narrower copy; chain recorded", cc["act"]["act"]["sub"] == "billing-agent",
              f"scope={cc['scope']!r}")
        ok, d = denied(lambda: delcred.attenuate(
            child, sub_agent_token=delcred.agent_token("mailer", base=h),
            scope="invoices:write", resource=RES, base=h))
        check("a child can never regain what it was not given", ok, d)

        out("9. stolen-token defence (DPoP, RFC 9449)")
        from delcred import pop
        key = pop.generate_key()
        bound = delcred.delegate(
            scope="invoices:read", resource=RES, user_token=user, agent_token=agent,
            dpop_jkt=pop.thumbprint(key), base=h)
        url = RES + "/invoices"
        ok, d = denied(lambda: delcred.verify(bound, expected_resource=RES, base=h))
        check("key-bound token is useless as a plain bearer token", ok, d)
        delcred.verify(bound, expected_resource=RES, base=h, http_method="GET", http_url=url,
                       dpop_proof=pop.make_proof(key, "GET", url, access_token=bound))
        check("…and works with a proof from its key", True)

        out("10. third parties verify offline (JWKS + signed revocation bulletin)")
        jwks = delcred.jwks(base=h)
        v = delcred.offline.verify_offline(tok, jwks=jwks, resource=RES,
                                           bulletin=delcred.bulletin.export(h))
        check("a resource server with no delcred home accepts it", v.ok, v.code)

        out("10b. policy stays live; tokens can be ended from either side")
        pol_path = h / "policy.yaml"
        saved = pol_path.read_text(encoding="utf-8")
        pol_path.write_text("grants: []\n", encoding="utf-8")
        ok, d = denied(lambda: delcred.verify(tok, expected_resource=RES, base=h, check_policy=True))
        check("grant removed -> already-minted token refused (check_policy)", ok, d)
        pol_path.write_text(saved, encoding="utf-8")
        mine = delcred.delegate(scope="invoices:read", resource=RES, user_token=user, agent_token=agent, base=h)
        check("the holder ends its own token when the task is done", delcred.revoke_presented(mine, base=h))
        ok, d = denied(lambda: delcred.verify(mine, expected_resource=RES, base=h))
        check("…and a leaked copy is already dead", ok, d)
        denied(lambda: delcred.verify(tok[:-4] + "AAAA", expected_resource=RES, base=h))
        check("a forged token leaves a trace in the audit log",
              any(e["event"] == "verify_rejected" for e in delcred.AuditLog(h).entries()))

        out("11. kill switch")
        delcred.revoke_agent("billing-agent", reason="demo: suspected prompt injection", base=h)
        ok, d = denied(lambda: delcred.verify(tok, expected_resource=RES, base=h))
        check("revoked agent's token dies instantly", ok, d)
        ok, _ = denied(lambda: delcred.verify_broker_key(apikey, base=h, expected_resource=RES))
        check("…and so does its API key", ok)
        ok, d = denied(lambda: delcred.verify(child, expected_resource=RES, base=h))
        check("…and every sub-agent token below it", ok, d)
        v = delcred.offline.verify_offline(tok, jwks=jwks, resource=RES,
                                           bulletin=delcred.bulletin.export(h))
        check("…and third-party verifiers see it via the bulletin", v.code == "revoked", v.code)

        out("12. tamper-evident audit trail")
        log = delcred.AuditLog(h)
        av = log.verify()
        check("hash chain intact", av.ok, f"{av.chained} entries, head {av.head[:12]}…")
        lines = log.path.read_text(encoding="utf-8").splitlines()
        i = next(n for n, line in enumerate(lines) if '"u_alice"' in line)
        lines[i] = lines[i].replace('"u_alice"', '"u_mallory"')
        log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        av = log.verify()
        check("an edited audit line is detected", not av.ok, av.problems[0] if av.problems else "")

    passed = sum(results)
    out(f"\n{passed}/{len(results)} guarantees held.")
    return passed == len(results)
