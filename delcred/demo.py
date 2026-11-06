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
        (h / "policy.yaml").write_text(_POLICY)

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
        key = delcred.delegate_api_key(
            scope="invoices:read", resource=RES, user_token=user, agent_token=agent, base=h
        )
        cap = delcred.verify_broker_key(key, base=h, expected_resource=RES)
        check("dk_ key redeems to a scoped capability", cap["scope"] == "invoices:read",
              f"{key[:7]}… → {cap['scope']}")

        out("7. single-use credentials")
        one = delcred.agent_token("one-shot-agent", base=h)
        st = delcred.delegate(
            scope="payments:create", resource=RES, user_token=user, agent_token=one, base=h
        )
        delcred.verify(st, expected_resource=RES, base=h)
        ok, d = denied(lambda: delcred.verify(st, expected_resource=RES, base=h))
        check("replay of a single-use token blocked", ok, d)

        out("8. kill switch")
        delcred.revoke_agent("billing-agent", reason="demo: suspected prompt injection", base=h)
        ok, d = denied(lambda: delcred.verify(tok, expected_resource=RES, base=h))
        check("revoked agent's token dies instantly", ok, d)
        ok, _ = denied(lambda: delcred.verify_broker_key(key, base=h, expected_resource=RES))
        check("…and so does its API key", ok)

        out("9. tamper-evident audit trail")
        log = delcred.AuditLog(h)
        v = log.verify()
        check("hash chain intact", v.ok, f"{v.chained} entries, head {v.head[:12]}…")
        lines = log.path.read_text().splitlines()
        i = next(n for n, line in enumerate(lines) if '"u_alice"' in line)
        lines[i] = lines[i].replace('"u_alice"', '"u_mallory"')
        log.path.write_text("\n".join(lines) + "\n")
        v = log.verify()
        check("an edited audit line is detected", not v.ok, v.problems[0] if v.problems else "")

    passed = sum(results)
    out(f"\n{passed}/{len(results)} guarantees held.")
    return passed == len(results)
