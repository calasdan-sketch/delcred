"""delcred CLI — `delcred <command> [options]`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import delcred
from delcred import keys as _keys
from delcred._common import home as _home
from delcred._common import safe_text as _st
from delcred.audit import AuditLog
from delcred.broker import Broker, BrokerError
from delcred.exchange import TOKEN_TYPE_BROKER_KEY, ExchangeError
from delcred.policy import PolicyError, policy_path
from delcred.policy import load as load_policy
from delcred.revocation import RevocationList
from delcred.tokens import InsufficientScope, TokenError, decode_unverified


def _base(args) -> Path:
    return Path(args.home) if args.home else _home()


def cmd_init(args):
    h = delcred.init(base=_base(args), force=args.force)
    print(f"initialized delcred home at {h}")
    print("  issuer key : 0600, never leaves this directory")
    print(f"  policy     : {policy_path(h)}  (edit your grants there)")


def cmd_key_rotate(args):
    h = _base(args)
    _, _, old = _keys.rotate(h, keep_old=args.keep_old or 0)
    print("issuer key rotated.")
    if old:
        print(
            f"old key {old} stays valid for verification for {args.keep_old}s "
            "(it never signs again; it is published in the JWKS until then)."
        )
        print("If the old key may be compromised, run `delcred key rotate` (hard cut) instead.")
    else:
        print("WARNING: tokens minted with the previous key no longer verify.")


def cmd_key_retire(args):
    if _keys.retire(args.kid, _base(args)):
        print(f"retired key {args.kid} removed; tokens it signed no longer verify.")
    else:
        sys.exit(f"no retired key {args.kid!r}")


def cmd_revocations_export(args):
    from delcred import bulletin

    print(bulletin.export(_base(args), ttl=args.ttl))


def cmd_offline_verify(args):
    """Verify with only a JWKS file (no delcred home) — what a third-party
    resource server sees."""
    from delcred.offline import verify_offline

    jwks = json.loads(Path(args.jwks_file).expanduser().read_text())
    bulletin = (
        Path(args.bulletin_file).expanduser().read_text().strip() if args.bulletin_file else None
    )
    v = verify_offline(
        args.token,
        jwks=jwks,
        resource=args.resource,
        required_scopes=args.require_scope or None,
        bulletin=bulletin,
        require_bulletin=args.require_bulletin,
    )
    if v.ok:
        c = v.claims
        print(f"VALID  sub={c['sub']} act={c['act']['sub']} scope={c['scope']!r} aud={c['aud']}")
        return
    print(f"INVALID: {_st(v.code)}: {_st(v.detail)}", file=sys.stderr)
    sys.exit(5 if v.code == "insufficient_scope" else 4)


def cmd_vectors(args):
    from delcred import vectors

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    vectors.write(out / "vectors.json")
    print(f"wrote {out / 'vectors.json'}")


def cmd_agent_token(args):
    print(delcred.agent_token(args.agent_id, ttl=args.ttl, base=_base(args)))


def cmd_user_token(args):
    print(delcred.user_token(args.user_id, ttl=args.ttl, base=_base(args)))


def _read_file_secret(path: str) -> str:
    p = Path(os.path.expanduser(path))
    try:
        value = p.read_text(encoding="utf-8").strip()
    except OSError as e:
        sys.exit(f"cannot read token file {p}: {e.strerror or e}")
    if not value:
        sys.exit(f"token file {p} is empty")
    return value


def _read_secret(args, name: str, env: str) -> str:
    """Read a token from --<name>, --<name>-file, $<env> or $<env>_FILE.

    Finding #7: passing tokens as CLI args leaks them via `ps`; prefer
    the -file or env forms in scripts. ``$<env>_FILE`` follows the Docker
    secrets convention (path to a file holding the token).
    """
    direct = getattr(args, name, None)
    if direct:
        return direct
    path = getattr(args, f"{name}_file", None)
    if path:
        return _read_file_secret(path)
    value = os.environ.get(env)
    if value:
        return value.strip()
    path = os.environ.get(env + "_FILE")
    if path:
        return _read_file_secret(path)
    sys.exit(
        f"need one of --{name.replace('_', '-')} / "
        f"--{name.replace('_', '-')}-file / ${env} / ${env}_FILE"
    )


def _chain(c) -> list[str]:
    from delcred.tokens import actor_chain

    try:
        return list(reversed(actor_chain(c)))  # root first
    except TokenError:
        return [str(c.get("act", {}).get("sub"))]


def cmd_exchange(args):
    subject_token = _read_secret(args, "subject_token", "DELCRED_SUBJECT_TOKEN")
    actor_token = _read_secret(args, "actor_token", "DELCRED_ACTOR_TOKEN")
    try:
        result_type = (
            TOKEN_TYPE_BROKER_KEY
            if args.as_api_key
            else "urn:ietf:params:oauth:token-type:jwt"
        )
        from delcred.exchange import exchange as _exchange

        result = _exchange(
            subject_token=subject_token,
            actor_token=actor_token,
            scope=args.scope,
            resource=args.resource,
            requested_token_type=result_type,
            ttl=args.ttl,
            dpop_jkt=args.dpop_jkt,
            base=_base(args),
        )
    except (ExchangeError, PolicyError) as e:
        print(f"exchange denied: {_st(e)}", file=sys.stderr)
        sys.exit(3)
    if args.quiet_claims:
        print(result.credential)
    else:
        c = result.claims
        print(result.credential)
        print(
            f"# sub={c['sub']} act={'>'.join(_chain(c))} scope={c['scope']!r} "
            f"resource={c['aud']} ttl={result.ttl}s jti={c['jti']}",
            file=sys.stderr,
        )


def cmd_verify(args):
    try:
        claims = delcred.verify(
            args.token,
            expected_resource=args.resource,
            required_scopes=args.require_scope or None,
            base=_base(args),
            check_policy=args.check_policy,
        )
    except InsufficientScope as e:
        print(f"INSUFFICIENT_SCOPE: missing {_st(' '.join(e.missing))}", file=sys.stderr)
        sys.exit(5)
    except (TokenError, ExchangeError) as e:
        print(f"INVALID: {_st(e)}", file=sys.stderr)
        sys.exit(4)
    if args.json:
        print(json.dumps(claims, indent=2, default=str))
    else:
        print(
            f"VALID  sub={claims['sub']} act={claims['act']['sub']} "
            f"scope={claims['scope']!r} aud={claims['aud']} "
            f"exp_in={claims['exp'] - claims['iat']}s jti={claims['jti']}"
        )


def cmd_inspect(args):
    # Unverified decode — for debugging only; never trust this output.
    print(json.dumps(decode_unverified(args.token), indent=2, default=str))


def cmd_broker_redeem(args):
    try:
        rec = delcred.verify_broker_key(
            args.key,
            base=_base(args),
            expected_resource=args.resource,
            required_scopes=args.require_scope or None,
        )
    except BrokerError as e:
        print(f"REJECTED: {_st(e)}", file=sys.stderr)
        sys.exit(4)
    print(json.dumps(rec, indent=2))


def cmd_revoke(args):
    h = _base(args)
    rl = RevocationList(h)
    if args.token_file:
        from delcred.exchange import revoke_presented

        done = revoke_presented(_read_file_secret(args.token_file), base=h)
        print("revoked the presented token" if done else "token not valid (nothing revoked)")
        if not done:
            sys.exit(1)
        return
    if args.jti:
        rl.revoke_jti(args.jti, reason=args.reason, expires_at=None)
        AuditLog(h).record("token_revoked", jti=args.jti, reason=args.reason)
        print(f"revoked token {args.jti}")
    elif args.agent:
        delcred.revoke_agent(args.agent, reason=args.reason, base=h)
        print(f"revoked ALL credentials for agent {args.agent!r} (user unaffected)")
    elif args.user:
        delcred.revoke_user(args.user, reason=args.reason, base=h, issuer=args.issuer)
        scope_ = f" from issuer {args.issuer}" if args.issuer else " (every issuer)"
        print(f"revoked ALL delegations by user {args.user!r}{scope_}")
    else:
        print("nothing to revoke: need one of --jti, --agent, --user, --token-file", file=sys.stderr)
        sys.exit(2)


def cmd_policy_check(args):
    pol = load_policy(_base(args))
    try:
        grant = pol.check(args.user, args.agent, args.scope, args.resource, args.ttl)
    except PolicyError as e:
        print(f"DENIED: {_st(e)}", file=sys.stderr)
        sys.exit(3)
    ttl = pol.effective_ttl(grant, args.ttl)
    print(f"ALLOWED  ttl={ttl}s scopes={sorted(grant.scopes)}")


def cmd_policy_validate(args):
    from delcred.policy import validate

    errors, warnings = validate(_base(args))
    for e in errors:
        print(f"ERROR: {_st(e, 600)}", file=sys.stderr)
    for w in warnings:
        print(f"warning: {_st(w, 600)}", file=sys.stderr)
    if errors:
        sys.exit(3)
    print(f"policy OK ({len(warnings)} warning(s))")
    if warnings and args.strict:
        sys.exit(1)


def cmd_status(args):
    h = _base(args)
    priv, _pub = _keys.key_paths(h)
    pol = load_policy(h)
    rl = RevocationList(h)
    try:
        from delcred.trust import TrustConfigError, trusted_issuers

        n_issuers = len(trusted_issuers(h))
    except (TrustConfigError, OSError, ValueError):
        # A broken trusted_issuers section must not break `status`.
        n_issuers = 0
    print(f"home:      {h}")
    print(f"issuer key: {'present' if priv.exists() else 'MISSING — run delcred init'}")
    print(
        f"agents:    {len(pol.agents)}  users: {len(pol.users)}  "
        f"grants: {len(pol.grants)}  trusted issuers: {n_issuers}"
    )
    print(f"revocation entries: {len(rl._entries())}")
    print(f"broker records:     {len(Broker(h)._records())}")


def cmd_trust_add(args):
    from delcred.trust import TrustConfigError, add_trusted_issuer

    try:
        dest = add_trusted_issuer(
            args.iss, args.key_file, base=_base(args), audience=args.audience
        )
    except TrustConfigError as e:
        print(f"trust-add failed: {_st(e)}", file=sys.stderr)
        sys.exit(3)
    print(f"trusted issuer {args.iss} -> {dest}")
    print("subject tokens from this issuer are now accepted in exchanges")


def cmd_audit(args):
    log = AuditLog(_base(args))
    if args.action == "checkpoint":
        try:
            print(log.checkpoint())
        except ValueError as e:
            print(f"cannot checkpoint: {_st(e)}", file=sys.stderr)
            sys.exit(6)
        print("# store this line OFF this host; verify later with: audit verify --checkpoint-file FILE", file=sys.stderr)
        return
    if args.action == "verify":
        cp = _read_file_secret(args.checkpoint_file) if args.checkpoint_file else None
        try:
            res = log.verify(checkpoint=cp)
        except ValueError as e:
            print(f"CHECKPOINT UNUSABLE: {_st(e)} (after a hard key rotation, take a new checkpoint)", file=sys.stderr)
            sys.exit(6)
        if res.ok:
            print(
                f"OK  {res.chained} hash-chained entries"
                + (f" (+{res.legacy} legacy, pre-0.3, unchained)" if res.legacy else "")
                + f"\nhead {res.head}"
            )
            if cp:
                print("matches the signed checkpoint: nothing before it was cut off or rewritten.")
            else:
                print("Anchor the head hash (or `audit checkpoint`) outside this host to also detect truncation.")
            return
        print(f"TAMPERED  {len(res.problems)} problem(s):", file=sys.stderr)
        for prob in res.problems[:50]:
            print(f"  {_st(prob, 400)}", file=sys.stderr)
        sys.exit(6)
    if args.action == "head":
        print(log.head())
        return
    since = None
    if args.since:
        import time as _t

        since = int(_t.time()) - _parse_duration(args.since)
    for e in log.tail(
        args.tail, event=args.event, agent=args.agent, user=args.user, since=since
    ):
        print(json.dumps(e))


def _parse_duration(text: str) -> int:
    """'90', '90s', '15m', '2h', '7d' → seconds."""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    t = text.strip().lower()
    mult = units.get(t[-1:], None)
    num = t[:-1] if mult else t
    try:
        n = int(num)
    except ValueError:
        sys.exit(f"bad duration {text!r}; use e.g. 90s, 15m, 2h, 7d")
    if n < 0:
        sys.exit("duration must be positive")
    return n * (mult or 1)


def cmd_jwks(args):
    print(json.dumps(delcred.jwks(base=_base(args)), indent=2))


def cmd_prune(args):
    h = _base(args)
    r = RevocationList(h).prune()
    b = Broker(h).prune()
    print(f"pruned {r} expired revocation entr{'y' if r == 1 else 'ies'}, {b} expired broker record(s)")


def cmd_mcp_headers(args):
    """Claude Code `headersHelper`: print {"Authorization": "Bearer …"} JSON.

    Claude Code runs the helper on each MCP connection and sets
    $CLAUDE_CODE_MCP_SERVER_URL; that URL is the default resource, so the
    token's audience is exactly the MCP server being connected to.
    """
    resource = args.resource or os.environ.get("CLAUDE_CODE_MCP_SERVER_URL")
    if not resource:
        sys.exit("need --resource or $CLAUDE_CODE_MCP_SERVER_URL")
    scope = args.scope or os.environ.get("DELCRED_SCOPE")
    if not scope:
        sys.exit("need --scope or $DELCRED_SCOPE")
    subject_token = _read_secret(args, "subject_token", "DELCRED_SUBJECT_TOKEN")
    actor_token = _read_secret(args, "actor_token", "DELCRED_ACTOR_TOKEN")
    from delcred.exchange import exchange as _exchange

    try:
        result = _exchange(
            subject_token=subject_token,
            actor_token=actor_token,
            scope=scope,
            resource=resource,
            requested_token_type=(
                TOKEN_TYPE_BROKER_KEY if args.as_api_key else "urn:ietf:params:oauth:token-type:jwt"
            ),
            ttl=args.ttl,
            base=_base(args),
        )
    except (ExchangeError, PolicyError) as e:
        print(f"delcred: delegation denied for {_st(resource)}: {_st(e)}", file=sys.stderr)
        sys.exit(3)
    # stdout carries ONLY the JSON object Claude Code parses.
    sys.stdout.write(json.dumps({"Authorization": f"Bearer {result.credential}"}))
    sys.stdout.flush()


def cmd_demo(args):
    from delcred.demo import run_demo

    if not run_demo():
        sys.exit(1)


def cmd_serve(args):
    from delcred.server import serve

    admin = None
    if args.admin_token_file:
        admin = _read_file_secret(args.admin_token_file)
    serve(
        port=args.port,
        base=_base(args),
        rate=args.rate_limit,
        admin_token=admin,
        public_url=args.public_url,
    )


def cmd_sidecar(args):
    from delcred.sidecar import run_sidecar

    # The sidecar's own identity: prefer files/env over ps-visible CLI args
    # (finding #7 applies to the operator's tokens too).
    user_token = _read_secret(args, "user_token", "DELCRED_SIDECAR_USER_TOKEN")
    agent_token = _read_secret(args, "agent_token", "DELCRED_SIDECAR_AGENT_TOKEN")
    mapping = {}
    for item in args.map or []:
        upstream, _, spec = item.partition("=")
        if not upstream or not spec or "|" not in spec:
            sys.exit(
                f"bad --map entry {item!r}; want upstream=scope|resource[|api-key]"
            )
        mapping[upstream] = spec
    run_sidecar(
        port=args.port,
        mapping=mapping,
        user_token=user_token,
        agent_token=agent_token,
        base=_base(args),
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="delcred",
        description="Short-lived, per-task, per-user-scoped credentials for AI agents.",
    )
    p.add_argument("--home", help="delcred home dir (default ~/.delcred)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create issuer keypair + default policy")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("key", help="issuer key operations")
    ks = s.add_subparsers(dest="keycmd", required=True)
    r = ks.add_parser(
        "rotate",
        help="rotate the issuer key (hard cut by default: old tokens stop verifying)",
    )
    r.add_argument(
        "--keep-old",
        nargs="?",
        type=int,
        const=86460,
        default=0,
        metavar="SECONDS",
        help="overlap window: keep the old key verifying (never signing) for this long "
        "(default 86460 = 24h+60s, longer than an agent token). Omit after a compromise.",
    )
    r.set_defaults(func=cmd_key_rotate)
    r = ks.add_parser("retire", help="stop trusting one retired key right now")
    r.add_argument("kid")
    r.set_defaults(func=cmd_key_retire)

    s = sub.add_parser("agent-token", help="mint an agent identity token")
    s.add_argument("agent_id")
    s.add_argument("--ttl", type=int, default=86400)
    s.set_defaults(func=cmd_agent_token)

    s = sub.add_parser("user-token", help="mint a local user assertion (dev)")
    s.add_argument("user_id")
    s.add_argument("--ttl", type=int, default=3600)
    s.set_defaults(func=cmd_user_token)

    s = sub.add_parser("exchange", help="RFC 8693 token exchange → delegation")
    s.add_argument(
        "--subject-token",
        help="user token (prefer --subject-token-file or "
        "$DELCRED_SUBJECT_TOKEN: CLI args leak via ps)",
    )
    s.add_argument("--subject-token-file", help="file containing the user token")
    s.add_argument(
        "--actor-token",
        help="agent token (prefer --actor-token-file or $DELCRED_ACTOR_TOKEN)",
    )
    s.add_argument("--actor-token-file", help="file containing the agent token")
    s.add_argument(
        "--scope", required=True, help="space-delimited, e.g. 'invoices:read'"
    )
    s.add_argument(
        "--resource", required=True, help="RFC 8707 resource indicator (URL)"
    )
    s.add_argument("--ttl", type=int, default=900)
    s.add_argument(
        "--as-api-key", action="store_true", help="issue opaque dk_… key instead of JWT"
    )
    s.add_argument(
        "--dpop-jkt",
        help="bind the token to a DPoP key (RFC 7638 thumbprint, see delcred.pop.thumbprint)",
    )
    s.add_argument(
        "--quiet-claims",
        action="store_true",
        help="print only the credential on stdout",
    )
    s.set_defaults(func=cmd_exchange)

    s = sub.add_parser("verify", help="verify a delegation token")
    s.add_argument("token")
    s.add_argument(
        "--resource",
        required=True,
        help="REQUIRED: enforce audience pinning (confused-deputy defense)",
    )
    s.add_argument(
        "--require-scope",
        action="append",
        metavar="SCOPE",
        help="scope this operation needs (repeatable); exit 5 if missing",
    )
    s.add_argument(
        "--check-policy",
        action="store_true",
        help="also refuse tokens whose grant was removed/narrowed in policy.yaml since minting",
    )
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("inspect", help="decode claims WITHOUT verifying (debug only)")
    s.add_argument("token")
    s.set_defaults(func=cmd_inspect)

    s = sub.add_parser("broker", help="opaque API-key broker operations")
    bs = s.add_subparsers(dest="brokercmd", required=True)
    r = bs.add_parser("redeem", help="redeem a dk_… key → capability record")
    r.add_argument("key")
    r.add_argument("--resource", help="pin redemption to this API (recommended)")
    r.add_argument("--require-scope", action="append", metavar="SCOPE")
    r.set_defaults(func=cmd_broker_redeem)

    s = sub.add_parser("revoke", help="revoke a token, agent, or user")
    s.add_argument("--jti")
    s.add_argument("--agent")
    s.add_argument("--user")
    s.add_argument(
        "--issuer", help="with --user: only that IdP's user (default: the id under every issuer)"
    )
    s.add_argument("--reason", default="")
    s.add_argument(
        "--token-file",
        help="revoke the delegation token in this file (what a holder does when its task is done)",
    )
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("policy", help="policy operations")
    ps = s.add_subparsers(dest="policycmd", required=True)
    c = ps.add_parser("check", help="dry-run a delegation request against policy")
    c.add_argument("--user", required=True)
    c.add_argument("--agent", required=True)
    c.add_argument("--scope", required=True)
    c.add_argument("--resource", required=True)
    c.add_argument("--ttl", type=int, default=900)
    c.set_defaults(func=cmd_policy_check)

    c = ps.add_parser("validate", help="lint policy.yaml: types, typos, duplicate grants")
    c.add_argument("--strict", action="store_true", help="exit 1 on warnings too")
    c.set_defaults(func=cmd_policy_validate)

    s = sub.add_parser("status", help="show home/policy/revocation state")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser(
        "audit",
        help="show / verify the tamper-evident audit log (no secrets)",
        description="audit [show]: recent events; audit verify: check the hash "
        "chain (exit 6 if tampered); audit head: print the newest hash to anchor.",
    )
    s.add_argument("action", nargs="?", default="show", choices=["show", "verify", "head", "checkpoint"])
    s.add_argument("--checkpoint-file", help="with verify: a signed checkpoint from `audit checkpoint`")
    s.add_argument("--tail", type=int, default=20)
    s.add_argument("--event", help="only this event type, e.g. token_issued")
    s.add_argument("--agent")
    s.add_argument("--user")
    s.add_argument("--since", help="only events newer than e.g. 15m, 2h, 7d")
    s.set_defaults(func=cmd_audit)

    s = sub.add_parser("jwks", help="print the issuer's public JWK Set")
    s.set_defaults(func=cmd_jwks)

    s = sub.add_parser("revocations", help="signed revocation bulletin for third-party verifiers")
    rs = s.add_subparsers(dest="revcmd", required=True)
    r = rs.add_parser("export", help="print the signed bulletin (compact JWS)")
    r.add_argument("--ttl", type=int, default=300, help="seconds the bulletin stays fresh")
    r.set_defaults(func=cmd_revocations_export)

    s = sub.add_parser(
        "offline-verify",
        help="verify a token with only a JWKS file (no delcred home) — the third-party view",
    )
    s.add_argument("token")
    s.add_argument("--jwks-file", required=True)
    s.add_argument("--resource", required=True)
    s.add_argument("--require-scope", action="append")
    s.add_argument("--bulletin-file", help="signed revocation bulletin (delcred revocations export)")
    s.add_argument("--require-bulletin", action="store_true", help="fail closed if no fresh bulletin")
    s.set_defaults(func=cmd_offline_verify)

    s = sub.add_parser("vectors", help="regenerate the cross-language test vectors")
    s.add_argument("--out", default="spec/vectors")
    s.set_defaults(func=cmd_vectors)

    s = sub.add_parser("prune", help="drop expired revocation + broker records")
    s.set_defaults(func=cmd_prune)

    s = sub.add_parser(
        "demo", help="zero-config, self-checking tour in a throwaway home"
    )
    s.set_defaults(func=cmd_demo)

    s = sub.add_parser(
        "mcp-headers",
        help="Claude Code headersHelper: print a fresh delegated Authorization header",
    )
    s.add_argument("--scope", help="scopes to delegate (or $DELCRED_SCOPE)")
    s.add_argument(
        "--resource",
        help="audience (default: $CLAUDE_CODE_MCP_SERVER_URL set by Claude Code)",
    )
    s.add_argument("--subject-token", help=argparse.SUPPRESS)
    s.add_argument("--subject-token-file", help="file holding the user token")
    s.add_argument("--actor-token", help=argparse.SUPPRESS)
    s.add_argument("--actor-token-file", help="file holding the agent token")
    s.add_argument("--ttl", type=int, default=900)
    s.add_argument("--as-api-key", action="store_true")
    s.set_defaults(func=cmd_mcp_headers)

    s = sub.add_parser("serve", help="run the HTTP exchange API")
    s.add_argument("--port", type=int, default=8400)
    s.add_argument(
        "--rate-limit", type=int, default=60,
        help="max /token, /exchange, /revoke requests per minute per client IP (0 = off)",
    )
    s.add_argument(
        "--admin-token-file",
        help="file holding the bearer token /revoke requires (or $DELCRED_ADMIN_TOKEN); "
        "without one, /revoke accepts loopback clients only",
    )
    s.add_argument(
        "--public-url", help="external base URL, used as issuer in RFC 8414 metadata"
    )
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("sidecar", help="run the credential-injecting forward proxy")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument(
        "--map",
        action="append",
        help="upstream_host=scope|resource[|api-key] (repeatable)",
    )
    s.add_argument(
        "--user-token",
        default=None,
        help="sidecar's user token (prefer --user-token-file or "
        "$DELCRED_SIDECAR_USER_TOKEN: CLI args leak via ps)",
    )
    s.add_argument("--user-token-file", help="file containing the sidecar's user token")
    s.add_argument(
        "--agent-token",
        default=None,
        help="sidecar's agent token (prefer --agent-token-file or "
        "$DELCRED_SIDECAR_AGENT_TOKEN)",
    )
    s.add_argument("--agent-token-file", help="file containing the sidecar's agent token")
    s.set_defaults(func=cmd_sidecar)

    s = sub.add_parser(
        "trust-add", help="trust an external IdP's subject tokens (by issuer)"
    )
    s.add_argument("--iss", required=True, help="issuer URL, e.g. https://idp.example.com")
    s.add_argument(
        "--key-file",
        required=True,
        help="PEM file with the issuer's Ed25519 public key",
    )
    s.add_argument(
        "--audience",
        help="aud the IdP's subject tokens must carry (default: 'delcred')",
    )
    s.set_defaults(func=cmd_trust_add)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except PolicyError as e:  # e.g. a malformed policy.yaml: say so, no traceback
        print(f"policy error: {_st(e, 600)}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
