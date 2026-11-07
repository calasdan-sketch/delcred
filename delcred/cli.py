"""delcred CLI — `delcred <command> [options]`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import delcred
from delcred import keys as _keys
from delcred._common import HomeError
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
    try:
        h = delcred.init(base=_base(args), force=args.force)
    except FileExistsError:
        sys.exit(
            f"already initialised: an issuer key exists in {_base(args)}. "
            "`delcred init --force` replaces it, which invalidates every token and key issued so far."
        )
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

    try:
        jwks = json.loads(_read_text_arg(args.jwks_file, "JWKS file"))
    except ValueError as e:
        sys.exit(f"JWKS file {args.jwks_file} is not valid JSON: {_st(e, 200)}")
    bulletin = _read_text_arg(args.bulletin_file, "bulletin file").strip() if args.bulletin_file else None
    v = verify_offline(
        _token_arg(args.token),
        jwks=jwks,
        resource=args.resource,
        required_scopes=args.require_scope or None,
        bulletin=bulletin,
        require_bulletin=args.require_bulletin,
    )
    if v.ok:
        c = v.claims
        if args.json:
            _jprint({"valid": True, "claims": c})
            return
        print(f"VALID  sub={c['sub']} act={c['act']['sub']} scope={c['scope']!r} aud={c['aud']}")
        return
    print(f"INVALID: {_st(v.code)}: {_st(v.detail)}", file=sys.stderr)
    if args.json:
        _jprint({"valid": False, "code": _st(v.code), "detail": _st(v.detail)})
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


_MAX_TEXT_FILE = 1024 * 1024  # tokens are <= 16 KiB; JWKS/bulletins/checkpoints are small


def _decode_text_file(raw: bytes, name: str) -> str:
    """Decode a small text file the way Windows tools write it.

    PowerShell 5's ``>`` writes UTF-16 with a BOM and Notepad may add a UTF-8
    BOM; both are accepted. Anything else must be UTF-8.
    """
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        sys.exit(f"{name} is not valid UTF-8 text; re-save it as UTF-8 (or ASCII)")


def _read_text_arg(path: str, what: str) -> str:
    p = Path(os.path.expanduser(path))
    try:
        with open(p, "rb") as f:
            raw = f.read(_MAX_TEXT_FILE + 1)
    except OSError as e:
        sys.exit(f"cannot read {what} {p}: {e.strerror or e}")
    if len(raw) > _MAX_TEXT_FILE:
        sys.exit(f"{what} {p} is larger than {_MAX_TEXT_FILE // 1024} KiB; that is not a token, key set or checkpoint")
    return _decode_text_file(raw, f"{what} {p}")


def _read_file_secret(path: str) -> str:
    p = Path(os.path.expanduser(path))
    value = _read_text_arg(path, "token file").strip()
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


def _token_arg(value: str) -> str:
    """A token given as ``-`` is read from stdin (keeps it out of `ps`)."""
    if value != "-":
        return value
    text = _decode_text_file(sys.stdin.buffer.read(64 * 1024), "standard input").strip()
    if not text:
        sys.exit("no token on standard input")
    return text.splitlines()[0].strip()


def _jprint(obj) -> None:
    """One JSON document on stdout (the --json contract); diagnostics stay on stderr."""
    print(json.dumps(obj, indent=2, default=str, sort_keys=True))


def cmd_verify(args):
    try:
        claims = delcred.verify(
            _token_arg(args.token),
            expected_resource=args.resource,
            required_scopes=args.require_scope or None,
            base=_base(args),
            check_policy=args.check_policy,
        )
    except InsufficientScope as e:
        print(f"INSUFFICIENT_SCOPE: missing {_st(' '.join(e.missing))}", file=sys.stderr)
        if args.json:
            _jprint({"valid": False, "code": "insufficient_scope", "missing": [_st(m) for m in e.missing]})
        sys.exit(5)
    except (TokenError, ExchangeError) as e:
        print(f"INVALID: {_st(e)}", file=sys.stderr)
        if args.json:
            _jprint({"valid": False, "code": "invalid_token", "detail": _st(e)})
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
    print(json.dumps(decode_unverified(_token_arg(args.token)), indent=2, default=str))


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
        if args.json:
            _jprint({"allowed": False, "detail": _st(e)})
        sys.exit(3)
    ttl = pol.effective_ttl(grant, args.ttl)
    if args.json:
        _jprint({"allowed": True, "ttl": ttl, "scopes": sorted(grant.scopes)})
        return
    print(f"ALLOWED  ttl={ttl}s scopes={sorted(grant.scopes)}")


def cmd_policy_validate(args):
    from delcred.policy import validate

    errors, warnings = validate(_base(args))
    if args.json:
        _jprint({"ok": not errors, "errors": [_st(e, 600) for e in errors],
                 "warnings": [_st(w, 600) for w in warnings]})
        sys.exit(3 if errors else (1 if warnings and args.strict else 0))
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
    if args.json:
        _jprint({
            "home": str(h), "issuer_key_present": priv.exists(),
            "agents": len(pol.agents), "users": len(pol.users), "grants": len(pol.grants),
            "trusted_issuers": n_issuers, "revocation_entries": len(rl._entries()),
            "broker_records": len(Broker(h)._records()),
        })
        return
    print(f"home:      {h}")
    print(f"issuer key: {'present' if priv.exists() else 'MISSING — run delcred init'}")
    print(
        f"agents:    {len(pol.agents)}  users: {len(pol.users)}  "
        f"grants: {len(pol.grants)}  trusted issuers: {n_issuers}"
    )
    print(f"revocation entries: {len(rl._entries())}")
    print(f"broker records:     {len(Broker(h)._records())}")


def _doctor_policy(h: Path, add) -> None:
    if not policy_path(h).exists():
        add("FAIL", "policy.yaml", "missing; run `delcred init` (or create it) before minting anything")
        return
    try:
        pol = load_policy(h)
    except (PolicyError, OSError) as e:
        add("FAIL", "policy.yaml", _st(e, 300))
        return
    note = "" if pol.grants else " (deny by default: nothing can be minted yet)"
    add("ok" if pol.grants else "warn", "policy.yaml", f"{len(pol.grants)} grant(s){note}")


def _doctor_audit(h: Path, add) -> None:
    if not (h / "audit.jsonl").exists():
        add("warn", "audit log", "no audit.jsonl yet (nothing recorded)")
        return
    try:
        res = AuditLog(h).verify()
    except (OSError, ValueError) as e:
        add("FAIL", "audit log", _st(e, 300))
        return
    if res.ok:
        add("ok", "audit log", f"{res.chained} chained entries")
    else:
        add("FAIL", "audit log", f"{len(res.problems)} problem(s); run `delcred audit verify`")


def cmd_doctor(args):
    """Check that a delcred home is healthy; read-only (creates nothing)."""
    import stat as _stat

    # Resolve the folder WITHOUT creating it (`_base` would mkdir ~/.delcred).
    h = Path(args.home) if args.home else Path(os.environ.get("DELCRED_HOME", Path.home() / ".delcred"))
    rows: list[tuple[str, str, str]] = []  # (level, check, detail)

    def add(level: str, check: str, detail: str = "") -> None:
        rows.append((level, check, detail))

    if not h.is_dir():
        add("FAIL", "home folder", f"{h} does not exist; run `delcred init`")
    else:
        add("ok", "home folder", str(h))
        if os.name != "nt":
            mode = _stat.S_IMODE(h.stat().st_mode)
            add("ok" if not mode & 0o077 else "warn", "home permissions",
                oct(mode) + ("" if not mode & 0o077 else " (others can list it; chmod 700)"))
        try:
            _keys.load_private(h)
            _keys.load_public(h)
            add("ok", "issuer key", "loads (Ed25519)")
        except (OSError, HomeError, PermissionError) as e:
            add("FAIL", "issuer key", _st(e, 300))
        _doctor_policy(h, add)
        _doctor_audit(h, add)
    add("ok", "delcred", f"{delcred.__version__} on Python {sys.version_info.major}.{sys.version_info.minor}")
    bad = any(level == "FAIL" for level, _, _ in rows)
    if args.json:
        _jprint({"ok": not bad, "checks": [{"level": a, "check": b, "detail": c} for a, b, c in rows]})
    else:
        for level, check, detail in rows:
            print(f"[{level:>4}] {check}: {detail}")
    if bad:
        sys.exit(1)


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
        if args.json:
            _jprint({"ok": res.ok, "chained": res.chained, "legacy": res.legacy, "head": res.head,
                     "checkpoint_matched": bool(cp) and res.ok,
                     "problems": [_st(x, 400) for x in res.problems]})
            sys.exit(0 if res.ok else 6)
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
    for entry in log.tail(
        args.tail, event=args.event, agent=args.agent, user=args.user, since=since
    ):
        print(json.dumps(entry))


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


def _port(text: str) -> int:
    try:
        n = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a port number") from None
    if not 0 <= n <= 65535:
        raise argparse.ArgumentTypeError("port must be between 0 and 65535")
    return n


def _version_text() -> str:
    return f"delcred {delcred.__version__}"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="delcred",
        description="Short-lived, per-task, per-user-scoped credentials for AI agents.",
    )
    p.add_argument("--version", action="version", version=_version_text())
    p.add_argument("--home", help="delcred home dir (default $DELCRED_HOME or ~/.delcred)")
    sub = p.add_subparsers(dest="cmd")

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
    c.add_argument("--json", action="store_true", help="print the result as one JSON object on stdout")
    c.set_defaults(func=cmd_policy_check)

    c = ps.add_parser("validate", help="lint policy.yaml: types, typos, duplicate grants")
    c.add_argument("--strict", action="store_true", help="exit 1 on warnings too")
    c.add_argument("--json", action="store_true", help="print the result as one JSON object on stdout")
    c.set_defaults(func=cmd_policy_validate)

    s = sub.add_parser("doctor", help="check the home folder, key, policy and audit log (read-only)")
    s.add_argument("--json", action="store_true", help="print the checks as one JSON object on stdout")
    s.set_defaults(func=cmd_doctor)

    s = sub.add_parser("status", help="show home/policy/revocation state")
    s.add_argument("--json", action="store_true", help="print the state as one JSON object on stdout")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser(
        "audit",
        help="show / verify the tamper-evident audit log (no secrets)",
        description="audit [show]: recent events; audit verify: check the hash "
        "chain (exit 6 if tampered); audit head: print the newest hash to anchor.",
    )
    s.add_argument("action", nargs="?", default="show", choices=["show", "verify", "head", "checkpoint"])
    s.add_argument("--json", action="store_true", help="with verify: print the result as one JSON object")
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
    s.add_argument("--json", action="store_true", help="print the result as one JSON object on stdout")
    s.set_defaults(func=cmd_offline_verify)

    s = sub.add_parser("vectors", help="regenerate the cross-language test vectors")
    s.add_argument("--out", default="spec/vectors", help="folder to write vectors.json into (default: ./spec/vectors)")
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
    s.add_argument("--port", type=_port, default=8400)
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
    s.add_argument("--port", type=_port, default=8080)
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


_NOT_SET_UP_NAMES = {
    "issuer.key", "issuer.pub", "policy.yaml", "audit.jsonl", "revocations.jsonl", "broker.jsonl",
}


def _fail(msg: str, code: int = 1) -> None:
    print(f"delcred: {msg}", file=sys.stderr)
    sys.exit(code)


def _explain_oserror(e: OSError, args) -> str:
    """Plain-English text for a file-system problem (no traceback for user errors)."""
    name = Path(str(e.filename)).name if e.filename else ""
    if isinstance(e, FileNotFoundError):
        if e.filename is None:  # our own messages already say what to do
            return _st(e, 400)
        if name in _NOT_SET_UP_NAMES:
            return (
                f"no delcred home found at {_st(Path(str(e.filename)).parent, 300)} "
                f"(missing {name}); run `delcred init` first"
            )
        return f"no such file or directory: {_st(e.filename, 300)}"
    if isinstance(e, PermissionError):
        if e.filename is None:
            return _st(e, 400)
        return f"permission denied: {_st(e.filename, 300)}"
    if e.errno == 30:  # EROFS
        return f"the file system is read-only: {_st(e.filename or '', 300)} (use --home or $DELCRED_HOME for a writable folder)"
    if e.filename:
        return f"{_st(e.strerror or e, 200)}: {_st(e.filename, 300)}"
    return _st(e, 400)


def _quiet_stdout() -> None:
    """After EPIPE (``delcred ... | head``): stop Python flushing into a dead pipe."""
    try:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    except (OSError, ValueError, AttributeError):
        pass


def main(argv=None):
    # A cp1252 / ASCII console must never turn a hostile or accented string into
    # a UnicodeEncodeError traceback: print an escape instead.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help(sys.stderr)
        sys.exit(2)
    debug = bool(os.environ.get("DELCRED_DEBUG"))
    try:
        args.func(args)
        sys.stdout.flush()
    except BrokenPipeError:
        _quiet_stdout()
        sys.exit(1)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        sys.exit(130)
    except PolicyError as e:  # e.g. a malformed policy.yaml: say so, no traceback
        print(f"policy error: {_st(e, 600)}", file=sys.stderr)
        sys.exit(3)
    except SystemExit:
        raise
    except Exception as e:
        if debug:
            raise
        _report_unexpected(e, args)


def _report_unexpected(e: Exception, args) -> None:
    from delcred._jws import JWSError
    from delcred.broker import BrokerError as _BE
    from delcred.pop import PopError
    from delcred.trust import TrustConfigError

    if isinstance(e, HomeError):
        _fail(_st(e, 600))
    if isinstance(e, InsufficientScope):
        _fail(f"INSUFFICIENT_SCOPE: missing {_st(' '.join(e.missing))}", 5)
    if isinstance(e, (TokenError, JWSError, PopError, _BE)):
        _fail(f"INVALID: {_st(e, 400)}", 4)
    if isinstance(e, (ExchangeError, TrustConfigError)):
        _fail(f"denied: {_st(e, 400)}", 3)
    if isinstance(e, OSError):
        _fail(_explain_oserror(e, args))
    if isinstance(e, (ValueError, TypeError)):  # includes JSON/Unicode decode errors
        _fail(f"invalid input: {_st(e, 400)}", 2)
    if isinstance(e, OverflowError):
        _fail(f"invalid number: {_st(e, 200)}", 2)
    _fail(
        f"internal error ({type(e).__name__}: {_st(e, 200)}). This is a bug in delcred; "
        "rerun with DELCRED_DEBUG=1 for a traceback.",
        70,
    )


if __name__ == "__main__":
    main()
