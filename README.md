# delcred — delegated credentials for AI agents

**Stop giving agents your real API keys.** delcred mints short-lived,
per-task credentials that name both the human (`sub`) and the agent (`act`),
are pinned to one API, carry only the scopes the task needs, and expire in
minutes. Revoke the agent without locking out the human. Every issue,
use and revocation lands in a tamper-evident audit log.

One `pip install`, three small dependencies (PyJWT, cryptography, PyYAML), no
server, database or cloud account required.

## Quick start (60 seconds)

```bash
pip install delcred
delcred demo
```

`delcred demo` runs the whole tour in a throwaway directory (your real
`~/.delcred` is never touched) and checks each guarantee as it goes:

```
2. delegation (RFC 8693 exchange)
  [ok] 15-min token names human AND agent  (sub=u_alice act=billing-agent exp_in=900s)
3. least privilege
  [ok] agent cannot mint beyond its grant  (PolicyError: scope(s) not granted: ['admin:all'] …)
  [ok] read token refused for a write operation  (InsufficientScope: …)
4. confused-deputy defense
  [ok] token for API A rejected by API B  (InvalidToken: audience mismatch …)
5. MCP resource server (spec-shaped 401/403)
  [ok] 403 insufficient_scope with step-up challenge
…
8. kill switch
  [ok] revoked agent's token dies instantly
9. tamper-evident audit trail
  [ok] an edited audit line is detected  (line 2: content altered (hash mismatch))

13/13 guarantees held.
```

Then set up your own home:

```bash
delcred init                       # Ed25519 issuer key (0600) + deny-by-default policy
$EDITOR ~/.delcred/policy.yaml     # one grant per (user, agent) pair — see Policy below

delcred agent-token billing-agent > agent.jwt
delcred user-token  u_alice       > user.jwt    # dev only; production uses your IdP's JWT

delcred exchange --subject-token-file user.jwt --actor-token-file agent.jwt \
                 --scope "invoices:read" --resource https://api.acme.test/v1 > token.jwt
# stderr: # sub=u_alice act=billing-agent scope='invoices:read' resource=… ttl=900s jti=…

delcred verify "$(head -1 token.jwt)" --resource https://api.acme.test/v1 \
               --require-scope invoices:read
delcred revoke --agent billing-agent --reason "suspected prompt injection"
delcred audit verify               # hash chain intact? prints the head hash
```

Tokens are read from `--*-file`, `$DELCRED_SUBJECT_TOKEN` / `$DELCRED_ACTOR_TOKEN`,
or `$…_FILE` (Docker-secrets style). Avoid passing them as CLI arguments —
command lines are visible in `ps`.

## Use it from Claude Code (MCP `headersHelper`)

Claude Code can run a command on each connection to an HTTP MCP server and
use its JSON output as request headers (`headersHelper`, which receives
`$CLAUDE_CODE_MCP_SERVER_URL`). `delcred mcp-headers` is that command: it
mints a fresh 15-minute token whose audience is exactly the MCP server being
connected to, so Claude Code never holds a long-lived secret.

```json
{
  "mcpServers": {
    "billing": {
      "type": "http",
      "url": "https://mcp.acme.test/mcp",
      "headersHelper": "delcred mcp-headers --scope 'tools:call' --subject-token-file ~/.delcred/me.jwt --actor-token-file ~/.delcred/claude-code.jwt"
    }
  }
}
```

The policy needs a grant whose `resources` contains the MCP server URL
(`https://mcp.acme.test/mcp`). Output is exactly one JSON object
(`{"Authorization": "Bearer …"}`) on stdout; denials go to stderr with exit
code 3. If your Claude Code version has trouble passing arguments, put the
command in a two-line shell script and point `headersHelper` at it.
Some Claude Code versions have had open bug reports about `headersHelper`
output not being applied
([#48514](https://github.com/anthropics/claude-code/issues/48514)) — check
your server receives the header.

## Protect an MCP server (or any API) in a few lines

`delcred.mcp` gives a resource server the pieces the
[MCP authorization spec](https://modelcontextprotocol.info/specification/2025-11-25/basic/authorization/)
asks for — audience validation (RFC 8707), `401` with a `resource_metadata`
challenge, `403 insufficient_scope` for step-up, and the RFC 9728 metadata
document — with no framework dependency:

```python
from delcred.mcp import authorize, protected_resource_metadata, metadata_path

RESOURCE = "https://mcp.acme.test/mcp"
PRM_URL  = "https://mcp.acme.test" + metadata_path(RESOURCE)  # /.well-known/oauth-protected-resource/mcp

def handle(request):
    d = authorize(request.headers.get("Authorization"),
                  resource=RESOURCE, required_scopes="tools:call",
                  resource_metadata_url=PRM_URL)
    if not d.ok:                        # 401 or 403, WWW-Authenticate ready to send
        return Response(status=d.status, headers=d.headers)
    run_tool(user=d.user, agent=d.agent)

# serve this JSON at PRM_URL:
protected_resource_metadata(RESOURCE, ["https://auth.acme.test"], scopes_supported=["tools:call"])
```

`authorize` accepts both delegation JWTs and opaque `dk_…` keys, checks
signature, expiry, audience, scopes and revocation, and never tells the
caller *why* a credential failed (the audit log records it). Following the
spec's no-token-passthrough rule, mint a *separate* delegation for each
upstream API your server calls.

Resource servers that don't run delcred can verify tokens with any JWT
library using the issuer's public key: `delcred jwks` (or
`GET /.well-known/jwks.json` on `delcred serve`). Every token carries a
`kid` (RFC 7638 thumbprint).

## Library

```python
import delcred

tok = delcred.delegate(scope="invoices:read", resource="https://api.acme.test/v1",
                       user_token=user_jwt, agent_token=agent_jwt)
claims = delcred.verify(tok, expected_resource="https://api.acme.test/v1",
                        required_scopes="invoices:read")      # InsufficientScope if not

key = delcred.delegate_api_key(...)                            # opaque dk_… credential
cap = delcred.verify_broker_key(key, expected_resource="https://api.acme.test/v1")

delcred.revoke_agent("billing-agent", reason="...")  # kill switch, user untouched
delcred.revoke_user("u_alice")                       # kill switch
delcred.revoke_token(jti)                            # one token

delcred.AuditLog().verify().ok                       # tamper check
```

`delegate(user=..., agent=...)` optionally asserts the identities inside the
tokens (catches swapped tokens before anything is minted).

## HTTP API (`delcred serve`)

`delcred serve --port 8400` (binds 127.0.0.1):

| Endpoint | Purpose |
|---|---|
| `POST /token` | **Standard RFC 8693 token exchange** (form-encoded `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token`, `actor_token`, `*_token_type`, `scope`, `resource`). Returns `access_token`, `issued_token_type`, `token_type`, `expires_in`, `scope`; errors use RFC 6749/8693 codes (`invalid_scope`, `invalid_target`, `invalid_grant`, …). `Cache-Control: no-store`. |
| `POST /exchange` | JSON form of the same (0.2-compatible) |
| `POST /verify` | `{"token","resource","scope"?}` → claims, or 403 `insufficient_scope` |
| `POST /broker/redeem` | `{"key","resource"?,"scope"?}` → capability |
| `POST /revoke` | `{"jti"|"agent"|"user","reason"?}` |
| `GET /.well-known/jwks.json` | issuer public key |
| `GET /health` | liveness |

## The sidecar pattern

Agents need never see a token. The sidecar mints, caches and injects
credentials for allowlisted upstreams:

```bash
delcred sidecar --port 8080 \
  --map 'api.acme.test=invoices:read|https://api.acme.test/v1' \
  --user-token-file user.jwt --agent-token-file agent.jwt
# agent calls http://localhost:8080 with X-Delcred-Upstream: api.acme.test
# sidecar injects: Authorization: Bearer <15-min delegation token>
```

## External IdPs (production subject tokens)

delcred is **not** an IdP — it never does login or OAuth flows. It accepts
your IdP's user JWTs as `subject_token` once the issuer is registered:

```bash
delcred trust-add --iss https://idp.example.com --key-file ./idp-pub.pem
```

or in `policy.yaml`: `trusted_issuers: {"https://idp.example.com": "trusted_issuers/idp.pem"}`.
The local issuer can never be shadowed, unknown issuers are rejected, and a
trusted token with `kind: agent` is still refused as a subject.

## Policy (`~/.delcred/policy.yaml`)

Deny by default. A grant is the *only* thing that lets an exchange mint:

```yaml
grants:
  - user: u_alice
    agent: billing-agent
    scopes: ["invoices:read"]
    resources: ["https://api.acme.test/v1"]  # exact match (RFC 8707)
    max_ttl: 900        # seconds; global hard cap is 3600
    single_use: false   # true → jti burned on first successful verify
```

Dry-run: `delcred policy check --user u_alice --agent billing-agent --scope invoices:read --resource https://api.acme.test/v1`

## Audit trail

`~/.delcred/audit.jsonl` records every exchange, denial, verify, redeem,
replay and revocation with user, agent, scope, resource and `jti` — never
token or key values. Each line is hash-chained to the previous one:

```bash
delcred audit                          # recent events
delcred audit --agent billing-agent --since 2h
delcred audit verify                   # exit 6 + line numbers if anything was edited,
                                       # deleted, inserted or reordered
delcred audit head                     # newest hash — store it somewhere else
```

A hash chain proves the log was not altered *in the middle*. It cannot by
itself prove the newest lines were not cut off, or that someone with write
access did not rewrite the entire file — anchor `audit head` outside the
host (SIEM, ticket, commit) to cover that.

## How it compares

Statements below are limited to what each vendor's own page says (linked);
"—" means the page did not say, not that the feature is missing.

| | delcred | [Auth0 for AI Agents](https://www.okta.com/newsroom/press-releases/auth0-platform-innovation/) | [Aembit](https://docs.aembit.io/get-started/use-cases/ai-agents/) | [Keycard](https://www.helpnetsecurity.com/2026/05/15/keycard-for-multi-agent-apps/) | [Arcade](https://docs.arcade.dev/home/auth/how-arcade-helps) | [HashiCorp Vault](https://developer.hashicorp.com/validated-patterns/vault/ai-agent-identity-with-hashicorp-vault) |
|---|---|---|---|---|---|---|
| Delivery | MIT library + CLI, runs locally | Hosted platform | Hosted platform | Hosted platform | Platform | Self-hosted cluster or HCP |
| User + agent in one credential | yes (`sub` + `act`) | — | yes ("blended identity") | yes (delegation chains) | per-user OAuth | via OBO token claims |
| RFC 8693 token exchange | yes (`POST /token`) | — | — | yes | — | named as an alternative to OBO |
| Third-party OAuth token vault (Gmail, Slack…) | **no** | yes (Token Vault) | — | — | yes | dynamic secrets for DBs/clouds |
| Per-operation scope check with MCP 401/403 challenges | yes (`delcred.mcp`) | — | policies per user + agent | — | per-tool scopes | — |
| Credential injection proxy | yes (sidecar) | — | yes (MCP Identity Gateway) | — | — | — |
| Tamper-evident (hash-chained) audit | yes | — | logs every request | near-real-time logging | — | audit devices (HMAC'd fields) |
| Multi-agent chained delegation | **no** (single hop) | — | — | yes | — | — |

Where they are ahead: hosted platforms give you an admin UI, central
multi-host revocation, IdP/SCIM integration, and (Auth0, Arcade) real OAuth
connections to SaaS tools with refresh handling. Keycard handles
multi-hop delegation and runtime attestation. Vault covers database and
cloud dynamic secrets. delcred is the small, auditable, zero-infrastructure
option you can read in an afternoon and run on a laptop or inside one
service.

## Security model

- **Ed25519 only.** Strict `algorithms=["EdDSA"]`, issuer pinned, `typ: at+jwt`,
  `kid` checked. `none`/HS256/RSA confusion rejected.
- **Short lifetimes are the primary control:** default 15 min, hard cap 60 min,
  clamped server-side.
- **Confused-deputy defense:** every token carries an RFC 8707 resource
  indicator; `verify` requires the expected audience. Broker keys can be pinned
  the same way (`expected_resource`).
- **Least privilege twice:** requested scopes must be ⊆ the grant at mint time,
  and verifiers can require specific scopes per operation. Scope/audience
  failures are checked *before* a single-use credential is burned.
- **Revocation:** per-token `jti` denylist + per-agent and per-user kill
  switches, checked on every verify. Single-use credentials burn atomically.
- **Broker keys:** only SHA-256 hashes stored; constant-time compare over all
  records; uniform error messages (no key-existence oracle); each key is bound
  to its delegation JWT.
- **Hygiene:** private keys 0600 (refuses to load otherwise on POSIX), state dir
  0700, cross-process file locks (POSIX `flock`, Windows `msvcrt`) on stable
  sibling `.lock` files, hash-chained audit log that drops token/key fields.
- **Trust boundary:** agent identity tokens are operator-asserted — whoever
  controls the delcred home defines agent identities.

## Limitations (read before production)

1. **Bearer tokens.** Anyone holding a delegation JWT or `dk_…` key can use it
   until it expires. Mitigations: 15-min default TTL, single-use option,
   resource pinning, instant local revocation. Sender-constrained tokens
   (DPoP/mTLS) are not implemented.
2. **Single-host state.** Revocations, broker records and the audit log live in
   one delcred home. There is no multi-host revocation sync — run one issuer
   per trust domain. Third-party verifiers using only the JWKS do **not** see
   revocations; they rely on short expiry.
3. **Key rotation is a hard cut.** `delcred key rotate` invalidates every token
   signed by the old key (`kid mismatch`). There is no overlap window yet.
4. **Single-use ≠ exactly-once.** It bounds credential replay, not downstream
   side effects.
5. **Local user assertions are dev-only.** In production register your IdP
   with `trust-add`; only Ed25519 (EdDSA) IdP keys are supported, and keys are
   static PEM files (no JWKS fetching).
6. **`delcred serve` has no authentication.** It binds localhost; anyone who can
   reach it can mint within policy and call `/revoke`. Put TLS + auth in front
   before exposing it.
7. **No chained delegation** (`may_act`, agent → sub-agent).
8. **Windows** is supported by design (portable locking, no POSIX-only
   imports) but the test suite runs on Linux; on Windows the 0600 key-file
   check is skipped and protection relies on your profile's NTFS ACLs.
9. **Scale.** State files are JSONL scanned on each check. Measured on a
   Linux dev box: a revocation check over 10,000 entries takes ~15 ms, so
   this suits thousands of live records, not millions. Run `delcred prune`
   to drop expired entries. Agent/user kill switches are permanent (there is
   no un-revoke command yet).
10. **Clock skew.** 60 s leeway is assumed.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]" ruff
.venv/bin/python -m pytest -q
.venv/bin/ruff check delcred tests
```

Layout: `delcred/{tokens,keys,policy,exchange,revocation,broker,audit,mcp,cli,server,sidecar,demo,_lock}.py`

## License

MIT — Calas Automations Inc. See [LICENSE](LICENSE).
