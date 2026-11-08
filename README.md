# delcred — delegated credentials for AI agents

**Stop giving agents your real API keys.** delcred mints short-lived,
per-task credentials that name both the human (`sub`) and the agent (`act`),
are pinned to one API, carry only the scopes the task needs, can be bound to a
key so a leaked token is useless (DPoP), and expire in minutes. Agents can hand
sub-agents a *narrower* copy but never a broader one. Revoke the agent without
locking out the human. Every issue, use and revocation lands in a
tamper-evident audit log, and any language can verify tokens offline against a
published spec and 96 test vectors. Take a grant out of the policy and
already-minted tokens can die with it (`verify --check-policy`).

One `pip install`, three small dependencies (PyJWT, cryptography, PyYAML), no
server, database or cloud account required.

## Quick start (60 seconds)

```bash
pip install "delcred>=0.4"     # Python 3.10+; adds the `delcred` command
delcred --version
delcred demo
```

PyPI currently carries only the old 0.2.0 (checked with `pip index versions delcred`
on the day of this commit). The `>=0.4` makes pip fail loudly instead of installing
that old code; until 0.4.0 is published, install from a checkout:

```bash
git clone https://github.com/calasdan-sketch/delcred && cd delcred && pip install .
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
…
10b. policy stays live; tokens can be ended from either side
  [ok] grant removed -> already-minted token refused (check_policy)
  [ok] the holder ends its own token when the task is done
11. kill switch
  [ok] revoked agent's token dies instantly
12. tamper-evident audit trail
  [ok] an edited audit line is detected  (line 2: content altered (hash mismatch))

24/24 guarantees held.
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
delcred policy validate            # typos, duplicate grants, wrong types in policy.yaml
```

Tokens are read from `--*-file`, `$DELCRED_SUBJECT_TOKEN` / `$DELCRED_ACTOR_TOKEN`,
or `$…_FILE` (Docker-secrets style). Avoid passing them as CLI arguments —
command lines are visible in `ps`. `verify`, `offline-verify` and `inspect`
accept `-` as the token to read it from standard input
(`delcred exchange ... | delcred verify - --resource ...`). Token files may be
UTF-8, UTF-8 with BOM, or the UTF-16 that Windows PowerShell 5's `>` writes.

### Scripting: exit codes, `--json`, stdout vs stderr

Results go to stdout, diagnostics to stderr; user mistakes (missing home, bad
file, bad port, damaged key) print one plain sentence, never a traceback
(`DELCRED_DEBUG=1` restores tracebacks for bug reports).

| Exit | Meaning |
|---|---|
| 0 | success |
| 1 | something outside delcred's control or a missing prerequisite (no home yet, unreadable file, nothing revoked, `policy validate --strict` warnings) |
| 2 | bad command line or invalid input value |
| 3 | denied by policy / exchange refused / bad `policy.yaml` |
| 4 | credential invalid, expired or revoked |
| 5 | valid credential but missing a required scope |
| 6 | audit log tampered or checkpoint unusable |
| 70 | internal error in delcred (please report; rerun with `DELCRED_DEBUG=1`) |
| 130 | interrupted (Ctrl-C) |

`--json` on `verify`, `offline-verify`, `status`, `policy check`, `policy validate`
and `audit verify` prints exactly one JSON object on stdout (also on failure,
alongside the non-zero exit code).

## A real agent loop in one file

`python examples/agent_loop.py` runs a scripted agent against a tool server:
the agent holds a key-bound 15-minute token, a prompt-injected document tells
it to delete an invoice (refused, 403 `insufficient_scope`) and to leak its
token (useless without the key), a sub-agent receives a narrower copy, and
pulling the kill switch refuses both. The "model" is a stand-in; swap `plan()`
for your LLM call.

## Sub-delegation: a child never gets more than its parent

```yaml
grants:
  - user: u_alice
    agent: orchestrator
    scopes: ["invoices:read", "invoices:write"]
    resources: ["https://api.acme.test/v1"]
    delegate_to: [summarizer]   # deny by default: nobody else may receive a copy
    max_depth: 2                # hops below the orchestrator (hard cap 4)
```

```python
child = delcred.attenuate(parent_token,
                          sub_agent_token=delcred.agent_token("summarizer"),
                          scope="invoices:read", resource=RESOURCE)
```

The child's `act` nests per RFC 8693 §4.4 (`summarizer` acting for
`orchestrator` acting for `u_alice`) and `chain` lists ancestor token ids.
Enforced at mint time: scope ⊆ parent's *and* ⊆ the user's current grant; same
audience; `exp` ≤ parent's; named sub-agent proves its identity with its own
agent token; no cycles; single-use parents cannot delegate; a DPoP-bound parent
needs a proof and the child stays bound. Revoking an ancestor token, **any**
agent in the chain, or the user kills the child. `POST /token` does the same
with a delegation token as `subject_token`. A committed fuzz run
(`bench/run_bench.py`) tries 3,000 widening attempts: 0 invariant violations.
(An earlier run on a slow disk caught a one-second overshoot: a child could
expire a second after its parent when the clock ticked mid-call; `exp` is now
capped at the parent's absolute `exp` and a regression test pins it.)

## Stolen-token defence: DPoP (RFC 9449, Ed25519)

```python
from delcred import pop
key = pop.generate_key()                                    # stays in the agent
tok = delcred.delegate(..., dpop_jkt=pop.thumbprint(key))   # token carries cnf.jkt
proof = pop.make_proof(key, "GET", url, access_token=tok)   # per request
# server: Authorization: DPoP <tok> + DPoP: <proof>
delcred.verify(tok, expected_resource=RES, dpop_proof=proof, http_method="GET", http_url=url)
```

A leaked bound token fails without the key; the proof is checked before
revocation and before a single-use burn, so a thief cannot even consume it.
`delcred.mcp.authorize(..., dpop_proof=, http_method=, http_url=)` returns the
RFC 9449 `DPoP` challenge. `POST /token` accepts a `DPoP` header (or
`dpop_jkt`) and answers `token_type: DPoP`.

## Verify from any language (offline) + revocation that third parties see

`spec/VERIFICATION.md` is the verifier spec; `spec/vectors/vectors.json` has 96
cases (alg confusion, embedded-key headers, `crit`, NBSP-in-scope, leeway
boundaries, chains, DPoP, bulletins). Dependency-free Node
(`spec/verifiers/node`) and Go (`spec/verifiers/go`) verifiers pass all of
them; so does `delcred.offline.verify_offline`. A JWKS alone cannot reveal
revocations, so the issuer publishes a short-lived **signed bulletin**
(`delcred revocations export`, `GET /revocations.jwt`); pass it to the verifier
and a kill switch reaches third parties within the bulletin age (default 5 min)
instead of at token expiry. `delcred offline-verify TOKEN --jwks-file ...`
shows the third-party view.

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
`GET /.well-known/jwks.json` on `delcred serve`, also advertised as
`jwks_uri` in its RFC 8414 metadata — not in the RFC 9728 resource document,
whose `jwks_uri` is reserved for the resource's own keys). Every token carries a
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
| `POST /broker/redeem` | `{"key","resource"?,"scope"?}` → capability, or 403 `insufficient_scope` |
| `POST /revoke` | `{"jti"|"agent"|"user","issuer"?,"reason"?}` — needs `Authorization: Bearer <admin token>` if `--admin-token-file` / `$DELCRED_ADMIN_TOKEN` is set, otherwise loopback clients only; ids ≤ 256 chars |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata (`token_endpoint`, `jwks_uri`) so OAuth/MCP clients can discover `/token`; `--public-url` sets `issuer` |
| `GET /.well-known/jwks.json` | issuer public key |
| `GET /health` | liveness |

| `POST /oauth/revoke` | RFC 7009: the **holder** ends its own token (`token=…`, form or JSON); always 200, no oracle; advertised as `revocation_endpoint` |

A server bound to a loopback address answers only to loopback `Host` headers
(421 otherwise: DNS-rebinding guard; add your public name with `--public-url`),
and refuses POSTs that a browser marks cross-site (`Origin` /
`Sec-Fetch-Site`), so a web page cannot reach `/revoke` as "a loopback
client". There is no CORS support by design.

Requests run on threads with a 10-second socket timeout, and `/token`,
`/exchange`, `/revoke` and `/oauth/revoke` are limited to `--rate-limit` requests per minute
per client IP (default 60; HTTP 429 with `Retry-After`).

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

What the sidecar enforces, because the caller may be a prompt-injected agent:
the credential only ever goes to the allowlisted host (an absolute-form request
line or `X-Delcred-Upstream` naming a different host is refused, as is a path
that does not start with `/`); only `https` (plain `http` solely for loopback
targets); redirects are **not** followed (the 3xx is returned to the caller,
without the token); the caller's own `Authorization` header is dropped;
upstream 4xx/5xx statuses and headers pass through (so an agent sees a real
`403 insufficient_scope`, not a blanket 502); bodies are capped (16 MiB in,
32 MiB out). Request lines are origin-form (`GET /path`) with the
`X-Delcred-Upstream` header, or absolute-form naming the same host. Proxy
environment variables (`HTTPS_PROXY`, `NO_PROXY`) are honoured as before.

## External IdPs (production subject tokens)

delcred is **not** an IdP — it never does login or OAuth flows. It accepts
your IdP's user JWTs as `subject_token` once the issuer is registered:

```bash
delcred trust-add --iss https://idp.example.com --key-file ./idp-pub.pem \
                  --audience delcred        # aud the IdP's tokens must carry (default)
```

Rules that keep an IdP from becoming a back door:

- An external IdP is trusted **only for the subject (user) token**. Agent
  tokens and delegation tokens must be signed by delcred's own key — an IdP
  cannot mint itself an agent identity or a delegation.
- The IdP token's `aud` must contain the configured audience, so a token the
  IdP issued for some other app cannot be replayed into delcred.
- Users are identified by **(issuer, user id)**. A grant covers local users
  unless it names the IdP:

  ```yaml
  grants:
    - user: u_alice
      issuer: "https://idp.example.com"   # without this line: local users only
      agent: billing-agent
      scopes: ["invoices:read"]
      resources: ["https://api.acme.test/v1"]
  ```

  Delegation tokens record it as `user_iss`. `delcred revoke --user u_alice
  --issuer https://idp.example.com` revokes only that IdP's user; without
  `--issuer` the id is revoked under every issuer (fail-closed).

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

`delcred policy validate` lints the file (misspelt keys such as `scope:`,
duplicate grants where only the first counts, `http://` or trailing-slash
resources, wildcard-looking scopes, an unknown agent). A wrong type, e.g. a bare
string where a list belongs (`scopes: "a b"`), is now an error instead of being
read as a set of single characters, and a malformed file denies every exchange.

Tokens already minted stay valid until they expire (at most 60 minutes) even
after you delete their grant, unless the verifier asks for
`delcred.verify(..., check_policy=True)` / `delcred verify --check-policy` /
`mcp.authorize(..., check_policy=True)`; that re-reads `policy.yaml` on every
call (it needs the delcred home, so it fits a verifier beside the issuer, not
an offline one) and costs a YAML parse per verify.

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

Credentials that fail verification (bad signature, wrong audience, expired,
malformed) are logged too, as `verify_rejected` with the failure class and
sanitised, clearly-labelled *claimed* identity hints (never the token). Because
anyone can trigger them, they are rate-limited (burst 50, then about 5/s) and
the next entry that gets through carries `suppressed=N`.

`delcred audit` reads only the tail of the file (1 ms for the last 20 of
100,000 entries; it used to read the whole file), and `audit verify` streams.
`DELCRED_AUDIT_FSYNC=routine-off` skips the per-line `fsync` for `verify_*`
events only (mints, denials and revocations always sync): faster on slow
disks, but the last few verify lines can be lost in a power cut.

A hash chain proves the log was not altered *in the middle*. It cannot by
itself prove the newest lines were not cut off, or that someone with write
access did not rewrite the entire file — anchor `audit head` outside the
host (SIEM, ticket, commit) to cover that.
`delcred audit checkpoint` prints a signed statement of "N entries, ending in
this hash"; keep it off the host and later run
`delcred audit verify --checkpoint-file cp.txt`: it fails if newer entries were
cut off or the log was rewritten as a fresh consistent chain. It is signed by
the issuer key, so someone who steals that key *and* the log can forge a newer
checkpoint but not recreate one you already stored elsewhere. After a hard key
rotation old checkpoints can no longer be verified; take a new one.

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
| Multi-agent chained delegation | yes (attenuation-only, issuer-mediated, 4 hops max) | — | — | yes | — | — |

### Closer to the metal: token formats you can `pip install`

Measured by `bench/run_bench.py` (one Linux x86-64 machine, Python 3.13,
single thread, operations per second; re-run it, ratios matter more than
absolutes):

| | delcred 0.4 | PyJWT EdDSA (plain JWT) | Biscuit (`biscuit-python`) | pymacaroons |
|---|---|---|---|---|
| Verify | 260/s full (signature, audience, scope, revocation, **fsynced** audit line), 1,000/s with `DELCRED_AUDIT_FSYNC=routine-off`; 4,100/s offline | 5,050/s | 7,640/s parse+authorize | 41,400/s (HMAC, issuer-only) |
| Holder narrows a token offline | no (issuer-mediated) | no | **yes** (18,100/s) | **yes** |
| Issuer enforces user/agent/scope policy, audit log, kill switches | **yes** | no | no (bring your own) | no |
| Third-party verification without the secret | yes (JWKS + bulletin) | yes | yes | no |
| Sender-constrained (key-bound) tokens | **yes** (DPoP) | DIY | DIY | DIY |
| Token size, 1 hop / 2 hops | 541 / 604 bytes | n/a | 288 / 460 bytes | 220 bytes (3 caveats) |

The numbers come from one shared Linux sandbox with slow `fsync` and noisy
timing (the same run varied up to 2x), so only the ratios mean anything; the
committed 0.4 numbers measured on a faster machine were about 4x higher for
every row. Re-run `bench/run_bench.py` on your own hardware (it needs
`pip install pymacaroons biscuit-python` for the last two columns).
Biscuit's authorizer has a roughly 1 ms wall-clock limit, so the benchmark
retries the occasional run that trips it on a loaded machine.

Where they win: Biscuit and Macaroons let a *holder* attenuate with no round
trip and carry richer logic ([Biscuit](https://github.com/eclipse-biscuit/biscuit-rust):
"offline delegation" and public-key verification; it lists revocation as
requiring "external state management"). delcred's bet is the opposite
trade-off: the issuer checks every narrowing against a user-owned policy,
records it, and can kill a whole chain by agent or user.

Cloud and platform identity, from their own docs: AWS IAM Roles Anywhere
sessions last 15 min to 12 h and are obtained by signing with an X.509
certificate ([AWS](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session));
Microsoft Entra Agent ID models autonomous and on-behalf-of agents through
Entra-registered agent identities
([Microsoft Learn](https://learn.microsoft.com/en-sg/entra/msidweb/agent-id-sdk/agent-identities));
Descope's Agentic Identity Hub provides per-MCP-server authorization servers,
a credential vault and per-agent/per-tool scopes
([Descope](https://www.descope.com/blog/post/agentic-identity-hub)).
All are tied to their platform; none of those pages describe an
open verifier spec or offline conformance vectors (absence on a page is not
proof of absence). SPIRE/SPIFFE, WorkOS and Stytch were not evaluated.

Where they are ahead: hosted platforms give you an admin UI, central
multi-host revocation, IdP/SCIM integration, and (Auth0, Arcade) real OAuth
connections to SaaS tools with refresh handling. Keycard describes
multi-hop delegation and runtime attestation (delcred's chains are
issuer-mediated and narrow-only, with no runtime attestation). Vault covers database and
cloud dynamic secrets. delcred is the small, auditable, zero-infrastructure
option you can read in an afternoon and run on a laptop or inside one
service.

## Security model

- **Ed25519 only.** Strict `algorithms=["EdDSA"]`, issuer pinned (delegation and
  agent tokens: local issuer only), `typ: at+jwt` required on delegation tokens,
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

1. **Bearer tokens by default.** Anyone holding a delegation JWT or `dk_…` key
   can use it until it expires. Mitigations: 15-min default TTL, single-use
   option, resource pinning, instant local revocation, and **DPoP key binding**
   (JWTs only; `dk_` keys cannot be bound; mTLS binding is not implemented).
   The DPoP replay cache is process-local: run one verifier process or share it.
2. **Single-host state.** Revocations, broker records and the audit log live in
   one delcred home. There is no multi-host revocation sync — run one issuer
   per trust domain. Third-party verifiers using only the JWKS do **not** see
   revocations; they rely on short expiry.
3. **Key rotation is a hard cut by default.** `delcred key rotate` invalidates
   every token signed by the old key. Routine rotation: `delcred key rotate
   --keep-old` keeps the old key verifying (never signing, published in the
   JWKS) for 24 h + 60 s, or a number of seconds you choose; `delcred key retire
   KID` ends it early. After a suspected compromise use the hard cut.
4. **Single-use ≠ exactly-once.** It bounds credential replay, not downstream
   side effects.
5. **Local user assertions are dev-only.** In production register your IdP
   with `trust-add`; only Ed25519 (EdDSA) IdP keys are supported, and keys are
   static PEM files (no JWKS fetching).
6. **`delcred serve` has no client authentication for minting.** It binds
   localhost; anyone who can reach `/token` or `/exchange` can mint within
   policy (rate-limited). `/revoke` is loopback-only unless you set an admin
   token. Put TLS + auth in front before exposing it. `/token` also accepts
   JSON bodies and requires `scope`, which is stricter than RFC 8693.
7. **Chained delegation is issuer-mediated.** Sub-agents get tokens by asking
   the issuer (which enforces attenuation); there is no offline, holder-side
   attenuation as in Biscuit/Macaroons, and no `may_act` claim.
8. **Windows has never been run.** It is supported by design (portable
   locking, no POSIX-only imports, UTF-8 everywhere, `\n`-exact key files,
   retry on sharing violations when replacing a file) and a CI workflow for it
   is included (`.github/workflows/ci.yml`), but every test so far ran on
   Linux. On Windows the 0600 key-file check is skipped and protection relies on
   your profile's NTFS ACLs; `msvcrt` locks are exclusive-only, so concurrent
   readers serialize.
9. **Scale.** Broker and audit files are JSONL. Revocation lookups
   are indexed in memory (one `stat` per check, only new bytes parsed after an
   append): 0.004 ms at 100,000 entries versus 173 ms in 0.3.0 (`bench/`).
   The index is per process and the files still grow without bound, so run
   `delcred prune`; signed bulletins list every live revocation and grow with it. Agent/user kill switches are permanent (there is
   no un-revoke command yet: restoring an agent while keeping its old tokens
   dead needs a bulletin-format change, so it is not built).
10. **Clock skew.** 60 s leeway is assumed.
11. **Token `iss` is not a URL.** Tokens carry `iss: "delcred"` while the
    RFC 8414 metadata reports the server URL as `issuer`. OAuth clients that
    insist the access token's `iss` equals the metadata issuer will object;
    resource servers using delcred (or `delcred_token_issuer` from the
    metadata) are unaffected. Changing `iss` would invalidate every existing
    token, so it is left for a deliberate major release.
12. **Not tested here:** Windows (locking and the audit streaming reader are
    written for it but only exercised on Linux), real IdPs, real TLS upstreams
    through the sidecar (tests use loopback `http`), and multi-host setups.
    The DPoP replay cache is still per process; `check_policy` does not apply
    to opaque `dk_` keys; DPoP server nonces (RFC 9449 section 8) are not
    implemented.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]" ruff
.venv/bin/python -m pytest -q
.venv/bin/ruff check delcred tests
```

Layout: `delcred/{tokens,keys,policy,exchange,revocation,broker,audit,mcp,pop,offline,bulletin,vectors,cli,server,sidecar,demo,_lock,_jws}.py`, `spec/`, `examples/`, `bench/`.

## License

MIT — Calas Automations Inc. See [LICENSE](LICENSE).

---

Release notes: `CHANGELOG.md`. Review history and what was *not* done: `docs/ROUND4.md` and `docs/ROUND5.md`. Release steps for the maintainer: `PUBLISH-CHECKLIST.md`.
