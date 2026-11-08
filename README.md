# delcred — delegated credentials for AI agents

**Stop giving agents your real API keys.** delcred mints short-lived,
per-task, per-user-scoped credentials for agents: one credential naming both
the human (`sub`) and the agent (`act`), pinned to a single API, expiring in
minutes. Revoke the agent without locking out the human.

This is **market-gap #1 (Agent Identity & Delegated Credentials) merged with
#10 (Agent API Key Broker)** — the broker is the redemption half of
delegation: agents get *capability-shaped* credentials (a scoped JWT or an
opaque `dk_…` key), never the underlying secret.

**Platform: Linux and macOS only.** delcred relies on `fcntl` file locks and
POSIX `0600` permission checks; on Windows `import delcred` raises a clear
`ImportError` (and the test suite is skipped).

```
pip install delcred
delcred init
# edit ~/.delcred/policy.yaml — one grant per (user, agent) pair
```

## 30-second tour

```bash
# 1. identities (agent = actor_token, user = subject_token)
delcred agent-token billing-agent > /tmp/agent.jwt
delcred user-token u_alice > /tmp/user.jwt        # dev only; prod uses your IdP's JWT

# 2. exchange → delegation (RFC 8693 style).
#    Prefer files/env over CLI args — command lines are visible in `ps`.
delcred exchange --subject-token-file /tmp/user.jwt \
                 --actor-token-file   /tmp/agent.jwt \
                 --scope "invoices:read" --resource https://api.acme.test/v1
# ($DELCRED_SUBJECT_TOKEN / $DELCRED_ACTOR_TOKEN work too)
# → eyJhbGciOiJFZERTQSIs...   (15-min JWT: sub=u_alice, act=billing-agent)

# 3. or an opaque API-key-shaped credential instead of a JWT
delcred exchange ... --as-api-key
# → dk_7f3a...

# 4. verify — --resource is REQUIRED (audience pinning is the confused-deputy defense)
delcred verify <token> --resource https://api.acme.test/v1

# 5. revoke the agent — the human is untouched
delcred revoke --agent billing-agent --reason "suspected prompt injection"
```

## External IdPs (production subject tokens)

delcred is **not** an IdP — it never does login or OAuth flows. But it
accepts your IdP's user JWTs as `subject_token`: register the issuer once
(its public key and the one algorithm it signs with), then pass the IdP's
tokens straight into `exchange`:

```bash
delcred trust-add --iss https://idp.example.com --key-file ./idp-pub.pem
# → EdDSA (Ed25519) issuer; copies the key to ~/.delcred/trusted_issuers/
#   and records the mapping in policy.yaml under `trusted_issuers:`
delcred trust-add --iss https://okta.example.com --key-file ./okta-pub.pem --alg RS256
# → RS256 issuer (RSA >= 2048 bits); --alg ES256 takes an EC P-256 key

delcred exchange --subject-token-file /tmp/idp-user.jwt \
                 --actor-token-file   /tmp/agent.jwt \
                 --scope "invoices:read" --resource https://api.acme.test/v1
# subject claims come from the IdP token (iss/sub verified against the
# registered key, with that issuer's pinned alg only).
```

Or declare it directly in `policy.yaml`:

```yaml
trusted_issuers:
  "https://idp.example.com": "trusted_issuers/idp.pem"   # EdDSA; relative to ~/.delcred
  "https://okta.example.com": {key: "trusted_issuers/okta.pem", alg: RS256}
```

Each issuer is pinned to exactly one algorithm and the key type must match
it (checked when the policy loads). A token's own `alg` header never picks
the algorithm: an RS256 token for an EdDSA issuer, or an HS256 token signed
with an issuer's public key as the HMAC secret, is rejected.

Notes: the local issuer (`iss: delcred`) can never be shadowed by this
registry; unknown issuers are rejected; a trusted token with `kind: agent`
is still refused as a subject (no token laundering). Trusted IdPs vouch for
*users* only: actor (agent) tokens and delegation tokens are accepted only
from the local issuer, so an IdP cannot mint around your policy.

## Library (5 lines)

```python
import delcred

tok = delcred.delegate(scope="invoices:read",
                       resource="https://api.acme.test/v1",
                       user_token=user_jwt, agent_token=agent_jwt)
claims = delcred.verify(tok, expected_resource="https://api.acme.test/v1")

key = delcred.delegate_api_key(...)          # opaque dk_… credential
cap = delcred.verify_broker_key(key)         # redeem → capability record

delcred.revoke_agent("billing-agent", reason="...")  # kill switch
delcred.revoke_user("u_alice")                       # kill switch
delcred.revoke_token(jti)                            # single token
```

## The sidecar pattern (recommended)

Agents should never see tokens at all. Run the sidecar; it mints, caches,
and injects credentials for allowlisted upstreams:

```bash
delcred sidecar --port 8080 \
  --map 'api.acme.test=invoices:read|https://api.acme.test/v1' \
  --user-token-file /tmp/user.jwt --agent-token-file /tmp/agent.jwt
# agent calls http://localhost:8080 with X-Delcred-Upstream: api.acme.test
# sidecar injects: Authorization: Bearer <15-min delegation token>
#
# The sidecar's own identity can come from --user-token/--agent-token,
# --user-token-file/--agent-token-file, or $DELCRED_SIDECAR_USER_TOKEN /
# $DELCRED_SIDECAR_AGENT_TOKEN. Prefer files or env — command lines are
# visible in `ps`. The sidecar reads them once at startup into memory.
```

Or run the HTTP API: `delcred serve --port 8400`
(`POST /exchange`, `/verify`, `/broker/redeem`, `/revoke`, `GET /health`).

## Policy (`~/.delcred/policy.yaml`)

Deny by default. A grant is the *only* thing that lets an exchange mint:

```yaml
grants:
  - user: u_alice
    agent: billing-agent
    scopes: ["invoices:read"]
    resources: ["https://api.acme.test/v1"]  # exact match (RFC 8707)
    max_ttl: 900        # seconds; global hard cap is 3600
    single_use: false   # true → jti burned on first verify
```

Dry-run: `delcred policy check --user u_alice --agent billing-agent --scope invoices:read --resource https://api.acme.test/v1`

## Security model

- **One algorithm per issuer.** Everything delcred mints (user, agent and
  delegation tokens) is Ed25519 with strict `algorithms=["EdDSA"]`, issuer
  pinned, `typ: at+jwt` on delegations. Trusted IdP subject tokens are
  verified with the single alg pinned to that issuer (EdDSA, RS256 or ES256).
  `none`/HS256/alg-swap confusion rejected.
- **Short lifetimes are the primary control:** default 15 min, hard cap 60 min,
  clamped server-side no matter what the requester asks.
- **Confused-deputy defense:** every token carries an RFC 8707 resource
  indicator; verifiers must check audience (`delcred verify --resource`).
- **Scope discipline:** requested scopes must be ⊆ the grant; agents can never
  mint beyond their grant.
- **Revocation:** per-token `jti` denylist + per-agent and per-user kill
  switches, checked on every verify. Single-use tokens burn on first verify.
- **Broker keys:** only SHA-256 hashes stored; constant-time compare on redeem;
  uniform error messages (no key-existence oracle); every broker key is bound
  to its delegation JWT — revoking the JWT's `jti` kills the key too.
- **Hygiene:** private keys 0600 (refuses to load otherwise), state dir 0700,
  fcntl-locked append-only JSONL, audit log never contains token/key values,
  token inputs via file/env (not `ps`-visible CLI args).
- **Trust boundary:** agent identity tokens are operator-asserted — whoever
  controls the delcred home defines agent identities. Host access control
  *is* the identity root.

## Limitations (read before production)

1. **Bearer tokens.** Delegation JWTs and `dk_…` keys are bearer credentials:
   anyone holding one can use it until it expires. Mitigations shipped: 15-min
   default TTL, single-use option, resource pinning, instant local revocation.
   Sender-constrained tokens (DPoP/mTLS) are **not** in v1 — on the roadmap.
2. **Single-writer revocation.** The denylist lives in one delcred home.
   There is no multi-host revocation sync in v1 — run one issuer per trust
   domain, or accept that a revocation on host A doesn't reach host B.
3. **Single-use semantics.** The burn is atomic across processes and threads
   (check-and-set under an exclusive lock): exactly one concurrent verify or
   redeem wins, the rest are rejected. Don't use single-use as an exactly-once
   *execution* primitive — it bounds credential replay, not downstream effects.
4. **Local user assertions are dev-only.** `delcred user-token` mints a
   self-asserted subject token. In production, register your IdP with
   `delcred trust-add` and pass its real user JWTs as `subject_token` —
   delcred verifies signature/issuer/expiry against the registered key, not
   your login flow. delcred is a token service, not an IdP.
5. **`delcred serve` binds localhost without auth.** Put TLS + authentication
   in front before exposing it; anyone who can reach `/exchange` can mint
   within policy.
6. **No chained delegation.** `may_act` (agent→sub-agent) is deferred to v2.
7. **Clock skew.** 60s leeway is assumed; larger drift breaks verification.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest tests/ -q
```

Layout: `delcred/{tokens,keys,policy,exchange,revocation,broker,audit,cli,server,sidecar}.py`

## License

MIT — Calas Automations Inc.
