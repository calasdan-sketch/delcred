# Changelog

## 0.4.0 - unreleased (expert-2 round)

### Added
- **Sub-delegation (agent -> sub-agent), attenuation only.** `delcred.attenuate()`,
  or `POST /token` / `exchange()` with a delegation token as `subject_token`.
  Grants gain `delegate_to` and `max_depth` (deny by default, hard cap 4). Child:
  scope within the parent's and the user's current grant, same audience, `exp`
  no later, proven sub-agent identity, no cycles, single-use parents refused.
  `act` nests per RFC 8693 4.4; `chain` lists ancestor jtis. Revocation checks
  every actor and ancestor in the chain (previously only the leaf agent).
- **DPoP (RFC 9449, Ed25519):** `delcred.pop`, `delegate(dpop_jkt=)`,
  `verify(dpop_proof=, http_method=, http_url=)`, `mcp.authorize(...)` with the
  `DPoP` scheme and challenge, `/token` `DPoP` header. Bound tokens fail closed
  without a proof; the proof is checked before revocation and single-use burn.
- **Offline verifier + spec + vectors:** `delcred.offline.verify_offline`,
  `spec/VERIFICATION.md`, 89 deterministic vectors (`delcred vectors`),
  dependency-free Node and Go verifiers, `delcred offline-verify`.
- **Signed revocation bulletin:** `delcred revocations export`,
  `GET /revocations.jwt`, `delcred.bulletin`.
- **Key rotation with overlap:** `delcred key rotate --keep-old [SECONDS]`,
  `key retire KID`; retired keys verify but never sign and appear in the JWKS.
- `examples/agent_loop.py`; `bench/run_bench.py` (+ `bench/results.json`);
  `demo` now covers sub-delegation, DPoP, offline verification (20 checks).

### Changed
- **Revocation lookups are indexed** (one `stat` per check; only appended bytes
  parsed): 173 ms -> 0.004 ms at 100,000 entries; single-use burns at 100k
  entries 6.7/s -> ~3,500/s.
- Tokens larger than 16 KiB are refused before parsing (a 5 MB token cost 0.45 s).
- JWS headers `jwk jku x5u x5c x5t x5t#S256 crit` are rejected; unknown `cnf`
  members fail closed.
- `/.well-known/oauth-authorization-server` advertises DPoP and the bulletin URI.

### Fixed
- Non-canonical base64url (non-zero trailing bits) is rejected by the offline verifier and both reference verifiers; a differential fuzz against the PyJWT path found the two disagreeing on a flipped last signature character.
- A crash-torn revocation line is terminated before the next append (the next
  revocation or single-use burn was previously glued onto it and lost).
- Scopes are parsed per RFC 6749 (ASCII space only; NBSP/tab/Unicode spaces and
  non-token characters are rejected). Python's `split()` and other languages'
  verifiers disagreed about such scopes.
- `ttl` must be a positive integer (floats, bools and strings used to mint odd
  `exp` values or raise `TypeError`).
- User/agent ids with control, bidi, zero-width or whitespace characters are
  refused at mint and exchange (terminal-escape injection into logs).

### Compatibility
- All 0.3 APIs and tokens keep working. A delegation token used as
  `subject_token` previously always failed; it now works only for agents the
  grant lists in `delegate_to`, otherwise it still fails.
- `key rotate` without flags is still a hard cut.

## 0.3.0 — unreleased

### Added
- **Least-privilege verification:** `verify(..., required_scopes=...)`,
  `verify --require-scope` (exit 5), `/verify {"scope"}`; new
  `delcred.InsufficientScope`. Scope and audience failures are checked
  before a single-use credential is burned.
- **Broker key resource pinning:** `verify_broker_key(key, expected_resource=,
  required_scopes=)`, `broker redeem --resource/--require-scope`.
- **`delcred.mcp`** resource-server helpers aligned with the MCP authorization
  spec (2025-11-25): `authorize()` returns 401 / 403 `insufficient_scope`
  decisions with ready `WWW-Authenticate` challenges; RFC 9728
  `protected_resource_metadata()` and `metadata_path()`.
- **RFC 8693 `POST /token`** on `delcred serve` (form-encoded request,
  standard response and error codes, `Cache-Control: no-store`).
- **JWKS + `kid`:** every token carries an RFC 7638 `kid`; `delcred jwks` and
  `GET /.well-known/jwks.json` let third parties verify with any JWT library.
  Tokens signed by a rotated key fail with an explicit "kid mismatch".
- **Tamper-evident audit log:** hash-chained entries, `delcred audit verify`
  (exit 6 on tampering), `audit head`, filters `--event/--agent/--user/--since`.
- **Claude Code integration:** `delcred mcp-headers` for MCP `headersHelper`.
- **`delcred demo`:** zero-config, self-checking tour in a throwaway home.
- `delcred prune`; `$DELCRED_*_TOKEN_FILE` env vars; `~` expansion in token
  file paths.
- `delegate()` / `delegate_api_key()` now honour the `user=` / `agent=`
  arguments as assertions (previously silently ignored).

### Changed
- Portable cross-process locking (POSIX `flock`, Windows `msvcrt`) on stable
  sibling `*.lock` files; `fcntl` is no longer imported unconditionally, so the
  package imports on Windows.
- Revocation message no longer repeats "token revoked:".

### Fixed
- `prune` could lose a concurrent append: the lock was held on the inode that
  `os.replace` swapped out. Locks now live on a file that is never replaced.
- A torn (crash-truncated) audit line is no longer glued to the next entry.
- `delcred serve`: negative `Content-Length` no longer blocks the handler;
  non-object JSON bodies and wrong-typed fields return 400 instead of a
  dropped connection.
- Broker key lookup scans all records (no early exit) for timing uniformity.

### Security (panel review of synapse-1)
- **CRITICAL fixed:** a trusted external IdP could sign its own
  `kind: delegation` or `kind: agent` tokens and bypass policy. Delegation and
  agent tokens must now be signed by the local issuer; external issuers are
  accepted only for an exchange `subject_token`
  (`verify_signature(..., allow_external=True)`).
- **HIGH fixed:** users are keyed on `(issuer, sub)`. Grants take an optional
  `issuer:` (default local); delegation tokens and broker records carry
  `user_iss`; `revoke_user(..., issuer=)` / `revoke --issuer` scope a kill
  switch to one IdP (no issuer = every issuer). External subject tokens must
  carry `aud` matching the configured audience (`trust-add --audience`,
  default `"delcred"`; `trusted_issuers` entries may be `{key, audience}`).
  Agent identity tokens are no longer matched against user kill switches.
- **HIGH fixed:** `serve` and `sidecar` use `ThreadingHTTPServer` with a 10 s
  socket timeout, so a stalled client cannot freeze them; per-IP token-bucket
  rate limit on `/token`, `/exchange`, `/revoke` (`--rate-limit`, HTTP 429).
- **MEDIUM fixed:** the audit chain's first hashed entry is anchored to
  `GENESIS` or to the real digest of the last legacy line; deleting the oldest
  entries and padding with fake legacy lines is now detected.
- **MEDIUM fixed:** a broker key that lacks a required scope raises
  `BrokerScopeError` → 403 `insufficient_scope` (was 401), matching JWTs.
- **MCP:** `authorize()` always emits `resource_metadata` (derived from
  `resource` when not given); `serve` publishes RFC 8414
  `/.well-known/oauth-authorization-server`; `protected_resource_metadata()`
  drops its `jwks_uri` parameter (RFC 9728 reserves it for the resource's own
  keys; unreleased API, no compatibility impact).
- **LOW fixed:** `/revoke` requires an admin bearer token when configured
  (`--admin-token-file` / `$DELCRED_ADMIN_TOKEN`), otherwise loopback clients
  only, with field length caps; `write_private` now writes a fresh
  `O_EXCL` 0600 temp file and renames it (a pre-existing world-readable file
  is never written into); delegation tokens must carry `typ: at+jwt`
  (the docstring claimed this before it was enforced).

### Breaking (security)
- IdP subject tokens without the configured `aud` are rejected — add
  `aud: delcred` at the IdP or set `trust-add --audience`.
- IdP users no longer match grants written for local users with the same id;
  add `issuer:` to those grants.
- `tokens.verify_signature()` accepts only the local issuer unless called with
  `allow_external=True`.

### Repository
- Removed committed `.venv/`, `delcred.egg-info/` and `__pycache__/`; added
  `.gitignore` and the MIT `LICENSE` file the metadata already referenced.

### Compatibility
- All 0.2 public APIs keep working. Audit entries written by 0.2 are reported
  as "legacy" (unchained) by `audit verify`; new entries chain after them.
- Tokens minted by 0.2 (no `kid`) still verify.
- State lock files changed (`*.jsonl.lock`): stop 0.2 processes before running
  0.3 against the same home.
