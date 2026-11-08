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
  `spec/VERIFICATION.md`, 96 deterministic vectors (`delcred vectors`),
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

### Round 5 (expert-2, cross-language and upgrade review)

- **Fixed (upgrade path): tokens minted by delcred 0.2.0 stopped verifying after
  `delcred key rotate --keep-old`.** 0.2.0 tokens carry no `kid`, and the verifier
  only tried the current key. It now finds the signing key among the current and
  still-valid retired keys. A hard-cut rotation still invalidates them; a token
  signed by any other key is still refused.
- **Fixed (verifiers disagreed):** a differential fuzz of 32,000 mutated tokens
  found the Python, Node and Go verifiers disagreeing on JSON edge cases. Now all
  three agree and the spec says so: duplicate members, `NaN`/`Infinity`, nesting
  deeper than 32, whole-valued floats (`1800000840.0`), exponents, integers above
  2^53-1 and `"chain": null` are all `invalid_token`. The Node verifier also
  crashed on a non-string header `typ`; fixed. 7 new vectors (96 total).
- Changed: `delcred audit verify` explains "unhashed entry inside the chain" (an
  older delcred still writing to the same home after an upgrade).
- Added: `delcred.__author__`; `hypothesis` in the `dev` extra; `tests/test_round5.py`
  (property, mutation-style, differential, golden-shape and author-pin tests).
- Author/maintainer everywhere is "Calas Automations Inc." (already the case; now pinned by a test).

### Round 3 (expert-2, second review)

#### Security
- **HIGH fixed: the sidecar could be steered into sending its token anywhere.**
  An absolute-form request line (`GET http://attacker/x`) together with an
  allowlisted `X-Delcred-Upstream` made the sidecar send the bearer token to the
  attacker's host; `file://` and `ftp://` URLs were opened by `urllib`; redirects
  were followed with the token attached; `GET @host/x` could smuggle a host via
  userinfo. The upstream is now fixed by the allowlist, schemes are limited to
  https (http for loopback), redirects are not followed, the caller's
  `Authorization` is dropped, Content-Length is validated and bodies are capped.
  Upstream 4xx/5xx now pass through (they were all turned into 502).
- **HIGH fixed: `delcred serve` was reachable by web pages.** `/revoke` trusted
  "loopback client", so any page in the user's browser could POST a kill switch;
  Host headers were unchecked (DNS rebinding). Loopback-bound servers now require
  a loopback `Host` (421) and refuse browser cross-site POSTs (`Origin`,
  `Sec-Fetch-Site`).
- **MEDIUM fixed: rejected credentials left no audit trail** (the docs said they
  did). `verify_rejected` entries (rate-limited, token never stored, identity
  hints labelled `claimed_*`).
- **MEDIUM fixed: child token could outlive its parent by 1 s** when the clock
  ticked between two reads (found by the benchmark fuzz on a slow disk).
  `mint_delegation_token(exp_cap=)`.
- Revocation reasons, policy errors and other untrusted strings are escaped
  (`_common.safe_text`) before reaching a terminal; reasons are sanitised at rest.

#### Added
- `verify(check_policy=True)`, `delcred verify --check-policy`,
  `mcp.authorize(check_policy=True)`: refuse tokens whose grant was removed or
  narrowed after minting.
- `delcred audit checkpoint` / `audit verify --checkpoint-file` and
  `AuditLog.checkpoint()` / `verify(checkpoint=)`: signed "N entries, head H"
  statements that detect truncation and wholesale rewrites.
- RFC 7009 holder-side revocation: `POST /oauth/revoke` (advertised as
  `revocation_endpoint`), `delcred.revoke_presented()`, `delcred revoke --token-file`.
- `delcred policy validate [--strict]`.
- `DELCRED_AUDIT_FSYNC=routine-off` (routine `verify_*` lines skip fsync only).
- Demo step 10b (24 checks); benchmark rows for check_policy, rejected
  credentials, audit tail/verify at 100k entries; the benchmark now retries
  Biscuit's occasional wall-clock authorizer limit.

#### Changed / fixed
- `policy.yaml` is parsed strictly: wrong types (a bare string for a list,
  `max_ttl: 0` or non-integer, a non-boolean `single_use`, a scope containing a
  space, grants that are not mappings) raise `PolicyError` and deny exchanges;
  before, `scopes: "a b"` silently became a set of characters and some shapes
  crashed with `AttributeError`. **Behaviour change:** policies that relied on
  those readings now fail loudly. The CLI prints `policy error:` instead of a traceback.
- `audit` tail, filters and verification stream the file (100,000 entries:
  tail 3.8 s and 370 MB -> 1 ms and 34 MB; `verify` no longer holds the lock).
- `delcred init` (and `--home NEWDIR init`) creates a missing home directory
  (it crashed with FileNotFoundError).
- DPoP `ath` over a non-ASCII token raises `PopError`, not `UnicodeEncodeError`.
- Two wall-clock assertions in the test suite (`fsync` speed) are now
  deterministic or looser; they failed on slow disks.
- README: the quick start no longer says `pip install delcred` (PyPI still has
  only the old 0.2.0, checked with `pip index`); sample demo output, the
  chained-delegation row of the comparison and the benchmark table were stale.

### Round 4 (what a stranger gets from `pip install`)

Registry check: PyPI has only 0.2.0 (same author). 0.3.0 was never uploaded, so the
next upload is **0.4.0**, which contains everything listed under 0.3.0 and 0.4.0
and is breaking relative to 0.2.0 (see the "Breaking (security)" list below).

#### Added
- `delcred --version`; `delcred` with no command prints the help (exit 2).
- `delcred doctor [--json]`: read-only health check of home, key, policy and audit log.
- `--json` on `status`, `policy check`, `policy validate`, `audit verify`,
  `offline-verify`, and on the failure paths of `verify`: one JSON object on stdout.
- `verify -`, `offline-verify -`, `inspect -` read the token from stdin (keeps it out of `ps`).
- Token files written by Windows tools (UTF-8 BOM, UTF-16 from PowerShell 5, CRLF) are read correctly.
- Documented exit codes (README "Scripting"), `DELCRED_DEBUG=1` for tracebacks.
- `py.typed` (mypy is clean on `delcred/`), `MANIFEST.in` (sdist now carries CHANGELOG, spec, examples, bench),
  SPDX `license = "MIT"`, Python 3.10-3.13 / OS / typing classifiers, project URLs, `.github/workflows/ci.yml`
  (tests on Linux, Windows, macOS; build + `twine check`; never publishes).

#### Fixed
- Every user mistake that used to print a traceback now prints one plain sentence: no home yet
  (`status`, `audit`, `revoke`, `policy`, `jwks`, `agent-token`...), unreadable or non-UTF-8 files,
  `inspect`/`verify` on garbage, `--port 99999`, damaged or world-readable issuer key, read-only
  file system, `init` twice, hostile ids. Unexpected exceptions exit 70 with a one-line bug notice.
- `delcred ... | head` no longer ends in `BrokenPipeError`.
- Windows (static fixes, **not run on Windows**): every text read/write is UTF-8 (cp1252 would corrupt or
  reject non-ASCII policy/trust files); key files are opened `O_BINARY` (no `\r\n` injected into PEM);
  `os.replace` retries on sharing violations; console output uses `backslashreplace` instead of raising
  `UnicodeEncodeError`.
- Token/JWKS/bulletin/checkpoint files larger than 1 MiB are refused instead of read into memory.
- 21 mypy errors (none were runtime bugs).
- Test suite passes on the declared minimum dependencies (PyJWT 2.8, cryptography 41, PyYAML 6.0.1);
  the one test that uses PyJWT's `PyJWK` with an Ed25519 JWK is skipped on PyJWT < 2.9 (a PyJWT limitation).

### Compatibility
- All 0.3 APIs and tokens keep working. A delegation token used as
  `subject_token` previously always failed; it now works only for agents the
  grant lists in `delegate_to`, otherwise it still fails.
- `key rotate` without flags is still a hard cut.

## 0.3.0 — never published (folded into 0.4.0)

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
