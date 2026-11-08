# Round 5 - cross-language and upgrade review

Branch `expert-2`. **Honest note on method:** I cannot spawn independent sub-agents here.
One author played each specialist in turn, so these are perspectives, not independent
reviewers. Every finding names the command that proved it.

## Baseline (before any change)

| | |
|---|---|
| Tests | 342 passed (109 s) |
| Registry | `pip index versions delcred` -> only 0.2.0 (so 0.4.0 is still unpublished) |
| Benchmark | `bench/results.json` from round 4 (shared machine, noisy) |

## Author line

Already "Calas Automations Inc." in `pyproject.toml` (authors), `LICENSE`, README. No email exists, none added. Re-grep for `calasdan|Dan Calas|DC Enterprises` finds only the real GitHub URLs. New: `delcred.__author__` and `test_author_string_is_pinned_everywhere`. Proof from the built wheel: `unzip -p delcred-0.4.0-py3-none-any.whl '*/METADATA'` shows `Author: Calas Automations Inc.`. The repo's `origin` is a github.com URL; I could not check whether the repo is private, so `PUBLISH-CHECKLIST.md` still tells Dan to delete `[project.urls]` if it is.

## Specialists and findings

| # | Specialist | Finding | Proved by |
|---|---|---|---|
| 1 | Applied cryptographer | Ed25519 signature malleability and non-canonical encodings already covered. New: nothing wrong with key handling; JWKS/`kid` lookup is by exact thumbprint. | read of `keys.py`, `offline.py`; vectors `signature_noncanonical_base64`, `kid_unknown` |
| 2 | OAuth/JWT/IAM engineer | **Upgrade defect:** a token minted by delcred 0.2.0 (no `kid` header) stopped verifying right after `delcred key rotate --keep-old`, even though the old key was kept for verification. | built a 0.2.0 home with `pip download delcred==0.2.0` in a scratch venv, minted a token, ran the new code: `verify` -> "Signature verification failed" after rotate. Fixed (`tokens._signer_among`); test `test_kidless_0_2_token_survives_rotation_with_overlap` fails on the old code, passes now. |
| 2 | OAuth/JWT/IAM engineer | Everything else from a 0.2.0 home still works in 0.4.0: exchange, `dk_` broker keys (stored hash redeems), revoke by agent and jti, kill switch, prune, key rotate. | `/tmp` scratch home, commands as in the table above (no data migration needed) |
| 3 | Security auditor | Old (< 0.3) delcred still running during an upgrade appends unchained audit lines after new chained ones, so `audit verify` says TAMPERED with a cryptic message. Kept fail-closed, message now says why. | mixed old/new commands on one home; `test_legacy_audit_lines_after_chain_explain_themselves` |
| 4 | Spec editor (cross-language vectors) | **Three verifiers disagreed** on JSON edge cases. A seeded differential fuzz (32,000 mutated signed tokens, expectations = Python) found: Go rejected integers >= 2^63 while Python/Node accepted; Node accepted `1800000840.0` as an integer, Python did not; Node treated `"chain": null` as absent, Python/Go rejected; Python accepted `NaN`/`Infinity`; Go and Node silently kept the last of two duplicate members (Python rejected); nesting depth was unbounded in Python. Node also **crashed** (uncaught TypeError) on a non-string header `typ`. | `/tmp/r5-delcred/fz/difffuzz.py` seeds 1-6 against `node verify.mjs` and `go run .`; now 0 disagreements over 32,000 cases. Rules written into `spec/VERIFICATION.md`; 7 new vectors (96); committed 600-case seeded fuzz per language in `tests/test_round5.py`. |
| 5 | QA / test methodology | Property tests (hypothesis): scope parsing idempotent/order-free; no odd whitespace survives; JSON parser never raises an unexpected type; attenuation never widens scope (25 random policies). Mutation-style: break signature check, loosen integer rule, ignore required scopes, loosen the scope regex -> each is caught. Golden output shapes for `status/audit verify/verify/doctor --json`. | `tests/test_round5.py` (28 tests); the `kid` test was run against the pre-fix code and failed as it should |
| 6 | Hostile-input / debug | Spaces and non-ASCII in `--home`, `LC_ALL=C`, 3 MB token argument and via stdin, 6 parallel `revoke` processes (audit chain intact), `--home` that does not exist: all clean, plain-English, no traceback. Cosmetic only: under `LC_ALL=C` a non-ASCII home path is shown as `\udcc3...` escapes. | commands in scratch dir |
| 7 | Release manager | Version stays 0.4.0 (registry still 0.2.0). `MANIFEST.in` now ships `tests/golden/*.json` so the sdist's tests can run. `twine check` PASSED on both files. | `python -m build`, `twine check` |

## Idea list (scored 1-5; effort/risk 5 = high)

| # | Idea | Value | Diff. | Effort | Risk | Status |
|---|---|---|---|---|---|---|
| 1 | 0.2.0 kid-less tokens survive overlap rotation | 4 | 1 | 1 | 1 | DONE |
| 2 | Strict JSON rules identical in 3 languages | 5 | 4 | 3 | 2 | DONE |
| 3 | Differential fuzz Python vs Node vs Go in the test suite | 5 | 4 | 2 | 1 | DONE |
| 4 | Node verifier no longer crashes on odd `typ` | 4 | 1 | 1 | 1 | DONE |
| 5 | Property tests (hypothesis) | 4 | 2 | 2 | 1 | DONE |
| 6 | Mutation-style sanity tests of the vectors | 4 | 3 | 2 | 1 | DONE |
| 7 | Golden CLI `--json` shapes | 3 | 2 | 1 | 1 | DONE |
| 8 | Clear audit message for old-process-after-upgrade | 3 | 1 | 1 | 1 | DONE |
| 9 | Pin author string by test, `__author__` | 3 | 1 | 1 | 1 | DONE |
| 10 | Ship golden JSON in sdist | 2 | 1 | 1 | 1 | DONE |
| 11 | Differential fuzz of DPoP proofs and bulletins across languages | 4 | 4 | 3 | 1 | NOT-DONE (only access-token paths fuzzed) |
| 12 | Lone-surrogate / Unicode-normalisation agreement (`\ud800` in strings; Go replaces with U+FFFD) | 3 | 3 | 3 | 2 | NOT-DONE (needs a spec decision) |
| 13 | A Rust or Java reference verifier | 3 | 4 | 4 | 1 | NOT-DONE |
| 14 | Trusted Publishing (OIDC) release workflow | 4 | 4 | 2 | 3 | NOT-DONE (Dan's account decision) |
| 15 | Fetch IdP keys from a JWKS URL | 4 | 3 | 4 | 4 | NOT-DONE (network trust decision) |
| 16 | Holder-side offline attenuation (Biscuit style) | 3 | 4 | 5 | 4 | NOT-DONE (opposite design bet) |
| 17 | Multi-host revocation sync | 4 | 4 | 5 | 4 | NOT-DONE |
| 18 | `audit repair --accept-legacy-tail` for mixed-version logs | 2 | 2 | 3 | 4 | NOT-DONE (weakens tamper evidence) |
| 19 | Un-revoke an agent | 3 | 2 | 4 | 3 | NOT-DONE (bulletin format change) |
| 20 | Human durations for `--ttl` (`15m`) | 2 | 1 | 1 | 1 | NOT-DONE |
| 21 | `pip-audit` / SBOM in CI | 3 | 2 | 1 | 1 | NOT-DONE (after first release) |
| 22 | Spec: allow kid-less tokens for 0.2.0 interop in third-party verifiers | 2 | 1 | 2 | 3 | NOT-DONE (deliberately no: kid is required offline) |
| 23 | Native Windows run of the test suite | 5 | 1 | 1 | 1 | NOT-DONE (CI job exists, never run) |
| 24 | Man pages / docs site | 2 | 1 | 3 | 1 | NOT-DONE |

## Competitors re-checked (read-only, this round)

* Biscuit (biscuitsec.org, fetched today): "decentralized verification, offline attenuation" confirmed. The README's quote that revocation needs "external state management" was *not* re-found on the repo page today; treat that sub-claim as unverified.
* Descope blog post (fetched today): "credential vault ... short-lived and scoped credentials" confirmed. The per-MCP-server claim phrase was not found by my keyword grep (page text may differ); treat as unverified.
* No competitor features were added or removed from the README.

## Pass B - attacking my own result

* Re-read the diff: `strictScan` (Go) first had a bug where a closing `}` after the last member short-circuited the scan, so duplicates after a nested object were missed. The new vectors caught it (2 Go failures); fixed and the 32k fuzz re-run clean.
* Node `Object.create(null)` objects broke `String(header.typ)`; fixed and covered.
* `is_safe_int` made a `TypeGuard`; `mypy delcred` clean, `ruff check` clean.
* From a **fresh, non-editable wheel install** in a new venv: `delcred --version`, `delcred demo` (24/24), `delcred vectors` output byte-identical to the committed file, `offline-verify --json`, 0.2.0-home upgrade scenario (rotate with overlap, then kill switch) all as documented.
* Behaviour change to note: the offline verifier now rejects whole-valued floats, integers above 2^53-1, `NaN`/`Infinity`, duplicate members and nesting over 32. No real delcred token has any of these.

## Final numbers

| | before | after |
|---|---|---|
| Tests | 342 passed | 370 passed (28 new, `tests/test_round5.py`) |
| Vectors | 89 | 96 |
| Cross-language fuzz disagreements | 16 (seed 1) and 42 (seed 2) per 6,000 | 0 per 32,000 |
| Offline verify (same-process A/B, best of 7 x 0.5 s) | ~1,530/s | ~1,070-1,490/s (within run-to-run noise on this shared machine; the depth walk adds a few microseconds) |
| `bench/results.json` | round 4 | re-run today; this machine was ~2-4x slower and noisy than when round 4 was recorded, so absolute values dropped on every row, including rows I did not touch (e.g. signature-only). Compare ratios only. |

## What I could not test

* **Windows and macOS, at all** (no runner). The CI matrix exists and has never run.
* DPoP and bulletin paths in the cross-language fuzz (idea 11).
* Real PyPI upload (`twine check` only). Nothing was uploaded, tagged or pushed.
* Whether the GitHub repo is private.
* Independent human review.
