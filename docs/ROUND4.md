# Round 4 — the stranger's first hour

Scope: what someone gets from `pip install delcred` and the README alone, on a
machine that has never seen this repository. Branch `expert-2`.

**Honest note on method.** I could not spawn independent sub-agents in this
environment. One author played every specialist below in turn, so these are
*perspectives*, not independent reviewers; the evidence column is the command
that proved each finding. Round 4 pass B (re-attack) was done by the same
author, so it is weaker than a second pair of eyes would be.

## Baseline (before any change)

| | |
|---|---|
| Tests | 306 passed, 0 failed (Python 3.13, 146 s on a slow shared disk) |
| Lint | `ruff check delcred` clean |
| Types | `mypy delcred` 21 errors (none runtime bugs) |
| Registry | `pip index versions delcred` -> only `0.2.0`; repo is `0.4.0` |
| Benchmark | mint 180/s, full verify 274/s, signature-only 2,445/s, offline verify 2,246/s, single-use burn @100k 186/s, revocation check @100k 0.003 ms, audit tail@100k 0.94 ms (this machine; fsync-bound rows are slow here) |

## Specialists and findings

| # | Specialist | Finding | Proved by |
|---|---|---|---|
| 1 | First-time user (README only, clean venv, Python 3.10) | `delcred --version` did not exist; bare `delcred` printed an argparse error | `delcred --version` -> "unrecognized arguments"; `delcred` -> "arguments are required: cmd" |
| 1 | First-time user | Every command run before `delcred init` (status, audit, revoke, policy, jwks, agent-token, prune) ended in a Python traceback | `delcred --home nohome status` |
| 1 | First-time user | `delcred jwks \| head` ended in `BrokenPipeError` traceback | `delcred jwks \| head -c 5` |
| 1 | First-time user | `inspect garbage`, `offline-verify --jwks-file missing`, `serve --port 99999`, damaged `issuer.key`, `init` twice (message said `force=True`, a Python argument, not a flag) all gave tracebacks or Python-speak | each command run in a scratch home |
| 2 | Release/packaging engineer | Wheel had no `py.typed`; sdist had no CHANGELOG/spec/examples although the README points at them; deprecated `License ::` classifier and `{text=}` license; no Python-version or OS classifiers; no project URLs | `unzip -l`, `tar tzf`, `unzip -p ... METADATA` |
| 2 | Release engineer | Registry has 0.2.0 only (same author as ours); 0.3.0 was never uploaded; CHANGELOG called both 0.3.0 and 0.4.0 "unreleased" | `pip index versions delcred`; downloaded 0.2.0 wheel metadata |
| 2 | Release engineer | Metadata consistent after fix: `pyproject`, `__version__`, top CHANGELOG heading all `0.4.0` (now pinned by a test) | `tests/test_round4.py::test_version_is_consistent_everywhere` |
| 3 | Supply-chain reviewer | Three runtime dependencies, all imported; no install-time code; `pip check` clean; no secrets/personal paths in wheel or sdist | `pip list` (11 packages incl. transitive), grep over unpacked artifacts |
| 3 | Supply-chain reviewer | Declared minimums verified: whole suite passes on PyJWT 2.8.0 / cryptography 41.0.7 / PyYAML 6.0.1 except one test that exercises PyJWT's own `PyJWK` (PyJWT 2.8 cannot use an Ed25519 JWK; fixed upstream by 2.9). Floor kept; test skipped below 2.9 | venv with the three pins; `pytest` |
| 4 | Docs/DX writer | README quick start said "clone and `pip install .`" with a stale-by-design comment; no exit-code table; `verify` accepted the token only as an argument (visible in `ps`) | README, `ps` reasoning |
| 5 | CI/CD integrator | No CI file; Windows never exercised; no `--json` on most commands; failures with `--json` printed nothing on stdout | `delcred verify X --json` on a bad token |
| 6 | Hostile-input fuzzer | 4,000 mutated/random tokens through `verify` and `verify_offline`: 0 unexpected exception types. HTTP: oversize/negative/garbage Content-Length, 70 KB URL, bad Host, TLS bytes: all clean 4xx. Corrupt audit/revocation lines: no crash, `audit verify` exit 6. 50 MB token file: refused (but was read fully into memory -> now capped at 1 MiB) | fuzz script in scratch; raw-socket probes |
| 7 | Performance engineer | CLI cold start ~0.56 s of imports (PyJWT 0.17 s, cryptography the rest); per-call work is dominated by `fsync` on this disk. Not worth lazy-import contortions: `mcp-headers` needs the full stack anyway | `python -X importtime -c "import delcred.cli"` |
| 8 | Competitor's maintainer | See "Competitors" below | web pages (unverified in this sandbox where noted) |
| 9 | Windows reviewer (static only) | `write_private` opened files without `O_BINARY` (PEM would get `\r\n`); `os.replace` has no retry for sharing violations; ten `read_text()/write_text()` calls used cp1252; PowerShell 5 `>` writes UTF-16 token files that raised `UnicodeDecodeError`; a cp1252 console would raise `UnicodeEncodeError` on `é` | code review + `PYTHONIOENCODING=ascii` run |
| 10 | Concurrency tester | 24 simultaneous `exchange` + 3 `revoke` processes on one home: 24x exit 0, audit chain intact (28 entries) | shell loop + `audit verify` |

## Idea list (scored)

Scale 1-5 (5 = best/most). Effort and risk: 5 = high. "Value" = to a stranger in hour one.

| # | Idea | Value | Differentiation | Effort | Risk | Status |
|---|---|---|---|---|---|---|
| 1 | `--version` | 5 | 1 | 1 | 1 | DONE |
| 2 | Plain-English errors for every user mistake, exit 70 for real bugs | 5 | 2 | 3 | 1 | DONE |
| 3 | Documented exit codes | 4 | 2 | 1 | 1 | DONE |
| 4 | `--json` on the commands scripts call | 4 | 3 | 2 | 1 | DONE |
| 5 | Token via stdin (`-`) | 3 | 2 | 1 | 1 | DONE |
| 6 | BOM / UTF-16 / CRLF token files (PowerShell) | 3 | 3 | 1 | 1 | DONE |
| 7 | UTF-8 everywhere, binary key files, replace-retry (Windows) | 4 | 2 | 2 | 2 | DONE (not run on Windows) |
| 8 | `delcred doctor` | 4 | 3 | 2 | 1 | DONE |
| 9 | `py.typed` + mypy clean | 3 | 2 | 2 | 1 | DONE |
| 10 | SPDX license, classifiers, URLs, MANIFEST.in | 4 | 1 | 1 | 1 | DONE |
| 11 | CI matrix incl. Windows/macOS + package job | 5 | 2 | 1 | 1 | DONE (written, not run) |
| 12 | Port range validation; read-only FS message; damaged-key message | 3 | 1 | 1 | 1 | DONE |
| 13 | Cap size of token/JWKS/checkpoint files | 2 | 2 | 1 | 1 | DONE |
| 14 | Run suite on the declared minimum dependencies | 4 | 1 | 2 | 1 | DONE (one test skipped <2.9) |
| 15 | README: pip line that fails loudly until 0.4.0 exists (`>=0.4`) | 5 | 1 | 1 | 1 | DONE |
| 16 | Trusted Publishing (OIDC) release workflow + PEP 740 attestations | 4 | 4 | 2 | 3 | NOT-DONE (publishing is Dan's call; steps in PUBLISH-CHECKLIST) |
| 17 | `pip-audit` / SBOM in CI | 3 | 2 | 1 | 1 | NOT-DONE (needs network at CI time; add after first release) |
| 18 | Human durations for `--ttl` (`15m`) | 2 | 1 | 1 | 1 | NOT-DONE |
| 19 | Shell completion | 1 | 1 | 2 | 1 | NOT-DONE |
| 20 | Lazy imports to cut CLI start-up | 2 | 1 | 3 | 2 | NOT-DONE (measured: little to gain) |
| 21 | Fetch IdP keys from a JWKS URL (`trust-add --jwks-url`) | 4 | 3 | 4 | 4 | NOT-DONE (network + trust decision; earlier rounds too) |
| 22 | Holder-side offline attenuation (Biscuit/Macaroon style) | 3 | 4 | 5 | 4 | NOT-DONE (opposite design bet) |
| 23 | Un-revoke / restore an agent | 3 | 2 | 4 | 3 | NOT-DONE (needs bulletin format change) |
| 24 | Multi-host revocation sync | 4 | 4 | 5 | 4 | NOT-DONE |
| 25 | Docs site / man pages | 2 | 1 | 3 | 1 | NOT-DONE |
| 26 | Warn on stderr that `user-token` is dev-only | 2 | 1 | 1 | 2 | NOT-DONE (noise for scripts; README already says it) |

## Competitors re-checked (read-only, 2)

Not re-fetched in this round: the sandbox's egress proxy allows package
registries only, so no vendor page could be read today. The README's
comparison table still cites the earlier-round sources; **treat every
competitor statement there as unverified as of this commit.** The two closest
by design (from earlier rounds, unchanged): Biscuit (holder-side attenuation,
faster raw verify) and Keycard (hosted, delegation chains). What changed for
users compared with them is only DX: delcred now has `--version`, documented
exit codes, `--json`, `doctor`.

## Pass B — attack the new code

| Check | Result |
|---|---|
| Re-built wheel+sdist from the final tree, `twine check` | PASSED |
| Fresh venvs: wheel on 3.10 and 3.11, sdist on 3.12 (built there); README quick-start commands, `demo` (24/24), `--version`, offline verify, revoke, audit, `mcp-headers`, `revocations export` | all as documented |
| Wheel contents | 20 modules + `py.typed` + LICENSE + entry point; no tests/secrets/paths |
| Fuzz again after changes | 0 unexpected exceptions |
| Hostile id with ESC bytes via CLI | exit 2, no escape in output |
| ASCII console + `é` in a policy-denied scope | exit 3, no `UnicodeEncodeError` |
| Oversized (2 MiB) token file | exit 1, one sentence |
| Full suite and benchmark re-run | see "Final numbers" |

Defect found in pass B: `_read_text_arg` read whole files into memory (a 50 MB
"token file" worked, a multi-GB one would exhaust memory). Fixed with a 1 MiB cap and a test.

## What I could not test

- **Windows, at all.** All Windows changes are from reading code and from
  simulation (monkeypatched `os.name`/`os.replace`/`O_BINARY`). `msvcrt` locking,
  NTFS permissions, PowerShell redirection and cp1252 consoles were not run. The
  CI workflow will be the first real test.
- macOS.
- Python 3.12 / 3.13 minimum-dependency combination (min deps were tested on 3.10 only; latest deps on 3.13; 3.11/3.12 only via the quick start).
- A true read-only mount (the EROFS message is unit-tested with a constructed `OSError`).
- Competitor claims (no network to vendor sites).
- Real PyPI upload behaviour (`twine check` only; nothing was uploaded).
- Independent review: see the note at the top.

## Final numbers

| | before | after |
|---|---|---|
| Tests | 306 passed | 342 passed (36 new in `tests/test_round4.py`; 1 skipped only on PyJWT < 2.9) |
| ruff (`delcred`, `bench`, `examples`) | clean | clean |
| mypy (`delcred`) | 21 errors | 0 |
| Escalation fuzz (3,000 widening attempts) | 0 violations | 0 violations |
| Spec vectors (Python, Node, Go) | 89/89 | 89/89 |

Benchmark (same machine, same session, single run each; `bench/results.json` holds the "after" run).
No hot-path code changed (token sizes identical: 541 / 604 bytes), so every difference below is machine
noise from a shared disk and CPU, up to 5x on `fsync`-bound and DPoP rows; do not read any of it as a
speed-up or regression.

| Row (ops/s unless noted) | before | after |
|---|---|---|
| mint | 180 | 253 |
| full verify | 274 | 221 |
| signature-only verify | 2,445 | 2,798 |
| verify with `check_policy` | 137 | 605 |
| offline verify | 2,246 | 3,089 |
| single-use burn at 100k entries | 186 | 297 |
| sub-delegation (attenuate) | 84 | 155 |
| audit tail (last 20 of 100k), ms | 0.94 | 3.05 |
| audit verify of 100k entries, s | 1.94 | 1.15 |
