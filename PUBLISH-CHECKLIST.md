# Publish checklist for delcred (written for Dan; nothing here has been run)

**Version to release: 0.4.0.** PyPI has only 0.2.0. 0.3.0 was never uploaded, so
0.4.0 contains both 0.3.0 and 0.4.0 work. It is a breaking release compared with
0.2.0 (the CHANGELOG "Breaking (security)" list says what changes), which is
fine for a 0.x version.

## Check first (5 minutes)

1. `git status` is clean and you are on the branch you want to release (this
   work is on `expert-2`; merge it to your main branch first if that is your habit).
2. Open `pyproject.toml`: `version = "0.4.0"`, the author, and the four URLs. The
   URLs point at `github.com/calasdan-sketch/delcred`. **If that repository is
   private or the name is different, delete the `[project.urls]` block**, because
   PyPI will show dead links forever for this version.
3. Push the branch and look at the **ci** run on GitHub. Windows and macOS have
   never been tested; if a Windows job fails, fix that before releasing.
4. Read the top of `CHANGELOG.md` and change `0.4.0 - unreleased` to
   `0.4.0 - <today's date>`.

## Build and look (in a clean folder, nothing is uploaded)

```bash
python -m venv /tmp/rel && /tmp/rel/bin/pip install build twine
/tmp/rel/bin/python -m build
/tmp/rel/bin/twine check dist/*
```
Expect two files: `delcred-0.4.0.tar.gz` and `delcred-0.4.0-py3-none-any.whl`, and `PASSED` twice.

Try the wheel in a second clean environment:
```bash
python -m venv /tmp/try && /tmp/try/bin/pip install dist/delcred-0.4.0-py3-none-any.whl
/tmp/try/bin/delcred --version      # delcred 0.4.0
/tmp/try/bin/delcred demo           # ends with: 24/24 guarantees held.
```

## Upload (costs nothing; cannot be undone, a version number can never be reused)

1. Test first, if you want a dry run: `twine upload --repository testpypi dist/*`
   (needs a separate TestPyPI account and token).
2. Real upload: `twine upload dist/*` with a PyPI API token scoped to the
   `delcred` project only. Never paste the token into a file in the repo.
3. Tag: `git tag v0.4.0 && git push origin v0.4.0`.

## After upload

1. In a clean environment: `pip install delcred` must say 0.4.0, then run
   `delcred --version` and `delcred demo`.
2. The README already says `pip install "delcred>=0.4"`; you may simplify it to
   `pip install delcred` and delete the "until 0.4.0 is published" paragraph.
3. Optional hardening for later: switch to PyPI "Trusted Publishing" so no token
   is needed and releases carry attestations (set up in the PyPI project settings;
   not done here because it is your account decision).
