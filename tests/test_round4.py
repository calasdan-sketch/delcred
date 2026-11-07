"""Round 4: what a stranger gets from `pip install delcred` (CLI behaviour, packaging, Windows-safety)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import types
from pathlib import Path

import pytest

import delcred
from delcred import _common

ROOT = Path(__file__).resolve().parent.parent
RES = "https://api.acme.test/v1"


def cli(*argv, home=None, input=None, env=None, raw=False):
    """Run the real CLI in a subprocess (what a user types)."""
    cmd = [sys.executable, "-m", "delcred.cli"]
    if home is not None:
        cmd += ["--home", str(home)]
    e = dict(os.environ)
    e["PYTHONPATH"] = str(ROOT) + os.pathsep + e.get("PYTHONPATH", "")
    e.pop("DELCRED_DEBUG", None)
    e.update(env or {})
    p = subprocess.run(
        [*cmd, *argv], input=input, capture_output=True, env=e, timeout=60, check=False,
    )
    if raw:
        return p
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def no_traceback(err: str) -> None:
    assert "Traceback" not in err, err


@pytest.fixture
def toks(home, tmp_path):
    a = delcred.agent_token("billing-agent", base=home)
    u = delcred.user_token("u_alice", base=home)
    (tmp_path / "a.jwt").write_text(a)
    (tmp_path / "u.jwt").write_text(u)
    return tmp_path / "u.jwt", tmp_path / "a.jwt"


# --- version / help --------------------------------------------------------

def test_version_flag_matches_package():
    rc, out, _ = cli("--version")
    assert rc == 0 and out.strip() == f"delcred {delcred.__version__}"


def test_no_command_prints_help_and_exits_2():
    rc, _, err = cli()
    assert rc == 2 and "usage: delcred" in err and "init" in err
    no_traceback(err)


def test_version_is_consistent_everywhere():
    py = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    pyver = re.search(r'^version = "([^"]+)"', py, re.MULTILINE).group(1)
    assert pyver == delcred.__version__
    top = re.search(r"^## (\d+\.\d+\.\d+)", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), re.MULTILINE).group(1)
    assert top == pyver


def test_packaging_metadata_is_sane():
    py = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert (ROOT / "delcred" / "py.typed").exists() and "Typing :: Typed" in py
    assert 'license = "MIT"' in py and "License ::" not in py   # SPDX expression, no deprecated classifier
    assert (ROOT / "LICENSE").exists() and "requires-python" in py
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    for need in ("CHANGELOG.md", "spec", "examples"):
        assert need in manifest


def test_no_text_io_without_explicit_encoding():
    """Windows' default codec is cp1252: every text read/write must say utf-8."""
    bad = []
    for f in (ROOT / "delcred").glob("*.py"):
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"\.read_text\(\s*\)", line) or (
                re.search(r"\.write_text\(", line) and "encoding" not in line
            ):
                bad.append(f"{f.name}:{n}")
    assert not bad, bad


# --- user errors never show a traceback -------------------------------------

@pytest.mark.parametrize("argv", [
    ["status"], ["audit"], ["audit", "verify"], ["revoke", "--agent", "a"], ["policy", "validate"],
    ["jwks"], ["agent-token", "a"], ["prune"], ["revocations", "export"],
])
def test_uninitialised_home_is_a_plain_error(tmp_path, argv):
    rc, _, err = cli(*argv, home=tmp_path / "nothing-here")
    assert rc == 1, (rc, err)
    assert "delcred init" in err
    no_traceback(err)
    assert not (tmp_path / "nothing-here").exists() or argv[0] in ("revoke", "audit", "prune")


def test_inspect_garbage_is_exit_4(home):
    rc, _, err = cli("inspect", "garbage", home=home)
    assert rc == 4 and "INVALID" in err
    no_traceback(err)


def test_unreadable_files_are_plain_errors(home, tmp_path):
    rc, _, err = cli("offline-verify", "x", "--jwks-file", str(tmp_path / "missing.json"),
                     "--resource", RES, home=home)
    assert rc == 1 and "missing.json" in err
    no_traceback(err)
    (tmp_path / "bad.json").write_text("{not json")
    rc, _, err = cli("offline-verify", "x", "--jwks-file", str(tmp_path / "bad.json"),
                     "--resource", RES, home=home)
    assert rc == 1 and "not valid JSON" in err
    no_traceback(err)


def test_port_out_of_range_is_a_usage_error(home):
    rc, _, err = cli("serve", "--port", "99999", home=home)
    assert rc == 2 and "port must be between" in err
    no_traceback(err)


def test_damaged_issuer_key_is_explained(home):
    (home / "issuer.key").write_bytes(b"not a pem")
    os.chmod(home / "issuer.key", 0o600)
    rc, _, err = cli("agent-token", "a", home=home)
    assert rc == 1 and "damaged" in err and "init --force" in err
    no_traceback(err)


def test_world_readable_key_is_refused_plainly(home):
    if os.name == "nt":
        pytest.skip("POSIX modes only")
    os.chmod(home / "issuer.key", 0o644)
    rc, _, err = cli("agent-token", "a", home=home)
    assert rc == 1 and "too open" in err
    no_traceback(err)


def test_hostile_id_is_exit_2_not_traceback(home):
    rc, _, err = cli("agent-token", "bad\x1b[31mid", home=home)
    assert rc == 2 and "forbidden character" in err and "\x1b" not in err
    no_traceback(err)


def test_non_utf8_policy_is_a_policy_error(home):
    (home / "policy.yaml").write_bytes(b"\xff\xfe\x00 nope")
    rc, _, err = cli("policy", "validate", home=home)
    assert rc == 3
    no_traceback(err)


def test_broken_pipe_is_silent(home):
    p = subprocess.Popen(
        [sys.executable, "-m", "delcred.cli", "--home", str(home), "audit", "--tail", "1"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )
    p.stdout.close()   # reader goes away immediately, like `| head -0`
    err = p.stderr.read().decode()
    p.wait(timeout=30)
    no_traceback(err)


def test_ascii_console_does_not_crash_on_unicode(home):
    rc, _, err = cli(
        "policy", "check", "--user", "u_alice", "--agent", "billing-agent",
        "--scope", "café", "--resource", RES, home=home,
        env={"PYTHONIOENCODING": "ascii", "PYTHONUTF8": "0", "LC_ALL": "C"},
    )
    assert rc in (2, 3), err
    no_traceback(err)
    assert "UnicodeEncodeError" not in err


# --- tokens on Windows-style files / stdin -------------------------------------

@pytest.mark.parametrize("enc", ["crlf", "bom", "utf16"])
def test_token_files_written_by_windows_tools(home, toks, tmp_path, enc):
    subject, actor = toks
    t = actor.read_text().strip()
    raw = {
        "crlf": (t + "\r\n").encode(),
        "bom": b"\xef\xbb\xbf" + t.encode() + b"\r\n",
        "utf16": b"\xff\xfe" + (t + "\r\n").encode("utf-16-le"),
    }[enc]
    f = tmp_path / f"actor-{enc}.jwt"
    f.write_bytes(raw)
    rc, out, err = cli("exchange", "--subject-token-file", str(subject), "--actor-token-file", str(f),
                       "--scope", "invoices:read", "--resource", RES, home=home)
    assert rc == 0, err
    assert out.strip().count(".") == 2          # the token alone on stdout
    assert err.startswith("# sub=u_alice")      # the summary on stderr


def test_binary_garbage_token_file_is_plain(home, toks, tmp_path):
    subject, _ = toks
    f = tmp_path / "junk"
    f.write_bytes(b"\xc3\x28\xff\xfe\xfa")
    rc, _, err = cli("exchange", "--subject-token-file", str(subject), "--actor-token-file", str(f),
                     "--scope", "invoices:read", "--resource", RES, home=home)
    assert rc != 0
    no_traceback(err)


def test_verify_reads_token_from_stdin(home, toks):
    subject, actor = toks
    rc, tok, err = cli("exchange", "--subject-token-file", str(subject), "--actor-token-file", str(actor),
                       "--scope", "invoices:read", "--resource", RES, home=home)
    assert rc == 0
    rc, out, err = cli("verify", "-", "--resource", RES, "--require-scope", "invoices:read",
                       home=home, input=tok.encode())
    assert rc == 0 and out.startswith("VALID"), err
    rc, out, err = cli("verify", "-", "--resource", RES, home=home, input=b"")
    assert rc == 1 and "no token on standard input" in err


# --- --json contract: one JSON document on stdout, exit code still meaningful -----

def test_json_outputs(home, toks, tmp_path):
    subject, actor = toks
    rc, out, _ = cli("status", "--json", home=home)
    assert rc == 0 and json.loads(out)["issuer_key_present"] is True
    rc, out, _ = cli("policy", "validate", "--json", home=home)
    assert rc == 0 and json.loads(out) == {"ok": True, "errors": [], "warnings": json.loads(out)["warnings"]}
    rc, out, _ = cli("policy", "check", "--user", "u_alice", "--agent", "billing-agent", "--scope",
                     "invoices:read", "--resource", RES, "--json", home=home)
    assert rc == 0 and json.loads(out)["allowed"] is True
    rc, out, err = cli("policy", "check", "--user", "u_alice", "--agent", "billing-agent", "--scope",
                       "admin:all", "--resource", RES, "--json", home=home)
    assert rc == 3 and json.loads(out)["allowed"] is False and "DENIED" in err
    rc, out, _ = cli("audit", "verify", "--json", home=home)
    assert rc == 0 and json.loads(out)["ok"] is True
    rc, tok, _ = cli("exchange", "--subject-token-file", str(subject), "--actor-token-file", str(actor),
                     "--scope", "invoices:read", "--resource", RES, home=home)
    rc, out, _ = cli("verify", tok.strip(), "--resource", RES, "--require-scope", "invoices:write",
                     "--json", home=home)
    assert rc == 5 and json.loads(out) == {"valid": False, "code": "insufficient_scope", "missing": ["invoices:write"]}
    rc, jwks, _ = cli("jwks", home=home)
    (tmp_path / "jwks.json").write_text(jwks)
    rc, out, _ = cli("offline-verify", tok.strip(), "--jwks-file", str(tmp_path / "jwks.json"),
                     "--resource", RES, "--json", home=home)
    assert rc == 0 and json.loads(out)["valid"] is True
    rc, out, _ = cli("offline-verify", tok.strip(), "--jwks-file", str(tmp_path / "jwks.json"),
                     "--resource", "https://other.test", "--json", home=home)
    assert rc == 4 and json.loads(out)["valid"] is False


# --- Windows-safety helpers (simulated: NOT run on Windows) ---------------------------

def test_replace_file_retries_sharing_violation_only_on_windows(monkeypatch, tmp_path):
    calls = {"n": 0}

    def flaky(src, dst):
        calls["n"] += 1
        if calls["n"] < 3:
            raise PermissionError("sharing violation")
        Path(dst).write_text(Path(src).read_text())
        os.unlink(src)

    fake = types.SimpleNamespace(name="nt", replace=flaky)
    monkeypatch.setattr(_common, "os", fake)
    monkeypatch.setattr("time.sleep", lambda s: None)
    src, dst = tmp_path / "s", tmp_path / "d"
    src.write_text("x")
    _common.replace_file(src, dst)
    assert calls["n"] == 3 and dst.read_text() == "x"
    # POSIX: a PermissionError is real and must surface immediately
    calls["n"] = 0
    src.write_text("y")
    monkeypatch.setattr(_common, "os", types.SimpleNamespace(name="posix", replace=flaky))
    with pytest.raises(PermissionError):
        _common.replace_file(src, dst)
    assert calls["n"] == 1


def test_write_private_requests_binary_mode(monkeypatch, tmp_path):
    """On Windows os.open without O_BINARY would write \\r\\n into PEM files."""
    seen = {}
    real_open = os.open

    def spy(path, flags, mode=0o777):
        seen["flags"] = flags
        return real_open(path, flags & ~0x8000, mode)

    monkeypatch.setattr(os, "O_BINARY", 0x8000, raising=False)
    monkeypatch.setattr(os, "open", spy)
    _common.write_private(tmp_path / "k", b"a\nb\n")
    assert seen["flags"] & 0x8000
    assert (tmp_path / "k").read_bytes() == b"a\nb\n"


def test_readonly_filesystem_message(monkeypatch, capsys):
    import errno

    from delcred import cli as clim

    e = OSError(errno.EROFS, "Read-only file system", "/x/audit.jsonl")
    msg = clim._explain_oserror(e, types.SimpleNamespace(home=None))
    assert "read-only" in msg and "--home" in msg


def test_init_twice_explains_force_flag(home):
    rc, _, err = cli("init", home=home)
    assert rc == 1 and "--force" in err and "already initialised" in err
    no_traceback(err)


def test_doctor_reports_health_and_problems(home, tmp_path):
    rc, out, err = cli("doctor", home=home)
    assert rc == 0 and "[  ok] issuer key" in out and "[  ok] audit log" in out, out
    rc, out, err = cli("doctor", "--json", home=home)
    assert rc == 0 and json.loads(out)["ok"] is True
    rc, out, err = cli("doctor", home=tmp_path / "absent")
    assert rc == 1 and "FAIL" in out and "delcred init" in out
    assert not (tmp_path / "absent").exists()      # read-only: creates nothing
    no_traceback(err)
    (home / "issuer.key").write_bytes(b"junk")
    os.chmod(home / "issuer.key", 0o600)
    rc, out, err = cli("doctor", home=home)
    assert rc == 1 and "[FAIL] issuer key" in out
    no_traceback(err)


def test_oversized_token_file_is_refused_without_reading_it_all(home, toks, tmp_path):
    subject, _ = toks
    big = tmp_path / "big.txt"
    big.write_bytes(b"A" * (2 * 1024 * 1024))
    rc, _, err = cli("exchange", "--subject-token-file", str(subject), "--actor-token-file", str(big),
                     "--scope", "invoices:read", "--resource", RES, home=home)
    assert rc == 1 and "larger than" in err
    no_traceback(err)


def test_doctor_never_creates_the_default_home(tmp_path):
    target = tmp_path / "not-created"
    p = subprocess.run(
        [sys.executable, "-m", "delcred.cli", "doctor"], capture_output=True, check=False, timeout=60,
        env={**os.environ, "PYTHONPATH": str(ROOT), "DELCRED_HOME": str(target)},
    )
    assert p.returncode == 1 and b"delcred init" in p.stdout
    assert not target.exists()
