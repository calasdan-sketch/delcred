"""`delcred doctor`: read-only home/policy lint. Exit 0 clean, 1 issues, 2 no home."""

import os

import pytest

from delcred.cli import main


def doctor(home, capsys):
    with pytest.raises(SystemExit) as e:
        main(["--home", str(home), "doctor"])
    return e.value.code, capsys.readouterr().out


def _grant(home, **over):
    g = {"scopes": '["invoices:read"]', "resources": '["https://api.acme.test/v1"]',
         "max_ttl": "900", "single_use": "false"}
    g.update(over)
    (home / "policy.yaml").write_text(
        "grants:\n  - user: u_alice\n    agent: billing-agent\n"
        + "".join(f"    {k}: {v}\n" for k, v in g.items())
    )


def test_clean_home_exits_0(home, capsys):
    os.chmod(home, 0o700)
    code, out = doctor(home, capsys)
    assert code == 0, out


def test_no_home_exits_2(tmp_path, capsys):
    missing = tmp_path / "nope"
    code, _ = doctor(missing, capsys)
    assert code == 2
    assert not missing.exists()  # read-only: never creates the home


def test_home_too_open(home, capsys):
    os.chmod(home, 0o755)
    code, out = doctor(home, capsys)
    assert code == 1 and "0700" in out


def test_private_key_too_open(home, capsys):
    os.chmod(home, 0o700)
    os.chmod(home / "issuer.key", 0o644)
    code, out = doctor(home, capsys)
    assert code == 1 and "issuer.key" in out


def test_policy_unparseable(home, capsys):
    os.chmod(home, 0o700)
    (home / "policy.yaml").write_text("grants: [unclosed\n")
    code, out = doctor(home, capsys)
    assert code == 1 and "policy.yaml" in out


@pytest.mark.parametrize("over, needle", [
    ({"resources": "[]"}, "resources"),
    ({"resources": '["https://api.acme.test/*"]'}, "resource"),
    ({"resources": '["api.acme.test"]'}, "resource"),
    ({"scopes": '["invoices:*"]'}, "scope"),
    ({"max_ttl": "7200"}, "max_ttl"),
    ({"single_use": '"yes"'}, "single_use"),
])
def test_grant_lint(home, capsys, over, needle):
    os.chmod(home, 0o700)
    _grant(home, **over)
    code, out = doctor(home, capsys)
    assert code == 1 and needle in out


def test_trusted_issuer_key_missing(home, capsys):
    os.chmod(home, 0o700)
    with open(home / "policy.yaml", "a") as f:
        f.write('\ntrusted_issuers:\n  "https://idp.example.com": "trusted_issuers/gone.pem"\n')
    code, out = doctor(home, capsys)
    assert code == 1 and "trusted_issuers" in out


def test_audit_log_not_writable(home, capsys):
    os.chmod(home, 0o700)
    p = home / "audit.jsonl"
    if p.exists():
        p.unlink()
    p.mkdir()  # a directory cannot be appended to, even by root
    code, out = doctor(home, capsys)
    assert code == 1 and "audit" in out
