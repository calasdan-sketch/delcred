"""Shared fixtures: isolated delcred home per test."""

import sys

import pytest

if sys.platform == "win32":
    # delcred is Linux/macOS only (fcntl locks, POSIX perms) — see README.
    collect_ignore_glob = ["test_*.py"]
else:
    import delcred


@pytest.fixture
def home(tmp_path):
    """Fresh delcred home with issuer keypair + a test policy."""
    delcred.init(base=tmp_path)
    (tmp_path / "policy.yaml").write_text(
        """agents:
  billing-agent: {}
  rogue-agent: {}
users:
  u_alice: {}
  u_bob: {}
grants:
  - user: u_alice
    agent: billing-agent
    scopes: ["invoices:read", "customers:read"]
    resources: ["https://api.acme.test/v1"]
    max_ttl: 900
    single_use: false
  - user: u_bob
    agent: billing-agent
    scopes: ["invoices:read"]
    resources: ["https://api.acme.test/v1"]
    max_ttl: 60
    single_use: true
"""
    )
    return tmp_path


@pytest.fixture
def actor(home):
    return delcred.agent_token("billing-agent", base=home)


@pytest.fixture
def rogue_actor(home):
    return delcred.agent_token("rogue-agent", base=home)


@pytest.fixture
def subject(home):
    return delcred.user_token("u_alice", base=home)


@pytest.fixture
def bob_subject(home):
    return delcred.user_token("u_bob", base=home)
