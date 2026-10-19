"""Policy: deny by default, scope subset, exact resource, TTL clamp."""

import pytest

from delcred._common import MAX_TTL
from delcred.policy import Grant, Policy, PolicyError, load

RES = "https://api.acme.test/v1"


def test_deny_by_default(home):
    pol = load(home)
    with pytest.raises(PolicyError, match="no delegation grant"):
        pol.check("u_alice", "rogue-agent", "invoices:read", RES, 60)


def test_scope_subset_ok(home):
    pol = load(home)
    g = pol.check("u_alice", "billing-agent", "invoices:read", RES, 60)
    assert isinstance(g, Grant)


def test_scope_escalation_denied(home):
    pol = load(home)
    with pytest.raises(PolicyError, match="not granted"):
        pol.check("u_alice", "billing-agent", "invoices:read invoices:write", RES, 60)


def test_unknown_scope_denied(home):
    pol = load(home)
    with pytest.raises(PolicyError, match="not granted"):
        pol.check("u_alice", "billing-agent", "admin:all", RES, 60)


def test_resource_must_match_exactly(home):
    pol = load(home)
    with pytest.raises(PolicyError, match="not granted"):
        pol.check(
            "u_alice",
            "billing-agent",
            "invoices:read",
            "https://api.acme.test/v1/admin",
            60,
        )
    with pytest.raises(PolicyError, match="not granted"):
        pol.check(
            "u_alice", "billing-agent", "invoices:read", "https://api.evil.test/v1", 60
        )


def test_ttl_clamped_to_grant(home):
    pol = load(home)
    g = pol.check("u_bob", "billing-agent", "invoices:read", RES, 900)
    assert pol.effective_ttl(g, 900) == 60  # grant max_ttl wins


def test_ttl_clamped_to_global_max():
    pol = Policy(
        grants=[
            Grant(user="u", agent="a", scopes={"x"}, resources=[RES], max_ttl=99999)
        ]
    )
    g = pol.check("u", "a", "x", RES, 99999)
    assert pol.effective_ttl(g, 99999) == MAX_TTL


def test_nonpositive_ttl_denied(home):
    pol = load(home)
    with pytest.raises(PolicyError, match="positive"):
        pol.check("u_alice", "billing-agent", "invoices:read", RES, 0)


def test_empty_scope_denied(home):
    # Finding #8: scope-less delegations fail closed.
    pol = load(home)
    with pytest.raises(PolicyError, match="must not be empty"):
        pol.check("u_alice", "billing-agent", "", RES, 60)
    with pytest.raises(PolicyError, match="must not be empty"):
        pol.check("u_alice", "billing-agent", "   ", RES, 60)


def test_missing_policy_file_gets_default(tmp_path):
    import delcred

    delcred.init(base=tmp_path)
    p = tmp_path / "policy.yaml"
    p.unlink()
    pol = load(tmp_path)  # recreates default
    assert p.exists()
    assert pol.grant_for("u_example", "example-agent") is not None
