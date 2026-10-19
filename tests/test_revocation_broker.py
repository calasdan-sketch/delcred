"""Revocation list + broker (opaque key) tests."""

import hashlib
import time

import pytest

import delcred
from delcred.broker import Broker, BrokerError
from delcred.revocation import RevocationList

RES = "https://api.acme.test/v1"


def _claims(jti="j1", user="u_alice", agent="billing-agent"):
    return {
        "jti": jti,
        "sub": user,
        "act": {"sub": agent},
        "exp": int(time.time()) + 600,
    }


def test_revoke_jti(home):
    rl = RevocationList(home)
    assert rl.is_revoked(_claims())[0] is False
    rl.revoke_jti("j1", reason="leak")
    revoked, why = rl.is_revoked(_claims())
    assert revoked and "leak" in why


def test_agent_kill_switch(home):
    rl = RevocationList(home)
    rl.revoke_agent("billing-agent", reason="compromised")
    revoked, why = rl.is_revoked(_claims(agent="billing-agent"))
    assert revoked and "compromised" in why
    # other agents unaffected
    assert rl.is_revoked(_claims(agent="other-agent"))[0] is False


def test_user_kill_switch(home):
    rl = RevocationList(home)
    rl.revoke_user("u_alice")
    assert rl.is_revoked(_claims(user="u_alice"))[0] is True
    assert rl.is_revoked(_claims(user="u_bob"))[0] is False


def test_expired_jti_entries_ignored(home):
    rl = RevocationList(home)
    rl.revoke_jti("j1", expires_at=int(time.time()) - 10)
    assert rl.is_revoked(_claims())[0] is False


def test_prune_removes_expired(home):
    rl = RevocationList(home)
    rl.revoke_jti("j1", expires_at=int(time.time()) - 10)
    rl.revoke_jti("j2", expires_at=int(time.time()) + 900)
    assert rl.prune() == 1
    assert len(rl._entries()) == 1


def test_broker_issue_redeem_roundtrip(home, subject, actor):
    key = delcred.delegate_api_key(
        scope="invoices:read",
        resource=RES,
        user_token=subject,
        agent_token=actor,
        base=home,
    )
    rec = Broker(home).redeem(key)
    assert rec["scope"] == "invoices:read"
    assert rec["resource"] == RES
    assert rec["expires_at"] > time.time()


def test_broker_unknown_key_rejected(home):
    with pytest.raises(BrokerError, match="invalid API key"):
        Broker(home).redeem("dk_" + "x" * 43)


def test_broker_raw_key_never_stored(home, subject, actor):
    key = delcred.delegate_api_key(
        scope="invoices:read",
        resource=RES,
        user_token=subject,
        agent_token=actor,
        base=home,
    )
    raw = (home / "broker.jsonl").read_text()
    assert key not in raw  # only the hash is stored
    assert hashlib.sha256(key.encode()).hexdigest() in raw


def test_broker_expired_rejected(home):
    b = Broker(home)
    key = b.issue(
        user="u", agent="a", scope="x", resource=RES, ttl=-5, delegation_jwt="dummy"
    )
    with pytest.raises(BrokerError, match="invalid API key"):
        b.redeem(key)


def test_broker_revoke_key(home, subject, actor):
    key = delcred.delegate_api_key(
        scope="invoices:read",
        resource=RES,
        user_token=subject,
        agent_token=actor,
        base=home,
    )
    assert Broker(home).revoke_key(key, reason="test") is True
    with pytest.raises(BrokerError, match="invalid API key"):
        Broker(home).redeem(key)


def test_broker_revoke_unknown_key_false(home):
    assert Broker(home).revoke_key("dk_nonexistent") is False


def test_broker_agent_kill_switch_kills_keys(home, subject, actor):
    key = delcred.delegate_api_key(
        scope="invoices:read",
        resource=RES,
        user_token=subject,
        agent_token=actor,
        base=home,
    )
    delcred.revoke_agent("billing-agent", base=home)
    with pytest.raises(BrokerError, match="invalid API key"):
        Broker(home).redeem(key)


def test_broker_single_use_burns(home):
    b = Broker(home)
    key = b.issue(
        user="u_bob",
        agent="billing-agent",
        scope="invoices:read",
        resource=RES,
        ttl=300,
        delegation_jwt="dummy",
        single_use=True,
    )
    b.redeem(key)  # first OK
    with pytest.raises(BrokerError, match="invalid API key"):
        b.redeem(key)  # second dies


def test_broker_prune(home):
    b = Broker(home)
    b.issue(
        user="u", agent="a", scope="x", resource=RES, ttl=-5, delegation_jwt="dummy"
    )
    b.issue(
        user="u", agent="a", scope="x", resource=RES, ttl=500, delegation_jwt="dummy"
    )
    assert b.prune() == 1


# --- scrutiny findings -----------------------------------------------------


def test_broker_key_dies_with_delegation_jti(home, subject, actor):
    # Finding #1: revoking the delegation JWT's jti kills the broker key
    # issued alongside it.
    from delcred.exchange import TOKEN_TYPE_BROKER_KEY, exchange

    result = exchange(
        subject_token=subject,
        actor_token=actor,
        scope="invoices:read",
        resource=RES,
        requested_token_type=TOKEN_TYPE_BROKER_KEY,
        base=home,
    )
    key = result.credential
    Broker(home).redeem(key)  # valid before
    delcred.revoke_token(result.claims["jti"], reason="test", base=home)
    with pytest.raises(BrokerError, match="invalid API key"):
        Broker(home).redeem(key)


def test_broker_check_non_consuming(home, subject, actor):
    b = Broker(home)
    key = b.issue(
        user="u_bob",
        agent="billing-agent",
        scope="invoices:read",
        resource=RES,
        ttl=300,
        delegation_jwt="dummy",
        single_use=True,
    )
    assert b.check(key) is True
    b.redeem(key)  # consumes the single-use key
    assert b.check(key) is False  # now dead, without a second burn
    assert b.check("dk_nonexistent") is False


def test_broker_redeem_failure_is_audited(home):
    from delcred.audit import AuditLog

    with pytest.raises(BrokerError):
        Broker(home).redeem("dk_nonexistent")
    events = AuditLog(home).tail(3)
    assert any(
        e["event"] == "broker_redeem_failed" and e["reason"] == "unknown_key"
        for e in events
    )
    # and the audit log contains no key material
    assert "dk_nonexistent" not in AuditLog(home).path.read_text()


# --- audit-phase hardening --------------------------------------------------


def test_burn_once_is_atomic_across_threads(home):
    """Two concurrent single-use redeems: exactly one wins (no double-spend)."""
    import threading

    b = Broker(home)
    key = b.issue(
        user="u_bob",
        agent="billing-agent",
        scope="invoices:read",
        resource=RES,
        ttl=300,
        delegation_jwt="dummy",
        single_use=True,
    )
    wins, losses = [], []
    barrier = threading.Barrier(8)

    def attempt():
        barrier.wait()
        try:
            Broker(home).redeem(key)
            wins.append(1)
        except BrokerError:
            losses.append(1)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(wins) == 1, f"expected exactly one winner, got {len(wins)}"
    assert len(losses) == 7


def test_burn_once_returns_false_when_already_burned(home):
    rl = RevocationList(home)
    assert rl.burn_once("j9", reason="first") is True
    assert rl.burn_once("j9", reason="second") is False
    # and a plain revoke_jti also counts as burned
    rl.revoke_jti("j10", reason="operator")
    assert rl.burn_once("j10") is False


def test_single_use_verify_race_exactly_one_winner(home, subject, actor):
    """Two concurrent verifies of a single-use JWT: exactly one succeeds."""
    import threading

    from delcred.exchange import ExchangeError, exchange, verify
    from delcred.tokens import TokenError

    # u_bob's grant is single_use in the fixture policy
    bob = delcred.user_token("u_bob", base=home)
    result = exchange(
        subject_token=bob,
        actor_token=actor,
        scope="invoices:read",
        resource=RES,
        base=home,
    )
    assert result.claims.get("single_use") is True
    tok = result.credential
    wins, losses = [], []
    barrier = threading.Barrier(8)

    def attempt():
        barrier.wait()
        try:
            verify(tok, expected_resource=RES, base=home)
            wins.append(1)
        except (TokenError, ExchangeError):
            losses.append(1)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(wins) == 1, f"expected exactly one winner, got {len(wins)}"
    assert len(losses) == 7


def test_prune_keeps_concurrent_appends(home):
    """Entries appended during prune() must survive the replace."""
    import threading

    rl = RevocationList(home)
    for i in range(20):
        rl.revoke_jti(f"stale-{i}", expires_at=1)  # long expired
    stop = threading.Event()
    appended = []

    def appender():
        n = 0
        while not stop.is_set():
            rl.revoke_agent(f"agent-{n}")
            appended.append(f"agent-{n}")
            n += 1

    t = threading.Thread(target=appender)
    t.start()
    try:
        for _ in range(10):
            rl.prune()
    finally:
        stop.set()
        t.join()
    remaining = {e.get("agent") for e in rl._entries() if e.get("type") == "agent"}
    assert set(appended) <= remaining, "prune() lost concurrent revocation entries"
