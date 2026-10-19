"""Ephemeral API-key broker (merged market-gap #10).

Problem: agents today hold raw API keys (Stripe keys, DB passwords) in their
environment — one prompt injection and the key is exfiltrated. delcred's
answer: the agent never sees the real key. Instead it gets an *opaque,
short-lived, single-purpose* key (``dk_<urlsafe>``) that maps to a delegation
record. Redeeming it yields the *capability* (a delegation JWT scoped to one
resource), never the underlying secret.

Storage: only SHA-256 hashes of keys are kept (constant-time compare on
redeem). Records carry the same TTL + revocation semantics as JWT
delegations. This module is intentionally the *redemption half* of the
exchange — every broker key is born from a policy-checked delegation.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from ._common import KEY_PREFIX, home
from .audit import AuditLog
from .revocation import RevocationList
from .tokens import InvalidToken, decode_unverified

# fcntl locks are process-associated (see revocation.py): this module-level
# lock provides the intra-process half of mutual exclusion for the broker
# file. Never nest it.
_thread_lock = threading.Lock()

# Grace added to revocation entries so a burned jti stays denylisted past
# the token's exp + clock-skew leeway (finding #5).
BURN_GRACE = 300


def _now() -> int:
    return int(time.time())


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class BrokerError(Exception):
    pass


class Broker:
    """Issues and redeems opaque ephemeral keys backed by delegation records."""

    def __init__(self, base: Path | None = None):
        self.base = base or home()
        self.path = self.base / "broker.jsonl"
        self.path.touch(exist_ok=True)
        self.revocations = RevocationList(self.base)
        self.audit = AuditLog(self.base)

    def _append(self, record: dict[str, Any]) -> None:
        with _thread_lock, open(self.path, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.write(json.dumps(record) + "\n")
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    def _records(self) -> list[dict[str, Any]]:
        rows = []
        with _thread_lock, open(self.path) as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            rows.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        return rows

    def issue(
        self,
        *,
        user: str,
        agent: str,
        scope: str,
        resource: str,
        ttl: int,
        delegation_jwt: str,
        single_use: bool = False,
        label: str = "",
    ) -> str:
        """Create an opaque key bound to an already-minted delegation JWT."""
        raw = KEY_PREFIX + secrets.token_urlsafe(32)
        now = _now()
        try:
            delegation_jti = decode_unverified(delegation_jwt).get("jti")
        except InvalidToken:
            delegation_jti = None
        self._append(
            {
                "key_hash": _hash(raw),
                "jti": f"broker-{secrets.token_urlsafe(12)}",
                # Finding #1: bind the key to its delegation JWT so revoking
                # the JWT's jti also kills this key.
                "delegation_jti": delegation_jti,
                "user": user,
                "agent": agent,
                "scope": scope,
                "resource": resource,
                "issued_at": now,
                "expires_at": now + ttl,
                "single_use": single_use,
                "label": label,
                # NOTE: the raw key is never written anywhere; only its hash.
            }
        )
        return raw

    def _reject(self, reason: str, **fields: Any) -> BrokerError:
        # Finding #6: uniform outward message (no key-existence oracle);
        # distinct reason only in the audit log, never with key material.
        self.audit.record("broker_redeem_failed", reason=reason, **fields)
        return BrokerError("invalid API key")

    def check(self, key: str) -> bool:
        """Non-consuming validity check (no single-use burn).

        Used by the sidecar to re-validate cached broker keys.
        Returns True only if the key would redeem successfully.
        """
        want = _hash(key)
        match: dict[str, Any] | None = None
        for rec in self._records():
            if hmac.compare_digest(rec.get("key_hash", ""), want):
                match = rec
                break
        if match is None or match["expires_at"] < _now():
            return False
        claims = {
            "jti": match["jti"],
            "sub": match["user"],
            "act": {"sub": match["agent"]},
        }
        revoked, _ = self.revocations.is_revoked(claims)
        if not revoked and match.get("delegation_jti"):
            revoked, _ = self.revocations.is_revoked(
                {**claims, "jti": match["delegation_jti"]}
            )
        # NOTE: single-use keys report False once consumed — the sidecar
        # then mints a fresh one instead of serving a dead credential.
        return not revoked

    def redeem(self, key: str) -> dict[str, Any]:
        """Validate an opaque key → capability record. Burns single-use keys.

        Raises BrokerError("invalid API key") on any failure — unknown,
        expired, or revoked are indistinguishable by design.
        """
        want = _hash(key)
        match: dict[str, Any] | None = None
        for rec in self._records():
            if hmac.compare_digest(rec.get("key_hash", ""), want):
                match = rec
                break
        if match is None:
            raise self._reject("unknown_key")
        now = _now()
        if match["expires_at"] < now:
            raise self._reject("expired", jti=match["jti"])
        claims = {
            "jti": match["jti"],
            "sub": match["user"],
            "act": {"sub": match["agent"]},
        }
        revoked, why = self.revocations.is_revoked(claims)
        # Finding #1: also honor revocation of the bound delegation JWT.
        if not revoked and match.get("delegation_jti"):
            revoked, why = self.revocations.is_revoked(
                {**claims, "jti": match["delegation_jti"]}
            )
        if revoked:
            raise self._reject("revoked", jti=match["jti"], detail=why)
        if match.get("single_use"):
            # Atomic burn: exactly one concurrent redeem wins; the losers get
            # the uniform "invalid API key" (no double-spend, no oracle).
            burned = self.revocations.burn_once(
                match["jti"],
                reason="single-use broker key consumed",
                expires_at=match["expires_at"] + BURN_GRACE,
            )
            if not burned:
                raise self._reject("replay", jti=match["jti"])
        self.audit.record(
            "broker_redeemed",
            jti=match["jti"],
            user=match["user"],
            agent=match["agent"],
            resource=match["resource"],
        )
        return {
            "user": match["user"],
            "agent": match["agent"],
            "scope": match["scope"],
            "resource": match["resource"],
            "expires_at": match["expires_at"],
            "label": match.get("label", ""),
        }

    def revoke_key(self, key: str, reason: str = "") -> bool:
        """Revoke by raw key value (hashes it, denylists the record's jti)."""
        want = _hash(key)
        for rec in self._records():
            if hmac.compare_digest(rec.get("key_hash", ""), want):
                self.revocations.revoke_jti(
                    rec["jti"],
                    reason=reason or "broker key revoked",
                    expires_at=rec["expires_at"],
                )
                return True
        return False

    def prune(self) -> int:
        """Drop expired records. Returns number removed.

        The read-filter-replace cycle holds an exclusive lock throughout:
        keys issued concurrently (mid-prune) are never lost to the replace.
        """
        now = _now()
        with _thread_lock, open(self.path, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.seek(0)
                kept, dropped = [], 0
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if r.get("expires_at", 0) < now:
                        dropped += 1
                        continue
                    kept.append(r)
                if dropped:
                    tmp = self.path.with_suffix(".tmp")
                    with open(tmp, "w") as tf:
                        for r in kept:
                            tf.write(json.dumps(r) + "\n")
                        tf.flush()
                        os.fsync(tf.fileno())
                    os.replace(tmp, self.path)
                return dropped
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
