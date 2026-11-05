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
from ._lock import atomic_rewrite, file_lock
from .audit import AuditLog
from .revocation import RevocationList
from .tokens import InvalidToken, decode_unverified

# OS file locks are process-associated (see revocation.py): this module-level
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
        with _thread_lock, file_lock(self.path), open(
            self.path, "a", encoding="utf-8"
        ) as f:
            f.write(json.dumps(record) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def _records(self) -> list[dict[str, Any]]:
        rows = []
        with _thread_lock, file_lock(self.path, shared=True), open(
            self.path, encoding="utf-8"
        ) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
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

    def _find(self, key: str) -> dict[str, Any] | None:
        if not isinstance(key, str) or not key:
            return None
        want = _hash(key)
        match: dict[str, Any] | None = None
        # Scan every record (no early exit) so lookup time does not depend
        # on where — or whether — the key sits in the file.
        for rec in self._records():
            if hmac.compare_digest(str(rec.get("key_hash", "")), want) and match is None:
                match = rec
        return match

    def check(self, key: str) -> bool:
        """Non-consuming validity check (no single-use burn).

        Used by the sidecar to re-validate cached broker keys.
        Returns True only if the key would redeem successfully.
        """
        match = self._find(key)
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

    def redeem(
        self,
        key: str,
        *,
        expected_resource: str | None = None,
        required_scopes: str | list[str] | set[str] | None = None,
    ) -> dict[str, Any]:
        """Validate an opaque key → capability record. Burns single-use keys.

        ``expected_resource`` (strongly recommended) pins the key to the
        API redeeming it — the same confused-deputy defense as JWT audience
        checks. ``required_scopes`` enforces least privilege per operation.
        Both are checked *before* a single-use key is burned, so presenting a
        key to the wrong API does not destroy it.

        Raises BrokerError("invalid API key") on any failure — unknown,
        expired, revoked, wrong resource or missing scope are
        indistinguishable by design (the audit log records which).
        """
        match = self._find(key)
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
        if expected_resource is not None and match["resource"] != expected_resource:
            raise self._reject("wrong_resource", jti=match["jti"])
        if required_scopes:
            from .tokens import normalize_scopes

            missing = normalize_scopes(required_scopes) - set(
                str(match.get("scope", "")).split()
            )
            if missing:
                raise self._reject(
                    "insufficient_scope", jti=match["jti"], missing=sorted(missing)
                )
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
        rec = self._find(key)
        if rec is None:
            return False
        self.revocations.revoke_jti(
            rec["jti"],
            reason=reason or "broker key revoked",
            expires_at=rec["expires_at"],
        )
        return True

    def prune(self) -> int:
        """Drop expired records. Returns number removed.

        The read-filter-replace cycle holds an exclusive lock throughout:
        keys issued concurrently (mid-prune) are never lost to the replace.
        """
        now = _now()
        with _thread_lock, file_lock(self.path):
            kept, dropped = [], 0
            with open(self.path, encoding="utf-8") as f:
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
                    kept.append(json.dumps(r))
            if dropped:
                atomic_rewrite(self.path, kept)
            return dropped
