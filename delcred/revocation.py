"""Revocation: instant local denylist.

Entries are JSONL rows, append-only, fcntl-locked for atomic multi-process
updates::

    {"type": "jti",   "jti": "...", "revoked_at": 169..., "reason": "...",
     "expires_at": 169...}              # pruned once past expires_at
    {"type": "agent", "agent": "...", "revoked_at": 169..., "reason": "..."}
    {"type": "user",  "user": "...",  "revoked_at": 169..., "reason": "..."}

``is_revoked(claims)`` answers: this jti? any kill-switch on its agent or
user? Single-writer assumption — one delcred home per host. Distributed
revocation sync is an explicit v1 non-goal (see README Limitations).
"""

from __future__ import annotations

import fcntl
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from ._common import home

# fcntl locks are process-associated: two threads of the SAME process holding
# "exclusive" fcntl locks on different fds do NOT exclude each other (POSIX).
# This module-level lock provides the intra-process half of mutual exclusion;
# fcntl provides the inter-process half. Every file mutation/read below takes
# both (thread lock outermost — never nest them).
_thread_lock = threading.Lock()


def _now() -> int:
    return int(time.time())


class RevocationList:
    def __init__(self, base: Path | None = None):
        self.path = (base or home()) / "revocations.jsonl"
        self.path.touch(exist_ok=True)

    # -- mutation (locked, atomic append) ---------------------------------

    def _append(self, entry: dict[str, Any]) -> None:
        with _thread_lock, open(self.path, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.write(json.dumps(entry) + "\n")
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    def revoke_jti(
        self, jti: str, reason: str = "", expires_at: int | None = None
    ) -> None:
        self._append(
            {
                "type": "jti",
                "jti": jti,
                "revoked_at": _now(),
                "reason": reason,
                "expires_at": expires_at,
            }
        )

    def revoke_agent(self, agent: str, reason: str = "") -> None:
        """Kill switch: invalidate every token ever minted for this agent."""
        self._append(
            {"type": "agent", "agent": agent, "revoked_at": _now(), "reason": reason}
        )

    def revoke_user(self, user: str, reason: str = "") -> None:
        """Kill switch: invalidate every token delegated by this user."""
        self._append(
            {"type": "user", "user": user, "revoked_at": _now(), "reason": reason}
        )

    def burn_once(
        self, jti: str, reason: str = "", expires_at: int | None = None
    ) -> bool:
        """Atomically burn a jti iff it is not already denylisted.

        Returns True when this call performed the burn, False when the jti
        was already burned/revoked. The check-and-append holds an exclusive
        lock for the whole operation, so two concurrent single-use verifies
        (or redeems) cannot both succeed — exactly one wins, the loser is
        rejected. This is what makes single-use credentials actually
        single-use across processes.
        """
        with _thread_lock, open(self.path, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.seek(0)
                now = _now()
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if e.get("type") != "jti" or e.get("jti") != jti:
                        continue
                    exp = e.get("expires_at")
                    if exp is None or exp >= now:
                        return False  # already denylisted
                f.write(
                    json.dumps(
                        {
                            "type": "jti",
                            "jti": jti,
                            "revoked_at": now,
                            "reason": reason,
                            "expires_at": expires_at,
                        }
                    )
                    + "\n"
                )
                f.flush()
                os.fsync(f.fileno())
                return True
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    # -- reads ------------------------------------------------------------

    def _entries(self) -> list[dict[str, Any]]:
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

    def is_revoked(self, claims: dict[str, Any]) -> tuple[bool, str]:
        """Check jti + agent kill-switch + user kill-switch. Returns (revoked, why)."""
        now = _now()
        jti = claims.get("jti")
        # Agent identity: for delegation tokens the agent is act.sub; for
        # agent-identity tokens (kind="agent") it is sub itself.
        agent = (claims.get("act") or {}).get("sub")
        if agent is None and claims.get("kind") == "agent":
            agent = claims.get("sub")
        user = claims.get("sub")
        for e in self._entries():
            exp = e.get("expires_at")
            if exp is not None and exp < now:
                continue  # stale jti entry; token is expired anyway
            t = e.get("type")
            if t == "jti" and jti and e.get("jti") == jti:
                return True, f"token revoked: {e.get('reason') or 'jti denylisted'}"
            if t == "agent" and agent and e.get("agent") == agent:
                return (
                    True,
                    f"agent {agent!r} revoked: {e.get('reason') or 'kill switch'}",
                )
            if t == "user" and user and e.get("user") == user:
                return (
                    True,
                    f"user {user!r} revoked: {e.get('reason') or 'kill switch'}",
                )
        return False, ""

    def prune(self) -> int:
        """Drop expired jti entries. Returns number removed.

        The read-filter-replace cycle holds an exclusive lock throughout:
        entries appended concurrently (e.g. a revocation landing mid-prune)
        are never lost to the replace.
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
                        e = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    exp = e.get("expires_at")
                    if e.get("type") == "jti" and exp is not None and exp < now:
                        dropped += 1
                        continue
                    kept.append(e)
                if dropped:
                    tmp = self.path.with_suffix(".tmp")
                    with open(tmp, "w") as tf:
                        for e in kept:
                            tf.write(json.dumps(e) + "\n")
                        tf.flush()
                        os.fsync(tf.fileno())
                    # The lock is held on the original fd; the replace is
                    # atomic and no concurrent writer can slip between.
                    os.replace(tmp, self.path)
                return dropped
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
