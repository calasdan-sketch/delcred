"""Revocation: instant local denylist.

Entries are JSONL rows, append-only, file-locked (POSIX flock / Windows msvcrt) for atomic multi-process
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

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from ._common import home
from ._lock import atomic_rewrite, file_lock

# OS file locks are process-associated: two threads of the SAME process do
# NOT exclude each other through them. This module-level lock provides the
# intra-process half of mutual exclusion; ``_lock.file_lock`` provides the
# inter-process half (POSIX flock / Windows msvcrt). Every file mutation/read
# below takes both (thread lock outermost — never nest them).
_thread_lock = threading.Lock()

_cache_lock = threading.Lock()
# path -> (inode, bytes consumed, _Index). Grown incrementally on append.
_INDEX_CACHE: dict[str, tuple[int, int, _Index]] = {}


class _Index:
    """Revocation entries grouped for O(1) lookup."""

    def __init__(self) -> None:
        self.jti: dict[str, list[tuple[int | None, str]]] = {}
        self.agent: dict[str, list[tuple[int | None, str]]] = {}
        self.user: dict[str, list[tuple[int | None, str, str | None]]] = {}

    def add(self, e: Any) -> None:
        if not isinstance(e, dict):
            return
        exp, reason, t = e.get("expires_at"), str(e.get("reason") or ""), e.get("type")
        if t == "jti" and isinstance(e.get("jti"), str):
            self.jti.setdefault(e["jti"], []).append((exp, reason))
        elif t == "agent" and isinstance(e.get("agent"), str):
            self.agent.setdefault(e["agent"], []).append((exp, reason))
        elif t == "user" and isinstance(e.get("user"), str):
            self.user.setdefault(e["user"], []).append((exp, reason, e.get("iss")))


def _heal_tail(f) -> None:
    """If a crash left a torn final line, terminate it so the next entry does
    not get glued onto it (which would silently lose that entry)."""
    f.seek(0, os.SEEK_END)
    if f.tell() == 0:
        return
    f.seek(-1, os.SEEK_END)
    if f.read(1) != b"\n":
        f.write(b"\n")
        f.flush()


def _now() -> int:
    return int(time.time())


class RevocationList:
    def __init__(self, base: Path | None = None):
        self.path = (base or home()) / "revocations.jsonl"
        self.path.touch(exist_ok=True)

    # -- mutation (locked, atomic append) ---------------------------------

    def _append(self, entry: dict[str, Any]) -> None:
        with _thread_lock, file_lock(self.path), open(self.path, "ab+") as f:
            _heal_tail(f)
            f.write((json.dumps(entry) + "\n").encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())

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

    def revoke_user(self, user: str, reason: str = "", issuer: str | None = None) -> None:
        """Kill switch: invalidate every token delegated by this user.

        Users are ``(issuer, user)`` pairs. With ``issuer=None`` the switch
        covers the id under *every* issuer (fail-closed); pass an issuer to
        revoke only that IdP's user.
        """
        entry = {"type": "user", "user": user, "revoked_at": _now(), "reason": reason}
        if issuer:
            entry["iss"] = issuer
        self._append(entry)

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
        with _thread_lock, file_lock(self.path), open(self.path, "ab+") as f:
            now = _now()
            _heal_tail(f)
            idx = self._refresh(f)  # amortised O(new bytes), not O(file)
            for exp, _ in idx.jti.get(jti, ()):
                if exp is None or exp >= now:
                    return False  # already denylisted
            f.write(
                (
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
                ).encode("utf-8")
            )
            f.flush()
            os.fsync(f.fileno())
            return True

    # -- reads ------------------------------------------------------------

    def _entries(self) -> list[dict[str, Any]]:
        """Every parseable row (used by ``status``; lookups use the index)."""
        rows = []
        with _thread_lock, file_lock(self.path, shared=True), open(self.path, "rb") as f:
            for raw in f:
                line = raw.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue
        return rows

    def _refresh(self, f) -> _Index:
        """Bring the cached index up to date using the open handle ``f``.

        The caller holds a lock on the data file (shared or exclusive), so
        every line it sees is complete. Only the bytes appended since the
        last refresh are parsed; a replaced (pruned) or truncated file is
        re-read from the start.
        """
        key = str(self.path)
        st = os.fstat(f.fileno())
        with _cache_lock:
            ent = _INDEX_CACHE.get(key)
            if ent is not None and ent[0] == st.st_ino and ent[1] <= st.st_size:
                _, offset, idx = ent
            else:
                offset, idx = 0, _Index()
            if offset == st.st_size and ent is not None and ent[0] == st.st_ino:
                return idx
            f.seek(offset)
            data = f.read()
            end = data.rfind(b"\n") + 1  # a torn final line is not consumed
            for raw in data[:end].splitlines():
                line = raw.strip()
                if not line:
                    continue
                try:
                    idx.add(json.loads(line))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
            if len(_INDEX_CACHE) > 64:
                _INDEX_CACHE.clear()
            _INDEX_CACHE[key] = (st.st_ino, offset + end, idx)
            return idx

    def _index(self) -> _Index:
        """Parsed view of the file. A cache hit costs one ``stat``; after an
        append only the new bytes are parsed (measured in ``bench/``)."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return _Index()
        ent = _INDEX_CACHE.get(str(self.path))
        if ent is not None and ent[0] == st.st_ino and ent[1] == st.st_size:
            return ent[2]
        with _thread_lock, file_lock(self.path, shared=True), open(self.path, "rb") as f:
            return self._refresh(f)

    def is_revoked(self, claims: dict[str, Any]) -> tuple[bool, str]:
        """Check jti, ancestor jtis, every agent in the actor chain, and the user.

        Returns ``(revoked, why)``. A chained delegation dies when its own
        jti, ANY ancestor delegation's jti, ANY agent in the chain, or the
        user is revoked.
        """
        now = _now()
        from .tokens import user_issuer

        agents: list[str] = []
        node: Any = claims.get("act")
        while isinstance(node, dict) and len(agents) < 16:
            if isinstance(node.get("sub"), str):
                agents.append(node["sub"])
            node = node.get("act")
        # Agent identity tokens (kind="agent") name the agent in ``sub``.
        if not agents and claims.get("kind") == "agent" and isinstance(claims.get("sub"), str):
            agents.append(claims["sub"])
        jtis = [j for j in [claims.get("jti"), *(claims.get("chain") or [])] if isinstance(j, str)]
        # Agent identity tokens name an agent in ``sub``, not a user.
        user = None if claims.get("kind") == "agent" else claims.get("sub")
        user_iss = user_issuer(claims)
        idx = self._index()
        for j in jtis:
            for exp, reason in idx.jti.get(j, ()):
                if exp is None or exp >= now:
                    who = "token" if j == claims.get("jti") else "parent delegation"
                    return True, f"{who} revoked: {reason or 'jti denylisted'}"
        for a in agents:
            for exp, reason in idx.agent.get(a, ()):
                if exp is None or exp >= now:
                    return True, f"agent {a!r} revoked: {reason or 'kill switch'}"
        if user:
            for exp, reason, iss in idx.user.get(user, ()):
                if (exp is None or exp >= now) and (not iss or iss == user_iss):
                    return True, f"user {user!r} revoked: {reason or 'kill switch'}"
        return False, ""

    def snapshot(self) -> dict[str, Any]:
        """Live (non-expired) revocations, for the signed bulletin."""
        now = _now()
        idx = self._index()
        return {
            "jtis": sorted(
                j for j, v in idx.jti.items() if any(e is None or e >= now for e, _ in v)
            ),
            "agents": sorted(
                a for a, v in idx.agent.items() if any(e is None or e >= now for e, _ in v)
            ),
            "users": sorted(
                (
                    {"sub": u, **({"iss": iss} if iss else {})}
                    for u, v in idx.user.items()
                    for e, _, iss in v
                    if e is None or e >= now
                ),
                key=lambda d: (d["sub"], d.get("iss", "")),
            ),
        }

    def prune(self) -> int:
        """Drop expired jti entries. Returns number removed.

        The read-filter-replace cycle holds an exclusive lock throughout:
        entries appended concurrently (e.g. a revocation landing mid-prune)
        are never lost to the replace.
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
                        e = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    exp = e.get("expires_at")
                    if e.get("type") == "jti" and exp is not None and exp < now:
                        dropped += 1
                        continue
                    kept.append(json.dumps(e))
            if dropped:
                # The data file is closed before the replace (Windows refuses
                # to replace an open file); the sibling lock is still held, so
                # no concurrent writer can slip between read and replace.
                atomic_rewrite(self.path, kept)
            return dropped
