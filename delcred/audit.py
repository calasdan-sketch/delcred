"""Append-only, tamper-evident audit log (hash-chained JSONL).

Every security-relevant event is logged with actor identities, jti, scope,
resource, and outcome — but NEVER token values or raw API keys.

Tamper evidence: each entry carries ``prev`` (the previous entry's hash) and
``hash`` = SHA-256 over the canonical JSON of the entry *without* ``hash``.
Editing, inserting, reordering or deleting any line breaks the chain, which
``delcred audit verify`` (``AuditLog.verify()``) detects and pinpoints.

What a hash chain cannot do on its own: detect that the *newest* entries were
truncated, or that the whole file was rewritten by someone holding write
access. Anchor the head hash somewhere the host cannot rewrite (a ticket, a
SIEM, a commit) — ``delcred audit head`` prints it — and compare later.

Entries written by delcred < 0.3 have no ``hash``; they are reported as
legacy. The first hashed entry is anchored: it must chain onto ``GENESIS``
(fresh log) or onto the SHA-256 of the raw last legacy line, so deleting the
oldest hashed entries is detected even if fake legacy lines are added.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._common import home
from ._lock import file_lock

# Intra-process half of mutual exclusion (see revocation.py): keeps
# concurrent threads from interleaving JSON lines.
_thread_lock = threading.Lock()

GENESIS = "0" * 64

# Field names that must never reach the log, whatever a caller passes.
_BANNED = frozenset(
    {
        "token",
        "subject_token",
        "actor_token",
        "api_key",
        "key",
        "credential",
        "access_token",
        "secret",
        "password",
    }
)


def _canonical(entry: dict[str, Any]) -> bytes:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()


def _digest(entry: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(entry)).hexdigest()


def _last_line(path: Path, chunk: int = 8192) -> str:
    """Return the last non-empty line of ``path`` without reading it all."""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        buf = b""
        pos = end
        while pos > 0:
            step = min(chunk, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            stripped = buf.rstrip(b"\r\n")
            nl = stripped.rfind(b"\n")
            if nl != -1:
                return stripped[nl + 1 :].decode("utf-8", "replace")
        return buf.rstrip(b"\r\n").decode("utf-8", "replace")


@dataclass
class AuditVerifyResult:
    ok: bool
    entries: int = 0
    chained: int = 0
    legacy: int = 0
    head: str = GENESIS
    problems: list[str] = field(default_factory=list)


class AuditLog:
    def __init__(self, base: Path | None = None):
        self.path = (base or home()) / "audit.jsonl"
        self.path.touch(exist_ok=True)

    def _prev_hash(self) -> str:
        last = _last_line(self.path)
        if not last:
            return GENESIS
        try:
            h = json.loads(last).get("hash")
        except (json.JSONDecodeError, AttributeError):
            h = None
        # A corrupt/legacy tail restarts nothing silently: we chain onto the
        # digest of the raw line, so `verify` still flags the bad line itself.
        if isinstance(h, str) and len(h) == 64:
            return h
        return hashlib.sha256(last.encode()).hexdigest()

    def record(self, event: str, **fields: Any) -> None:
        entry: dict[str, Any] = {"ts": int(time.time()), "event": event}
        # Defense in depth: never allow a token/key value into the log, even
        # if a caller passes one by mistake. ``prev``/``hash`` are reserved.
        for k, v in fields.items():
            if k in _BANNED or k in ("prev", "hash", "ts", "event"):
                continue
            entry[k] = v
        with _thread_lock, file_lock(self.path):
            entry["prev"] = self._prev_hash()
            entry["hash"] = _digest(entry)
            line = json.dumps(entry, default=str)
            with open(self.path, "a+b") as f:
                # A crash mid-write can leave a torn last line with no
                # newline; never glue a new entry onto it.
                f.seek(0, os.SEEK_END)
                if f.tell():
                    f.seek(-1, os.SEEK_END)
                    if f.read(1) != b"\n":
                        line = "\n" + line
                f.seek(0, os.SEEK_END)
                f.write((line + "\n").encode("utf-8"))
                f.flush()
                os.fsync(f.fileno())

    def _iter_lines(self) -> Iterator[tuple[int, str]]:
        with _thread_lock, file_lock(self.path, shared=True), open(
            self.path, encoding="utf-8", errors="replace"
        ) as f:
            lines = f.read().splitlines()
        for i, line in enumerate(lines, start=1):
            if line.strip():
                yield i, line

    def entries(self) -> list[dict[str, Any]]:
        out = []
        for _, line in self._iter_lines():
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(e, dict):
                out.append(e)
        return out

    def tail(
        self,
        n: int = 20,
        *,
        event: str | None = None,
        agent: str | None = None,
        user: str | None = None,
        since: int | None = None,
    ) -> list[dict[str, Any]]:
        """Most recent ``n`` entries, optionally filtered (exact matches)."""
        rows = self.entries()
        if event:
            rows = [e for e in rows if e.get("event") == event]
        if agent:
            rows = [e for e in rows if e.get("agent") == agent]
        if user:
            rows = [e for e in rows if e.get("user") == user]
        if since is not None:
            rows = [e for e in rows if isinstance(e.get("ts"), int) and e["ts"] >= since]
        return rows[-n:] if n > 0 else []

    def head(self) -> str:
        """Hash of the newest entry — anchor it externally to detect truncation."""
        with _thread_lock, file_lock(self.path, shared=True):
            return self._prev_hash()

    def verify(self) -> AuditVerifyResult:
        """Recompute the hash chain. ``ok`` is False on any break."""
        res = AuditVerifyResult(ok=True)
        prev: str | None = None  # None until the first hashed entry
        # Genesis anchor: the first hashed entry must chain onto GENESIS (new
        # log) or onto the SHA-256 of the raw last legacy line (0.2 log being
        # upgraded) — exactly what record() wrote. Deleting the oldest hashed
        # entries and padding with fake "legacy" lines therefore breaks the
        # chain unless the attacker finds a SHA-256 preimage.
        legacy_digest = GENESIS
        for lineno, line in self._iter_lines():
            res.entries += 1
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                res.ok = False
                res.problems.append(f"line {lineno}: not valid JSON")
                prev = hashlib.sha256(line.encode()).hexdigest()
                continue
            if not isinstance(e, dict) or "hash" not in e:
                if prev is None:
                    res.legacy += 1
                    legacy_digest = hashlib.sha256(line.encode()).hexdigest()
                    continue
                res.ok = False
                res.problems.append(f"line {lineno}: unhashed entry inside the chain")
                prev = hashlib.sha256(line.encode()).hexdigest()
                continue
            res.chained += 1
            expected_prev = legacy_digest if prev is None else prev
            if e.get("prev") != expected_prev:
                res.ok = False
                res.problems.append(
                    f"line {lineno}: chain broken (prev does not match the previous "
                    "entry — a line was deleted, inserted or reordered)"
                )
            if _digest(e) != e.get("hash"):
                res.ok = False
                res.problems.append(f"line {lineno}: content altered (hash mismatch)")
            prev = e.get("hash")
        res.head = prev or GENESIS
        return res
