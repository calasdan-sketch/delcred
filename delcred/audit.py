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
from collections import deque
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
CHECKPOINT_TYP = "delcred-audit-checkpoint+jwt"

# Events that are safe to lose on a power cut (the credential they describe is
# validated again on the next use). Everything else - mints, denials, revokes,
# replays - is always fsynced. Set DELCRED_AUDIT_FSYNC=routine-off to skip the
# fsync for these only (about 3x more verifies per second on a spinning or
# network disk); the default fsyncs every entry.
_ROUTINE_EVENTS = frozenset({"verify_ok", "verify_rejected", "verify_insufficient_scope"})
_THROTTLE: dict[str, list[float]] = {}  # path -> [tokens, last_monotonic, suppressed]
_THROTTLE_BURST = 50.0
_THROTTLE_PER_SEC = 5.0
_throttle_lock = threading.Lock()

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

    def record_throttled(self, event: str, **fields: Any) -> None:
        """``record`` for events an outsider can trigger at will (rejected
        credentials): at most ~5/s sustained after a burst of 50; the next
        entry that gets through carries ``suppressed=N`` so the gap is visible."""
        now = time.monotonic()
        with _throttle_lock:
            st = _THROTTLE.setdefault(str(self.path), [_THROTTLE_BURST, now, 0.0])
            st[0] = min(_THROTTLE_BURST, st[0] + (now - st[1]) * _THROTTLE_PER_SEC)
            st[1] = now
            if st[0] < 1.0:
                st[2] += 1
                return
            st[0] -= 1.0
            dropped, st[2] = int(st[2]), 0.0
            if len(_THROTTLE) > 256:
                _THROTTLE.clear()
        if dropped:
            fields["suppressed"] = dropped
        self.record(event, **fields)

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
                if not (
                    event in _ROUTINE_EVENTS
                    and os.environ.get("DELCRED_AUDIT_FSYNC") == "routine-off"
                ):
                    os.fsync(f.fileno())

    def _size(self) -> int:
        with _thread_lock, file_lock(self.path, shared=True):
            return self.path.stat().st_size

    def _iter_lines(self) -> Iterator[tuple[int, str]]:
        """Stream complete lines without holding the lock or the whole file.

        The log is append-only, so the size read under the lock marks a
        boundary after which only whole lines exist; later appends are simply
        not seen by this pass.
        """
        limit = self._size()
        read = 0
        with open(self.path, "rb") as f:
            for lineno, raw in enumerate(f, start=1):
                read += len(raw)
                if read > limit:
                    break
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line.strip():
                    yield lineno, line

    def _iter_entries(self) -> Iterator[dict[str, Any]]:
        for _, line in self._iter_lines():
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(e, dict):
                yield e

    def entries(self) -> list[dict[str, Any]]:
        return list(self._iter_entries())

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
        if 0 < n <= 1000 and not (event or agent or user or since is not None):
            return self._last_entries(n)
        keep: deque[dict[str, Any]] = deque(maxlen=max(n, 0))
        for e in self._iter_entries():
            if event and e.get("event") != event:
                continue
            if agent and e.get("agent") != agent:
                continue
            if user and e.get("user") != user:
                continue
            if since is not None and not (isinstance(e.get("ts"), int) and e["ts"] >= since):
                continue
            keep.append(e)
        return list(keep) if n > 0 else []

    def _last_entries(self, n: int, chunk: int = 65536) -> list[dict[str, Any]]:
        """The last ``n`` parseable entries, reading only the file's tail."""
        limit = self._size()
        buf = b""
        pos = limit
        with open(self.path, "rb") as f:
            while pos > 0:
                step = min(chunk, pos)
                pos -= step
                f.seek(pos)
                buf = f.read(step) + buf
                if buf.count(b"\n") > n * 2 + 4 or pos == 0:
                    break
            lines = buf[: max(0, limit - pos)].split(b"\n")
        if pos > 0:
            lines = lines[1:]  # first piece may be cut mid-line
        out: list[dict[str, Any]] = []
        for raw in lines:
            try:
                e = json.loads(raw.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(e, dict):
                out.append(e)
        return out[-n:]

    def head(self) -> str:
        """Hash of the newest entry — anchor it externally to detect truncation."""
        with _thread_lock, file_lock(self.path, shared=True):
            return self._prev_hash()

    def checkpoint(self) -> str:
        """Signed statement "the log had ``entries`` lines ending in ``head``".

        Store it OFF this host (ticket, SIEM, object store). Later,
        ``verify(checkpoint=...)`` proves nothing before that point was cut
        off or rewritten, which the bare hash chain cannot. It is signed with
        the issuer key, so a host compromise that also steals the key could
        forge a newer one; that is why the copy must live elsewhere.
        """
        from . import keys as _keys
        from ._common import ISSUER_ID
        from ._jws import sign_compact

        res = self.verify()
        if not res.ok:
            raise ValueError("refusing to checkpoint a log that fails verification")
        base = self.path.parent
        priv = _keys.load_private(base)
        payload = {
            "iss": ISSUER_ID,
            "iat": int(time.time()),
            "entries": res.entries,
            "head": res.head,
        }
        header = {"alg": "EdDSA", "typ": CHECKPOINT_TYP, "kid": _keys.key_id(priv.public_key())}
        return sign_compact(header, payload, priv)

    def _read_checkpoint(self, token: str) -> dict[str, Any]:
        from . import keys as _keys
        from ._jws import JWSError, check_header, ed25519_verify, parse_compact

        try:
            header, claims, signing_input, sig = parse_compact(token.strip())
            check_header(header)
        except JWSError as e:
            raise ValueError(f"malformed checkpoint: {e}") from e
        if header.get("typ") != CHECKPOINT_TYP:
            raise ValueError("not an audit checkpoint")
        base = self.path.parent
        pubs = _keys.verification_keys(base)
        kid = header.get("kid")
        pub = pubs.get(kid) if isinstance(kid, str) else None
        if pub is None:
            raise ValueError("checkpoint was signed by an unknown key")
        if not ed25519_verify(_keys.public_jwk(pub)["x"], signing_input, sig):
            raise ValueError("checkpoint signature invalid")
        n, head = claims.get("entries"), claims.get("head")
        if isinstance(n, bool) or not isinstance(n, int) or n < 0 or not (
            isinstance(head, str) and len(head) == 64
        ):
            raise ValueError("checkpoint claims are malformed")
        return claims

    def verify(self, checkpoint: str | None = None) -> AuditVerifyResult:
        """Recompute the hash chain. ``ok`` is False on any break.

        With ``checkpoint`` (from :meth:`checkpoint`), also require that the
        log still contains the checkpointed head at the checkpointed position:
        catches truncation of recent entries and wholesale rewrites that the
        chain alone cannot.
        """
        cp = self._read_checkpoint(checkpoint) if checkpoint is not None else None
        res = AuditVerifyResult(ok=True)
        cp_seen = cp is None or cp["entries"] == 0
        prev: str | None = None  # None until the first hashed entry
        # Genesis anchor: the first hashed entry must chain onto GENESIS (new
        # log) or onto the SHA-256 of the raw last legacy line (0.2 log being
        # upgraded) — exactly what record() wrote. Deleting the oldest hashed
        # entries and padding with fake "legacy" lines therefore breaks the
        # chain unless the attacker finds a SHA-256 preimage.
        legacy_digest = GENESIS
        for lineno, line in self._iter_lines():
            res.entries += 1
            if len(res.problems) >= 1000:
                res.ok = False
                res.problems.append("... more problems omitted")
                break
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
                res.problems.append(
                    f"line {lineno}: unhashed entry inside the chain (log padded by hand, or a delcred older "
                    "than 0.3 is still writing to this home - stop old processes before upgrading)"
                )
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
            if cp is not None and res.entries == cp["entries"]:
                cp_seen = True
                if prev != cp["head"]:
                    res.ok = False
                    res.problems.append(
                        f"line {lineno}: does not match the checkpoint head "
                        "(the log was rewritten after the checkpoint was taken)"
                    )
        if cp is not None and not cp_seen:
            res.ok = False
            res.problems.append(
                f"log has {res.entries} entries but the checkpoint covers {cp['entries']}: "
                "recent entries were removed"
            )
        res.head = prev or GENESIS
        return res
