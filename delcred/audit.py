"""Append-only audit log (JSONL).

Every security-relevant event is logged with actor identities, jti, scope,
resource, and outcome — but NEVER token values or raw API keys.
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

# Intra-process half of mutual exclusion (see revocation.py): keeps
# concurrent threads from interleaving JSON lines.
_thread_lock = threading.Lock()


class AuditLog:
    def __init__(self, base: Path | None = None):
        self.path = (base or home()) / "audit.jsonl"
        self.path.touch(exist_ok=True)

    def record(self, event: str, **fields: Any) -> None:
        entry = {"ts": int(time.time()), "event": event}
        entry.update(fields)
        # Defense in depth: never allow a token/key value into the log, even
        # if a caller passes one by mistake.
        for banned in ("token", "subject_token", "actor_token", "api_key", "key"):
            entry.pop(banned, None)
        with _thread_lock, open(self.path, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.write(json.dumps(entry) + "\n")
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    def tail(self, n: int = 20) -> list[dict[str, Any]]:
        lines = self.path.read_text().splitlines()
        out = []
        for line in lines[-n:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
