"""Cross-platform, cross-process file locking (stdlib only).

Every state file (``revocations.jsonl``, ``broker.jsonl``, ``audit.jsonl``)
is guarded by a dedicated sibling lock file ``<name>.lock``:

* POSIX  — ``fcntl.flock`` (shared or exclusive).
* Windows — ``msvcrt.locking`` on byte 0 of the lock file (always exclusive;
  Windows has no shared byte-range lock in msvcrt).

Why a separate lock file instead of locking the data file itself: ``prune``
atomically *replaces* the data file. A lock held on the old inode does not
protect writers that reopen the path afterwards — they could append to the
unlinked file and lose an entry (a revocation!). The lock file is never
replaced, so the lock is stable across prunes. It also lets Windows replace
the data file, which it refuses to do while a handle is open with a lock.

fcntl/msvcrt locks are per-process; callers additionally hold a
``threading.Lock`` for intra-process exclusion (thread lock outermost).
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from delcred._common import replace_file

if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI only
    import msvcrt

    def _acquire(fd: int, shared: bool) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        while True:
            try:
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                return
            except OSError:
                # LK_LOCK gives up after ~10 s of retries; keep waiting.
                time.sleep(0.05)

    def _release(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _acquire(fd: int, shared: bool) -> None:
        fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)

    def _release(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


def lock_path_for(path: Path) -> Path:
    return path.with_name(path.name + ".lock")


@contextmanager
def file_lock(path: Path, *, shared: bool = False) -> Iterator[None]:
    """Hold an inter-process lock guarding ``path`` for the ``with`` body."""
    fd = os.open(lock_path_for(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        _acquire(fd, shared)
        try:
            yield
        finally:
            _release(fd)
    finally:
        os.close(fd)


def atomic_rewrite(path: Path, lines: list[str]) -> None:
    """Replace ``path`` with ``lines`` atomically (caller holds the lock)."""
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as tf:
        tf.writelines(line + "\n" for line in lines)
        tf.flush()
        os.fsync(tf.fileno())
    replace_file(tmp, path)
