"""delcred home-directory layout and shared helpers."""

from __future__ import annotations

import json
import os
import secrets
import stat
from pathlib import Path

DEFAULT_TTL = 900  # 15 minutes — the primary blast-radius control
MAX_TTL = 3600  # hard cap: 60 minutes, enforced server-side
CLOCK_SKEW_LEEWAY = 60  # seconds of acceptable clock skew
ISSUER_ID = "delcred"
KEY_PREFIX = "dk_"  # opaque broker keys look like: dk_<urlsafe>


def home() -> Path:
    """State directory: $DELCRED_HOME or ~/.delcred (created 0700)."""
    p = Path(os.environ.get("DELCRED_HOME", Path.home() / ".delcred"))
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Harden pre-existing dirs too.
    try:
        os.chmod(p, 0o700)
    except OSError:
        pass
    return p


def assert_private(path: Path) -> None:
    """Refuse to use a private key file that is readable by group/other.

    On Windows, POSIX mode bits are not meaningful (access is governed by
    NTFS ACLs, which a user profile directory already restricts), so the
    check is skipped there — see README "Limitations".
    """
    if os.name == "nt":  # pragma: no cover
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise PermissionError(
            f"refusing to use {path}: permissions {oct(mode)} are too open "
            "(must be 0600 or stricter)"
        )


def write_private(path: Path, data: bytes) -> None:
    """Write a secret file that is never readable by group/other, even briefly.

    The bytes go to a fresh temp file created with ``O_CREAT | O_EXCL`` and
    mode 0600 (so a pre-existing or planted file is never reused), are
    fsynced, then atomically renamed over ``path``. A pre-existing
    world-readable ``path`` is replaced, not written into.
    """
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)  # umask can only remove bits; be explicit
        except (AttributeError, OSError):  # pragma: no cover - Windows
            pass
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        tmp.unlink(missing_ok=True)
        raise
    os.close(fd)
    os.replace(tmp, path)


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default
