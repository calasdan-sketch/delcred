"""delcred home-directory layout and shared helpers."""

from __future__ import annotations

import json
import os
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
    """Refuse to use a private key file that is readable by group/other."""
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise PermissionError(
            f"refusing to use {path}: permissions {oct(mode)} are too open "
            "(must be 0600 or stricter)"
        )


def write_private(path: Path, data: bytes) -> None:
    """Write a secret file with 0600 permissions (no races via O_CREAT|O_EXCL)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default
