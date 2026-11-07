"""delcred home-directory layout and shared helpers."""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import unicodedata
from pathlib import Path

DEFAULT_TTL = 900  # 15 minutes — the primary blast-radius control
MAX_TTL = 3600  # hard cap: 60 minutes, enforced server-side
CLOCK_SKEW_LEEWAY = 60  # seconds of acceptable clock skew
ISSUER_ID = "delcred"
KEY_PREFIX = "dk_"  # opaque broker keys look like: dk_<urlsafe>
MAX_TOKEN_BYTES = 16 * 1024  # any JWT larger than this is junk or an attack
MAX_CHAIN_DEPTH = 4  # hard cap on agent -> sub-agent hops
MAX_ID_CHARS = 256


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


# RFC 6749 §3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ), separated by
# a single ASCII space. Python's str.split() also splits on NBSP, tabs and
# other Unicode spaces, which other languages' verifiers would NOT — a
# cross-language disagreement about what a scope string means. Be strict.
_SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]+\Z")


def parse_scope(scope: object) -> list[str]:
    """Strictly parse an RFC 6749 scope string into a sorted, de-duplicated list.

    Raises ``ValueError`` for non-strings, empty strings, and any scope
    containing characters outside the RFC 6749 scope-token alphabet
    (including every non-ASCII-space whitespace character).
    """
    if not isinstance(scope, str):
        raise TypeError("scope must be a string")
    parts = [p for p in scope.split(" ") if p]
    if not parts:
        raise ValueError("scope must not be empty")
    for p in parts:
        if not _SCOPE_TOKEN.match(p):
            raise ValueError(f"invalid scope token {p[:40]!r} (RFC 6749 §3.3)")
    return sorted(set(parts))


def check_identifier(value: object, what: str = "identifier") -> str:
    """Validate a user/agent id: 1..256 chars, no control, format, separator,
    private-use or unassigned code points (terminal escapes, bidi overrides,
    zero-width characters, line breaks) and no whitespace at all."""
    if not isinstance(value, str):
        raise TypeError(f"{what} must be a string")
    if not value:
        raise ValueError(f"{what} must not be empty")
    if len(value) > MAX_ID_CHARS:
        raise ValueError(f"{what} longer than {MAX_ID_CHARS} characters")
    for ch in value:
        if unicodedata.category(ch)[0] in ("C", "Z"):
            raise ValueError(
                f"{what} contains a forbidden character (U+{ord(ch):04X}): "
                "control, format, whitespace and separator characters are not allowed"
            )
    return value


def check_ttl(ttl: object) -> int:
    """TTL must be a positive int (bool and float are rejected)."""
    if isinstance(ttl, bool) or not isinstance(ttl, int):
        raise ValueError("ttl must be an integer number of seconds")  # noqa: TRY004 - callers map ValueError to a policy denial
    if ttl <= 0:
        raise ValueError("ttl must be positive")
    return ttl
