"""Signed revocation bulletins: revocation that third-party verifiers can see.

A bare JWKS lets any resource server check signatures but tells it nothing
about revocation; a stolen token then lives until it expires. The issuer
therefore publishes a small, short-lived, *signed* list of everything it has
revoked. A verifier fetches it every few seconds (or on each request, it is
tiny) and passes it to :func:`delcred.offline.verify_offline`.

The bulletin is an EdDSA JWS (``typ: delcred-rev+jwt``) signed by the issuer
key, so a network attacker cannot forge an empty one, and it carries
``iat``/``exp`` so replaying an old (pre-revocation) bulletin is refused
once it is older than the verifier's ``bulletin_max_age``. It lists only
non-expired entries; ``seq`` increases monotonically so verifiers can detect
rollback.
"""

from __future__ import annotations

import time
from pathlib import Path

from . import keys as _keys
from ._common import ISSUER_ID, home
from ._jws import sign_compact
from .offline import BULLETIN_MAX_AGE, BULLETIN_TYP
from .revocation import RevocationList


def export(base: Path | None = None, *, ttl: int = BULLETIN_MAX_AGE) -> str:
    """Return the current signed bulletin (compact JWS)."""
    h = base or home()
    snap = RevocationList(h).snapshot()
    now = int(time.time())
    priv = _keys.load_private(h)
    payload = {
        "iss": ISSUER_ID,
        "iat": now,
        "exp": now + ttl,
        "seq": time.time_ns() // 1_000_000,  # monotonic across restarts
        **snap,
    }
    header = {"alg": "EdDSA", "typ": BULLETIN_TYP, "kid": _keys.key_id(priv.public_key())}
    return sign_compact(header, payload, priv)
