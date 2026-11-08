"""Sender-constrained tokens: DPoP (RFC 9449) with Ed25519.

A bearer token that leaks (prompt injection, a log line, a compromised tool)
is usable by anyone. A token bound to a key (``cnf.jkt``) is useless without
the private key: every request carries a short-lived *proof* signed by that
key, naming the HTTP method, URL and the token's hash (``ath``).

Client side::

    key = pop.generate_key()
    tok = delcred.delegate(..., dpop_jkt=pop.thumbprint(key))
    proof = pop.make_proof(key, "GET", "https://api.acme.test/v1/invoices", access_token=tok)
    # send:  Authorization: DPoP <tok>   +   DPoP: <proof>

Server side: ``delcred.verify(tok, ..., dpop_proof=proof, http_method="GET",
http_url=...)`` or :func:`delcred.mcp.authorize` with ``dpop=``.

Only Ed25519 (``EdDSA``) keys are accepted. Replay protection is a
process-local jti cache (see :class:`ReplayCache`); run one verifier process
or share the cache if you scale out.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import keys as _keys
from ._jws import (
    JWSError,
    b64url_decode,
    b64url_encode,
    check_header,
    ed25519_verify,
    is_safe_int,
    parse_compact,
    sign_compact,
)

MAX_PROOF_BYTES = 4096
PROOF_MAX_AGE = 120  # seconds a proof stays acceptable after its iat
PROOF_LEEWAY = 60  # clock skew into the future


class PopError(Exception):
    """A DPoP proof was missing, malformed, mismatched or replayed."""


def generate_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _x(pub: Ed25519PublicKey) -> str:
    return b64url_encode(
        pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def public_jwk(key: Ed25519PrivateKey | Ed25519PublicKey) -> dict[str, str]:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return {"kty": "OKP", "crv": "Ed25519", "x": _x(pub)}


def thumbprint(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    """RFC 7638 JWK thumbprint — the value that goes into ``cnf.jkt``."""
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return _keys.key_id(pub)


def jwk_thumbprint(jwk: dict) -> str:
    """Thumbprint of a received OKP/Ed25519 JWK (validated)."""
    if (
        jwk.get("kty") != "OKP"
        or jwk.get("crv") != "Ed25519"
        or not isinstance(jwk.get("x"), str)
        or "d" in jwk
        or len(b64url_decode(jwk["x"])) != 32
    ):
        raise PopError("proof key must be a public Ed25519 OKP JWK")
    canon = f'{{"crv":"Ed25519","kty":"OKP","x":"{jwk["x"]}"}}'
    return b64url_encode(hashlib.sha256(canon.encode()).digest())


def normalize_htu(url: str) -> str:
    """RFC 9449 §4.3: compare scheme/host/path only (no query, no fragment)."""
    p = urlsplit(url)
    if not p.scheme or not p.hostname:
        raise PopError("htu must be an absolute URL")
    scheme = p.scheme.lower()
    host = p.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    try:
        port = p.port
    except ValueError as e:
        raise PopError("htu has an invalid port") from e
    default = {"http": 80, "https": 443}.get(scheme)
    netloc = host if port is None or port == default else f"{host}:{port}"
    return f"{scheme}://{netloc}{p.path or '/'}"


def access_token_hash(access_token: str) -> str:
    try:
        raw = access_token.encode("ascii")
    except UnicodeEncodeError as e:
        raise PopError("access token is not ASCII") from e
    return b64url_encode(hashlib.sha256(raw).digest())


def make_proof(
    key: Ed25519PrivateKey,
    method: str,
    url: str,
    *,
    access_token: str | None = None,
    nonce: str | None = None,
    now: int | None = None,
) -> str:
    """Build a DPoP proof JWT for one request."""
    claims: dict = {
        "jti": secrets.token_urlsafe(16),
        "htm": method,
        "htu": normalize_htu(url),
        "iat": int(time.time()) if now is None else now,
    }
    if access_token is not None:
        claims["ath"] = access_token_hash(access_token)
    if nonce:
        claims["nonce"] = nonce
    header = {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": public_jwk(key)}
    return sign_compact(header, claims, key)


class ReplayCache:
    """Remembers proof ``jti``s until they can no longer be accepted.

    Bounded: ``per_key`` entries per key thumbprint (so one key cannot evict
    another's), ``max_total`` overall. When a bound is hit the proof is
    REFUSED (fail closed) rather than an old entry silently evicted.
    """

    def __init__(self, per_key: int = 2000, max_total: int = 200_000):
        self.per_key = per_key
        self.max_total = max_total
        self._seen: dict[tuple[str, str], int] = {}
        self._count: dict[str, int] = {}
        self._lock = threading.Lock()

    def _purge(self, now: int) -> None:
        dead = [k for k, exp in self._seen.items() if exp < now]
        for k in dead:
            del self._seen[k]
            self._count[k[0]] -= 1
            if not self._count[k[0]]:
                del self._count[k[0]]

    def add(self, jkt: str, jti: str, expires: int, now: int) -> None:
        with self._lock:
            if len(self._seen) >= self.max_total // 2 or self._count.get(jkt, 0) >= self.per_key:
                self._purge(now)
            if (jkt, jti) in self._seen:
                raise PopError("DPoP proof replayed")
            if self._count.get(jkt, 0) >= self.per_key or len(self._seen) >= self.max_total:
                raise PopError("DPoP replay cache is full for this key; try again shortly")
            self._seen[(jkt, jti)] = expires
            self._count[jkt] = self._count.get(jkt, 0) + 1


DEFAULT_CACHE = ReplayCache()


def verify_proof(
    proof: object,
    *,
    method: str,
    url: str,
    access_token: str | None = None,
    expected_jkt: str | None = None,
    now: int | None = None,
    cache: ReplayCache | None = None,
) -> str:
    """Validate a DPoP proof; returns the proof key's thumbprint (``jkt``).

    Checks, in order: structure, ``typ=dpop+jwt``, EdDSA, embedded public
    key, signature, ``htm``, ``htu``, ``iat`` window, ``ath`` (when an access
    token is presented), key == ``expected_jkt``, then burns the ``jti``.
    """
    t = int(time.time()) if now is None else now
    if not isinstance(proof, str) or not proof or len(proof) > MAX_PROOF_BYTES:
        raise PopError("DPoP proof missing or oversized")
    try:
        header, claims, signing_input, sig = parse_compact(proof)
        check_header(header, allow_jwk=True)
    except JWSError as e:
        raise PopError(f"malformed DPoP proof: {e}") from e
    if header.get("typ") != "dpop+jwt":
        raise PopError("DPoP proof typ must be 'dpop+jwt'")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise PopError("DPoP proof header lacks a jwk")
    try:
        jkt = jwk_thumbprint(jwk)
    except JWSError as e:
        raise PopError(str(e)) from e
    if not ed25519_verify(jwk["x"], signing_input, sig):
        raise PopError("DPoP proof signature invalid")
    jti, htm, htu, iat = (claims.get(k) for k in ("jti", "htm", "htu", "iat"))
    if not (isinstance(jti, str) and 0 < len(jti) <= 256):
        raise PopError("DPoP proof lacks a jti")
    if htm != method:
        raise PopError("DPoP proof htm does not match the request method")
    if not isinstance(htu, str) or normalize_htu(htu) != normalize_htu(url):
        raise PopError("DPoP proof htu does not match the request URL")
    if not is_safe_int(iat):
        raise PopError("DPoP proof iat missing")
    if iat < t - PROOF_MAX_AGE or iat > t + PROOF_LEEWAY:
        raise PopError("DPoP proof is outside the acceptable time window")
    if access_token is not None:
        ath = claims.get("ath")
        if not isinstance(ath, str) or not hmac.compare_digest(
            ath.encode(), access_token_hash(access_token).encode()
        ):
            raise PopError("DPoP proof ath does not match the access token")
    if expected_jkt is not None and not hmac.compare_digest(jkt.encode(), expected_jkt.encode()):
        raise PopError("DPoP proof key does not match the token's cnf.jkt")
    (cache or DEFAULT_CACHE).add(jkt, jti, iat + PROOF_MAX_AGE + PROOF_LEEWAY, t)
    return jkt
