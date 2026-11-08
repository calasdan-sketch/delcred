"""Minimal, strict compact-JWS handling shared by every verifier in delcred.

The Python reference verifier (`delcred.offline`) and the Node/Go verifiers in
``spec/`` all implement exactly these rules, so they agree on every vector.
No PyJWT here: a verifier small enough to port is a verifier that can be
audited and re-implemented in another language.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, TypeGuard

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._common import MAX_TOKEN_BYTES

_B64URL = re.compile(r"[A-Za-z0-9_-]*\Z")
# Header parameters that carry or point at key material. An access token
# never legitimately uses them, and honouring them is the classic JWT
# key-injection bug, so their presence is a hard failure.
FORBIDDEN_HEADERS = ("jwk", "jku", "x5u", "x5c", "x5t", "x5t#S256", "crit")


class JWSError(Exception):
    """Structural problem with a compact JWS (maps to ``invalid_token``)."""


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    if not _B64URL.match(text):
        raise JWSError("segment is not base64url without padding")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as e:
        raise JWSError("segment is not valid base64url") from e
    if b64url_encode(raw) != text:
        # Non-zero trailing bits decode to the same bytes in some languages'
        # decoders and are rejected by others: a malleability and
        # cross-language disagreement. Require the canonical encoding.
        raise JWSError("segment is not canonical base64url")
    return raw


MAX_SAFE_INT = 2**53 - 1


def is_safe_int(v: Any) -> TypeGuard[int]:
    """A JSON integer every language can hold exactly: not bool, |v| <= 2**53 - 1."""
    return isinstance(v, int) and not isinstance(v, bool) and abs(v) <= MAX_SAFE_INT


def _no_constant(name: str):
    raise ValueError(f"{name} is not valid JSON")


MAX_JSON_DEPTH = 32


def _check_depth(obj: Any, what: str) -> None:
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        v, d = stack.pop()
        if isinstance(v, (dict, list)):
            if d > MAX_JSON_DEPTH:
                raise JWSError(f"{what} is nested deeper than {MAX_JSON_DEPTH} levels")
            stack.extend((c, d + 1) for c in (v.values() if isinstance(v, dict) else v))


def _json_object(raw: bytes, what: str) -> dict[str, Any]:
    def no_dups(pairs):
        d: dict[str, Any] = {}
        for k, v in pairs:
            if k in d:
                raise JWSError(f"{what} has a duplicate member {k!r}")
            d[k] = v
        return d

    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=no_dups, parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as e:  # JSONDecodeError is a ValueError
        raise JWSError(f"{what} is not valid UTF-8 JSON") from e
    if not isinstance(obj, dict):
        raise JWSError(f"{what} is not a JSON object")
    _check_depth(obj, what)
    return obj


def parse_compact(token: object) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Split ``h.p.s`` → ``(header, payload, signing_input, signature)``."""
    if not isinstance(token, str):
        raise JWSError("token must be a string")
    if len(token) > MAX_TOKEN_BYTES:
        raise JWSError(f"token longer than {MAX_TOKEN_BYTES} bytes")
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise JWSError("token is not a three-segment compact JWS")
    header = _json_object(b64url_decode(parts[0]), "header")
    payload = _json_object(b64url_decode(parts[1]), "payload")
    sig = b64url_decode(parts[2])
    return header, payload, (parts[0] + "." + parts[1]).encode("ascii"), sig


def check_header(header: dict[str, Any], *, allow_jwk: bool = False) -> None:
    """``allow_jwk`` is for DPoP proofs only, whose header MUST carry the key."""
    if header.get("alg") != "EdDSA":
        raise JWSError(f"alg {header.get('alg')!r} not accepted; only EdDSA")
    for name in FORBIDDEN_HEADERS:
        if name == "jwk" and allow_jwk:
            continue
        if name in header:
            raise JWSError(f"header parameter {name!r} is not accepted")


def ed25519_verify(public_x: str, signing_input: bytes, sig: bytes) -> bool:
    """Verify an Ed25519 signature against a JWK ``x`` value."""
    try:
        raw = b64url_decode(public_x)
        if len(raw) != 32 or len(sig) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, signing_input)
        return True
    except (InvalidSignature, JWSError, ValueError):
        return False


def sign_compact(header: dict[str, Any], payload: dict[str, Any], private_key) -> str:
    """Sign with an Ed25519 private key; canonical JSON (sorted, compact)."""
    h = b64url_encode(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    sig = private_key.sign(f"{h}.{p}".encode("ascii"))
    return f"{h}.{p}.{b64url_encode(sig)}"
