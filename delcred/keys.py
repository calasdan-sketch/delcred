"""Ed25519 issuer key management.

The issuer key is the root of trust for every credential delcred mints.
It lives at ``$DELCRED_HOME/issuer.key`` with 0600 permissions; delcred
refuses to load a key file that is group/world readable.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._common import HomeError, assert_private, home, write_private


def key_paths(base: Path | None = None) -> tuple[Path, Path]:
    h = base or home()
    return h / "issuer.key", h / "issuer.pub"


def generate(base: Path | None = None) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 issuer keypair and store it (0600)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_path, pub_path = key_paths(base)
    write_private(
        priv_path,
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    pub_path.write_bytes(
        pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    try:
        pub_path.chmod(0o644)
    except OSError:
        pass
    return priv, pub


def load_private(base: Path | None = None) -> Ed25519PrivateKey:
    priv_path, _ = key_paths(base)
    if not priv_path.exists():
        raise FileNotFoundError(
            f"no issuer key at {priv_path} — run `delcred init` first"
        )
    assert_private(priv_path)
    try:
        key = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    except (ValueError, TypeError) as e:
        raise HomeError(
            f"issuer key {priv_path} is damaged or not an unencrypted Ed25519 PEM key; "
            "restore it from a backup (or `delcred init --force` to start over, "
            "which invalidates every token and key issued so far)"
        ) from e
    if not isinstance(key, Ed25519PrivateKey):
        raise HomeError(f"issuer key {priv_path} is not an Ed25519 key")
    return key


def load_public(base: Path | None = None) -> Ed25519PublicKey:
    _, pub_path = key_paths(base)
    if not pub_path.exists():
        raise FileNotFoundError(
            f"no issuer public key at {pub_path} — run `delcred init` first"
        )
    try:
        key = serialization.load_pem_public_key(pub_path.read_bytes())
    except (ValueError, TypeError) as e:
        raise HomeError(f"issuer public key {pub_path} is damaged; re-create it with `delcred init --force` (invalidates all tokens)") from e
    if not isinstance(key, Ed25519PublicKey):
        raise HomeError(f"issuer public key {pub_path} is not an Ed25519 key")
    return key


def _b64url(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def key_id(pub: Ed25519PublicKey) -> str:
    """RFC 7638 JWK thumbprint (SHA-256, base64url) — stable ``kid``."""
    import hashlib
    import json

    x = _b64url(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    canon = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"))
    return _b64url(hashlib.sha256(canon.encode()).digest())


def public_jwk(pub: Ed25519PublicKey) -> dict[str, str]:
    """RFC 8037 OKP JWK for the issuer key (public half only)."""
    x = _b64url(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
        "kid": key_id(pub),
        "alg": "EdDSA",
        "use": "sig",
    }


# -- rotation with an overlap window -----------------------------------------
#
# A routine rotation must not kill every live token (agent identity tokens
# live 24 h by default). ``rotate(keep_old=...)`` moves the old public key to
# ``retired/<kid>.json`` with a deadline; until then it still VERIFIES but
# never signs, and it is published in the JWKS so third-party verifiers keep
# working. After a suspected compromise use a hard cut (``keep_old=0``).


def _retired_dir(base: Path | None) -> Path:
    return (base or home()) / "retired"


def retired_keys(base: Path | None = None, *, now: int | None = None) -> dict[str, Ed25519PublicKey]:
    """Retired-but-still-valid verification keys: ``{kid: public key}``."""
    import json
    import time

    t = int(time.time()) if now is None else now
    out: dict[str, Ed25519PublicKey] = {}
    d = _retired_dir(base)
    if not d.is_dir():
        return out
    for f in sorted(d.glob("*.json")):
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
            if int(rec["retire_after"]) < t:
                continue
            pub = serialization.load_pem_public_key(rec["pem"].encode())
            if isinstance(pub, Ed25519PublicKey) and key_id(pub) == rec["kid"] == f.stem:
                out[rec["kid"]] = pub
        except (OSError, KeyError, ValueError, TypeError):
            continue  # a damaged record never widens trust
    return out


def rotate(base: Path | None = None, *, keep_old: int = 0):
    """Generate a new issuer key. ``keep_old`` seconds of overlap (0 = hard cut).

    Returns ``(priv, pub, retired_kid | None)``.
    """
    import json
    import time

    h = base or home()
    retired_kid = None
    if keep_old > 0:
        try:
            old = load_public(h)
        except FileNotFoundError:
            old = None
        if old is not None:
            retired_kid = key_id(old)
            d = _retired_dir(h)
            d.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_private(
                d / f"{retired_kid}.json",
                json.dumps(
                    {
                        "kid": retired_kid,
                        "retire_after": int(time.time()) + int(keep_old),
                        "pem": old.public_bytes(
                            serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo,
                        ).decode(),
                    }
                ).encode(),
            )
    else:
        # Hard cut also forgets earlier overlaps: a compromised key must not survive.
        d = _retired_dir(h)
        if d.is_dir():
            for f in d.glob("*.json"):
                f.unlink(missing_ok=True)
    priv, pub = generate(h)
    return priv, pub, retired_kid


def retire(kid: str, base: Path | None = None) -> bool:
    """Stop trusting one retired key immediately. Returns True if it existed."""
    import re

    if not isinstance(kid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", kid):
        return False
    f = _retired_dir(base) / f"{kid}.json"
    if f.is_file() and f.parent.resolve() == _retired_dir(base).resolve():
        f.unlink()
        return True
    return False


def verification_keys(base: Path | None = None) -> dict[str, Ed25519PublicKey]:
    """Every key that may verify a delcred token right now: current + retired."""
    cur = load_public(base)
    keys = retired_keys(base)
    keys[key_id(cur)] = cur
    return keys


def jwks(base: Path | None = None) -> dict[str, list[dict[str, str]]]:
    """JWK Set publishing the current (and any still-valid retired) key (RFC 7517)."""
    cur = load_public(base)
    out = [public_jwk(cur)]
    out += [public_jwk(p) for k, p in retired_keys(base).items() if k != key_id(cur)]
    return {"keys": out}


def public_key_pem_b64url(pub: Ed25519PublicKey) -> str:
    """Raw 32-byte public key, base64url — for embedding in agent identity records."""
    import base64

    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")
