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

from ._common import assert_private, home, write_private


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
    return serialization.load_pem_private_key(priv_path.read_bytes(), password=None)


def load_public(base: Path | None = None) -> Ed25519PublicKey:
    _, pub_path = key_paths(base)
    if not pub_path.exists():
        raise FileNotFoundError(
            f"no issuer public key at {pub_path} — run `delcred init` first"
        )
    return serialization.load_pem_public_key(pub_path.read_bytes())


def public_key_pem_b64url(pub: Ed25519PublicKey) -> str:
    """Raw 32-byte public key, base64url — for embedding in agent identity records."""
    import base64

    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")
