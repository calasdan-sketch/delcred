"""Trust registry for external subject-token issuers (IdPs).

delcred is not an IdP: it never implements login, password, or OAuth
authorization flows. But it *accepts* subject tokens minted by your IdP —
configure each trusted issuer once in ``policy.yaml``::

    trusted_issuers:
      "https://idp.example.com": "trusted_issuers/idp.pem"

The value is a PEM file holding the issuer's **Ed25519 public key**
(relative paths resolve against the delcred home), or a mapping::

    trusted_issuers:
      "https://idp.example.com":
        key: "trusted_issuers/idp.pem"
        audience: "https://delcred.acme.internal"   # default: "delcred"

Subject tokens from an external issuer MUST carry that audience in ``aud``
— an IdP token minted for some other app cannot be replayed into delcred. Only ``EdDSA`` subject
tokens are accepted, mirroring the local token policy — delcred never
touches RSA/ECDSA confusion territory.

``delcred trust-add --iss URL --key-file ./idp-pub.pem`` manages this
section for you.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from ._common import ISSUER_ID, home


class TrustConfigError(ValueError):
    """The trusted_issuers configuration is malformed."""


def _policy_path(base: Path) -> Path:
    return base / "policy.yaml"


def trusted_issuers(base: Path | None = None) -> dict[str, Ed25519PublicKey]:
    """Load ``{iss: Ed25519PublicKey}`` from the policy file's trusted_issuers section."""
    return {iss: key for iss, (key, _aud) in trusted_issuer_configs(base).items()}


def trusted_issuer_configs(
    base: Path | None = None,
) -> dict[str, tuple[Ed25519PublicKey, str]]:
    """Load ``{iss: (Ed25519PublicKey, required_audience)}``."""
    home_ = base or home()
    p = _policy_path(home_)
    if not p.exists():
        return {}
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise TrustConfigError(f"cannot parse {p}: {e}") from e
    raw = data.get("trusted_issuers") or {}
    if not isinstance(raw, dict):
        raise TrustConfigError("policy.yaml: 'trusted_issuers' must be a mapping of iss -> key file")
    out: dict[str, tuple[Ed25519PublicKey, str]] = {}
    for iss, entry in raw.items():
        audience = ISSUER_ID
        key_file = entry
        if isinstance(entry, dict):
            key_file = entry.get("key")
            audience = entry.get("audience", ISSUER_ID)
            if not isinstance(audience, str) or not audience:
                raise TrustConfigError(
                    f"policy.yaml: trusted_issuers[{iss!r}].audience must be a non-empty string"
                )
        if not isinstance(iss, str) or not iss:
            raise TrustConfigError("policy.yaml: trusted_issuers keys must be non-empty issuer strings")
        if iss == ISSUER_ID:
            raise TrustConfigError(
                f"policy.yaml: trusted_issuers must not shadow the local issuer {ISSUER_ID!r}"
            )
        if not isinstance(key_file, str) or not key_file:
            raise TrustConfigError(f"policy.yaml: trusted_issuers[{iss!r}] must name a PEM key file")
        kp = Path(key_file)
        if not kp.is_absolute():
            kp = home_ / kp
        if not kp.exists():
            raise TrustConfigError(f"policy.yaml: trusted_issuers[{iss!r}]: key file not found: {kp}")
        try:
            key = load_pem_public_key(kp.read_bytes())
        except Exception as e:
            raise TrustConfigError(
                f"policy.yaml: trusted_issuers[{iss!r}]: cannot load public key from {kp}: {e}"
            ) from e
        if not isinstance(key, Ed25519PublicKey):
            raise TrustConfigError(
                f"policy.yaml: trusted_issuers[{iss!r}]: key in {kp} is not Ed25519 "
                "(delcred accepts EdDSA subject tokens only)"
            )
        out[iss] = (key, audience)
    return out


def add_trusted_issuer(
    iss: str, key_file: str, base: Path | None = None, audience: str | None = None
) -> Path:
    """Copy an IdP's Ed25519 public key into the home and register it.

    Returns the path the key was stored at. Updates (or appends) the
    ``trusted_issuers`` section of policy.yaml.
    """
    home_ = base or home()
    src = Path(key_file)
    if not src.exists():
        raise TrustConfigError(f"key file not found: {src}")
    try:
        key = load_pem_public_key(src.read_bytes())
    except Exception as e:
        raise TrustConfigError(f"cannot load public key from {src}: {e}") from e
    if not isinstance(key, Ed25519PublicKey):
        raise TrustConfigError(f"{src} is not an Ed25519 public key")
    if iss == ISSUER_ID:
        raise TrustConfigError(f"refusing to shadow the local issuer {ISSUER_ID!r}")
    if '"' in iss or "\n" in iss or not iss.strip():
        raise TrustConfigError(f"issuer {iss!r} is not a valid issuer string")
    if audience is not None and (not audience.strip() or '"' in audience or "\n" in audience):
        raise TrustConfigError(f"audience {audience!r} is not valid")

    dest_dir = home_ / "trusted_issuers"
    dest_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    slug = re.sub(r"[^A-Za-z0-9_.-]", "_", iss).strip("._") or "idp"
    dest = dest_dir / f"{slug}.pem"
    # Two distinct issuers can slug to the same filename — never silently
    # overwrite one issuer's key with another's.
    if dest.exists() and dest.read_bytes() != src.read_bytes():
        n = 2
        while (dest_dir / f"{slug}-{n}.pem").exists():
            n += 1
        dest = dest_dir / f"{slug}-{n}.pem"
    shutil.copyfile(src, dest)
    try:
        dest.chmod(0o644)
    except OSError:
        pass

    # Validate the resulting registry before returning (fail closed if the
    # written config does not load).
    rel = dest.relative_to(home_).as_posix()
    _upsert_policy_mapping(home_, iss, rel, audience)
    trusted_issuers(home_)
    return dest


def _upsert_policy_mapping(home_: Path, iss: str, rel: str, audience: str | None = None) -> None:
    p = _policy_path(home_)
    text = p.read_text(encoding="utf-8") if p.exists() else ""
    if audience is not None:
        data = yaml.safe_load(text) or {}
        section = data.get("trusted_issuers") or {}
        if not isinstance(section, dict):
            raise TrustConfigError("policy.yaml: 'trusted_issuers' must be a mapping")
        section[iss] = {"key": rel, "audience": audience}
        data["trusted_issuers"] = section
        p.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        return
    if "trusted_issuers:" not in text:
        # Append a new section — leaves hand-edited content byte-identical.
        if text and not text.endswith("\n"):
            text += "\n"
        text += f'\ntrusted_issuers:\n  "{iss}": "{rel}"\n'
        p.write_text(text, encoding="utf-8")
        return
    data = yaml.safe_load(text) or {}
    section = data.get("trusted_issuers") or {}
    if not isinstance(section, dict):
        raise TrustConfigError("policy.yaml: 'trusted_issuers' must be a mapping")
    section[iss] = rel
    data["trusted_issuers"] = section
    p.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
