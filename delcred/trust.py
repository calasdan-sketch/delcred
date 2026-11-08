"""Trust registry for external subject-token issuers (IdPs).

delcred is not an IdP: it never implements login, password, or OAuth
authorization flows. But it *accepts* subject tokens minted by your IdP —
configure each trusted issuer once in ``policy.yaml``::

    trusted_issuers:
      "https://idp.example.com": "trusted_issuers/idp.pem"

A plain string value is a PEM file holding the issuer's **Ed25519 public
key** (relative paths resolve against the delcred home); its tokens must be
``EdDSA``. For IdPs that sign with RS256 or ES256 (Okta, Auth0, Entra), use
the mapping form, which pins exactly one algorithm to that issuer::

    trusted_issuers:
      "https://okta.example.com": {key: "trusted_issuers/okta.pem", alg: RS256}

The key type must match the algorithm (RS256: RSA >= 2048 bits; ES256: EC
P-256; EdDSA: Ed25519) and tokens are verified with that one algorithm only,
so a token cannot pick its own algorithm (no RSA/HMAC confusion).

``delcred trust-add --iss URL --key-file ./idp-pub.pem [--alg RS256]``
manages this section for you.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from ._common import ISSUER_ID, home


class TrustConfigError(ValueError):
    """The trusted_issuers configuration is malformed."""


def _policy_path(base: Path) -> Path:
    return base / "policy.yaml"


ALGS = ("EdDSA", "RS256", "ES256")


def _key_mismatch(key, alg: str) -> str | None:
    """Return why ``key`` cannot verify ``alg`` tokens, or None if it fits."""
    if alg == "EdDSA" and not isinstance(key, Ed25519PublicKey):
        return "EdDSA requires an Ed25519 key"
    if alg == "RS256" and not (isinstance(key, RSAPublicKey) and key.key_size >= 2048):
        return "RS256 requires an RSA key of at least 2048 bits"
    if alg == "ES256" and not (
        isinstance(key, EllipticCurvePublicKey) and isinstance(key.curve, SECP256R1)
    ):
        return "ES256 requires an EC P-256 key"
    if alg not in ALGS:
        return f"alg must be one of {', '.join(ALGS)}, not {alg!r}"
    return None


def trusted_issuers(base: Path | None = None) -> dict:
    """Load ``{iss: public_key}`` from the policy file's trusted_issuers section."""
    return {iss: key for iss, (key, _) in trusted_issuer_algs(base).items()}


def trusted_issuer_algs(base: Path | None = None) -> dict:
    """Load ``{iss: (public_key, alg)}``: each issuer's key and its one pinned alg."""
    home_ = base or home()
    p = _policy_path(home_)
    if not p.exists():
        return {}
    try:
        data = yaml.safe_load(p.read_text()) or {}
    except yaml.YAMLError as e:
        raise TrustConfigError(f"cannot parse {p}: {e}") from e
    raw = data.get("trusted_issuers") or {}
    if not isinstance(raw, dict):
        raise TrustConfigError("policy.yaml: 'trusted_issuers' must be a mapping of iss -> key file")
    out: dict = {}
    for iss, entry in raw.items():
        if not isinstance(iss, str) or not iss:
            raise TrustConfigError("policy.yaml: trusted_issuers keys must be non-empty issuer strings")
        if iss == ISSUER_ID:
            raise TrustConfigError(
                f"policy.yaml: trusted_issuers must not shadow the local issuer {ISSUER_ID!r}"
            )
        key_file, alg = entry, "EdDSA"
        if isinstance(entry, dict):
            key_file, alg = entry.get("key"), entry.get("alg")
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
        why = _key_mismatch(key, alg)
        if why:
            raise TrustConfigError(f"policy.yaml: trusted_issuers[{iss!r}]: {kp}: {why}")
        out[iss] = (key, alg)
    return out


def add_trusted_issuer(
    iss: str, key_file: str, base: Path | None = None, alg: str = "EdDSA"
) -> Path:
    """Copy an IdP's public key into the home and register it, pinned to ``alg``.

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
    why = _key_mismatch(key, alg)
    if why:
        raise TrustConfigError(f"{src}: {why}")
    if iss == ISSUER_ID:
        raise TrustConfigError(f"refusing to shadow the local issuer {ISSUER_ID!r}")
    if '"' in iss or "\n" in iss or not iss.strip():
        raise TrustConfigError(f"issuer {iss!r} is not a valid issuer string")

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
    _upsert_policy_mapping(home_, iss, rel if alg == "EdDSA" else {"key": rel, "alg": alg})
    trusted_issuers(home_)
    return dest


def _upsert_policy_mapping(home_: Path, iss: str, rel) -> None:
    p = _policy_path(home_)
    text = p.read_text() if p.exists() else ""
    if "trusted_issuers:" not in text:
        # Append a new section — leaves hand-edited content byte-identical.
        if text and not text.endswith("\n"):
            text += "\n"
        # JSON is valid YAML flow syntax: quotes the path (and the mapping form).
        text += f'\ntrusted_issuers:\n  "{iss}": {json.dumps(rel)}\n'
        p.write_text(text)
        return
    data = yaml.safe_load(text) or {}
    section = data.get("trusted_issuers") or {}
    if not isinstance(section, dict):
        raise TrustConfigError("policy.yaml: 'trusted_issuers' must be a mapping")
    section[iss] = rel
    data["trusted_issuers"] = section
    p.write_text(yaml.safe_dump(data, sort_keys=False))
