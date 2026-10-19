import os
import stat

import pytest

from delcred import keys


def test_generate_creates_keypair(tmp_path):
    keys.generate(tmp_path)
    priv, pub = keys.key_paths(tmp_path)
    assert priv.exists() and pub.exists()


def test_private_key_is_0600(tmp_path):
    keys.generate(tmp_path)
    priv, _ = keys.key_paths(tmp_path)
    assert stat.S_IMODE(priv.stat().st_mode) == 0o600


def test_refuses_world_readable_key(tmp_path):
    keys.generate(tmp_path)
    priv, _ = keys.key_paths(tmp_path)
    os.chmod(priv, 0o644)
    with pytest.raises(PermissionError):
        keys.load_private(tmp_path)


def test_refuses_group_readable_key(tmp_path):
    keys.generate(tmp_path)
    priv, _ = keys.key_paths(tmp_path)
    os.chmod(priv, 0o640)
    with pytest.raises(PermissionError):
        keys.load_private(tmp_path)


def test_load_roundtrip(tmp_path):
    _priv1, _ = keys.generate(tmp_path)
    assert keys.load_private(tmp_path) is not None
    pub = keys.load_public(tmp_path)
    assert pub is not None


def test_missing_key_helpful_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="delcred init"):
        keys.load_private(tmp_path)


def test_regenerate_overwrites(tmp_path):
    keys.generate(tmp_path)
    k1 = keys.load_private(tmp_path)
    keys.generate(tmp_path)
    k2 = keys.load_private(tmp_path)
    from cryptography.hazmat.primitives import serialization

    b1 = k1.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    b2 = k2.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    assert b1 != b2
