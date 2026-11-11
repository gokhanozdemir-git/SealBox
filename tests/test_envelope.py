import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from sealbox.core import envelope as e
from sealbox.core.crypto import generate_key
from sealbox.core.errors import CryptoError
from sealbox.core.tokenization import TokenVault
from sealbox.models.enums import SecretCategory


def test_ed25519_to_x25519_conversion_is_consistent():
    # The public half of the converted private key must equal the converted public key.
    for _ in range(25):
        k = ed25519.Ed25519PrivateKey.generate()
        x = e.ed25519_seed_to_x25519(k.private_bytes_raw())
        expected = e.ed25519_pub_to_x25519(k.public_key().public_bytes_raw())
        assert e.x25519_public_bytes(x) == expected


def test_x25519_wrap_roundtrip_and_rejections():
    dek = generate_key()
    priv = X25519PrivateKey.generate()
    blob = e.wrap_x25519(dek, e.x25519_public_bytes(priv), b"aad-1")
    assert bytes(dek) not in blob
    assert e.unwrap_x25519(blob, priv, b"aad-1") == dek
    with pytest.raises(CryptoError):
        e.unwrap_x25519(blob, priv, b"aad-2")  # different project/member
    with pytest.raises(CryptoError):
        e.unwrap_x25519(blob, X25519PrivateKey.generate(), b"aad-1")  # different key
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(CryptoError):
        e.unwrap_x25519(tampered, priv, b"aad-1")
    # Every wrap uses a fresh ephemeral key, so the same DEK looks different each time.
    assert e.wrap_x25519(dek, e.x25519_public_bytes(priv), b"aad-1") != blob


def test_rsa_wrap_roundtrip_and_small_keys_rejected():
    dek = generate_key()
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    blob = e.wrap_rsa(dek, priv.public_key(), b"aad")
    assert e.unwrap_rsa(blob, priv, b"aad") == dek
    with pytest.raises(CryptoError):
        e.unwrap_rsa(blob, priv, b"other")
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 - checks that small keys are rejected
    with pytest.raises(CryptoError):
        e.wrap_rsa(dek, small.public_key(), b"aad")


def test_recovery_code_roundtrip_and_typos():
    raw = e.new_code_secret()
    code = e.encode_code(raw)
    groups = code.split("-")
    assert len(groups) == 8 and all(len(g) == 4 for g in groups)
    assert e.decode_code(code) == raw
    # Lower case, spaces and O/0 or I/1 mix-ups are tolerated.
    sloppy = code.lower().replace("-", " ").replace("0", "o").replace("1", "i")
    assert e.decode_code(sloppy) == raw
    wrong = code[:-1] + ("A" if code[-1] != "A" else "B")
    with pytest.raises(CryptoError, match="yazım"):
        e.decode_code(wrong)
    with pytest.raises(CryptoError):
        e.decode_code(code[:-5])


def test_argon2id_is_deterministic_and_salted():
    salt = b"s" * 16
    a = e.argon2id_kek(b"secret", salt)
    assert len(a) == 32
    assert e.argon2id_kek(b"secret", salt) == a
    assert e.argon2id_kek(b"secret", b"t" * 16) != a
    assert e.argon2id_kek(b"secreT", salt) != a
    with pytest.raises(CryptoError):
        e.argon2id_kek(b"secret", b"short")
    assert e.ARGON2_PARAMS == {"memory_kib": 65536, "iterations": 3, "lanes": 4}


def test_rekeyed_vault_keeps_placeholders_and_drops_old_key():
    old = TokenVault()
    ph = old.placeholder_for("hunter2-value", SecretCategory.PASSWORD)
    old.bind_env(ph, "DB_PASSWORD")
    new_key = generate_key()
    new = old.rekeyed(new_key)
    assert new.reveal(ph) == "hunter2-value"
    assert new.env_bindings() == {"DB_PASSWORD": ph}
    assert new.placeholder_for("hunter2-value", SecretCategory.PASSWORD) == ph
    with pytest.raises(CryptoError):
        TokenVault.from_encrypted(new.export_encrypted(), old.key)
    assert e.dek_id(new.key) != e.dek_id(old.key)
