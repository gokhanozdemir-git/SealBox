import pytest
from hypothesis import given
from hypothesis import strategies as st

from sealbox.core.crypto import (
    NONCE_BYTES,
    AesGcmCipher,
    generate_key,
    wipe,
)
from sealbox.core.errors import CryptoError


def test_roundtrip_exact():
    c = AesGcmCipher(generate_key())
    data = "şifre: ğüşıöç \r\n\x00 end".encode()
    assert c.decrypt(c.encrypt(data, b"aad"), b"aad") == data


@given(st.binary(max_size=4096), st.binary(max_size=64))
def test_roundtrip_property(data, aad):
    c = AesGcmCipher(generate_key())
    assert c.decrypt(c.encrypt(data, aad), aad) == data


def test_tampered_ciphertext_fails():
    c = AesGcmCipher(generate_key())
    blob = bytearray(c.encrypt(b"top secret"))
    blob[-1] ^= 0x01
    with pytest.raises(CryptoError):
        c.decrypt(bytes(blob))


def test_wrong_key_fails():
    blob = AesGcmCipher(generate_key()).encrypt(b"top secret")
    with pytest.raises(CryptoError):
        AesGcmCipher(generate_key()).decrypt(blob)


def test_wrong_aad_fails():
    c = AesGcmCipher(generate_key())
    blob = c.encrypt(b"v", b"placeholder-A")
    with pytest.raises(CryptoError):
        c.decrypt(blob, b"placeholder-B")


def test_malformed_blob_rejected():
    c = AesGcmCipher(generate_key())
    with pytest.raises(CryptoError):
        c.decrypt(b"\x01short")
    with pytest.raises(CryptoError):
        c.decrypt(b"\x02" + b"\x00" * 40)


def test_nonce_unique_per_encryption():
    c = AesGcmCipher(generate_key())
    nonces = {c.encrypt(b"same")[1 : 1 + NONCE_BYTES] for _ in range(2000)}
    assert len(nonces) == 2000


def test_same_plaintext_different_ciphertext():
    c = AesGcmCipher(generate_key())
    assert c.encrypt(b"x") != c.encrypt(b"x")


def test_bad_key_length():
    with pytest.raises(CryptoError):
        AesGcmCipher(b"\x00" * 16)


def test_repr_hides_key():
    key = generate_key()
    assert key.hex() not in repr(AesGcmCipher(key))


def test_wipe_zeroes_buffer():
    key = generate_key()
    wipe(key)
    assert key == bytearray(32)
