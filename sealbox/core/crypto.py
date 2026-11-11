"""AES-256-GCM encryption.

- Keys come from ``secrets.token_bytes`` (a CSPRNG).
- Every encryption uses a fresh random 96-bit nonce. A single ``AesGcmCipher``
  instance refuses to reuse a nonce and stays below the NIST SP 800-38D limit
  for random nonces (2^32 messages per key).
- Wire format: ``version(1) || nonce(12) || ciphertext || tag(16)``.
"""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sealbox.core.errors import CryptoError
from sealbox.i18n import _

KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
_VERSION = b"\x01"
_MAX_MESSAGES = 2**32


def generate_key() -> bytearray:
    """Generate a new AES-256 key.

    A ``bytearray`` is returned so the caller can ``wipe`` it when done. Python cannot
    guarantee that memory is really cleared; this is best effort only.
    """
    return bytearray(secrets.token_bytes(KEY_BYTES))


def wipe(buf: bytearray) -> None:
    """Overwrite a mutable buffer with zeros (best effort)."""
    for i in range(len(buf)):
        buf[i] = 0


class AesGcmCipher:
    """AES-256-GCM cipher bound to a single key."""

    __slots__ = ("_aead", "_count", "_used_nonces")

    def __init__(self, key: bytes | bytearray) -> None:
        if len(key) != KEY_BYTES:
            raise CryptoError(_("AES-256 anahtarı 32 bayt olmalı"))
        self._aead = AESGCM(bytes(key))
        self._used_nonces: set[bytes] = set()
        self._count = 0

    def __repr__(self) -> str:
        return "AesGcmCipher(<key hidden>)"

    def _fresh_nonce(self) -> bytes:
        if self._count >= _MAX_MESSAGES:
            raise CryptoError(_("Anahtar başına şifreleme sınırı aşıldı; anahtarı yenileyin"))
        while True:
            nonce = secrets.token_bytes(NONCE_BYTES)
            if nonce not in self._used_nonces:
                self._used_nonces.add(nonce)
                self._count += 1
                return nonce

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        nonce = self._fresh_nonce()
        return _VERSION + nonce + self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, blob: bytes, aad: bytes = b"") -> bytes:
        if len(blob) < 1 + NONCE_BYTES + TAG_BYTES or blob[:1] != _VERSION:
            raise CryptoError(_("Şifreli veri biçimi geçersiz"))
        nonce = blob[1 : 1 + NONCE_BYTES]
        try:
            return self._aead.decrypt(nonce, blob[1 + NONCE_BYTES :], aad)
        except InvalidTag:
            raise CryptoError(
                _("Şifre çözme başarısız: veri değiştirilmiş veya anahtar yanlış")
            ) from None
