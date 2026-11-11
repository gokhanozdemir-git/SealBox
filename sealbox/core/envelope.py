"""Envelope encryption: locking the project key (DEK) with other keys (KEKs).

- The recovery code is never used as an AES key directly. Argon2id derives a 256-bit
  recovery KEK from it, and that KEK is used as an X25519 private key. Because the public
  half is stored, new DEKs can be locked to recovery without asking for the code.
- GitHub SSH keys: ed25519 keys are converted to X25519 the same way ``age`` does it
  (Edwards to Montgomery); RSA keys use OAEP-SHA256.
- Every lock is AES-256-GCM bound through its AAD to the project ID, the member and the
  key fingerprint, so a locked copy cannot be moved to another project or member.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sealbox.core.crypto import KEY_BYTES, AesGcmCipher, wipe
from sealbox.core.errors import CryptoError
from sealbox.i18n import _

# Second recommended option of RFC 9106: 64 MiB memory, 3 passes, 4 lanes.
ARGON2_PARAMS: dict[str, int] = {"memory_kib": 64 * 1024, "iterations": 3, "lanes": 4}
SALT_BYTES = 16
CODE_SECRET_BYTES = 16
_CODE_CHECK_BYTES = 4
_WRAP_INFO = b"sealbox/dek-wrap/v1"
_X25519_BYTES = 32
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CONFUSABLE = str.maketrans({"O": "0", "I": "1", "L": "1", "U": "V"})
_P = 2**255 - 19


# --- Argon2id ------------------------------------------------------------------


def argon2id_kek(secret: bytes, salt: bytes, params: dict[str, int] | None = None) -> bytearray:
    """Derive a 256-bit KEK from the recovery secret."""
    p = params or ARGON2_PARAMS
    if len(salt) < SALT_BYTES:
        raise CryptoError(_("Argon2id tuzu en az 16 bayt olmalı"))
    kdf = Argon2id(
        salt=salt,
        length=KEY_BYTES,
        iterations=p["iterations"],
        lanes=p["lanes"],
        memory_cost=p["memory_kib"],
    )
    return bytearray(kdf.derive(secret))


# --- Recovery code -------------------------------------------------------------


def _code_check(raw: bytes) -> bytes:
    return hashlib.sha256(b"sealbox/recovery-code\x00" + raw).digest()[:_CODE_CHECK_BYTES]


def new_code_secret() -> bytearray:
    return bytearray(secrets.token_bytes(CODE_SECRET_BYTES))


def encode_code(raw: bytes | bytearray) -> str:
    """16 bytes + 4-byte checksum -> 32 Crockford base32 characters in groups of four."""
    if len(raw) != CODE_SECRET_BYTES:
        raise CryptoError(_("Kurtarma sırrı 16 bayt olmalı"))
    data = bytes(raw) + _code_check(bytes(raw))
    n = int.from_bytes(data, "big")
    chars = [CROCKFORD[(n >> (5 * i)) & 31] for i in reversed(range(32))]
    return group4("".join(chars))


def group4(chars: str) -> str:
    return "-".join(chars[i : i + 4] for i in range(0, len(chars), 4))


def crockford_clean(text: str) -> str:
    """Drop spaces and dashes, upper-case, and map look-alike characters (O->0, I/L->1)."""
    return "".join(text.upper().split()).replace("-", "").translate(_CONFUSABLE)


def decode_code(text: str) -> bytearray:
    """Decode a recovery code, rejecting typos (wrong character, missing group)."""
    cleaned = crockford_clean(text)
    if len(cleaned) != 32 or any(c not in CROCKFORD for c in cleaned):
        raise CryptoError(_("Kurtarma kodu 8 grup × 4 harf olmalı"))
    n = 0
    for c in cleaned:
        n = (n << 5) | CROCKFORD.index(c)
    data = n.to_bytes(CODE_SECRET_BYTES + _CODE_CHECK_BYTES, "big")
    raw, check = data[:CODE_SECRET_BYTES], data[CODE_SECRET_BYTES:]
    if not hmac.compare_digest(check, _code_check(raw)):
        raise CryptoError(_("Kurtarma kodunda yazım hatası var"))
    return bytearray(raw)


# --- X25519 wrapping -----------------------------------------------------------


def x25519_private(raw: bytes | bytearray) -> X25519PrivateKey:
    if len(raw) != _X25519_BYTES:
        raise CryptoError(_("X25519 gizli anahtarı 32 bayt olmalı"))
    return X25519PrivateKey.from_private_bytes(bytes(raw))


def x25519_public_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes_raw()


def _wrap_key(shared: bytes, eph_pub: bytes, rcpt_pub: bytes) -> bytearray:
    if not any(shared):
        raise CryptoError(_("Geçersiz açık anahtar"))
    hkdf = HKDF(
        algorithm=hashes.SHA256(), length=KEY_BYTES, salt=eph_pub + rcpt_pub, info=_WRAP_INFO
    )
    return bytearray(hkdf.derive(shared))


def wrap_x25519(dek: bytes | bytearray, rcpt_pub: bytes, aad: bytes) -> bytes:
    """Lock the DEK to a recipient's X25519 public key: ``eph_pub(32) || AES-GCM(DEK)``."""
    try:
        rcpt = X25519PublicKey.from_public_bytes(rcpt_pub)
        eph = X25519PrivateKey.generate()
        eph_pub = x25519_public_bytes(eph)
        key = _wrap_key(eph.exchange(rcpt), eph_pub, rcpt_pub)
    except ValueError:
        raise CryptoError(_("Geçersiz açık anahtar")) from None
    try:
        return eph_pub + AesGcmCipher(key).encrypt(bytes(dek), aad)
    finally:
        wipe(key)


def unwrap_x25519(blob: bytes, priv: X25519PrivateKey, aad: bytes) -> bytearray:
    if len(blob) <= _X25519_BYTES:
        raise CryptoError(_("Kilitli anahtar biçimi geçersiz"))
    eph_pub = blob[:_X25519_BYTES]
    try:
        shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    except ValueError:
        raise CryptoError(_("Kilitli anahtar biçimi geçersiz")) from None
    key = _wrap_key(shared, eph_pub, x25519_public_bytes(priv))
    try:
        return bytearray(AesGcmCipher(key).decrypt(blob[_X25519_BYTES:], aad))
    finally:
        wipe(key)


# --- SSH ed25519 -> X25519 (as in age's ssh-ed25519 recipient) -----------------


def ed25519_pub_to_x25519(pub: bytes) -> bytes:
    """Map the Edwards y coordinate to Montgomery u: ``u = (1 + y) / (1 - y) mod p``."""
    if len(pub) != _X25519_BYTES:
        raise CryptoError(_("ed25519 açık anahtarı 32 bayt olmalı"))
    y = int.from_bytes(pub, "little") & ((1 << 255) - 1)
    if y >= _P or y == 1:
        raise CryptoError(_("Geçersiz ed25519 açık anahtarı"))
    u = (1 + y) * pow(1 - y, _P - 2, _P) % _P
    return u.to_bytes(_X25519_BYTES, "little")


def ed25519_seed_to_x25519(seed: bytes | bytearray) -> X25519PrivateKey:
    """The ed25519 secret scalar is ``SHA-512(seed)[:32]``; X25519 applies clamping itself."""
    h = bytearray(hashlib.sha512(bytes(seed)).digest()[:_X25519_BYTES])
    try:
        return x25519_private(h)
    finally:
        wipe(h)


# --- RSA wrapping --------------------------------------------------------------

MIN_RSA_BITS = 2048


def _oaep(aad: bytes) -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=aad)


def wrap_rsa(dek: bytes | bytearray, pub: rsa.RSAPublicKey, aad: bytes) -> bytes:
    if pub.key_size < MIN_RSA_BITS:
        raise CryptoError(_(f"RSA anahtarı en az {MIN_RSA_BITS} bit olmalı"))
    return pub.encrypt(bytes(dek), _oaep(aad))


def unwrap_rsa(blob: bytes, priv: rsa.RSAPrivateKey, aad: bytes) -> bytearray:
    try:
        return bytearray(priv.decrypt(blob, _oaep(aad)))
    except ValueError:
        raise CryptoError(
            _("Şifre çözme başarısız: anahtar yanlış veya veri değiştirilmiş")
        ) from None


# --- Identifier and MAC key derived from the DEK -------------------------------


def dek_id(dek: bytes | bytearray) -> str:
    """Short identifier that tells whether the DEK changed without revealing it."""
    return hmac.new(bytes(dek), b"sealbox/dek-id/v1", hashlib.sha256).hexdigest()[:16]


def dek_mac(dek: bytes | bytearray, message: bytes) -> str:
    """MAC that binds team records to DEK holders; without the DEK, no record can be forged."""
    key = hmac.new(bytes(dek), b"sealbox/team-mac/v1", hashlib.sha256).digest()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except ValueError:
        raise CryptoError(_("Kilitli anahtar biçimi geçersiz")) from None
