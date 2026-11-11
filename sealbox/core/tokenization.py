"""Random placeholders and the encrypted placeholder-to-value store (the vault).

- Placeholder format: ``__SECURE_<CATEGORY>_<32 hex>__`` (128 bits of randomness).
- Real values are never kept in memory as plain text. Each one is encrypted with
  AES-256-GCM using the placeholder as AAD, so records cannot be swapped. An HMAC-SHA256
  index under a separate key maps a repeated value back to its existing placeholder.
- The vault and its key never leave the machine.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Iterator

from sealbox.core.crypto import AesGcmCipher, generate_key, wipe
from sealbox.core.errors import CryptoError, require_version
from sealbox.i18n import _
from sealbox.models.enums import SecretCategory

PLACEHOLDER_PREFIX = "__SECURE_"
PLACEHOLDER_RE = re.compile(r"__SECURE_([A-Z]+)_([0-9a-f]{32})__")
# Loose pattern that also catches damaged placeholders.
PLACEHOLDER_LOOSE_RE = re.compile(r"_{1,3}SECURE_[A-Za-z0-9_]*", re.IGNORECASE)

_EXPORT_AAD = b"sealbox/vault/v1"
VAULT_VERSION = 2


def new_placeholder(category: SecretCategory) -> str:
    return f"{PLACEHOLDER_PREFIX}{category.value}_{secrets.token_hex(16)}__"


class TokenVault:
    """Mapping between placeholders and encrypted values."""

    def __init__(self, key: bytes | bytearray | None = None) -> None:
        self._key = bytearray(key) if key is not None else generate_key()
        self._cipher = AesGcmCipher(self._key)
        self._hmac_key = hashlib.sha256(b"vault-index\x00" + bytes(self._key)).digest()
        self._by_digest: dict[bytes, str] = {}
        self._records: dict[str, bytes] = {}
        self._categories: dict[str, SecretCategory] = {}
        # placeholder -> name of the environment variable injected at run time
        self._env_names: dict[str, str] = {}

    def __repr__(self) -> str:
        return f"TokenVault(entries={len(self._records)})"

    def __len__(self) -> int:
        return len(self._records)

    def __contains__(self, placeholder: object) -> bool:
        return placeholder in self._records

    @property
    def key(self) -> bytes:
        """Raw key bytes, for key splitting only. Never log this."""
        return bytes(self._key)

    def _digest(self, value: str) -> bytes:
        return hmac.new(self._hmac_key, value.encode("utf-8"), hashlib.sha256).digest()

    def placeholder_for(self, value: str, category: SecretCategory) -> str:
        """Return the same placeholder every time for the same value."""
        digest = self._digest(value)
        existing = self._by_digest.get(digest)
        if existing is not None:
            return existing
        ph = new_placeholder(category)
        while ph in self._records:  # a 128-bit collision is practically impossible
            ph = new_placeholder(category)
        self._records[ph] = self._cipher.encrypt(value.encode("utf-8"), ph.encode())
        self._by_digest[digest] = ph
        self._categories[ph] = category
        return ph

    def reveal(self, placeholder: str) -> str:
        blob = self._records.get(placeholder)
        if blob is None:
            raise CryptoError(_("Bilinmeyen yer tutucu"))
        return self._cipher.decrypt(blob, placeholder.encode()).decode("utf-8")

    def category_of(self, placeholder: str) -> SecretCategory:
        return self._categories[placeholder]

    def update_value(self, placeholder: str, value: str) -> None:
        """Change the value of an existing record; the placeholder stays the same."""
        if placeholder not in self._records:
            raise CryptoError(_("Bilinmeyen yer tutucu"))
        old = self._digest(self.reveal(placeholder))
        self._by_digest.pop(old, None)
        self._records[placeholder] = self._cipher.encrypt(
            value.encode("utf-8"), placeholder.encode()
        )
        self._by_digest[self._digest(value)] = placeholder

    def remove(self, placeholder: str) -> None:
        """Delete a record completely: value, category and environment variable binding."""
        if placeholder not in self._records:
            raise CryptoError(_("Bilinmeyen yer tutucu"))
        self._by_digest.pop(self._digest(self.reveal(placeholder)), None)
        del self._records[placeholder]
        del self._categories[placeholder]
        self._env_names.pop(placeholder, None)

    def rekeyed(self, key: bytes | bytearray) -> TokenVault:
        """Copy with the same placeholders and values, encrypted under a new key (DEK rotation).

        Placeholders are random, not derived from the key, so the files do not change.
        """
        new = TokenVault(key)
        for ph in self._records:
            value = self.reveal(ph)
            new._records[ph] = new._cipher.encrypt(value.encode("utf-8"), ph.encode())
            new._by_digest[new._digest(value)] = ph
            new._categories[ph] = self._categories[ph]
        new._env_names = dict(self._env_names)
        return new

    # --- Environment variable bindings ---------------------------------------

    def bind_env(self, placeholder: str, name: str) -> None:
        if placeholder not in self._records:
            raise CryptoError(_("Bilinmeyen yer tutucu"))
        owner = self.placeholder_for_env(name)
        if owner is not None and owner != placeholder:
            raise CryptoError(_("Ortam değişkeni adı başka bir kayda bağlı"))
        self._env_names[placeholder] = name

    def unbind_env(self, name: str) -> None:
        ph = self.placeholder_for_env(name)
        if ph is not None:
            del self._env_names[ph]

    def env_name_of(self, placeholder: str) -> str | None:
        return self._env_names.get(placeholder)

    def placeholder_for_env(self, name: str) -> str | None:
        for ph, n in self._env_names.items():
            if n == name:
                return ph
        return None

    def env_bindings(self) -> dict[str, str]:
        """``{environment variable name: placeholder}``"""
        return {n: ph for ph, n in self._env_names.items()}

    @property
    def placeholders(self) -> frozenset[str]:
        return frozenset(self._records)

    def iter_plain_values(self) -> Iterator[tuple[str, str]]:
        """``(placeholder, real value)`` pairs, for local leak checks only."""
        for ph in self._records:
            yield ph, self.reveal(ph)

    # --- Persistence ----------------------------------------------------------

    def export_encrypted(self) -> bytes:
        records: dict[str, dict[str, str]] = {}
        for ph, blob in self._records.items():
            rec = {"c": self._categories[ph].value, "v": base64.b64encode(blob).decode("ascii")}
            if ph in self._env_names:
                rec["e"] = self._env_names[ph]
            records[ph] = rec
        body = {"version": VAULT_VERSION, "records": records}
        return self._cipher.encrypt(json.dumps(body).encode("utf-8"), _EXPORT_AAD)

    @classmethod
    def from_encrypted(cls, blob: bytes, key: bytes | bytearray) -> TokenVault:
        vault = cls(key)
        body = json.loads(vault._cipher.decrypt(blob, _EXPORT_AAD))
        require_version(body.get("version"), VAULT_VERSION, _("kasa"))
        for ph, rec in body["records"].items():
            if not PLACEHOLDER_RE.fullmatch(ph):
                raise CryptoError(_("Vault kaydı geçersiz"))
            raw = base64.b64decode(rec["v"])
            value = vault._cipher.decrypt(raw, ph.encode()).decode("utf-8")
            vault._records[ph] = raw
            vault._categories[ph] = SecretCategory(rec["c"])
            vault._by_digest[vault._digest(value)] = ph
            if "e" in rec:  # absent in version 1 vaults
                vault._env_names[ph] = rec["e"]
        return vault

    def close(self) -> None:
        """Zero the key buffer and drop all records (best effort)."""
        wipe(self._key)
        self._records.clear()
        self._by_digest.clear()
        self._categories.clear()
        self._env_names.clear()
