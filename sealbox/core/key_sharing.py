"""Key sharing with Shamir's Secret Sharing (the recovery code is split into 2-of-3 shares).

The cryptography is delegated to ``shamir-mnemonic``, the SatoshiLabs reference
implementation of SLIP-0039; we do not roll our own secret sharing. A single group
``(threshold, count)`` is used. SLIP-39 shares carry an RS1024 checksum and a common
identifier, so corrupted shares and shares of a different key are rejected.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field

import shamir_mnemonic
from shamir_mnemonic.share import Share
from shamir_mnemonic.wordlist import mnemonic_from_indices, mnemonic_to_indices

from sealbox.core.envelope import CROCKFORD, crockford_clean, group4
from sealbox.core.errors import KeySharingError
from sealbox.i18n import _

THRESHOLD = 3
SHARE_COUNT = 5


@dataclass(frozen=True)
class KeyShare:
    """A single SLIP-39 share. Its ``repr`` never shows the mnemonic."""

    index: int
    mnemonic: str = field(repr=False)

    def __str__(self) -> str:
        return f"KeyShare(index={self.index}, <hidden>)"


def split_key(
    key: bytes | bytearray, threshold: int = THRESHOLD, count: int = SHARE_COUNT
) -> list[KeyShare]:
    """Split ``key`` into ``count`` shares; any ``threshold`` of them rebuild it."""
    if len(key) not in (16, 32):
        raise KeySharingError(_("Paylaşılacak anahtar 16 veya 32 bayt olmalı"))
    if not 2 <= threshold <= count <= 16:
        raise KeySharingError(_("Geçersiz parça sayısı"))
    groups = shamir_mnemonic.generate_mnemonics(
        group_threshold=1,
        groups=[(threshold, count)],
        master_secret=bytes(key),
        extendable=True,
        iteration_exponent=0,
    )
    return [KeyShare(index=i + 1, mnemonic=m) for i, m in enumerate(groups[0])]


def combine_shares(
    shares: list[KeyShare] | list[str], threshold: int = THRESHOLD, count: int = SHARE_COUNT
) -> bytes:
    """Rebuild the key from at least ``threshold`` valid shares.

    Error messages never include share contents.
    """
    mnemonics = [s.mnemonic if isinstance(s, KeyShare) else s for s in shares]
    unique = list(dict.fromkeys(m.strip() for m in mnemonics))
    if len(unique) < threshold:
        raise KeySharingError(
            _(f"Yetersiz parça: {len(unique)} benzersiz parça var, en az {threshold} gerekli")
        )
    if len(unique) > count:
        raise KeySharingError(_(f"En fazla {count} parça verilebilir"))
    # SLIP-39 expects exactly `threshold` shares. When more are given, every combination of
    # that size is tried, so a single corrupted share is tolerated.
    for combo in itertools.combinations(unique, threshold):
        try:
            return bytes(shamir_mnemonic.combine_mnemonics(list(combo)))
        except (shamir_mnemonic.MnemonicError, ValueError, KeyError, IndexError):
            continue
    raise KeySharingError(_("Parçalar reddedildi: bozuk, eksik ya da farklı anahtarlara ait"))


# --- Share code format ------------------------------------------------------
# Each SLIP-39 word is one of 1024 words (10 bits), which is exactly 2 Crockford characters
# (2 x 5 bits). Shares are shown as character groups that look like the recovery code
# instead of words. The mapping is one-to-one, so the SLIP-39 checksum still catches typos.


def share_to_code(mnemonic: str) -> str:
    """``academic acid ...`` -> ``0A1B-2C3D-...`` (two characters per word)."""
    try:
        indices = mnemonic_to_indices(mnemonic)
    except shamir_mnemonic.MnemonicError:
        raise KeySharingError(_("Parça geçersiz")) from None
    return group4("".join(CROCKFORD[i >> 5] + CROCKFORD[i & 31] for i in indices))


def code_to_share(text: str) -> str:
    """Convert a share code back to SLIP-39 words and verify its checksum."""
    cleaned = crockford_clean(text)
    if not cleaned or len(cleaned) % 2 or any(c not in CROCKFORD for c in cleaned):
        raise KeySharingError(_("Parça kodunda geçersiz harf var"))
    indices = [
        CROCKFORD.index(cleaned[i]) << 5 | CROCKFORD.index(cleaned[i + 1])
        for i in range(0, len(cleaned), 2)
    ]
    mnemonic: str = mnemonic_from_indices(indices)
    try:
        Share.from_mnemonic(mnemonic)
    except shamir_mnemonic.MnemonicError:
        raise KeySharingError(_("Parça kodunda yazım hatası var")) from None
    return mnemonic
