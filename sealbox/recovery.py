"""Recovery code: brings the vault key (DEK) back after it is lost.

Key hierarchy::

    code (128 random bits) --Argon2id--> recovery KEK (256 bits) = X25519 private key
    recovery public key (~/.sealbox/recovery.json) --X25519+HKDF+AES-GCM--> project DEK

- Because the public key is stored, new projects lock their DEK to recovery without asking
  for the code; the code is only needed when recovering. There is one code per user.
- Locked DEK copies live in ``~/.sealbox/recovery/<project-id>.json``. They survive deletion
  of the project folder and are never committed. ``export_kit`` produces a single file for
  a USB stick or cloud folder, which is useless without the code.
- The code can optionally be split into 2-of-3 Shamir (SLIP-39) shares. Shares are shown as
  character groups in the same style as the code (10 groups of 4) instead of words.
- The code and the shares are only shown or asked for in a dialog, never in the terminal.
"""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from shamir_mnemonic.wordlist import WORD_INDEX_MAP

from sealbox.approval import SecretAsker, SecretDisplay, SecretPrompt, SecretShower
from sealbox.core.crypto import wipe
from sealbox.core.envelope import (
    ARGON2_PARAMS,
    SALT_BYTES,
    argon2id_kek,
    b64d,
    b64e,
    crockford_clean,
    decode_code,
    dek_id,
    encode_code,
    new_code_secret,
    unwrap_x25519,
    wrap_x25519,
    x25519_private,
    x25519_public_bytes,
)
from sealbox.core.errors import (
    ApprovalDeniedError,
    CryptoError,
    KeySharingError,
    SealboxError,
    require_version,
)
from sealbox.core.fsutil import atomic_write
from sealbox.core.key_sharing import (
    code_to_share,
    combine_shares,
    share_to_code,
    split_key,
)
from sealbox.core.names import home_dir
from sealbox.core.tokenization import TokenVault
from sealbox.i18n import _

if TYPE_CHECKING:
    from sealbox.vaultstore import ProjectVault

RECOVERY_VERSION = 1
SHARE_THRESHOLD, SHARE_COUNT = 2, 3
# A SLIP-39 share of the 16-byte code secret is 20 words = 40 characters (10 groups);
# the code itself is 32 characters.
SHARE_WORDS, SHARE_CHARS, CODE_CHARS = 20, 40, 32
KIT_KIND = "sealbox-kit"


class RecoveryError(SealboxError):
    pass


def _aad(pid: str) -> bytes:
    return f"sealbox/recovery/v1|{pid}".encode()


def _check_pid(pid: str) -> str:
    if len(pid) != 32 or any(c not in "0123456789abcdef" for c in pid):
        raise RecoveryError(_("Proje kimliği bozuk"))
    return pid


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise RecoveryError(_(f"Kurtarma dosyası bozuk: {path.name}")) from None
    if not isinstance(data, dict):
        raise RecoveryError(_(f"Kurtarma dosyası bozuk: {path.name}"))
    require_version(data.get("version"), RECOVERY_VERSION, _("kurtarma dosyası"))
    return data


def _derive_private(secret: bytes | bytearray, salt: bytes, params: dict[str, int]) -> Any:
    kek = argon2id_kek(bytes(secret), salt, params)
    try:
        return x25519_private(kek)
    finally:
        wipe(kek)


class RecoveryStore:
    """Recovery data on this computer (in the home folder, outside any project)."""

    def __init__(self, home: Path, params: dict[str, int] | None = None) -> None:
        self.home = home
        self.meta_path = home / "recovery.json"
        self.dir = home / "recovery"
        self.params = params or ARGON2_PARAMS

    @classmethod
    def default(cls) -> RecoveryStore:
        return cls(home_dir())

    def meta(self) -> dict[str, Any] | None:
        return _read_json(self.meta_path)

    def is_set_up(self) -> bool:
        return self.meta_path.is_file()

    def project_file(self, pid: str) -> Path:
        return self.dir / f"{_check_pid(pid)}.json"

    def protects(self, pid: str, dek: bytes | bytearray | None = None) -> bool:
        """Is there a current recovery copy for this project (for ``dek``, if given)?"""
        meta, rec = self.meta(), _read_json(self.project_file(pid))
        if meta is None or rec is None or rec.get("pub") != meta["pub"]:
            return False
        return dek is None or rec.get("dek_id") == dek_id(dek)

    def protect(self, pid: str, dek: bytes | bytearray) -> bool:
        """Lock the DEK to the recovery public key (no code needed); False if not set up."""
        meta = self.meta()
        if meta is None:
            return False
        if self.protects(pid, dek):
            return True
        record = {
            "version": RECOVERY_VERSION,
            "project_id": pid,
            "pub": meta["pub"],
            "salt": meta["salt"],
            "params": meta["params"],
            "dek_id": dek_id(dek),
            "wrapped": b64e(wrap_x25519(dek, b64d(meta["pub"]), _aad(pid))),
        }
        atomic_write(self.project_file(pid), json.dumps(record, indent=2).encode())
        return True

    def retire(self, pid: str) -> None:
        """Used by ``vault reset``: the old copy is moved aside, never deleted."""
        path = self.project_file(pid)
        if path.is_file():
            path.rename(path.with_name(f"{pid}.lost-{time.strftime('%Y%m%d-%H%M%S')}.json"))

    def unlock_record(self, record: dict[str, Any], secret: bytes | bytearray) -> bytearray:
        """Unlock a locked DEK with the code secret (16 bytes)."""
        try:
            pid = _check_pid(str(record["project_id"]))
            salt, params = b64d(record["salt"]), dict(record["params"])
            pub, wrapped = b64d(record["pub"]), b64d(record["wrapped"])
        except (KeyError, TypeError, ValueError):
            raise RecoveryError(_("Kurtarma kaydı bozuk")) from None
        priv = _derive_private(secret, salt, params)
        if x25519_public_bytes(priv) != pub:
            raise RecoveryError(_("Kurtarma kodu bu kasaya ait değil (yanlış kod ya da eski kod)"))
        return unwrap_x25519(wrapped, priv, _aad(pid))

    def check_secret(self, secret: bytes | bytearray) -> None:
        meta = self.meta()
        if meta is None:
            raise RecoveryError(_("Bu bilgisayarda kurtarma kurulmamış ('recovery setup')"))
        priv = _derive_private(secret, b64d(meta["salt"]), dict(meta["params"]))
        if x25519_public_bytes(priv) != b64d(meta["pub"]):
            raise RecoveryError(_("Kurtarma kodu yanlış"))

    def write_meta(self, secret: bytes | bytearray) -> None:
        salt = secrets.token_bytes(SALT_BYTES)
        priv = _derive_private(secret, salt, self.params)
        meta = {
            "version": RECOVERY_VERSION,
            "kdf": "argon2id",
            "salt": b64e(salt),
            "params": self.params,
            "pub": b64e(x25519_public_bytes(priv)),
            "created": time.strftime("%Y-%m-%d"),
        }
        atomic_write(self.meta_path, json.dumps(meta, indent=2).encode())


# --- User flows -------------------------------------------------------------------


def _groups(code: str) -> list[str]:
    return code.split("-")


def setup_recovery(
    store: ProjectVault | None, rec: RecoveryStore, shower: SecretShower, replace: bool = False
) -> None:
    """Generate a new code and show it; set up recovery once the user confirms saving it."""
    if rec.is_set_up() and not replace:
        raise RecoveryError(
            _(
                "Kurtarma zaten kurulu. Yeni kod için: recovery setup --new "
                "(eski kodla yapılan kopyalar projeler açıldıkça yenilenir)"
            )
        )
    secret = new_code_secret()
    try:
        code = encode_code(secret)
        groups = _groups(code)
        a, b = sorted(secrets.SystemRandom().sample(range(len(groups)), 2))
        ok = shower(
            SecretDisplay(
                title=_("Kurtarma kodu"),
                intro=(
                    _(
                        "Bu kod kasa anahtarın kaybolursa (Windows sıfırlama, yeni bilgisayar) "
                        "kasalarını geri açar. Kağıda yaz ya da şifre yöneticine kaydet. "
                        "Bir daha GÖSTERİLMEYECEK; bizde de kopyası yok."
                    )
                ),
                secret=code,
                checks=[(_(f"{a + 1}. grup:"), groups[a]), (_(f"{b + 1}. grup:"), groups[b])],
            )
        )
        if not ok:
            raise ApprovalDeniedError(_("Kod kaydedilmedi; kurtarma kurulmadı"))
        rec.write_meta(secret)
    finally:
        wipe(secret)
    if store is not None and store.exists():
        vault = store.open()
        try:
            rec.protect(store.project_id(), vault.key)
        finally:
            vault.close()


def _ask_code(rec: RecoveryStore, asker: SecretAsker, why: str) -> bytearray:
    prompt = why + "\n" + _("Kurtarma kodunu yaz (XXXX-XXXX-...):")
    text = asker(SecretPrompt(_("Kurtarma kodu"), prompt))
    if text is None:
        raise ApprovalDeniedError(_("Kurtarma kodu girilmedi"))
    return decode_code(text)


def make_shares(rec: RecoveryStore, asker: SecretAsker, shower: SecretShower) -> None:
    """Split the code into 2-of-3 shares, each shown in its own dialog."""
    secret = _ask_code(rec, asker, _("Parçalar mevcut kurtarma kodundan üretilir."))
    try:
        rec.check_secret(secret)
        shares = split_key(secret, threshold=SHARE_THRESHOLD, count=SHARE_COUNT)
    finally:
        wipe(secret)
    where = [_("şifre yöneticine"), _("kağıda yazıp evde bir yere"), _("güvendiğin birine")]
    for share, place in zip(shares, where, strict=True):
        code = share_to_code(share.mnemonic)
        groups = _groups(code)
        i = secrets.randbelow(len(groups))
        ok = shower(
            SecretDisplay(
                title=_(f"Kurtarma parçası {share.index}/{SHARE_COUNT}"),
                intro=_(
                    f"{share.index}. parça. Bunu {place} kaydet. Herhangi {SHARE_THRESHOLD} "
                    "parça bir araya gelince kurtarma kodunun yerini tutar; tek parça hiçbir "
                    "şey açmaz. Kurtarırken iki parçayı aynı kutuya alt alta yazman yeterli."
                ),
                secret=code,
                checks=[(_(f"{i + 1}. grup:"), groups[i])],
            )
        )
        if not ok:
            raise ApprovalDeniedError(_("Parçalar kaydedilmedi; yeniden üretin"))


def _split_shares(text: str) -> list[str] | None:
    """Return SLIP-39 mnemonics if the input is one or more shares, or None for a code.

    Line breaks, spaces and dashes are ignored; shares are told apart by length. Shares
    written as SLIP-39 words are accepted too.
    """
    words = text.lower().split()
    if len(words) >= SHARE_WORDS and all(w in WORD_INDEX_MAP for w in words):
        if len(words) % SHARE_WORDS:
            raise RecoveryError(_(f"Kelimeli parçaların her biri {SHARE_WORDS} kelime olmalı"))
        return [" ".join(words[i : i + SHARE_WORDS]) for i in range(0, len(words), SHARE_WORDS)]
    cleaned = crockford_clean(text)
    if len(cleaned) == CODE_CHARS:
        return None
    if not cleaned or len(cleaned) % SHARE_CHARS:
        raise RecoveryError(
            _("Tanınmadı: kurtarma kodu 8 grup × 4 harf, her parça 10 grup × 4 harf olmalı")
        )
    shares = []
    for n, i in enumerate(range(0, len(cleaned), SHARE_CHARS), start=1):
        try:
            shares.append(code_to_share(cleaned[i : i + SHARE_CHARS]))
        except KeySharingError:
            raise RecoveryError(_(f"{n}. parçada yazım hatası var")) from None
    return shares


def parse_recovery_input(text: str) -> bytearray:
    """Accept a recovery code, or at least 2 shares in any layout."""
    shares = _split_shares(text)
    if shares is None:
        return decode_code(text)
    if len(set(shares)) < SHARE_THRESHOLD:
        raise RecoveryError(_(f"En az {SHARE_THRESHOLD} farklı parça gerekli"))
    return bytearray(combine_shares(shares, threshold=SHARE_THRESHOLD, count=SHARE_COUNT))


def restore(
    store: ProjectVault, rec: RecoveryStore, asker: SecretAsker, kit: Path | None = None
) -> int:
    """Recover the DEK with the code or shares and cache it. Returns the record count."""
    record: dict[str, Any] | None
    if kit is not None:
        record = _import_kit(store, kit)
    else:
        pid = store.project_id()
        record = _read_json(rec.project_file(pid))
        if record is None:
            raise RecoveryError(
                _(
                    "Bu proje için bu bilgisayarda kurtarma kopyası yok. Kurtarma kitin varsa: "
                    "recovery restore --kit DOSYA"
                )
            )
    text = asker(
        SecretPrompt(
            _("Kasayı kurtar"),
            _(
                "Kurtarma kodunu yaz (8 grup: XXXX-XXXX-...)\n"
                "ya da elindeki 2 kurtarma parçasını (10'ar grup) alt alta yaz:"
            ),
            multiline=True,
        )
    )
    if text is None:
        raise ApprovalDeniedError(_("Kurtarma kodu girilmedi"))
    secret = parse_recovery_input(text)
    try:
        dek = rec.unlock_record(record, secret)
    finally:
        wipe(secret)
    try:
        vault = TokenVault.from_encrypted(store.vault_path.read_bytes(), dek)
        count = len(vault)
        vault.close()
        store.cache_key(dek)
        rec.protect(store.project_id(), dek)
    except CryptoError:
        raise RecoveryError(
            _("Kurtarılan anahtar bu kasayı açmıyor (kasa sonradan yenilenmiş)")
        ) from None
    finally:
        wipe(dek)
    return count


def export_kit(store: ProjectVault, rec: RecoveryStore, dest: Path) -> None:
    """Write the locked DEK and the encrypted vault to one file (useless without the code)."""
    pid = store.project_id()
    vault = store.open()
    try:
        if not rec.protect(pid, vault.key):
            raise RecoveryError(_("Önce kurtarma kur: recovery setup"))
    finally:
        vault.close()
    if dest.exists():
        raise RecoveryError(_("Hedef dosya zaten var; üzerine yazılmaz"))
    record = _read_json(rec.project_file(pid))
    kit = {
        "kind": KIT_KIND,
        "version": RECOVERY_VERSION,
        "recovery": record,
        "vault": b64e(store.vault_path.read_bytes()),
        "names": store.names(),
        "masked": store.masked(),
    }
    atomic_write(dest, json.dumps(kit, indent=2).encode())


def _import_kit(store: ProjectVault, path: Path) -> dict[str, Any]:
    kit = _read_json(path)
    if kit is None or kit.get("kind") != KIT_KIND or not isinstance(kit.get("recovery"), dict):
        raise RecoveryError(_("Bu dosya bir kurtarma kiti değil"))
    record: dict[str, Any] = kit["recovery"]
    pid = _check_pid(str(record.get("project_id", "")))
    if store.id_path.is_file() and store.project_id() != pid:
        raise RecoveryError(_("Kit başka bir projeye ait"))
    if not store.exists():
        atomic_write(store.id_path, pid.encode("ascii"))
        atomic_write(store.vault_path, b64d(kit["vault"]))
        atomic_write(store.names_path, json.dumps(kit.get("names", {}), indent=2).encode())
        atomic_write(store.masked_path, json.dumps(kit.get("masked", {}), indent=2).encode())
    return record
