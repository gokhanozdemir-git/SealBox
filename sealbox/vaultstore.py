"""Persistent, encrypted vault, one per project.

- The vault lives in ``.sealbox/project.vault``, encrypted with AES-256-GCM
  (``TokenVault.export_encrypted``).
- The key (DEK) is never written to disk; it sits in the OS credential store (``keyring``:
  Windows Credential Manager, macOS Keychain, Linux Secret Service). That store is only a
  cache: the DEK is also locked to the team members' SSH keys (``team.json``, committed)
  and to the user's recovery code (``~/.sealbox/recovery``). Unlock order: credential
  store, then SSH, then an error that points to recovery.
- ``project.names`` holds only variable names and categories, never values, so the
  approval dialog and ``vault list`` can read it without opening the vault.
  ``project.masked`` lists the placeholders of redacted records that have no name.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import secrets
import time
from pathlib import Path
from typing import Protocol

from sealbox.core.crypto import AesGcmCipher, generate_key, wipe
from sealbox.core.envelope import dek_id
from sealbox.core.errors import CryptoError, SealboxError
from sealbox.core.fsutil import atomic_write
from sealbox.core.names import KEYRING_SERVICE, has_vault, state_dir
from sealbox.core.tokenization import TokenVault
from sealbox.i18n import N_, _
from sealbox.recovery import RecoveryStore
from sealbox.team import SshIdentity, TeamFile, unlock_with_ssh

__all__ = ["KeyMissingError", "ProjectVault", "atomic_write"]

_BACKUP_AAD = b"sealbox/seal-backup/v1"
# Kept out of git. The vault, the name files and team.json are committed (for team sharing).
_STATE_GITIGNORE = ("backups/", "locks/", "lost-*/", "vaults/", "last_run.json")
KEY_MISSING = N_("Kasa anahtarı bu bilgisayarın kimlik deposunda bulunamadı")


class KeyMissingError(SealboxError):
    pass


class KeyStore(Protocol):
    def get(self, account: str) -> str | None: ...

    def set(self, account: str, secret: str) -> None: ...


class SystemKeyStore:
    """The operating system's credential store."""

    def get(self, account: str) -> str | None:
        import keyring

        try:
            value: str | None = keyring.get_password(KEYRING_SERVICE, account)
            return value
        except Exception:
            raise SealboxError(_("İşletim sistemi kimlik deposuna erişilemedi")) from None

    def set(self, account: str, secret: str) -> None:
        import keyring

        try:
            keyring.set_password(KEYRING_SERVICE, account, secret)
        except Exception:
            raise SealboxError(_("İşletim sistemi kimlik deposuna yazılamadı")) from None


def find_project_root(start: Path) -> Path | None:
    """Find the first folder with a vault, starting at ``start`` and walking up."""
    current = start.resolve()
    for candidate in (current, *current.parents):
        if has_vault(candidate):
            return candidate
    return None


def parent_project_hint(start: Path) -> tuple[Path, str] | None:
    """Return ``(folder, reason)`` if a parent folder looks like the real project root.

    This prevents running ``seal`` inside ``src`` from silently leaving a ``.env`` in the
    parent exposed. The search stops below the home folder.
    """
    current = start.resolve()
    if has_vault(current) or (current / ".git").exists():
        return None
    home = Path.home().resolve()
    for parent in current.parents:
        if parent == home:
            break
        if has_vault(parent):
            return parent, _("kasası var")
        if (parent / ".git").exists():
            return parent, _("git deposunun kökü")
        envs = sorted(p.name for p in parent.glob(".env*") if p.is_file())
        if envs:
            return parent, _(f"{envs[0]} dosyası var")
    return None


class ProjectVault:
    def __init__(
        self,
        root: Path,
        keystore: KeyStore | None = None,
        identity: SshIdentity | None = None,
        recovery: RecoveryStore | None = None,
    ) -> None:
        self.root = root.resolve()
        self.state_dir = state_dir(self.root)
        self.vault_path = self.state_dir / "project.vault"
        self.names_path = self.state_dir / "project.names"
        self.masked_path = self.state_dir / "project.masked"
        self.id_path = self.state_dir / "project.id"
        self.team_path = self.state_dir / "team.json"
        self.keystore = keystore or SystemKeyStore()
        self.identity = identity or SshIdentity()
        self.recovery = recovery or RecoveryStore.default()

    def exists(self) -> bool:
        return self.vault_path.is_file()

    def project_id(self, create: bool = False) -> str:
        if self.id_path.is_file():
            pid = self.id_path.read_text(encoding="ascii").strip()
            if len(pid) == 32 and all(c in "0123456789abcdef" for c in pid):
                return pid
            raise SealboxError(_("Proje kimliği bozuk"))
        if not create:
            raise SealboxError(_("Bu projede kasa yok; önce 'seal' çalıştırın"))
        pid = secrets.token_hex(16)
        atomic_write(self.id_path, pid.encode("ascii"))
        return pid

    def _account(self, create: bool) -> str:
        return f"project:{self.project_id(create)}"

    def cache_key(self, key: bytes | bytearray) -> None:
        """Cache the DEK in this computer's credential store."""
        self.keystore.set(self._account(False), base64.b64encode(bytes(key)).decode("ascii"))

    def _cached_key(self, account: str) -> bytearray | None:
        stored = self.keystore.get(account)
        if stored is None:
            return None
        try:
            return bytearray(base64.b64decode(stored, validate=True))
        except (ValueError, binascii.Error):
            raise CryptoError(_("Kasa anahtarı bozuk")) from None

    def has_cached_key(self) -> bool:
        """Is an up-to-date key cached on this computer? Opens neither a dialog nor the vault."""
        key = self._cached_key(self._account(False))
        if key is None:
            return False
        try:
            team = TeamFile.load(self.team_path)
            return team is None or team.dek_id == dek_id(key)
        finally:
            wipe(key)

    def _key(self, create: bool) -> bytearray:
        account = self._account(create)
        team = TeamFile.load(self.team_path)
        key = self._cached_key(account)
        if key is not None:
            if team is None or team.dek_id == dek_id(key):
                self._protect(key)
                return key
            wipe(key)  # an owner rotated the key (member removed); fetch the new one via SSH
        elif create and not self.exists():
            key = generate_key()
            self.cache_key(key)
            self._protect(key)
            return key
        if team is not None:
            key = unlock_with_ssh(team, self.project_id(), self.identity)
            if key is not None:
                self.cache_key(key)
                self._protect(key)
                return key
        hint = (
            _("Bu proje için kurtarma kopyası var: 'sealbox recovery restore'")
            if self.recovery.protects(self.project_id())
            else _("Kurtarma kodun ve kitin varsa: 'sealbox recovery restore --kit DOSYA'")
        )
        team_hint = (
            _(
                " Ekipteysen: bu bilgisayarın SSH anahtarını GitHub'a ekle ve bir sahibe "
                "'team add' yaptır."
            )
            if team is not None
            else ""
        )
        raise KeyMissingError(
            _(f"{_(KEY_MISSING)}. {hint}.{team_hint} Hiçbiri yoksa: 'sealbox vault reset'")
        )

    def _protect(self, key: bytes | bytearray) -> None:
        """If recovery is set up, keep a current recovery copy of the DEK (no code needed)."""
        # Failing to write the recovery copy must not block using the vault.
        with contextlib.suppress(OSError, SealboxError):
            self.recovery.protect(self.project_id(), key)

    def open(self, create: bool = False) -> TokenVault:
        """Open the vault. The caller must have obtained user approval first."""
        key = self._key(create)
        try:
            if self.exists():
                return TokenVault.from_encrypted(self.vault_path.read_bytes(), key)
            if not create:
                raise SealboxError(_("Bu projede kasa yok; önce 'seal' çalıştırın"))
            return TokenVault(key)
        finally:
            wipe(key)

    def save(self, vault: TokenVault) -> None:
        self.ensure_gitignore()
        atomic_write(self.vault_path, vault.export_encrypted())
        names = {
            name: vault.category_of(ph).value for name, ph in sorted(vault.env_bindings().items())
        }
        atomic_write(self.names_path, json.dumps(names, indent=2).encode("utf-8"))
        # Records without a name (e-mail, national ID...): their placeholders are already
        # visible in the files, so listing them reveals nothing.
        masked = {
            ph: vault.category_of(ph).value
            for ph in sorted(vault.placeholders)
            if vault.env_name_of(ph) is None
        }
        atomic_write(self.masked_path, json.dumps(masked, indent=2).encode("utf-8"))

    def ensure_gitignore(self) -> None:
        """Add any missing lines to the vault's .gitignore without touching the user's lines."""
        path = self.state_dir / ".gitignore"
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        missing = [ln for ln in _STATE_GITIGNORE if ln not in text.splitlines()]
        if missing:
            sep = "" if not text or text.endswith("\n") else "\n"
            atomic_write(path, (text + sep + "\n".join(missing) + "\n").encode())

    @staticmethod
    def _read_map(path: Path) -> dict[str, str]:
        if not path.is_file():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in data.items()}

    def names(self) -> dict[str, str]:
        """``{variable name: category}``; no values, readable without opening the vault."""
        return self._read_map(self.names_path)

    def masked(self) -> dict[str, str]:
        """``{placeholder: category}`` for redacted records that have no variable name."""
        return self._read_map(self.masked_path)

    def save_backup(self, vault: TokenVault, rel: str, data: bytes) -> Path:
        """Back up a file's original content, encrypted with the vault key.

        Plain-text backups are never written, because agents can read the vault folder too.
        """
        stamp = time.strftime("%Y%m%d-%H%M%S")
        dest = self.state_dir / "backups" / f"seal-{stamp}" / (rel + ".enc")
        cipher = AesGcmCipher(vault.key)
        atomic_write(dest, cipher.encrypt(data, _BACKUP_AAD + rel.encode("utf-8")))
        return dest

    def _backups(self) -> list[tuple[Path, bytes]]:
        """``(file, AAD)`` pairs; a backup's AAD is its path relative to its seal run."""
        out = []
        for run in sorted((self.state_dir / "backups").glob("seal-*")):
            for path in sorted(run.rglob("*.enc")):
                rel = path.relative_to(run).as_posix().removesuffix(".enc")
                out.append((path, _BACKUP_AAD + rel.encode("utf-8")))
        return out

    def rotate(self, old: TokenVault, new: TokenVault) -> None:
        """Rotate the DEK: re-encrypt backups, write the vault, update the cached key.

        The cache and the recovery copy are written first, so an interrupted rotation never
        loses the new key.
        """
        self.cache_key(new.key)
        self._protect(new.key)
        old_c, new_c = AesGcmCipher(old.key), AesGcmCipher(new.key)
        for path, aad in self._backups():
            try:
                atomic_write(path, new_c.encrypt(old_c.decrypt(path.read_bytes(), aad), aad))
            except CryptoError:
                continue  # already re-encrypted by an earlier, interrupted rotation
        self.save(new)

    def reset(self) -> list[str]:
        """Last resort: move the old vault aside (never delete it) and start an empty one.

        Returns the variable names and placeholders whose values are lost; files still
        reference them.
        """
        lost = sorted(self.names()) + sorted(self.masked())
        aside = self.state_dir / f"lost-{time.strftime('%Y%m%d-%H%M%S')}"
        aside.mkdir(parents=True)
        for path in (self.vault_path, self.names_path, self.masked_path, self.team_path):
            if path.is_file():
                path.rename(aside / path.name)
        backups = self.state_dir / "backups"
        if backups.is_dir():
            backups.rename(aside / "backups")
        self.recovery.retire(self.project_id())
        # New project ID, so the old vault can still be opened if its key ever turns up.
        self.id_path.rename(aside / "project.id")
        vault = self.open(create=True)
        try:
            self.save(vault)
        finally:
            vault.close()
        return lost
