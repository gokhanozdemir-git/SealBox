"""Team sharing: locking the vault key (DEK) to the members' GitHub SSH keys.

- ``.sealbox/team.json`` is committed. It holds each member's role, their SSH public keys
  from GitHub and the DEK locked to each of those keys. It contains no secret values;
  unlocking the DEK requires the member's own private SSH key.
- Public keys are fetched from the public ``https://github.com/<user>.keys`` endpoint.
- Every member record is MAC'd with a key derived from the DEK, so someone who can push to
  the repository but does not know the DEK cannot add fake members or roles. Owner/member
  roles are enforced in software only: a member who has the DEK could technically pass it on.
- Unencrypted SSH keys are rejected, because an agent could read them. The passphrase is
  asked for in a dialog, never in the terminal.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from sealbox.approval import (
    ApprovalRequest,
    Approver,
    SecretAsker,
    SecretPrompt,
    require_approval,
    tk_ask_secret,
)
from sealbox.core.crypto import generate_key, wipe
from sealbox.core.envelope import (
    MIN_RSA_BITS,
    b64d,
    b64e,
    dek_id,
    dek_mac,
    ed25519_pub_to_x25519,
    ed25519_seed_to_x25519,
    unwrap_rsa,
    unwrap_x25519,
    wrap_rsa,
    wrap_x25519,
)
from sealbox.core.errors import ApprovalDeniedError, SealboxError, require_version
from sealbox.core.fsutil import atomic_write
from sealbox.i18n import N_, _

if TYPE_CHECKING:
    from sealbox.vaultstore import ProjectVault

TEAM_VERSION = 1
OWNER, MEMBER = "owner", "member"
ROLE_LABELS = {OWNER: N_("sahip"), MEMBER: N_("üye")}
GITHUB_KEYS_URL = "https://github.com/{user}.keys"
_USER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
_KINDS = ("ssh-ed25519", "ssh-rsa")
_MAX_KEYS_BYTES = 64 * 1024
_PASSPHRASE_TRIES = 3

PrivateKey = ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey


class TeamError(SealboxError):
    pass


# --- SSH public keys --------------------------------------------------------------


@dataclass(frozen=True)
class SshPublicKey:
    kind: str  # "ssh-ed25519" | "ssh-rsa"
    line: str  # "<kind> <base64>", without the comment
    fp: str  # OpenSSH fingerprint: "SHA256:..."


def parse_public_key(line: str) -> SshPublicKey | None:
    """Parse a supported SSH public key line; return None if it is not supported."""
    parts = line.split()
    if len(parts) < 2 or parts[0] not in _KINDS:
        return None
    try:
        blob = base64.b64decode(parts[1], validate=True)
        key = serialization.load_ssh_public_key(f"{parts[0]} {parts[1]}".encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return None
    if isinstance(key, rsa.RSAPublicKey) and key.key_size < MIN_RSA_BITS:
        return None
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return SshPublicKey(parts[0], f"{parts[0]} {parts[1]}", fp)


def _public_key_obj(pub: SshPublicKey) -> ed25519.Ed25519PublicKey | rsa.RSAPublicKey:
    key = serialization.load_ssh_public_key(pub.line.encode("ascii"))
    if not isinstance(key, ed25519.Ed25519PublicKey | rsa.RSAPublicKey):
        raise TeamError(_("Desteklenmeyen SSH anahtarı"))
    return key


def check_user(user: str) -> str:
    user = user.removeprefix("@")
    if not _USER_RE.fullmatch(user):
        raise TeamError(_(f"Geçersiz GitHub kullanıcı adı: {user[:40]!r}"))
    return user


KeyFetcher = Callable[[str], list[SshPublicKey]]


def fetch_github_keys(user: str) -> list[SshPublicKey]:
    """The SSH public keys a user has added to GitHub (public endpoint)."""
    user = check_user(user)
    url = GITHUB_KEYS_URL.format(user=user)
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310 - fixed https URL
            body = resp.read(_MAX_KEYS_BYTES).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise TeamError(_(f"GitHub'da @{user} adında kullanıcı yok")) from None
        raise TeamError(_(f"GitHub yanıt vermedi (HTTP {e.code})")) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise TeamError(_("GitHub'a ulaşılamadı; internet bağlantısını kontrol edin")) from None
    keys = [k for k in (parse_public_key(line) for line in body.splitlines()) if k]
    if not keys:
        raise TeamError(
            _(f"@{user} GitHub hesabına ed25519 ya da RSA (≥2048) SSH anahtarı eklememiş")
        )
    return keys


# --- SSH identity on this computer ---------------------------------------------------


def _load_private(data: bytes, password: bytes | None) -> Any:
    if data.lstrip().startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
        return serialization.load_ssh_private_key(data, password)
    return serialization.load_pem_private_key(data, password)


class SshIdentity:
    """The private SSH key on this computer; its passphrase is asked for on first use."""

    def __init__(self, paths: list[Path] | None = None, asker: SecretAsker | None = None) -> None:
        ssh = Path.home() / ".ssh"
        self.paths = paths or [ssh / "id_ed25519", ssh / "id_rsa"]
        self.asker = asker or tk_ask_secret
        self._loaded: dict[str, PrivateKey] = {}

    def public_keys(self) -> list[SshPublicKey]:
        """Read from the ``.pub`` files; never asks for a passphrase."""
        found = []
        for path in self.paths:
            pub_path = path.with_name(path.name + ".pub")
            if path.is_file() and pub_path.is_file():
                key = parse_public_key(pub_path.read_text(encoding="utf-8", errors="replace"))
                if key is not None:
                    found.append(key)
        return found

    def _path_for(self, fp: str) -> Path:
        for path in self.paths:
            pub_path = path.with_name(path.name + ".pub")
            if path.is_file() and pub_path.is_file():
                key = parse_public_key(pub_path.read_text(encoding="utf-8", errors="replace"))
                if key is not None and key.fp == fp:
                    return path
        raise TeamError(_("Bu SSH anahtarı bu bilgisayarda yok"))

    def private_key(self, fp: str) -> PrivateKey:
        if fp in self._loaded:
            return self._loaded[fp]
        path = self._path_for(fp)
        data = path.read_bytes()
        try:
            _load_private(data, None)
        except TypeError:
            pass  # encrypted, as expected
        except Exception:
            raise TeamError(_(f"SSH anahtarı okunamadı: {path}")) from None
        else:
            raise TeamError(
                _(
                    f"SSH anahtarın şifresiz: {path}\n"
                    "Şifresiz anahtarı bilgisayardaki herhangi bir program (ajanlar dahil) "
                    "okuyabilir. "
                    f'Şifre ekle: ssh-keygen -p -f "{path}"'
                )
            )
        for attempt in range(_PASSPHRASE_TRIES):
            note = "" if attempt == 0 else _("Şifre yanlış. ")
            pw = self.asker(
                SecretPrompt(
                    _("SSH anahtarı"),
                    note + _(f"{path.name} anahtarının şifresi (kasayı açmak için):"),
                )
            )
            if pw is None:
                raise ApprovalDeniedError(_("SSH şifresi girilmedi; kasa açılmadı"))
            try:
                key = _load_private(data, pw.encode("utf-8"))
            except ValueError:
                continue
            if not isinstance(key, ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey):
                raise TeamError(_("Desteklenmeyen SSH anahtarı türü"))
            self._loaded[fp] = key
            return key
        raise TeamError(_("SSH şifresi 3 kez yanlış girildi"))


# --- Key wrapping ------------------------------------------------------------------


def _aad(pid: str, user: str, fp: str) -> bytes:
    return f"sealbox/team/v1|{pid}|{user}|{fp}".encode()


def wrap_for(dek: bytes | bytearray, pub: SshPublicKey, aad: bytes) -> bytes:
    key = _public_key_obj(pub)
    if isinstance(key, ed25519.Ed25519PublicKey):
        return wrap_x25519(dek, ed25519_pub_to_x25519(key.public_bytes_raw()), aad)
    return wrap_rsa(dek, key, aad)


def unwrap_with(blob: bytes, priv: PrivateKey, aad: bytes) -> bytearray:
    if isinstance(priv, ed25519.Ed25519PrivateKey):
        seed = bytearray(priv.private_bytes_raw())
        try:
            return unwrap_x25519(blob, ed25519_seed_to_x25519(seed), aad)
        finally:
            wipe(seed)
    return unwrap_rsa(blob, priv, aad)


# --- team.json -----------------------------------------------------------------------


class TeamFile:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    @classmethod
    def new(cls, dek: bytes | bytearray) -> TeamFile:
        return cls({"version": TEAM_VERSION, "dek_id": dek_id(dek), "members": {}})

    @classmethod
    def load(cls, path: Path) -> TeamFile | None:
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                require_version(data.get("version"), TEAM_VERSION, "team.json")
            assert data["version"] == TEAM_VERSION and isinstance(data["dek_id"], str)
            for user, m in data["members"].items():
                check_user(user)
                assert m["role"] in (OWNER, MEMBER) and isinstance(m["mac"], str)
                for k in m["keys"]:
                    assert all(isinstance(k[f], str) for f in ("kind", "line", "fp", "wrapped"))
        except (OSError, ValueError, KeyError, TypeError, AssertionError, AttributeError):
            raise TeamError(_("team.json bozuk ya da tanınmayan biçimde")) from None
        return cls(data)

    def save(self, path: Path) -> None:
        atomic_write(path, (json.dumps(self.data, indent=2, sort_keys=True) + "\n").encode())

    @property
    def dek_id(self) -> str:
        return str(self.data["dek_id"])

    @property
    def members(self) -> dict[str, dict[str, Any]]:
        members: dict[str, dict[str, Any]] = self.data["members"]
        return members

    def owners(self) -> list[str]:
        return sorted(u for u, m in self.members.items() if m["role"] == OWNER)

    def find_by_fp(self, fp: str) -> tuple[str, dict[str, str]] | None:
        for user, m in self.members.items():
            for k in m["keys"]:
                if k["fp"] == fp:
                    return user, k
        return None

    def _mac_message(self, pid: str, user: str, m: dict[str, Any]) -> bytes:
        body = {
            "pid": pid,
            "dek_id": self.dek_id,
            "user": user,
            "role": m["role"],
            "keys": m["keys"],
        }
        return json.dumps(body, sort_keys=True).encode()

    def verify(self, pid: str, dek: bytes | bytearray, user: str | None = None) -> None:
        """Verify that records were written by DEK holders (only ``user``'s, if given)."""
        if dek_id(dek) != self.dek_id:
            raise TeamError(_("team.json bu kasanın anahtarıyla uyuşmuyor"))
        for u in [user] if user else list(self.members):
            m = self.members[u]
            if dek_mac(dek, self._mac_message(pid, u, m)) != m["mac"]:
                raise TeamError(
                    _(f"team.json'daki @{u} kaydı doğrulanamadı (elle değiştirilmiş olabilir)")
                )

    def set_member(
        self, pid: str, user: str, role: str, pubs: list[SshPublicKey], dek: bytes | bytearray
    ) -> None:
        keys = [
            {
                "kind": p.kind,
                "line": p.line,
                "fp": p.fp,
                "wrapped": b64e(wrap_for(dek, p, _aad(pid, user, p.fp))),
            }
            for p in pubs
        ]
        m: dict[str, Any] = {"role": role, "keys": keys}
        m["mac"] = dek_mac(dek, self._mac_message(pid, user, m))
        self.members[user] = m

    def rekey(self, pid: str, new_dek: bytes | bytearray) -> None:
        """Lock a new DEK to every member's registered public keys."""
        old = {
            u: (m["role"], [parse_public_key(k["line"]) for k in m["keys"]])
            for u, m in self.members.items()
        }
        self.data["dek_id"] = dek_id(new_dek)
        self.data["members"] = {}
        for user, (role, pubs) in old.items():
            self.set_member(pid, user, role, [p for p in pubs if p is not None], new_dek)


def unlock_with_ssh(team: TeamFile, pid: str, identity: SshIdentity) -> bytearray | None:
    """Unlock the DEK if this computer's SSH key belongs to the team; otherwise None."""
    for pub in identity.public_keys():
        found = team.find_by_fp(pub.fp)
        if found is None:
            continue
        user, rec = found
        dek = unwrap_with(
            b64d(rec["wrapped"]), identity.private_key(pub.fp), _aad(pid, user, pub.fp)
        )
        try:
            team.verify(pid, dek, user)
        except TeamError:
            wipe(dek)
            raise
        return dek
    return None


# --- Team operations -----------------------------------------------------------------


def _git_ignores(root: Path, rel: str) -> bool:
    try:
        res = subprocess.run(  # noqa: S603 - fixed git command
            ["git", "check-ignore", "-q", rel],  # noqa: S607
            cwd=root,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return res.returncode == 0


def sharing_warning(store: ProjectVault) -> str | None:
    """Warning text if the vault is git-ignored, since teammates would never receive it."""
    folder = store.state_dir.name
    if _git_ignores(store.root, f"{folder}/team.json"):
        return _(
            f".gitignore dosyası {folder} klasörünü dışarıda bırakıyor; arkadaşın kasayı "
            f"alamaz. .gitignore'dan '{folder}/' satırını kaldırın (yedekler ve kilitler "
            f"{folder}/.gitignore ile zaten dışarıda kalır)."
        )
    return None


def _require_team(store: ProjectVault) -> TeamFile:
    team = TeamFile.load(store.team_path)
    if team is None:
        raise TeamError(_("Bu projede ekip kurulmamış; önce: team init --github <kullanıcı adın>"))
    return team


def _require_owner(team: TeamFile, identity: SshIdentity) -> str:
    """Prove that the caller is an owner by unlocking their private SSH key."""
    for pub in identity.public_keys():
        found = team.find_by_fp(pub.fp)
        if found is not None:
            user = found[0]
            if team.members[user]["role"] != OWNER:
                raise TeamError(_(f"@{user} bu projede üye; bu işlemi yalnızca sahipler yapabilir"))
            identity.private_key(pub.fp)
            return user
    raise TeamError(_("Bu bilgisayarın SSH anahtarı ekipte kayıtlı değil"))


def team_init(
    store: ProjectVault,
    me: str,
    approver: Approver,
    identity: SshIdentity,
    fetch: KeyFetcher = fetch_github_keys,
) -> list[SshPublicKey]:
    me = check_user(me)
    if store.team_path.is_file():
        raise TeamError(_("Bu projede ekip zaten kurulu ('team list' üyeleri gösterir)"))
    local = {p.fp for p in identity.public_keys()}
    if not local:
        raise TeamError(
            _(
                "Bu bilgisayarda SSH anahtarı yok (~/.ssh/id_ed25519 ve .pub). Oluştur: "
                "ssh-keygen -t ed25519 (şifre koy), sonra .pub içeriğini "
                "GitHub → Settings → SSH keys'e ekle"
            )
        )
    pubs = fetch(me)
    match = [p for p in pubs if p.fp in local]
    if not match:
        raise TeamError(
            _(
                f"Bu bilgisayardaki SSH anahtarı @{me} GitHub hesabında yok. "
                "Önce .pub içeriğini GitHub → Settings → SSH keys'e ekle."
            )
        )
    identity.private_key(match[0].fp)  # rejects unencrypted keys and proves possession
    require_approval(
        approver,
        ApprovalRequest(
            _("Ekip kurmak (sen sahip olursun)"),
            f"team init @{me}",
            str(store.root),
            [f"@{me} {p.fp}" for p in pubs],
        ),
    )
    vault = store.open()
    try:
        team = TeamFile.new(vault.key)
        team.set_member(store.project_id(), me, OWNER, pubs, vault.key)
        team.save(store.team_path)
    finally:
        vault.close()
    return pubs


def team_add(
    store: ProjectVault,
    user: str,
    approver: Approver,
    identity: SshIdentity,
    fetch: KeyFetcher = fetch_github_keys,
    role: str = MEMBER,
) -> list[SshPublicKey]:
    user = check_user(user)
    team = _require_team(store)
    _require_owner(team, identity)
    pubs = fetch(user)
    require_approval(
        approver,
        ApprovalRequest(
            _(f"@{user} kullanıcısına kasa erişimi vermek ({_(ROLE_LABELS[role])})"),
            f"team add @{user}",
            str(store.root),
            [f"@{user} {p.fp}" for p in pubs],
        ),
    )
    vault = store.open()
    try:
        team.verify(store.project_id(), vault.key)
        team.set_member(store.project_id(), user, role, pubs, vault.key)
        team.save(store.team_path)
    finally:
        vault.close()
    return pubs


def team_promote(store: ProjectVault, user: str, approver: Approver, identity: SshIdentity) -> None:
    user = check_user(user)
    team = _require_team(store)
    _require_owner(team, identity)
    if user not in team.members:
        raise TeamError(_(f"@{user} ekipte değil"))
    require_approval(
        approver,
        ApprovalRequest(
            _(f"@{user} kullanıcısını sahip yapmak"),
            f"team promote @{user}",
            str(store.root),
            [f"@{user}"],
        ),
    )
    vault = store.open()
    try:
        pid = store.project_id()
        team.verify(pid, vault.key)
        pubs = [p for p in (parse_public_key(k["line"]) for k in team.members[user]["keys"]) if p]
        team.set_member(pid, user, OWNER, pubs, vault.key)
        team.save(store.team_path)
    finally:
        vault.close()


def team_remove(
    store: ProjectVault, user: str, approver: Approver, identity: SshIdentity
) -> list[str]:
    """Remove a member and rotate the DEK. Returns the records that member may have seen."""
    user = check_user(user)
    team = _require_team(store)
    _require_owner(team, identity)
    if user not in team.members:
        raise TeamError(_(f"@{user} ekipte değil"))
    if team.owners() == [user]:
        raise TeamError(_("Son sahip çıkarılamaz; önce başka birini sahip yapın"))
    require_approval(
        approver,
        ApprovalRequest(
            _(f"@{user} kullanıcısını ekipten çıkarmak (kasa anahtarı yenilenir)"),
            f"team remove @{user}",
            str(store.root),
            [f"@{user}"],
        ),
    )
    old = store.open()
    new_key = generate_key()
    try:
        pid = store.project_id()
        team.verify(pid, old.key)
        del team.members[user]
        team.rekey(pid, new_key)
        new = old.rekeyed(new_key)
        try:
            store.rotate(old, new)
            team.save(store.team_path)
            seen = sorted(new.env_bindings())
            seen += sorted(
                f"{ph} ({new.category_of(ph).value})"
                for ph in new.placeholders
                if new.env_name_of(ph) is None
            )
        finally:
            new.close()
    finally:
        old.close()
        wipe(new_key)
    return seen


def team_members(store: ProjectVault) -> list[tuple[str, str, list[str]]]:
    """``(user, role, fingerprints)``, read without opening or verifying the vault."""
    team = TeamFile.load(store.team_path)
    if team is None:
        return []
    return [(u, m["role"], [k["fp"] for k in m["keys"]]) for u, m in sorted(team.members.items())]
