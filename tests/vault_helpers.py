"""Fake users for team and recovery tests (credential store, SSH key, recovery folder)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from sealbox.approval import SecretDisplay, SecretPrompt
from sealbox.config import SealboxConfig
from sealbox.recovery import RecoveryStore
from sealbox.sealing.sealer import Sealer
from sealbox.team import SshIdentity, SshPublicKey, parse_public_key
from sealbox.vaultstore import ProjectVault


class FakeKeyStore:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    def get(self, account: str) -> str | None:
        return self.data.get(account)

    def set(self, account: str, secret: str) -> None:
        self.data[account] = secret


class Approvals:
    def __init__(self, answer: bool = True) -> None:
        self.answer = answer
        self.requests: list[object] = []

    def __call__(self, req: object) -> bool:
        self.requests.append(req)
        return self.answer


class Asker:
    """Fake dialog that returns the given answers in order."""

    def __init__(self, *answers: str | None) -> None:
        self.answers = list(answers)
        self.prompts: list[SecretPrompt] = []

    def __call__(self, p: SecretPrompt) -> str | None:
        self.prompts.append(p)
        return self.answers.pop(0) if self.answers else None


class Shower:
    """Captures the secrets shown and assumes the user answers the checks correctly."""

    def __init__(self, answer: bool = True) -> None:
        self.answer = answer
        self.shown: list[SecretDisplay] = []

    def __call__(self, d: SecretDisplay) -> bool:
        self.shown.append(d)
        for _question, expected in d.checks:
            assert expected and expected in d.secret
        return self.answer


def write_ssh_key(directory: Path, kind: str = "ed25519", passphrase: bytes | None = b"pw") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    key: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey
    if kind == "ed25519":
        key = ed25519.Ed25519PrivateKey.generate()
        path = directory / "id_ed25519"
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        path = directory / "id_rsa"
    enc: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, enc)
    )
    pub = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    path.with_name(path.name + ".pub").write_bytes(pub + b" test@host\n")
    return path


def public_key_of(path: Path) -> SshPublicKey:
    key = parse_public_key(path.with_name(path.name + ".pub").read_text(encoding="utf-8"))
    assert key is not None
    return key


@dataclass
class User:
    """One person on one computer: their own credential store, SSH key and recovery folder."""

    name: str
    home: Path
    kind: str = "ed25519"
    passphrase: str = "pw"
    keystore: FakeKeyStore = field(default_factory=FakeKeyStore)

    def __post_init__(self) -> None:
        self.key_path = write_ssh_key(self.home / ".ssh", self.kind, self.passphrase.encode())
        self.recovery = RecoveryStore(self.home / ".sealbox")

    @property
    def pub(self) -> SshPublicKey:
        return public_key_of(self.key_path)

    def identity(self, *answers: str | None) -> SshIdentity:
        return SshIdentity([self.key_path], Asker(*(answers or (self.passphrase,) * 3)))

    def store(self, root: Path, *answers: str | None) -> ProjectVault:
        return ProjectVault(root, self.keystore, self.identity(*answers), self.recovery)


def seal_with(store: ProjectVault, config: SealboxConfig) -> None:
    vault = store.open(create=True)
    try:
        sealer = Sealer(config, vault)
        sealer.apply(sealer.plan(["."]), store)
    finally:
        vault.close()


class FakeGitHub:
    def __init__(self, *users: User) -> None:
        self.keys = {u.name: [u.pub] for u in users}
        self.calls: list[str] = []

    def __call__(self, user: str) -> list[SshPublicKey]:
        self.calls.append(user)
        return self.keys[user]
