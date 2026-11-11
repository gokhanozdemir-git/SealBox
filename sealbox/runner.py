"""Gatekeeper: runs any command with the vault's secrets as environment variables.

Language-agnostic: Python, Node, .NET, C and others all read environment variables in their
own standard way. The flow is:

1. Approval dialog, showing the command and the names of the variables to be passed.
2. The vault is opened and values go into the child process environment, never to disk.
3. The child's stdout/stderr are read line by line; known secret values are replaced with
   ``[REDACTED:..]`` before printing, so an agent reading the terminal does not see them.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import IO

from sealbox.approval import ApprovalRequest, Approver, require_approval
from sealbox.changes import find_risky_changes, remember
from sealbox.config import SealboxConfig
from sealbox.core.errors import SealboxError
from sealbox.core.leak_guard import LeakGuard
from sealbox.core.scanner import Scanner
from sealbox.core.tokenization import PLACEHOLDER_RE, TokenVault
from sealbox.i18n import _
from sealbox.models.enums import SecretCategory
from sealbox.sealing.sealer import ENV_LINE_RE, Sealer
from sealbox.vaultstore import KeyStore, ProjectVault


def sealed_env_entries(root: Path) -> list[tuple[str, str]]:
    """``(key, value or placeholder)`` pairs from the ``.env*.sealed`` files in the root."""
    entries: list[tuple[str, str]] = []
    for path in sorted(root.glob(".env*.sealed")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("#"):
                continue
            m = ENV_LINE_RE.match(line)
            if m is None:
                continue
            value = m.group("val")
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            entries.append((m.group("key"), value))
    return entries


def requested_names(store: ProjectVault) -> list[str]:
    names = set(store.names())
    names.update(k for k, v in sealed_env_entries(store.root) if PLACEHOLDER_RE.fullmatch(v))
    return sorted(names)


def build_env(vault: TokenVault, root: Path, base: Mapping[str, str]) -> dict[str, str]:
    env = dict(base)
    for name, ph in vault.env_bindings().items():
        env[name] = vault.reveal(ph)
    for key, value in sealed_env_entries(root):
        if PLACEHOLDER_RE.fullmatch(value):
            if value not in vault:
                raise SealboxError(_(f".env.sealed içindeki {key} kasada bulunamadı"))
            env[key] = vault.reveal(value)
        else:
            # Non-secret settings: as with dotenv, a real environment variable wins.
            env.setdefault(key, value)
    return env


def _pump(src: IO[bytes], dst: IO[str], redact: Callable[[str], str]) -> None:
    for raw in iter(src.readline, b""):
        text = redact(raw.decode("utf-8", errors="replace"))
        try:
            dst.write(text)
        except UnicodeEncodeError:
            enc = getattr(dst, "encoding", None) or "utf-8"
            dst.write(text.encode(enc, errors="replace").decode(enc))
        dst.flush()
    src.close()


def _display(command: list[str]) -> str:
    return subprocess.list2cmdline(command) if os.name == "nt" else " ".join(command)


def run_command(
    root: Path,
    command: list[str],
    approver: Approver,
    keystore: KeyStore | None = None,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
) -> int:
    if not command:
        raise SealboxError(_("Çalıştırılacak komut verilmedi"))
    store = ProjectVault(root, keystore)
    names = requested_names(store)
    require_approval(
        approver,
        ApprovalRequest(
            action=_("Programı çalıştırmak"),
            command=_display(command),
            cwd=str(Path.cwd()),
            names=names,
            changes=find_risky_changes(store.root, names),
        ),
    )
    vault = store.open()
    # Remember the approved state; the next dialog shows only what changed after this.
    remember(store.root)
    store.ensure_gitignore()
    try:
        env = build_env(vault, store.root, os.environ)
        redact = LeakGuard(Scanner(), vault).known_value_redactor()
    finally:
        vault.close()
    exe = shutil.which(command[0]) or command[0]
    try:
        proc = subprocess.Popen(  # noqa: S603 - the user approved this command
            [exe, *command[1:]], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    except OSError:
        raise SealboxError(_(f"Komut başlatılamadı: {command[0]}")) from None
    finally:
        env.clear()
    assert proc.stdout is not None and proc.stderr is not None
    pumps = [
        threading.Thread(target=_pump, args=(proc.stdout, stdout or sys.stdout, redact)),
        threading.Thread(target=_pump, args=(proc.stderr, stderr or sys.stderr, redact)),
    ]
    for t in pumps:
        t.daemon = True
        t.start()
    try:
        proc.wait()
    except KeyboardInterrupt:
        # Ctrl+C reaches every process on the console; wait for the child to exit.
        proc.wait()
    for t in pumps:
        t.join()
    return proc.returncode


# --- Vault management --------------------------------------------------------


def reveal_value(
    root: Path, name: str, approver: Approver, keystore: KeyStore | None = None
) -> str:
    store = ProjectVault(root, keystore)
    require_approval(
        approver,
        ApprovalRequest(_("Değeri göstermek"), f"vault reveal {name}", str(store.root), [name]),
    )
    vault = store.open()
    try:
        # Redacted data (national ID, e-mail...) is looked up by its placeholder, not a name.
        ph = name if PLACEHOLDER_RE.fullmatch(name) else vault.placeholder_for_env(name)
        if ph is None:
            ph = dict(sealed_env_entries(store.root)).get(name)
        if ph is None or ph not in vault:
            raise SealboxError(
                _(
                    f"Kasada böyle bir değişken yok: {name}. "
                    "Karalanmış veriler için dosyadaki __SECURE_..__ etiketini yazın "
                    "('vault list' hepsini gösterir)"
                )
            )
        return vault.reveal(ph)
    finally:
        vault.close()


def set_value(
    root: Path, name: str, value: str, approver: Approver, keystore: KeyStore | None = None
) -> bool:
    """Change a value or add a new variable. Returns True if the variable is new."""
    if not ENV_LINE_RE.match(f"{name}=x") or not value:
        raise SealboxError(_("Geçersiz değişken adı veya boş değer"))
    store = ProjectVault(root, keystore)
    require_approval(
        approver,
        ApprovalRequest(_("Değeri değiştirmek"), f"vault set {name}", str(store.root), [name]),
    )
    vault = store.open(create=True)
    try:
        ph = vault.placeholder_for_env(name) or dict(sealed_env_entries(store.root)).get(name)
        if ph is not None and ph in vault:
            vault.update_value(ph, value)
            created = False
        else:
            ph = vault.placeholder_for(value, SecretCategory.CUSTOM)
            other = vault.env_name_of(ph)
            if other not in (None, name):
                raise SealboxError(_(f"Bu değer zaten {other} adıyla kasada"))
            vault.bind_env(ph, name)
            created = True
        store.save(vault)
        return created
    finally:
        vault.close()


def expose_value(
    config: SealboxConfig, label: str, name: str | None = None, keystore: KeyStore | None = None
) -> tuple[str, list[str]]:
    """Make redacted data (national ID, e-mail...) available to the program at run time.

    The value is never shown; it is only passed to the program after an approved ``exec``,
    so no dialog is needed here. Code files that contain the placeholder are rewritten to
    read an environment variable. Returns ``(variable name, files written)``.
    """
    if not PLACEHOLDER_RE.fullmatch(label):
        raise SealboxError(_("Dosyadaki __SECURE_..__ etiketini yazın ('vault list' gösterir)"))
    store = ProjectVault(config.workspace_root, keystore)
    vault = store.open()
    try:
        sealer = Sealer(config, vault)
        env_name = sealer.expose(label, name)
        store.save(vault)
        files = [f for f in sealer.files_with(label) if not Path(f).name.startswith(".env")]
        written = sealer.apply(sealer.plan(files), store) if files else []
        return env_name, written
    finally:
        vault.close()


def remove_values(
    config: SealboxConfig,
    targets: list[str],
    approver: Approver,
    keystore: KeyStore | None = None,
    unused: bool = False,
    force: bool = False,
) -> list[str]:
    """Delete vault records; with ``unused``, every record that no file references.

    A record still referenced by a file (by placeholder or variable name) is only deleted
    with ``force``, because once the value is gone that file's secret cannot be restored.
    """
    store = ProjectVault(config.workspace_root, keystore)
    vault = store.open()
    try:
        texts = Sealer(config, vault).project_texts()

        def users(ph: str) -> list[str]:
            name = vault.env_name_of(ph)
            pattern = re.compile(rf"\b{re.escape(name)}\b") if name else None
            return [
                rel
                for rel, text in texts.items()
                if ph in text or (pattern is not None and pattern.search(text))
            ]

        if unused:
            chosen = sorted(ph for ph in vault.placeholders if not users(ph))
        else:
            chosen = []
            for t in targets:
                ph = t if PLACEHOLDER_RE.fullmatch(t) else vault.placeholder_for_env(t)
                if ph is None or ph not in vault:
                    raise SealboxError(_(f"Kasada böyle bir kayıt yok: {t}"))
                used = users(ph)
                if used and not force:
                    raise SealboxError(
                        _(
                            f"{t} hâlâ kullanılıyor ({', '.join(used[:3])}); silinirse bu dosyalar "
                            "çalışmaz. Yine de silmek için: --force"
                        )
                    )
                chosen.append(ph)
        if not chosen:
            return []
        labels = [vault.env_name_of(ph) or ph for ph in chosen]
        require_approval(
            approver,
            ApprovalRequest(
                _("Kasadan kalıcı olarak silmek"), "vault remove", str(store.root), labels
            ),
        )
        for ph in chosen:
            vault.remove(ph)
        store.save(vault)
        return labels
    finally:
        vault.close()
