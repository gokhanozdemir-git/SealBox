"""Searching git history and staged changes for vault values.

- ``scan_history``: vault values in lines added anywhere in ``git log --all -p``. Secrets
  committed before they were sealed stay in history; cleaning the file does not remove them.
- ``scan_staged``: ``git diff --cached`` (what is about to be committed); used by the
  pre-commit hook.
- ``install_hook``: writes ``sealbox hook run`` into ``.git/hooks/pre-commit``.

Findings carry only a name, a file and a commit; the value itself is never written anywhere.
The hook is a seat belt against accidents: ``git commit --no-verify`` skips it.
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from sealbox.core.errors import SealboxError
from sealbox.core.leak_guard import _variants
from sealbox.core.redaction import literal_pattern
from sealbox.core.scanner import Scanner
from sealbox.core.tokenization import TokenVault
from sealbox.i18n import _

# Shorter values (such as "1234") match almost anywhere and would only cause false alarms.
MIN_LEN = 6
HOOK_MARK = "# sealbox pre-commit"
_COMMIT = "\x00commit "
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


@dataclass
class Hit:
    label: str  # environment variable name or __SECURE_..__ placeholder
    named: bool  # named secrets can be rotated; redacted personal data cannot
    path: str
    line: int = 0  # staged scans only
    commit: str = ""
    date: str = ""
    count: int = 1  # number of commits containing the value
    pushed: bool = False  # also present on a remote branch


class Matcher:
    """Finds vault values (and their common encodings) with a single combined pattern."""

    def __init__(self, vault: TokenVault) -> None:
        self._labels: dict[str, tuple[str, bool]] = {}
        for ph, value in vault.iter_plain_values():
            if len(value) < MIN_LEN:
                continue
            name = vault.env_name_of(ph)
            for form in _variants(value):
                self._labels.setdefault(form, (name or ph, name is not None))
        forms = sorted(self._labels, key=len, reverse=True)
        self._re = (
            re.compile("|".join(f"(?:{literal_pattern(f).pattern})" for f in forms))
            if forms
            else None
        )

    def __bool__(self) -> bool:
        return self._re is not None

    def find(self, line: str) -> list[tuple[str, bool]]:
        if self._re is None:
            return []
        return list(dict.fromkeys(self._labels[m.group(0)] for m in self._re.finditer(line)))


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - fixed git command
        ["git", "-c", "core.quotepath=off", *args],  # noqa: S607
        cwd=root,
        capture_output=True,
        timeout=60,
    )


def is_git_repo(root: Path) -> bool:
    try:
        return _git(root, "rev-parse", "--git-dir").returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _diff_lines(root: Path, *args: str) -> Iterator[str]:
    """Stream git output line by line instead of loading it into memory (large repos)."""
    proc = subprocess.Popen(  # noqa: S603 - fixed git command
        ["git", "-c", "core.quotepath=off", *args],  # noqa: S607
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert proc.stdout is not None
    try:
        for raw in proc.stdout:
            yield raw.decode("utf-8", errors="replace").rstrip("\r\n")
    finally:
        proc.stdout.close()
        proc.wait()


def _new_path(line: str) -> str:
    """Path from a ``+++ b/<path>`` line; empty for deleted files (``+++ /dev/null``)."""
    # git appends a tab to paths that contain spaces.
    return line[6:].rstrip("\t") if line.startswith("+++ b/") else ""


def scan_history(root: Path, vault: TokenVault) -> list[Hit]:
    """For each value: where it first appeared in history and in how many commits."""
    matcher = Matcher(vault)
    if not matcher:
        return []
    remote = set(_git(root, "rev-list", "--remotes").stdout.decode("ascii", "replace").split())
    hits: dict[str, Hit] = {}
    seen: set[tuple[str, str]] = set()  # (label, commit): count each commit once
    commit = date = path = ""
    for line in _diff_lines(
        root,
        "log",
        "--all",
        "--reverse",
        "-p",
        "--no-color",
        "--no-ext-diff",
        "--format=%x00commit %H %cs",  # git prints %x00 as NUL (_COMMIT)
    ):
        if line.startswith(_COMMIT):
            commit, _sep, date = line[len(_COMMIT) :].partition(" ")
        elif line.startswith("+++ "):
            path = _new_path(line)
        elif line.startswith("+") and path:
            for label, named in matcher.find(line[1:]):
                hit = hits.get(label)
                if hit is None:
                    hit = hits[label] = Hit(label, named, path, commit=commit[:7], date=date)
                elif (label, commit) not in seen:
                    hit.count += 1
                seen.add((label, commit))
                hit.pushed = hit.pushed or commit in remote
    return sorted(hits.values(), key=lambda h: (not h.pushed, h.label))


def _staged_lines(root: Path) -> Iterator[tuple[str, int, str]]:
    """Added lines that are about to be committed: ``(file, line number, text)``."""
    path, lineno = "", 0
    for line in _diff_lines(root, "diff", "--cached", "-U0", "--no-color", "--no-ext-diff"):
        if line.startswith("+++ "):
            path = _new_path(line)
        elif m := _HUNK.match(line):
            lineno = int(m.group(1))
        elif line.startswith("+") and path:
            yield path, lineno, line[1:]
            lineno += 1


def scan_staged(root: Path, vault: TokenVault) -> list[Hit]:
    """Vault values in staged added lines, with file and line number."""
    matcher = Matcher(vault)
    if not matcher:
        return []
    return [
        Hit(label, named, path, lineno)
        for path, lineno, text in _staged_lines(root)
        for label, named in matcher.find(text)
    ]


def scan_staged_generic(root: Path) -> list[tuple[str, int, str]]:
    """Fallback when the vault cannot be opened: generic rules (file, line, category)."""
    scanner = Scanner()
    return [
        (path, lineno, d.category.value)
        for path, lineno, text in _staged_lines(root)
        for d in scanner.scan(text, path)
    ]


# --- Pre-commit hook --------------------------------------------------------------------


def hook_path(root: Path) -> Path:
    """Location of the pre-commit hook, honouring ``core.hooksPath``."""
    res = _git(root, "rev-parse", "--git-path", "hooks/pre-commit")
    if res.returncode != 0:
        raise SealboxError(_("Bu klasör bir git deposu değil"))
    return (root / res.stdout.decode("utf-8").strip()).resolve()


def hook_installed(root: Path) -> bool:
    try:
        path = hook_path(root)
    except (OSError, subprocess.SubprocessError, SealboxError):
        return False
    return path.is_file() and HOOK_MARK in path.read_text(encoding="utf-8", errors="replace")


def _hook_script(root: Path) -> str:
    # git runs hooks with its own sh even on Windows, so paths use forward slashes.
    python = Path(sys.executable).as_posix()
    return (
        "#!/bin/sh\n"
        f"{HOOK_MARK} (sealbox hook install)\n"
        f'exec "{python}" -m sealbox hook run -w "{root.as_posix()}"\n'
    )


def install_hook(root: Path) -> Path:
    """Write the hook, refusing to overwrite a hook that belongs to another tool."""
    path = hook_path(root)
    if path.is_file() and HOOK_MARK not in path.read_text(encoding="utf-8", errors="replace"):
        raise SealboxError(
            _(
                f"{path} başka bir araca ait; üzerine yazılmadı. O dosyanın sonuna şu satırı "
                f"ekle: sealbox hook run -w {root.as_posix()}"
            )
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_hook_script(root), encoding="utf-8", newline="\n")
    path.chmod(0o755)
    return path


def uninstall_hook(root: Path) -> bool:
    """Delete the hook only if sealbox wrote it."""
    if not hook_installed(root):
        return False
    hook_path(root).unlink()
    return True
