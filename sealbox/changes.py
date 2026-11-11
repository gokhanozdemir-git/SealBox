"""Lines changed since the last approval that could leak secrets.

When an ``exec`` is approved, short digests of every line in the project (never the lines
themselves) are written to ``.sealbox/last_run.json``. On the next ``exec`` only new or
changed lines are examined, and three kinds of risk are reported:

* ``send``  - sends data over the network (requests, fetch, curl...). SealBox cannot see this.
* ``write`` - writes to a file. SealBox cannot see this either.
* ``print`` - prints to the screen or a log. SealBox hides known values in its output, but
  may not recognise a value that was transformed (base64, reversed, and so on).

Only lines that touch secrets are reported (files that read environment variables, vault
names, expressions that dump the whole environment); listing every change would train
users to ignore the warning. This is an aid, not a guarantee: a determined author can
evade it.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from sealbox.config import load_config
from sealbox.core.errors import SealboxError
from sealbox.core.fsutil import atomic_write
from sealbox.core.names import CONFIG_FILES, state_dir
from sealbox.sealing.file_operations import SafeFS

SNAPSHOT = "last_run.json"
_VERSION = 1
_MAX_CODE = 70

_SEND = re.compile(
    r"\brequests\.(?:get|post|put|patch|delete|request)\(|\bhttpx\.|\burlopen\(|urllib\.request"
    r"|http\.client|HTTPConnection|\baiohttp\.|\bsocket\.|\.sendall?\(|\bsmtplib\.|\bftplib\."
    r"|\bfetch\(|\baxios\b|XMLHttpRequest|\bhttps?\.(?:request|get)\(|sendBeacon|new WebSocket"
    r"|\bnet\.connect\(|nodemailer|\bcurl\b|\bwget\b|Invoke-WebRequest|Invoke-RestMethod"
    r"|HttpClient|WebClient|\.PostAsync\(|http\.Post\(|webhook",
    re.IGNORECASE,
)
_WRITE = re.compile(
    r"\bopen\([^)]*['\"][wax]b?\+?['\"]|\.write_(?:text|bytes)\(|\bjson\.dump\(|\bpickle\.dump\("
    r"|\bshutil\.copy|fs\.(?:writeFile|appendFile|createWriteStream)|(?:write|append)FileSync"
    r"|Out-File|Set-Content|Add-Content|\btee\b|File\.Write|FileWriter"
)
_PRINT = re.compile(
    r"\bprint\(|\bpprint\(|console\.(?:log|error|warn|info|debug)\(|\blogging\.\w+\("
    r"|\blog(?:ger)?\.(?:debug|info|warning|warn|error|exception|critical)\("
    r"|sys\.(?:stdout|stderr)\.write|process\.(?:stdout|stderr)\.write|System\.out\.print"
    r"|Console\.Write|fmt\.Print|\becho\b|Write-(?:Host|Output)"
)
_ENV_READ = re.compile(
    r"os\.environ|getenv\(|process\.env|System\.getenv|GetEnvironmentVariable|\$env:|ENV\["
    r"|__SECURE_"
)
# Expressions that use the whole environment at once; the line does not say which secret.
_ENV_DUMP = re.compile(
    r"dict\(os\.environ\)|os\.environ\.(?:items|copy|values|keys)\(|os\.environ\s*(?:[),]|$)"
    r"|process\.env\s*(?:[),;]|$)|\((?:\.\.\.)?process\.env\b(?!\.|\[)|\bprintenv\b"
    r"|Get-ChildItem\s+env:|\benv\s*\|"
)
# Transformations that would hide a value from output redaction.
_DISGUISE = re.compile(
    r"base64|b64encode|\bbtoa\(|\[::-1\]|\.reverse\(\)|\.hex\(\)|codecs\.encode|rot13"
    r"|Buffer\.from|\.join\(|\bord\(|charCodeAt|\bencode\(|\bzlib\.|\bgzip\.|\bhashlib\."
)


@dataclass(frozen=True)
class RiskLine:
    line: int
    kind: str  # "send" | "write" | "print"
    strong: bool  # SealBox's output redaction would not catch this
    code: str


@dataclass(frozen=True)
class RiskFile:
    path: str
    lines: list[RiskLine] = field(default_factory=list)

    @property
    def strong(self) -> bool:
        return any(r.strong for r in self.lines)


@dataclass(frozen=True)
class ChangeReport:
    first_run: bool  # no earlier approval; comparison starts with the next run
    files: list[RiskFile] = field(default_factory=list)

    @property
    def strong(self) -> bool:
        return any(f.strong for f in self.files)


def _digest(line: str) -> str:
    # Ignore indentation changes. Only a short digest is stored, never the line itself.
    return hashlib.blake2b(line.strip().encode("utf-8"), digest_size=8).hexdigest()


def _project_texts(root: Path) -> dict[str, str]:
    cfg_path = next((root / n for n in CONFIG_FILES if (root / n).is_file()), None)
    fs = SafeFS(load_config(cfg_path, root))
    files, _skipped = fs.collect(["."])
    texts: dict[str, str] = {}
    for rel in files:
        try:
            texts[rel] = fs.resolve(rel).read_bytes().decode("utf-8")
        except (UnicodeDecodeError, OSError, SealboxError):
            continue
    return texts


def _load(root: Path) -> dict[str, dict[str, str]] | None:
    path = state_dir(root) / SNAPSHOT
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("version") != _VERSION:
        return None
    files = data.get("files")
    return files if isinstance(files, dict) else None


def _whole_file(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _classify(
    code: str, file_reads_secrets: bool, names: re.Pattern[str] | None
) -> RiskLine | None:
    touches = bool(_ENV_READ.search(code) or (names is not None and names.search(code)))
    dumps = bool(_ENV_DUMP.search(code))
    reaches = touches or dumps or file_reads_secrets
    if _SEND.search(code) and reaches:
        return RiskLine(0, "send", True, code)
    if _WRITE.search(code) and reaches:
        return RiskLine(0, "write", True, code)
    if _PRINT.search(code):
        disguised = bool(_DISGUISE.search(code))
        if dumps or (disguised and reaches):
            return RiskLine(0, "print", True, code)
        if touches:
            return RiskLine(0, "print", False, code)
    return None


def find_risky_changes(root: Path, names: list[str]) -> ChangeReport:
    """Risky lines added or changed since the last approved ``exec`` (no values)."""
    old = _load(root)
    if old is None:
        return ChangeReport(first_run=True)
    pattern = re.compile(r"\b(?:" + "|".join(map(re.escape, names)) + r")\b") if names else None
    found: list[RiskFile] = []
    for rel, text in _project_texts(root).items():
        before = old.get(rel)
        if isinstance(before, dict) and before.get("sha") == _whole_file(text):
            continue
        seen = before.get("lines", "") if isinstance(before, dict) else ""
        known = {seen[i : i + 16] for i in range(0, len(seen), 16)}
        reads = bool(_ENV_READ.search(text) or (pattern is not None and pattern.search(text)))
        risky: list[RiskLine] = []
        for no, line in enumerate(text.splitlines(), 1):
            if not line.strip() or _digest(line) in known:
                continue
            hit = _classify(line.strip(), reads, pattern)
            if hit is not None:
                code = hit.code if len(hit.code) <= _MAX_CODE else hit.code[: _MAX_CODE - 1] + "…"
                risky.append(RiskLine(no, hit.kind, hit.strong, code))
        if risky:
            found.append(RiskFile(rel, risky))
    found.sort(key=lambda f: (not f.strong, f.path))
    return ChangeReport(first_run=False, files=found)


def remember(root: Path) -> None:
    """Record the approved state of the project; the next approval compares against it."""
    files = {
        rel: {
            "sha": _whole_file(text),
            "lines": "".join(sorted({_digest(ln) for ln in text.splitlines() if ln.strip()})),
        }
        for rel, text in _project_texts(root).items()
    }
    directory = state_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"version": _VERSION, "files": files}, separators=(",", ":"))
    atomic_write(directory / SNAPSHOT, payload.encode("utf-8"))
