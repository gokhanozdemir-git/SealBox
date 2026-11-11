"""Moves secrets out of files on disk and into the project vault, permanently.

There are two kinds of secrets:

- **Runtime secrets** (passwords, tokens, API keys...): moved into the vault. The code is
  rewritten to the language's "read an environment variable" expression, and the value is
  injected during ``exec``.
- **Data secrets** (e-mail addresses, national IDs, phone numbers, names...): only replaced
  with a placeholder, because programs rarely need the real value. If a program does need
  one, ``vault expose`` gives it a name; from then on it behaves like a runtime secret and
  the placeholder in the file is rewritten to an environment variable read.

The vault is saved **before** the files: if saving the vault failed after a file was
rewritten, the secret would be lost. Original files are backed up, encrypted with the
vault key, before they are rewritten.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from sealbox.config import SealboxConfig
from sealbox.core.errors import PathSecurityError, SealboxError
from sealbox.core.redaction import literal_pattern
from sealbox.core.scanner import Scanner, line_col
from sealbox.core.tokenization import PLACEHOLDER_RE, TokenVault
from sealbox.i18n import _
from sealbox.models.enums import SecretCategory
from sealbox.sealing.file_operations import (
    SafeFS,
    SkippedFile,
    WriteOp,
    sha256_bytes,
)
from sealbox.sealing.rewriters import (
    env_name_hint,
    in_comment,
    language_for,
    literal_bounds,
)
from sealbox.vaultstore import ProjectVault, atomic_write

RUNTIME_CATEGORIES = frozenset(
    {
        SecretCategory.PASSWORD,
        SecretCategory.TOKEN,
        SecretCategory.API_KEY,
        SecretCategory.PRIVATE_KEY,
        SecretCategory.CUSTOM,
    }
)
# Config files: secrets are replaced with placeholders; the app must read an env variable.
CONFIG_SUFFIXES = frozenset(
    {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml"}
)
# Documents are not needed at run time, so everything in them is redacted.
DOC_SUFFIXES = frozenset({".md", ".txt", ".rst"})
_ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".sealed")
_MIN_SWEEP_LEN = 4
ENV_LINE_RE = re.compile(
    r"^(?P<lead>\s*(?:export\s+)?)(?P<key>[A-Za-z_][A-Za-z0-9_]*)(?P<eq>\s*=\s*)(?P<val>.*?)\s*$"
)


def is_env_file(rel: str) -> bool:
    name = PurePosixPath(rel).name
    return (name == ".env" or name.startswith(".env.")) and not name.endswith(
        _ENV_TEMPLATE_SUFFIXES
    )


def sealed_env_path(rel: str) -> str:
    return rel + ".sealed"


class UnverifiedRedactionError(SealboxError):
    """A moved value is still visible in the new text, so the file is not written."""


@dataclass(frozen=True)
class SealIssue:
    path: str
    line: int
    category: str
    message: str
    blocking: bool  # True: the secret is still on disk


@dataclass(frozen=True)
class SecretSpan:
    """Location of a secret in a file, without its value (used for editor diagnostics)."""

    line: int
    col: int
    end_line: int
    end_col: int
    category: str


def span_of(text: str, start: int, end: int, category: SecretCategory) -> SecretSpan:
    line, col = line_col(text, start)
    end_line, end_col = line_col(text, end)
    return SecretSpan(line, col, end_line, end_col, category.value)


@dataclass
class FileResult:
    path: str
    original: bytes = field(repr=False)
    new_text: str | None = field(repr=False)
    output_path: str
    moved: list[str] = field(default_factory=list)  # env variable names moved to the vault
    masked: int = 0  # number of values replaced with a placeholder
    issues: list[SealIssue] = field(default_factory=list)
    spans: list[SecretSpan] = field(default_factory=list)  # where the scanner found secrets

    @property
    def changed(self) -> bool:
        return self.new_text is not None


@dataclass
class SealReport:
    files: list[FileResult]
    skipped: list[SkippedFile]

    @property
    def changed(self) -> list[FileResult]:
        return [f for f in self.files if f.changed]

    @property
    def blocking_issues(self) -> list[SealIssue]:
        return [i for f in self.files for i in f.issues if i.blocking]

    @property
    def clean(self) -> bool:
        return not self.changed and not self.blocking_issues


class Sealer:
    def __init__(
        self, config: SealboxConfig, vault: TokenVault, scanner: Scanner | None = None
    ) -> None:
        self.config = config
        self.fs = SafeFS(config)
        self.vault = vault
        self.scanner = scanner or Scanner(config.scanner)

    # --- File collection -------------------------------------------------

    def collect(self, selections: list[str]) -> tuple[list[str], list[SkippedFile]]:
        files, skipped = self.fs.collect(selections)
        rest: list[SkippedFile] = []
        for s in skipped:
            # .env files are excluded by default, but sealing reads them on purpose.
            if is_env_file(s.path) and s.reason == _("Hassas yol varsayılan olarak hariç"):
                files.append(s.path)
            else:
                rest.append(s)
        return files, rest

    def _read(self, rel: str) -> bytes:
        path = self.fs.resolve(rel)
        if not path.is_file():
            raise PathSecurityError(_("Normal dosya değil"))
        data = path.read_bytes()
        if len(data) > self.config.max_file_bytes:
            raise PathSecurityError(_("Boyut sınırı aşıldı"))
        return data

    # --- Planning --------------------------------------------------------

    def plan(self, selections: list[str]) -> SealReport:
        files, skipped = self.collect(selections)
        results: list[FileResult] = []
        for rel in files:
            try:
                data = self._read(rel)
                text = data.decode("utf-8")
            except (PathSecurityError, UnicodeDecodeError) as e:
                reason = str(e) if isinstance(e, PathSecurityError) else _("UTF-8 olmayan dosya")
                skipped.append(SkippedFile(rel, reason))
                continue
            try:
                if is_env_file(rel):
                    results.append(self._plan_env(rel, data, text))
                else:
                    results.append(self._plan_code(rel, data, text))
            except UnverifiedRedactionError as e:
                # One bad file must not stop the whole scan: leave it untouched for review.
                issue = SealIssue(rel, 1, "CUSTOM", str(e), blocking=True)
                results.append(FileResult(rel, data, None, rel, issues=[issue]))
        return SealReport(results, skipped)

    def _bind(self, ph: str, hint: str, category: SecretCategory) -> str:
        existing = self.vault.env_name_of(ph)
        if existing:
            return existing
        base = hint or f"SECURE_{category.value}"
        name, i = base, 2
        while self.vault.placeholder_for_env(name) not in (None, ph):
            name, i = f"{base}_{i}", i + 1
        self.vault.bind_env(ph, name)
        return name

    # --- Exposing data secrets at run time ---------------------------------

    def project_texts(self) -> dict[str, str]:
        """All readable project files, ``.env*`` included; for local searches only."""
        files, skipped = self.fs.collect(["."])
        files += [s.path for s in skipped if PurePosixPath(s.path).name.startswith(".env")]
        texts = {}
        for rel in files:
            try:
                texts[rel] = self._read(rel).decode("utf-8")
            except (PathSecurityError, UnicodeDecodeError, OSError):
                continue
        return texts

    def files_with(self, needle: str) -> list[str]:
        return [rel for rel, text in self.project_texts().items() if needle in text]

    def expose(self, ph: str, name: str | None = None) -> str:
        """Bind an env variable name to redacted data so that ``exec`` passes it too."""
        if ph not in self.vault:
            raise SealboxError(_("Kasada böyle bir etiket yok ('vault list' hepsini gösterir)"))
        current = self.vault.env_name_of(ph)
        if current is not None:
            if name not in (None, current):
                raise SealboxError(_(f"Bu değer zaten {current} adıyla çalışırken veriliyor"))
            return current
        if name is not None:
            if not ENV_LINE_RE.match(f"{name}=x"):
                raise SealboxError(_(f"Geçersiz değişken adı: {name}"))
            if self.vault.placeholder_for_env(name) is not None:
                raise SealboxError(_(f"{name} adı kasada başka bir değere bağlı"))
            self.vault.bind_env(ph, name)
            return name
        return self._bind(ph, self._hint_for(ph), self.vault.category_of(ph))

    def _hint_for(self, ph: str) -> str:
        """Derive a name from the first assignment of the placeholder (``ADMIN_EMAIL = ...``)."""
        for rel in self.files_with(ph):
            lang = language_for(rel)
            if lang is None:
                continue
            text = self._read(rel).decode("utf-8")
            start = text.index(ph)
            bounds = literal_bounds(text, start, start + len(ph), lang)
            if bounds is not None and (hint := env_name_hint(text, bounds[0])):
                return hint
        return ""

    def _plan_code(self, rel: str, data: bytes, text: str) -> FileResult:
        lang = language_for(rel)
        suffix = PurePosixPath(rel).suffix.lower()
        res = FileResult(rel, data, None, rel)

        # 1) Store detections in the vault; name runtime secrets that are whole literals.
        for d in self.scanner.scan(text, rel):
            res.spans.append(span_of(text, d.start, d.end, d.category))
            ph = self.vault.placeholder_for(d.value, d.category)
            if d.category in RUNTIME_CATEGORIES and lang is not None:
                bounds = literal_bounds(text, d.start, d.end, lang)
                if bounds is not None:
                    self._bind(ph, env_name_hint(text, bounds[0]), d.category)

        # 2) Look for every known vault value in this file, including repeats in comments.
        new = text
        replaced: set[str] = set()
        left: set[str] = set()
        values = sorted(
            (kv for kv in self.vault.iter_plain_values() if len(kv[1]) >= _MIN_SWEEP_LEN),
            key=lambda kv: len(kv[1]),
            reverse=True,
        )
        for ph, value in values:
            category = self.vault.category_of(ph)
            ph_spans = [m.span() for m in PLACEHOLDER_RE.finditer(new)]
            matches = [
                m.span()
                for m in literal_pattern(value).finditer(new)
                if not any(s <= m.start() < e for s, e in ph_spans)
            ]
            # A data secret with a name: move it if possible, otherwise redact it as before.
            exposed = category not in RUNTIME_CATEGORIES and self.vault.env_name_of(ph) is not None
            for start, end in reversed(matches):
                line = line_col(new, start)[0]
                runtime = category in RUNTIME_CATEGORIES or exposed
                if not runtime or suffix in DOC_SUFFIXES:
                    new = new[:start] + ph + new[end:]
                    res.masked += 1
                    replaced.add(value)
                    continue
                bounds = literal_bounds(new, start, end, lang) if lang else None
                if lang is not None and bounds is not None:
                    name = self._bind(ph, env_name_hint(new, bounds[0]), category)
                    new = new[: bounds[0]] + lang.env_expr(name) + new[bounds[1] :]
                    res.moved.append(name)
                    replaced.add(value)
                elif exposed or (lang is not None and in_comment(new, start, lang)):
                    new = new[:start] + ph + new[end:]
                    res.masked += 1
                    replaced.add(value)
                elif suffix in CONFIG_SUFFIXES:
                    quoted = start > 0 and new[start - 1] in "\"'"
                    hint = env_name_hint(new, start - 1 if quoted else start)
                    name = self._bind(ph, hint, category)
                    new = new[:start] + ph + new[end:]
                    res.masked += 1
                    replaced.add(value)
                    res.issues.append(
                        SealIssue(
                            rel,
                            line,
                            category.value,
                            _(
                                f"Ayar dosyasında karalandı; uygulama bu değeri {name} "
                                "ortam değişkeninden okumalı"
                            ),
                            blocking=False,
                        )
                    )
                else:
                    left.add(value)
                    why = (
                        _("bu dosya türü otomatik desteklenmiyor")
                        if lang is None
                        else _("değer daha büyük bir metnin parçası")
                    )
                    res.issues.append(
                        SealIssue(
                            rel,
                            line,
                            category.value,
                            _(f"Elle taşınmalı ({why}); dosyada bırakıldı"),
                            blocking=True,
                        )
                    )

        # 3) Placeholders that were named after redaction: turn the literal into an env read.
        if lang is not None and suffix not in DOC_SUFFIXES:
            for m in reversed(list(PLACEHOLDER_RE.finditer(new))):
                bound = self.vault.env_name_of(m.group(0))
                bounds = literal_bounds(new, m.start(), m.end(), lang)
                if bound is None or bounds is None or in_comment(new, m.start(), lang):
                    continue
                new = new[: bounds[0]] + lang.env_expr(bound) + new[bounds[1] :]
                res.moved.append(bound)

        if res.moved and lang is not None and lang.ensure_imports is not None:
            new = lang.ensure_imports(new)
        res.moved = sorted(set(res.moved))
        if new != text:
            written = {lang.env_expr(n) for n in res.moved} if lang is not None else set()
            self._verify(rel, new, replaced - left, written)
            res.new_text = new
        return res

    def _plan_env(self, rel: str, data: bytes, text: str) -> FileResult:
        res = FileResult(rel, data, None, sealed_env_path(rel))
        # PowerShell and Notepad add a BOM, which would hide the key on the first line.
        text = text.removeprefix("﻿")
        detections = self.scanner.scan(text, rel)
        res.spans = [span_of(text, d.start, d.end, d.category) for d in detections]
        out_lines: list[str] = []
        moved_values: set[str] = set()
        offset = 0
        for raw_line in text.splitlines(keepends=True):
            line = raw_line.rstrip("\r\n")
            ending = raw_line[len(line) :]
            m = ENV_LINE_RE.match(line)
            line_off = offset
            offset += len(raw_line)
            if m is None or line.lstrip().startswith("#"):
                out_lines.append(raw_line)
                continue
            val_start, val_end = line_off + m.start("val"), line_off + m.end("val")
            hits = [d for d in detections if d.start < val_end and val_start < d.end]
            value = m.group("val")
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if not hits or not value or PLACEHOLDER_RE.fullmatch(value):
                out_lines.append(raw_line)
                continue
            key = m.group("key")
            ph = self.vault.placeholder_for(value, hits[0].category)
            line_no = text.count("\n", 0, line_off) + 1
            if self.vault.placeholder_for_env(key) not in (None, ph):
                self.vault.unbind_env(key)  # the name in .env wins; drop the old binding
                res.issues.append(
                    SealIssue(
                        rel,
                        line_no,
                        hits[0].category.value,
                        _(
                            f"{key} başka bir dosyada farklı değerle de vardı; "
                            f"çalışırken {rel} içindeki değer verilecek"
                        ),
                        blocking=False,
                    )
                )
            if self.vault.env_name_of(ph) not in (None, key):
                res.issues.append(
                    SealIssue(
                        rel,
                        line_no,
                        hits[0].category.value,
                        _(f"Aynı değer zaten {self.vault.env_name_of(ph)} adıyla kasada"),
                        blocking=False,
                    )
                )
            else:
                self.vault.bind_env(ph, key)
            out_lines.append(f"{m.group('lead')}{key}{m.group('eq')}{ph}{ending}")
            res.moved.append(key)
            moved_values.add(value)
        if res.moved:
            new = "".join(out_lines)
            new = self._merge_sealed(res.output_path, new)
            # Check only the values: in "TOKEN=TOKEN" the key is not the value.
            values_only = "\n".join(
                m.group("val") if (m := ENV_LINE_RE.match(ln)) else ln for ln in new.splitlines()
            )
            self._verify(rel, values_only, moved_values, set())
            res.new_text = new
        return res

    def _merge_sealed(self, sealed_rel: str, new: str) -> str:
        """Keep keys from an existing .env.sealed that are missing from the new content."""
        path = self.fs.resolve(sealed_rel, must_exist=False)
        if not path.is_file():
            return new
        new_keys = {m.group("key") for ln in new.splitlines() if (m := ENV_LINE_RE.match(ln))}
        extra = [
            ln
            for ln in path.read_text(encoding="utf-8").splitlines()
            if (m := ENV_LINE_RE.match(ln)) and m.group("key") not in new_keys
        ]
        if not extra:
            return new
        sep = "" if new.endswith("\n") or not new else "\n"
        return new + sep + "\n".join(extra) + "\n"

    def _verify(self, rel: str, new: str, values: set[str], written: set[str]) -> None:
        """Make sure no moved value is left in the new text.

        ``written`` holds the env reads and .env keys we wrote ourselves; in
        ``TOKEN = "TOKEN"`` -> ``process.env.TOKEN`` the name is not the value.
        """
        for part in sorted(written, key=len, reverse=True):
            new = new.replace(part, "")
        for value in values:
            if literal_pattern(value).search(new):
                raise UnverifiedRedactionError(_(f"Karalama doğrulanamadı, dosya yazılmadı: {rel}"))

    # --- Applying --------------------------------------------------------

    def apply(self, report: SealReport, store: ProjectVault) -> list[str]:
        changed = report.changed
        if not changed:
            return []
        # Vault first: if saving it failed after the files were written, secrets would be lost.
        store.save(self.vault)
        written: list[str] = []
        for f in changed:
            assert f.new_text is not None
            store.save_backup(self.vault, f.path, f.original)
            if f.output_path == f.path:
                op = WriteOp(f.path, f.new_text, sha256_bytes(f.original))
                written.extend(self.fs.apply([op], backup_dir=None))
                continue
            # .env -> .env.sealed: a sensitive path, so it is written outside SafeFS.apply but
            # with the same path checks; the original is deleted only once the new file exists.
            target = self.fs.resolve(f.output_path, must_exist=False)
            source = self.fs.resolve(f.path)
            if sha256_bytes(source.read_bytes()) != sha256_bytes(f.original):
                raise SealboxError(_(f"Dosya karalama sırasında değişmiş: {f.path}"))
            atomic_write(target, f.new_text.encode("utf-8"))
            source.unlink()
            written.append(f.output_path)
        return written
