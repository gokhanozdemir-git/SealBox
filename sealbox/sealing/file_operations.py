"""Safe reads and atomic writes inside the workspace.

- Paths are normalized. Absolute paths, ``..``, drive letters, NTFS alternate data streams
  (``:``), symbolic links and junctions are rejected.
- Sensitive paths (``.env``, keys, ``.git``...) are excluded by default.
- Binary and oversized files are skipped.
- Writes go: lock -> conflict check (SHA-256) -> backup -> temp file in the same folder +
  fsync -> ``os.replace``. If one step of a multi-file write fails, the files already
  replaced are restored from their backups.
"""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import os
import shutil
import stat
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from sealbox.config import SealboxConfig
from sealbox.core.errors import ConflictError, PathSecurityError
from sealbox.i18n import _

_BINARY_SNIFF = 8192


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class FileSnapshot:
    path: str  # POSIX path relative to the workspace
    text: str = field(repr=False)
    sha256: str
    size: int


@dataclass(frozen=True)
class SkippedFile:
    path: str
    reason: str


@dataclass(frozen=True)
class WriteOp:
    path: str
    new_text: str = field(repr=False)
    expected_sha256: str | None  # None means the file must not exist yet


def _matches(rel: PurePosixPath, pattern: str) -> bool:
    s = rel.as_posix()
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        return any(fnmatch.fnmatch(p, prefix) for p in rel.parts[:-1]) or s.startswith(prefix + "/")
    if "/" in pattern:
        return fnmatch.fnmatch(s, pattern)
    return any(fnmatch.fnmatch(part, pattern) for part in rel.parts)


def is_link_like(p: Path) -> bool:
    try:
        st = p.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    is_junction = getattr(p, "is_junction", None)
    if is_junction is not None and is_junction():
        return True
    # Windows reparse points (junctions, mount points)
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


class SafeFS:
    def __init__(self, config: SealboxConfig) -> None:
        self.config = config
        self.root = config.workspace_root.resolve()
        if not self.root.is_dir():
            raise PathSecurityError(_("Çalışma dizini bulunamadı"))

    # --- Path validation ----------------------------------------------------

    def normalize(self, rel: str) -> PurePosixPath:
        if not rel or "\x00" in rel:
            raise PathSecurityError(_("Geçersiz dosya yolu"))
        raw = rel.replace("\\", "/")
        p = PurePosixPath(raw)
        if p.is_absolute() or raw.startswith("//") or (len(raw) > 1 and raw[1] == ":"):
            raise PathSecurityError(_("Mutlak yollar kabul edilmez"))
        if ":" in raw:
            raise PathSecurityError(_("Yolda ':' karakteri kabul edilmez"))
        parts = [x for x in p.parts if x not in ("", ".")]
        if any(x == ".." for x in parts) or not parts:
            raise PathSecurityError(_("Çalışma dizini dışına çıkılamaz"))
        return PurePosixPath(*parts)

    def resolve(self, rel: str, must_exist: bool = True) -> Path:
        norm = self.normalize(rel)
        current = self.root
        for part in norm.parts:
            current = current / part
            if is_link_like(current):
                raise PathSecurityError(_("Sembolik bağlantı veya junction izlenmez"))
        if must_exist and not current.exists():
            raise PathSecurityError(_("Dosya bulunamadı"))
        real = Path(os.path.realpath(current))
        if not real.is_relative_to(self.root):
            raise PathSecurityError(_("Çalışma dizini dışına çıkılamaz"))
        return current

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def is_excluded(self, rel: str) -> bool:
        p = self.normalize(rel)
        if any(_matches(p, pat) or p.as_posix() == pat for pat in self.config.explicit_includes):
            return False
        return any(_matches(p, pat) for pat in self.config.excludes)

    # --- File listing -------------------------------------------------------

    def _walk(self, directory: Path) -> Iterator[Path]:
        for entry in sorted(directory.iterdir()):
            if is_link_like(entry):
                continue
            if entry.is_dir():
                if self.is_excluded(self.rel(entry) + "/x"):
                    continue
                yield from self._walk(entry)
            elif entry.is_file():
                yield entry

    def collect(self, selections: list[str]) -> tuple[list[str], list[SkippedFile]]:
        """Expand the selected files and folders into a list of safe files."""
        chosen: list[str] = []
        skipped: list[SkippedFile] = []
        for sel in selections:
            try:
                is_root = sel.replace("\\", "/").strip("/") in ("", ".")
                target = self.root if is_root else self.resolve(sel)
            except PathSecurityError as e:
                skipped.append(SkippedFile(sel, str(e)))
                continue
            files = list(self._walk(target)) if target.is_dir() else [target]
            for f in files:
                rel = self.rel(f)
                reason = self.check_readable(rel)
                if reason:
                    skipped.append(SkippedFile(rel, reason))
                elif rel not in chosen:
                    chosen.append(rel)
        return chosen, skipped

    def check_readable(self, rel: str) -> str | None:
        """Return why a file cannot be read, or None if it can."""
        try:
            path = self.resolve(rel)
        except PathSecurityError as e:
            return str(e)
        if self.is_excluded(rel):
            return _("Hassas yol varsayılan olarak hariç")
        if not path.is_file():
            return _("Normal dosya değil")
        if path.stat().st_size > self.config.max_file_bytes:
            return _("Boyut sınırı aşıldı")
        with path.open("rb") as fh:
            head = fh.read(_BINARY_SNIFF)
        if b"\x00" in head:
            return _("Binary dosya atlandı")
        return None

    # --- Reading ------------------------------------------------------------

    def read_snapshot(self, rel: str) -> FileSnapshot:
        reason = self.check_readable(rel)
        if reason:
            raise PathSecurityError(reason)
        path = self.resolve(rel)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(self.config.max_file_bytes + 1)
        if len(data) > self.config.max_file_bytes:
            raise PathSecurityError(_("Boyut sınırı aşıldı"))
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise PathSecurityError(_("UTF-8 olmayan dosya atlandı")) from None
        return FileSnapshot(
            path=self.rel(path), text=text, sha256=sha256_bytes(data), size=len(data)
        )

    def current_sha256(self, rel: str) -> str | None:
        path = self.resolve(rel, must_exist=False)
        if not path.exists():
            return None
        return sha256_bytes(path.read_bytes())

    # --- Writing ------------------------------------------------------------

    @contextlib.contextmanager
    def _lock(self, rel: str) -> Iterator[None]:
        lock_dir = self.config.state_dir / "locks"
        lock_dir.mkdir(parents=True, exist_ok=True)
        lock = lock_dir / (hashlib.sha256(rel.encode()).hexdigest()[:32] + ".lock")
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise ConflictError(_(f"Dosya başka bir işlem tarafından kilitli: {rel}")) from None
        os.close(fd)
        try:
            yield
        finally:
            with contextlib.suppress(FileNotFoundError):
                lock.unlink()

    def apply(self, ops: list[WriteOp], backup_dir: Path | None) -> list[str]:
        """Apply all writes or leave none of them in place (best effort)."""
        with contextlib.ExitStack() as stack:
            for op in ops:
                stack.enter_context(self._lock(op.path))
            # 1) Conflict check, before anything is written.
            for op in ops:
                if self.is_excluded(op.path):
                    raise PathSecurityError(_(f"Hassas yola yazılamaz: {op.path}"))
                if self.current_sha256(op.path) != op.expected_sha256:
                    raise ConflictError(
                        _(f"Dosya iş başladıktan sonra değişmiş, üzerine yazılmadı: {op.path}")
                    )
            # 2) Backups and temporary files.
            backups: dict[str, Path] = {}
            temps: dict[str, Path] = {}
            try:
                for op in ops:
                    target = self.resolve(op.path, must_exist=False)
                    if backup_dir is not None and target.exists():
                        dest = backup_dir / op.path
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(target, dest)
                        with contextlib.suppress(OSError):
                            os.chmod(dest, 0o600)
                        backups[op.path] = dest
                    target.parent.mkdir(parents=True, exist_ok=True)
                    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".sealbox-tmp-")
                    with os.fdopen(fd, "wb") as fh:
                        fh.write(op.new_text.encode("utf-8"))
                        fh.flush()
                        os.fsync(fh.fileno())
                    if target.exists():
                        shutil.copymode(target, tmp)
                    temps[op.path] = Path(tmp)
                # 3) Atomic replace.
                done: list[str] = []
                try:
                    for op in ops:
                        os.replace(temps[op.path], self.resolve(op.path, must_exist=False))
                        del temps[op.path]
                        done.append(op.path)
                except BaseException:
                    self._rollback(done, ops, backups)
                    raise
                return done
            finally:
                for leftover in temps.values():
                    with contextlib.suppress(OSError):
                        leftover.unlink()

    def _rollback(self, done: list[str], ops: list[WriteOp], backups: dict[str, Path]) -> None:
        by_path = {op.path: op for op in ops}
        for rel in reversed(done):
            target = self.resolve(rel, must_exist=False)
            if rel in backups:
                shutil.copy2(backups[rel], target)
            elif by_path[rel].expected_sha256 is None:
                with contextlib.suppress(FileNotFoundError):
                    target.unlink()
