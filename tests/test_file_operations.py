import _thread  # noqa: F401  (imported before _winapi for the Windows junction helper)
import os
import sys

import pytest

from sealbox.core.errors import ConflictError, PathSecurityError
from sealbox.sealing.file_operations import SafeFS, WriteOp, sha256_bytes


@pytest.mark.parametrize(
    "bad",
    [
        "../outside.txt",
        "src/../../x",
        "/etc/passwd",
        "C:/Windows/win.ini",
        "C:\\x",
        "\\\\server\\share",
        "src/config.py:stream",
        "",
        "a\x00b",
        "..",
        "./..",
    ],
)
def test_traversal_rejected(config, bad):
    with pytest.raises(PathSecurityError):
        SafeFS(config).resolve(bad)


def test_normal_paths(config):
    fs = SafeFS(config)
    assert fs.resolve("src/config.py").is_file()
    assert fs.resolve("./src//config.py").is_file()
    assert fs.resolve("src\\config.py").is_file()


def test_sensitive_defaults_excluded(config):
    fs = SafeFS(config)
    files, skipped = fs.collect(["."])
    assert "src/config.py" in files
    assert ".env" not in files and "image.bin" not in files
    reasons = {s.path: s.reason for s in skipped}
    assert "Hassas" in reasons[".env"]
    assert "Binary" in reasons["image.bin"]


def test_explicit_include_overrides(config, workspace):
    config.explicit_includes = [".env"]
    files, _ = SafeFS(config).collect([".env"])
    assert files == [".env"]


def test_size_limit(config, workspace):
    (workspace / "big.txt").write_bytes(b"a" * 2048)
    config.max_file_bytes = 1024
    _, skipped = SafeFS(config).collect(["big.txt"])
    assert skipped and "Boyut" in skipped[0].reason


def test_non_utf8_rejected(config, workspace):
    (workspace / "latin.txt").write_bytes("şifre".encode("cp1254"))
    with pytest.raises(PathSecurityError):
        SafeFS(config).read_snapshot("latin.txt")


def test_symlink_rejected(config, workspace, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("outside secret")
    link = workspace / "link.txt"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("Bu ortamda symlink oluşturulamıyor")
    fs = SafeFS(config)
    with pytest.raises(PathSecurityError):
        fs.resolve("link.txt")
    files, _ = fs.collect(["."])
    assert "link.txt" not in files


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junction testi")
def test_junction_rejected(config, workspace, tmp_path):
    import _winapi

    outside = tmp_path / "outside_dir"
    outside.mkdir()
    (outside / "s.txt").write_text("outside secret")
    _winapi.CreateJunction(str(outside), str(workspace / "jdir"))
    fs = SafeFS(config)
    with pytest.raises(PathSecurityError):
        fs.resolve("jdir/s.txt")
    files, _ = fs.collect(["."])
    assert not any(f.startswith("jdir") for f in files)


def test_atomic_apply_and_backup(config, workspace):
    fs = SafeFS(config)
    snap = fs.read_snapshot("src/util.py")
    backup = config.state_dir / "backups" / "j1"
    fs.apply([WriteOp("src/util.py", "new\r\ncontent\n", snap.sha256)], backup)
    assert (workspace / "src" / "util.py").read_bytes() == b"new\r\ncontent\n"
    assert (backup / "src" / "util.py").read_bytes() == snap.text.encode()
    assert not list((workspace / "src").glob(".sealbox-tmp-*"))


def test_conflict_detected(config, workspace):
    fs = SafeFS(config)
    snap = fs.read_snapshot("src/util.py")
    (workspace / "src" / "util.py").write_text("changed by someone else")
    with pytest.raises(ConflictError):
        fs.apply([WriteOp("src/util.py", "agent", snap.sha256)], None)
    assert (workspace / "src" / "util.py").read_text() == "changed by someone else"


def test_lock_prevents_concurrent_write(config, workspace):
    fs = SafeFS(config)
    snap = fs.read_snapshot("src/util.py")
    with fs._lock("src/util.py"), pytest.raises(ConflictError):
        fs.apply([WriteOp("src/util.py", "x", snap.sha256)], None)


def test_multi_file_rollback(config, workspace, monkeypatch):
    fs = SafeFS(config)
    a = fs.read_snapshot("src/util.py")
    b = fs.read_snapshot("src/config.py")
    original_a = (workspace / "src" / "util.py").read_bytes()
    real_replace = os.replace
    calls = {"n": 0}

    def flaky_replace(src, dst):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)
    with pytest.raises(OSError):
        fs.apply(
            [WriteOp("src/util.py", "A2", a.sha256), WriteOp("src/config.py", "B2", b.sha256)],
            config.state_dir / "backups" / "j2",
        )
    monkeypatch.setattr(os, "replace", real_replace)
    assert (workspace / "src" / "util.py").read_bytes() == original_a
    assert sha256_bytes((workspace / "src" / "config.py").read_bytes()) == b.sha256
    assert not list((workspace / "src").glob(".sealbox-tmp-*"))


def test_write_to_excluded_path_blocked(config):
    with pytest.raises(PathSecurityError):
        SafeFS(config).apply([WriteOp(".env", "X=1", None)], None)
