"""Git history scanning and the pre-commit hook (real git, temporary repository)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from sealbox import history as h
from tests.fixtures import FAKE_ANTHROPIC, FAKE_PASSWORD
from tests.vault_helpers import User, seal_with

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git yok")


def git(root: Path, *args: str) -> str:
    res = subprocess.run(  # noqa: S603 - testin kendi git komutu
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],  # noqa: S607
        cwd=root,
        capture_output=True,
        check=True,
    )
    return res.stdout.decode("utf-8")


@pytest.fixture
def repo(workspace: Path) -> Path:
    git(workspace, "init", "-q")
    git(workspace, "config", "core.hooksPath", ".git/hooks")  # ignore the user's global git config
    git(workspace, "add", "-A")
    git(workspace, "commit", "-q", "-m", "ilk")  # secrets are still exposed in the file
    return workspace


@pytest.fixture
def me(tmp_path: Path) -> User:
    return User("me", tmp_path / "me")


def sealed(repo: Path, me: User, config) -> None:
    seal_with(me.store(repo), config)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "mühürlendi")


def test_history_finds_values_committed_before_sealing(repo, me, config):
    sealed(repo, me, config)
    vault = me.store(repo).open()
    try:
        hits = {hit.label: hit for hit in h.scan_history(repo, vault)}
    finally:
        vault.close()
    pw = hits["DB_PASSWORD"]
    assert pw.path == "src/config.py" and pw.count == 1 and pw.named
    assert len(pw.commit) == 7 and pw.date
    assert not pw.pushed  # no remote
    assert "ANTHROPIC_API_KEY" in hits
    assert any(not hit.named for hit in hits.values())  # redacted e-mail / national ID


def test_history_marks_pushed_commits(repo, me, config, tmp_path):
    sealed(repo, me, config)
    remote = tmp_path / "remote.git"
    git(tmp_path, "init", "-q", "--bare", str(remote))
    git(repo, "remote", "add", "origin", str(remote))
    git(repo, "push", "-q", "origin", "HEAD:main")
    git(repo, "fetch", "-q", "origin")
    vault = me.store(repo).open()
    try:
        hits = h.scan_history(repo, vault)
    finally:
        vault.close()
    assert hits and all(hit.pushed for hit in hits)


def test_history_clean_when_sealed_before_first_commit(workspace, me, config):
    seal_with(me.store(workspace), config)
    git(workspace, "init", "-q")
    git(workspace, "add", "-A")
    git(workspace, "commit", "-q", "-m", "ilk")
    vault = me.store(workspace).open()
    try:
        assert h.scan_history(workspace, vault) == []
    finally:
        vault.close()


def test_staged_scan_reports_file_and_line(repo, me, config):
    sealed(repo, me, config)
    (repo / "leak.py").write_text(f'x = 1\nKEY = "{FAKE_ANTHROPIC}"\n', encoding="utf-8")
    git(repo, "add", "leak.py")
    vault = me.store(repo).open()
    try:
        hits = h.scan_staged(repo, vault)
    finally:
        vault.close()
    assert [(hit.path, hit.line, hit.label) for hit in hits] == [
        ("leak.py", 2, "ANTHROPIC_API_KEY")
    ]


def test_matcher_skips_short_values(me, tmp_path):
    from sealbox.core.tokenization import TokenVault
    from sealbox.models.enums import SecretCategory

    vault = TokenVault()
    try:
        vault.bind_env(vault.placeholder_for("1234", SecretCategory.PASSWORD), "PIN")
        vault.bind_env(vault.placeholder_for(FAKE_PASSWORD, SecretCategory.PASSWORD), "PW")
        m = h.Matcher(vault)
        assert m.find("pin 1234") == []
        assert m.find(f"pw={FAKE_PASSWORD}") == [("PW", True)]
    finally:
        vault.close()


# --- Hook --------------------------------------------------------------------------------


def test_install_writes_hook_and_refuses_foreign_hook(repo):
    path = h.install_hook(repo)
    assert h.hook_installed(repo)
    assert "sealbox hook run" in path.read_text(encoding="utf-8")
    h.install_hook(repo)  # may update its own hook
    assert h.uninstall_hook(repo) and not path.exists()
    path.write_text("#!/bin/sh\nnpx lint-staged\n", encoding="utf-8")
    with pytest.raises(h.SealboxError):
        h.install_hook(repo)
    assert not h.uninstall_hook(repo)
    assert path.read_text(encoding="utf-8") == "#!/bin/sh\nnpx lint-staged\n"


@pytest.fixture
def cli_keystore(me, monkeypatch):
    """Make the CLI use me's fake store instead of the real keyring."""
    import sealbox.vaultstore as vs

    monkeypatch.setattr(vs, "SystemKeyStore", lambda: me.keystore)
    monkeypatch.setattr(vs.RecoveryStore, "default", classmethod(lambda cls: me.recovery))


def test_hook_run_blocks_commit_with_vault_value(repo, me, config, cli_keystore, capsys):
    from sealbox.__main__ import main

    sealed(repo, me, config)
    (repo / "leak.py").write_text(f'PW = "{FAKE_PASSWORD}"\n', encoding="utf-8")
    git(repo, "add", "leak.py")
    assert main(["hook", "run", "-w", str(repo)]) == 1
    err = capsys.readouterr().err
    assert "leak.py:1  DB_PASSWORD" in err
    assert FAKE_PASSWORD not in err
    git(repo, "reset", "-q", "leak.py")
    assert main(["hook", "run", "-w", str(repo)]) == 0


def test_hook_run_without_key_only_warns(repo, me, config, monkeypatch, capsys):
    import sealbox.vaultstore as vs
    from sealbox.__main__ import main
    from tests.vault_helpers import FakeKeyStore

    sealed(repo, me, config)
    monkeypatch.setattr(vs, "SystemKeyStore", FakeKeyStore)  # empty store: no key
    (repo / "leak.py").write_text(f'KEY = "{FAKE_ANTHROPIC}"\n', encoding="utf-8")
    git(repo, "add", "leak.py")
    assert main(["hook", "run", "-w", str(repo)]) == 0
    err = capsys.readouterr().err
    assert "genel kurallarla" in err and "leak.py:1" in err


def test_history_command_and_init(repo, me, config, cli_keystore, capsys):
    from sealbox.__main__ import main

    sealed(repo, me, config)
    assert main(["history", "-w", str(repo)]) == 1
    out = capsys.readouterr().out
    assert "DB_PASSWORD: 1 commit'te açık" in out and "yalnızca bu bilgisayarda" in out
    assert FAKE_PASSWORD not in out
    assert main(["init", "-w", str(repo)]) == 0
    out = capsys.readouterr().out
    assert "Git geçmişi:" in out
    assert "sealbox hook install" in out


def test_json_outputs_for_editor(repo, me, config, cli_keystore, capsys):
    import json

    from sealbox.__main__ import main

    sealed(repo, me, config)
    assert main(["history", "--json", "-w", str(repo)]) == 1
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["git"] is True
    pw = next(hit for hit in data["hits"] if hit["label"] == "DB_PASSWORD")
    assert pw["path"] == "src/config.py" and pw["named"] is True and pw["pushed"] is False
    assert FAKE_PASSWORD not in out
    assert main(["hook", "status", "--json", "-w", str(repo)]) == 0
    assert json.loads(capsys.readouterr().out) == {"git": True, "installed": False}
    h.install_hook(repo)
    main(["hook", "status", "--json", "-w", str(repo)])
    assert json.loads(capsys.readouterr().out)["installed"] is True
