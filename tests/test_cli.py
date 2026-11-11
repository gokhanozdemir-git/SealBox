"""CLI: help, version, language, typo suggestions, init and status."""

import json

import pytest

from sealbox import __version__
from sealbox.__main__ import main
from sealbox.i18n import set_language


@pytest.fixture(autouse=True)
def reset_language():
    yield
    set_language(None)


def run(capsys, *args):
    try:
        code = main(list(args))
    except SystemExit as e:  # argparse --help / --version / hata
        code = e.code
    out = capsys.readouterr()
    return code, out.out, out.err


def test_overview_groups_commands_in_turkish(capsys):
    code, out, _ = run(capsys)
    assert code == 0
    assert "Kullanım: sealbox" in out
    for title in ("Başlarken:", "Günlük kullanım:", "Ekip:", "Kurtarma:", "Seçenekler:"):
        assert title in out
    for cmd in ("init", "status", "seal", "exec", "vault", "team", "recovery"):
        assert f"  {cmd} " in out
    assert "positional arguments" not in out and "show this help" not in out


def test_english_help(capsys):
    code, out, _ = run(capsys, "--lang", "en", "--help")
    assert code == 0
    assert "usage: sealbox" in out and "Getting started:" in out and "Kurtarma" not in out


def test_language_from_environment(capsys, monkeypatch):
    monkeypatch.setenv("SEALBOX_LANG", "en")
    _, out, _ = run(capsys, "help", "seal")
    assert "Examples:" in out and "sealbox seal --check" in out


def test_version(capsys):
    code, out, _ = run(capsys, "-V")
    assert code == 0 and out.strip() == f"sealbox {__version__}"


def test_typo_suggests_command(capsys):
    code, _, err = run(capsys, "sael")
    assert code == 2
    assert "Bunu mu demek istediniz: seal?" in err
    assert "sealbox --help" in err


def test_help_command_shows_examples_and_turkish_metavars(capsys):
    code, out, _ = run(capsys, "help", "seal")
    assert code == 0
    assert "Kullanım: sealbox seal" in out and "Örnekler:" in out
    assert "--workspace, -w KLASÖR" in out
    _, out, _ = run(capsys, "help", "recovery", "restore")
    assert "--kit DOSYA" in out


def test_lang_after_double_dash_is_left_for_the_program():
    from sealbox.__main__ import _take_language

    assert _take_language(["exec", "--", "tool", "--lang", "fr"]) == [
        "exec",
        "--",
        "tool",
        "--lang",
        "fr",
    ]


def test_status_of_new_project(capsys, workspace):
    code, out, _ = run(capsys, "status", "-w", str(workspace))
    assert code == 0
    assert "Bu projede henüz kasa yok  → sealbox seal" in out
    assert "Kurtarma kodu yok" in out
    assert "dosyada açık sır var" in out


def test_status_json(capsys, workspace):
    code, out, _ = run(capsys, "status", "-w", str(workspace), "--json")
    data = json.loads(out)
    assert code == 0 and data["ok"] is True
    levels = {c["text"]: c["level"] for c in data["checks"]}
    assert levels["Bu projede henüz kasa yok"] == "warn"


def test_status_reports_missing_key(capsys, workspace, config, tmp_path):
    from tests.vault_helpers import User, seal_with

    me = User("me", tmp_path / "me")
    seal_with(me.store(workspace), config)
    # No key in this computer's credential store (a fake, empty store replaces keyring).
    import sealbox.vaultstore as vs

    class Empty:
        def get(self, account):
            return None

        def set(self, account, secret):
            raise AssertionError("status hiçbir şey yazmamalı")

    original = vs.SystemKeyStore
    vs.SystemKeyStore = Empty  # type: ignore[misc]
    try:
        code, out, _ = run(capsys, "status", "-w", str(workspace))
    finally:
        vs.SystemKeyStore = original  # type: ignore[misc]
    assert code == 1
    assert "✗ Kasa anahtarı bu bilgisayarda yok  → sealbox recovery restore" in out


def test_init_lists_next_steps_and_changes_nothing(capsys, workspace):
    before = sorted(p.relative_to(workspace) for p in workspace.rglob("*"))
    code, out, _ = run(capsys, "init", "-w", str(workspace))
    assert code == 0
    assert "Sıradaki adımlar:" in out
    assert "1) sealbox seal" in out and "2) sealbox recovery setup" in out
    assert "git add .sealbox" in out
    assert sorted(p.relative_to(workspace) for p in workspace.rglob("*")) == before


def test_seal_check_prints_file_count(capsys, workspace):
    code, out, _ = run(capsys, "seal", "--check", "-w", str(workspace))
    assert code == 1
    assert "dosya tarandı" in out


def test_config_file_is_read_from_project_root(capsys, workspace):
    (workspace / "sealbox.toml").write_text(
        '[scanner]\nallow_values = ["topsecretvalue"]\n',
        encoding="utf-8",
    )
    _, out, _ = run(capsys, "seal", "--check", "--json", "-w", str(workspace))
    paths = {f["path"] for f in json.loads(out)["files"]}
    assert ".env" not in paths  # allow_values from sealbox.toml was applied


def test_password_inside_url_gets_a_box_and_a_status_reminder(capsys, tmp_path):
    from tests.fixtures import FAKE_PASSWORD

    root = tmp_path / "url"
    root.mkdir()
    (root / "db.py").write_text(
        f'URL = "postgres://admin:{FAKE_PASSWORD}@db.example.com/app"\n', encoding="utf-8"
    )
    code, out, _ = run(capsys, "seal", "--check", "-w", str(root))
    assert code == 1
    assert "DİKKAT: 1 sır dosyada AÇIK kaldı" in out
    assert "db.py:1" in out
    assert "'sealbox seal' çalıştırın" not in out  # seal cannot fix this; don't suggest it
    assert FAKE_PASSWORD not in out
    code, out, _ = run(capsys, "status", "-w", str(root))
    assert "⚠ 1 sır dosyada AÇIK kaldı, elle taşınmalı  → sealbox seal --check" in out
