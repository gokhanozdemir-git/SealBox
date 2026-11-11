import contextlib
import io
import json
import subprocess
import sys

import pytest

from sealbox.config import SealboxConfig
from sealbox.core.errors import ApprovalDeniedError, SealboxError
from sealbox.core.tokenization import PLACEHOLDER_RE, TokenVault
from sealbox.models.enums import SecretCategory
from sealbox.runner import (
    expose_value,
    remove_values,
    reveal_value,
    run_command,
    set_value,
)
from sealbox.sealing.rewriters import (
    JAVA,
    JAVASCRIPT,
    PYTHON,
    literal_bounds,
    to_env_name,
)
from sealbox.sealing.sealer import Sealer
from sealbox.vaultstore import ProjectVault, find_project_root
from tests.fixtures import (
    ALL_CONFIG_SECRETS,
    FAKE_ANTHROPIC,
    FAKE_AWS,
    FAKE_EMAIL,
    FAKE_PASSWORD,
)


class FakeKeyStore:
    def __init__(self):
        self.data: dict[str, str] = {}

    def get(self, account):
        return self.data.get(account)

    def set(self, account, secret):
        self.data[account] = secret


class Approvals:
    def __init__(self, answer=True):
        self.answer = answer
        self.requests = []

    def __call__(self, req):
        self.requests.append(req)
        return self.answer


@pytest.fixture
def keystore():
    return FakeKeyStore()


def seal(config: SealboxConfig, keystore, paths=(".",)):
    store = ProjectVault(config.workspace_root, keystore)
    vault = store.open(create=True)
    try:
        sealer = Sealer(config, vault)
        report = sealer.plan(list(paths))
        sealer.apply(report, store)
        return report
    finally:
        vault.close()


def test_python_secrets_move_to_env_and_data_is_masked(workspace, config, keystore):
    report = seal(config, keystore)
    text = (workspace / "src" / "config.py").read_text(encoding="utf-8")
    for secret in ALL_CONFIG_SECRETS:
        assert secret not in text
    assert 'DB_PASSWORD = os.environ["DB_PASSWORD"]' in text
    assert 'ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]' in text
    assert 'AWS_KEY_ID = os.environ["AWS_KEY_ID"]' in text
    # The data secret and the password repeated in a comment were both replaced.
    assert PLACEHOLDER_RE.search(text.split("ADMIN_EMAIL = ")[1])
    assert "# parola tekrar: __SECURE_PASSWORD_" in text
    result = next(f for f in report.files if f.path == "src/config.py")
    assert set(result.moved) == {"DB_PASSWORD", "ANTHROPIC_API_KEY", "AWS_KEY_ID"}
    compile(text, "config.py", "exec")


def test_vault_is_encrypted_on_disk_and_key_not_on_disk(workspace, config, keystore):
    seal(config, keystore)
    state = workspace / ".sealbox"
    blobs = b"".join(p.read_bytes() for p in state.rglob("*") if p.is_file())
    for secret in [*ALL_CONFIG_SECRETS, "topsecretvalue"]:
        assert secret.encode() not in blobs
    (key,) = keystore.data.values()
    assert key.encode() not in blobs
    assert find_project_root(workspace / "src") == workspace.resolve()


def test_env_file_replaced_by_sealed_file(workspace, config, keystore):
    (workspace / ".env").write_text("# yorum\nPORT=8000\nSECRET=topsecretvalue\n", "utf-8")
    seal(config, keystore)
    assert not (workspace / ".env").exists()
    sealed = (workspace / ".env.sealed").read_text(encoding="utf-8")
    assert "topsecretvalue" not in sealed
    assert "PORT=8000" in sealed and "# yorum" in sealed
    assert PLACEHOLDER_RE.fullmatch(sealed.split("SECRET=")[1].strip())


def test_javascript_rewrite(workspace, config, keystore):
    js = f'const dbPassword = "{FAKE_PASSWORD}";\nconst key = `{FAKE_ANTHROPIC}`;\n'
    (workspace / "src" / "app.js").write_text(js, encoding="utf-8")
    seal(config, keystore, ["src/app.js"])
    out = (workspace / "src" / "app.js").read_text(encoding="utf-8")
    assert "const dbPassword = process.env.DB_PASSWORD;" in out
    assert "const key = process.env.KEY;" in out


def test_java_rewrite(workspace, config, keystore):
    java = (
        "package app;\n\n"
        "public class Db {\n"
        "    /** Bağlantı ayarları. */\n"
        f'    private static final String DB_PASSWORD = "{FAKE_PASSWORD}";\n'
        f'    private String apiKey = "{FAKE_ANTHROPIC}";\n'
        f"    // eski parola: {FAKE_PASSWORD}\n"
        f'    String owner = "{FAKE_EMAIL}"; /* {FAKE_AWS} */\n'
        "}\n"
    )
    (workspace / "src" / "Db.java").write_text(java, encoding="utf-8")
    report = seal(config, keystore, ["src/Db.java"])
    out = (workspace / "src" / "Db.java").read_text(encoding="utf-8")
    assert 'private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");' in out
    assert 'private String apiKey = System.getenv("API_KEY");' in out
    for secret in (FAKE_PASSWORD, FAKE_ANTHROPIC, FAKE_EMAIL, FAKE_AWS):
        assert secret not in out
    # The comment repeat and e-mail are redacted, code stays intact, no import is added.
    assert "// eski parola: __SECURE_PASSWORD_" in out
    assert 'String owner = "__SECURE_EMAIL_' in out
    assert "import" not in out and out.startswith("package app;")
    assert not report.blocking_issues


def test_value_equal_to_its_env_name_is_not_a_false_alarm(workspace, config):
    # The value equals its own variable name: "TOKEN" -> process.env.TOKEN (a name, not a value).
    vault = TokenVault()
    vault.bind_env(vault.placeholder_for("TOKEN", SecretCategory.TOKEN), "TOKEN")
    (workspace / "src" / "t.js").write_bytes(b'const t = "TOKEN";\n')
    report = Sealer(config, vault).plan(["src/t.js"])
    (res,) = report.files
    assert res.new_text == "const t = process.env.TOKEN;\n"
    assert not res.issues


def test_one_unverifiable_file_does_not_stop_the_scan(workspace, config, monkeypatch):
    from sealbox.sealing import sealer as s

    real = s.Sealer._verify

    def verify(self, rel, new, values, written):
        if rel == "src/config.py":
            raise s.UnverifiedRedactionError("doğrulanamadı")
        return real(self, rel, new, values, written)

    monkeypatch.setattr(s.Sealer, "_verify", verify)
    report = Sealer(config, TokenVault()).plan(["."])
    by_path = {f.path: f for f in report.files}
    assert not by_path["src/config.py"].changed
    assert by_path["src/config.py"].issues[0].blocking
    assert by_path[".env"].changed  # the other files were still planned


def test_secret_inside_larger_string_is_left_with_warning(workspace, config, keystore):
    src = f'URL = "postgres://admin:{FAKE_PASSWORD}@db/app"\n'
    (workspace / "src" / "db.py").write_text(src, encoding="utf-8")
    report = seal(config, keystore, ["src/db.py"])
    assert (workspace / "src" / "db.py").read_text(encoding="utf-8") == src
    (res,) = report.files
    assert not res.changed
    assert res.issues and res.issues[0].blocking
    assert report.blocking_issues


def test_unknown_language_is_not_touched(workspace, config, keystore):
    src = f'var password = "{FAKE_PASSWORD}";\n'
    (workspace / "src" / "App.cs").write_text(src, encoding="utf-8")
    report = seal(config, keystore, ["src/App.cs"])
    assert (workspace / "src" / "App.cs").read_text(encoding="utf-8") == src
    assert report.files[0].issues[0].blocking


def test_check_mode_writes_nothing(workspace, config):
    before = (workspace / "src" / "config.py").read_bytes()
    report = Sealer(config, TokenVault()).plan(["."])
    assert not report.clean
    assert (workspace / "src" / "config.py").read_bytes() == before
    assert not (workspace / ".sealbox").exists()


def test_seal_is_idempotent(workspace, config, keystore):
    seal(config, keystore)
    first = (workspace / "src" / "config.py").read_text(encoding="utf-8")
    report = seal(config, keystore)
    assert report.clean
    assert (workspace / "src" / "config.py").read_text(encoding="utf-8") == first


def test_encrypted_backup_restores_original(workspace, config, keystore):
    from sealbox.core.crypto import AesGcmCipher
    from sealbox.vaultstore import _BACKUP_AAD

    original = (workspace / "src" / "config.py").read_bytes()
    seal(config, keystore)
    (backup,) = (workspace / ".sealbox" / "backups").rglob("config.py.enc")
    vault = ProjectVault(workspace, keystore).open()
    try:
        plain = AesGcmCipher(vault.key).decrypt(backup.read_bytes(), _BACKUP_AAD + b"src/config.py")
    finally:
        vault.close()
    assert plain == original


@pytest.mark.parametrize(
    ("ident", "expected"),
    [("dbPass", "DB_PASS"), ("DB_PASSWORD", "DB_PASSWORD"), ("api-key", "API_KEY")],
)
def test_env_names(ident, expected):
    assert to_env_name(ident) == expected


@pytest.mark.parametrize(
    ("src", "lang", "ok"),
    [
        ('x = "SECRET"', PYTHON, True),
        ('x = r"SECRET"', PYTHON, True),
        ('x = f"SECRET"', PYTHON, False),
        ('x = b"SECRET"', PYTHON, False),
        ('x = """SECRET"""', PYTHON, False),
        ('x = "a SECRET"', PYTHON, False),
        ("x = `SECRET`", JAVASCRIPT, True),
        ('String x = "SECRET";', JAVA, True),
        ("char x = 'SECRET';", JAVA, False),
        ('String x = """SECRET""";', JAVA, False),
    ],
)
def test_literal_bounds(src, lang, ok):
    start = src.index("SECRET")
    assert (literal_bounds(src, start, start + 6, lang) is not None) is ok


# --- exec ------------------------------------------------------------------


CHILD = (
    "import os, sys; "
    "print('len', len(os.environ['DB_PASSWORD'])); "
    "print('raw', os.environ['DB_PASSWORD']); "
    "print('err', os.environ['SECRET'], file=sys.stderr)"
)


def test_exec_injects_env_and_redacts_output(workspace, config, keystore):
    seal(config, keystore)
    approvals = Approvals(True)
    out, err = io.StringIO(), io.StringIO()
    code = run_command(
        workspace, [sys.executable, "-c", CHILD], approvals, keystore, stdout=out, stderr=err
    )
    assert code == 0
    assert f"len {len(FAKE_PASSWORD)}" in out.getvalue()
    assert FAKE_PASSWORD not in out.getvalue()
    assert "raw [GİZLİ:" in out.getvalue()
    assert "topsecretvalue" not in err.getvalue() and "[GİZLİ:" in err.getvalue()
    (req,) = approvals.requests
    assert "DB_PASSWORD" in req.names and "SECRET" in req.names
    assert FAKE_PASSWORD not in repr(req)


def test_exec_denied_never_starts_process(workspace, config, keystore, tmp_path):
    seal(config, keystore)
    marker = tmp_path / "ran"
    cmd = [sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"]
    with pytest.raises(ApprovalDeniedError):
        run_command(workspace, cmd, Approvals(False), keystore)
    assert not marker.exists()


def test_exec_approver_crash_counts_as_denied(workspace, config, keystore):
    seal(config, keystore)

    def boom(req):
        raise RuntimeError("ekran yok")

    with pytest.raises(ApprovalDeniedError):
        run_command(workspace, [sys.executable, "-c", "pass"], boom, keystore)


def test_exec_without_key_fails_closed(workspace, config, keystore):
    seal(config, keystore)
    with pytest.raises(SealboxError):
        run_command(workspace, [sys.executable, "-c", "pass"], Approvals(True), FakeKeyStore())


def test_exec_returns_child_exit_code(workspace, config, keystore):
    seal(config, keystore)
    cmd = [sys.executable, "-c", "raise SystemExit(7)"]
    assert run_command(workspace, cmd, Approvals(True), keystore, io.StringIO(), io.StringIO()) == 7


def test_exec_window_shows_risky_changes_since_last_approval(workspace, config, keystore):
    seal(config, keystore)
    cmd = [sys.executable, "-c", "pass"]

    def ask(answer):
        approvals = Approvals(answer)
        with contextlib.suppress(ApprovalDeniedError):
            run_command(workspace, cmd, approvals, keystore, io.StringIO(), io.StringIO())
        return approvals.requests[0].changes

    assert ask(True).first_run
    assert not ask(True).files
    (workspace / "src" / "send.py").write_text(
        "import requests\nfrom config import DB_PASSWORD\nrequests.post(URL, data=DB_PASSWORD)\n",
        encoding="utf-8",
    )
    denied = ask(False)
    assert [f.path for f in denied.files] == ["src/send.py"] and denied.strong
    # A denied state is not recorded, so the next dialog shows it again.
    assert ask(True).strong
    assert not ask(True).files
    assert "last_run.json" in (workspace / ".sealbox" / ".gitignore").read_text("utf-8")


def test_vault_reveal_and_set(workspace, config, keystore):
    seal(config, keystore)
    assert reveal_value(workspace, "DB_PASSWORD", Approvals(True), keystore) == FAKE_PASSWORD
    assert (
        set_value(workspace, "DB_PASSWORD", "yeni-parola-123", Approvals(True), keystore) is False
    )
    assert reveal_value(workspace, "DB_PASSWORD", Approvals(True), keystore) == "yeni-parola-123"
    assert set_value(workspace, "NEW_TOKEN", "tok-abcdef", Approvals(True), keystore) is True
    assert "NEW_TOKEN" in ProjectVault(workspace, keystore).names()
    with pytest.raises(ApprovalDeniedError):
        reveal_value(workspace, "DB_PASSWORD", Approvals(False), keystore)


def test_unrelated_values_kept(workspace, config, keystore):
    seal(config, keystore)
    text = (workspace / "src" / "config.py").read_text(encoding="utf-8")
    assert 'DB_HOST = "db.internal"' in text
    assert "MAX_TOKENS = 1024" in text
    assert FAKE_EMAIL not in text and FAKE_AWS not in text


def test_cli_check_exit_code(workspace):
    cmd = [sys.executable, "-m", "sealbox", "seal", "--check", "-w", str(workspace)]
    proc = subprocess.run(cmd, capture_output=True, check=False)  # noqa: S603
    assert proc.returncode == 1
    for secret in ALL_CONFIG_SECRETS:
        assert secret.encode() not in proc.stdout


def test_masked_data_listed_and_revealable(workspace, config, keystore):
    seal(config, keystore)
    masked = ProjectVault(workspace, keystore).masked()
    email_ph = next(ph for ph, kind in masked.items() if kind == "EMAIL")
    assert email_ph in (workspace / "src" / "config.py").read_text(encoding="utf-8")
    assert FAKE_EMAIL.encode() not in (workspace / ".sealbox" / "project.masked").read_bytes()
    assert reveal_value(workspace, email_ph, Approvals(True), keystore) == FAKE_EMAIL
    with pytest.raises(ApprovalDeniedError):
        reveal_value(workspace, email_ph, Approvals(False), keystore)


def test_env_file_with_bom(workspace, config, keystore):
    (workspace / ".env").write_bytes("﻿DB_PASSWORD=demo-only-not-real\n".encode())
    seal(config, keystore)
    sealed = (workspace / ".env.sealed").read_text(encoding="utf-8")
    assert "demo-only-not-real" not in sealed
    assert reveal_value(workspace, "DB_PASSWORD", Approvals(True), keystore) == (
        "demo-only-not-real"
    )


def test_cli_seal_refuses_subfolder_of_project(workspace):
    cmd = [sys.executable, "-m", "sealbox", "seal", "--check"]
    proc = subprocess.run(  # noqa: S603
        cmd, cwd=workspace / "src", capture_output=True, text=True, check=False
    )
    assert proc.returncode == 2
    assert ".env" in proc.stderr and "-w ." in proc.stderr


def test_env_name_conflict_is_reported(workspace, config, keystore):
    (workspace / ".env").write_text("DB_PASSWORD=baska-bir-deger-99\n", "utf-8")
    report = seal(config, keystore)
    env = next(f for f in report.files if f.path == ".env")
    assert any("farklı değerle" in i.message for i in env.issues)
    assert reveal_value(workspace, "DB_PASSWORD", Approvals(True), keystore) == (
        "baska-bir-deger-99"
    )


def test_cli_check_json_has_positions_but_no_values(workspace):
    cmd = [sys.executable, "-m", "sealbox", "seal", "--check", "--json"]
    cmd += ["-w", str(workspace)]
    proc = subprocess.run(cmd, capture_output=True, check=False)  # noqa: S603
    assert proc.returncode == 1
    for secret in [*ALL_CONFIG_SECRETS, "topsecretvalue"]:
        assert secret.encode() not in proc.stdout
    report = json.loads(proc.stdout)
    assert report["clean"] is False and report["written"] == []
    cfg = next(f for f in report["files"] if f["path"] == "src/config.py")
    text = (workspace / "src" / "config.py").read_text(encoding="utf-8").splitlines()
    span = next(s for s in cfg["spans"] if s["category"] == "PASSWORD")
    line = text[span["line"] - 1]
    assert line[span["col"] - 1 : span["end_col"] - 1] == FAKE_PASSWORD


def test_reseal_after_undo_does_not_duplicate(workspace, config, keystore):
    original = (workspace / "src" / "config.py").read_bytes()
    seal(config, keystore)
    first = ProjectVault(workspace, keystore).open()
    count, names = len(first), first.env_bindings().keys()
    first.close()
    (workspace / "src" / "config.py").write_bytes(original)  # the user pressed Ctrl+Z
    seal(config, keystore)
    again = ProjectVault(workspace, keystore).open()
    try:
        assert len(again) == count and again.env_bindings().keys() == names
    finally:
        again.close()


def test_expose_turns_masked_data_into_env_read(workspace, config, keystore):
    seal(config, keystore)
    email_ph = next(
        ph for ph, k in ProjectVault(workspace, keystore).masked().items() if k == "EMAIL"
    )
    name, written = expose_value(config, email_ph, keystore=keystore)
    assert name == "ADMIN_EMAIL" and written == ["src/config.py"]
    text = (workspace / "src" / "config.py").read_text(encoding="utf-8")
    assert 'ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]' in text and email_ph not in text
    assert FAKE_EMAIL not in text
    store = ProjectVault(workspace, keystore)
    assert store.names()["ADMIN_EMAIL"] == "EMAIL" and email_ph not in store.masked()
    child = "import os, sys; sys.stdout.write(str(len(os.environ['ADMIN_EMAIL'])))"
    out = io.StringIO()
    code = run_command(
        workspace, [sys.executable, "-c", child], Approvals(True), keystore, out, io.StringIO()
    )
    assert code == 0 and out.getvalue() == str(len(FAKE_EMAIL))
    # If the same data is later written in plain text, it is moved to the variable too.
    path = workspace / "src" / "extra.py"
    path.write_text(f'OTHER = "{FAKE_EMAIL}"\n', encoding="utf-8")
    seal(config, keystore, ["src/extra.py"])
    assert path.read_text(encoding="utf-8") == 'import os\nOTHER = os.environ["ADMIN_EMAIL"]\n'


def test_expose_rejects_unknown_and_taken_names(workspace, config, keystore):
    seal(config, keystore)
    masked = ProjectVault(workspace, keystore).masked()
    with pytest.raises(SealboxError):
        expose_value(config, "__SECURE_EMAIL_" + "0" * 32 + "__", keystore=keystore)
    with pytest.raises(SealboxError):
        expose_value(config, next(iter(masked)), "DB_PASSWORD", keystore=keystore)


def test_remove_refuses_used_entry_and_prunes_unused(workspace, config, keystore):
    seal(config, keystore)
    with pytest.raises(SealboxError, match="kullanılıyor"):
        remove_values(config, ["DB_PASSWORD"], Approvals(True), keystore)
    # The password was changed, leaving the old value orphaned in the vault.
    extra = workspace / "src" / "old.py"
    extra.write_text('OLD_SECRET = "EskiParola!2024xyz"' + chr(10), encoding="utf-8")
    seal(config, keystore, ["src/old.py"])
    extra.unlink()
    with pytest.raises(ApprovalDeniedError):
        remove_values(config, [], Approvals(False), keystore, unused=True)
    before = len(ProjectVault(workspace, keystore).open())
    removed = remove_values(config, [], Approvals(True), keystore, unused=True)
    assert removed == ["OLD_SECRET"]
    after = ProjectVault(workspace, keystore).open()
    try:
        assert len(after) == before - 1
        assert "EskiParola!2024xyz" not in [v for _, v in after.iter_plain_values()]
    finally:
        after.close()
    assert remove_values(config, [], Approvals(True), keystore, unused=True) == []
