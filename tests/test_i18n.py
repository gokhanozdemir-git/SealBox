"""Translations: every marked string has an English entry and no entry is unused."""

import ast
from pathlib import Path

import pytest

import sealbox
from sealbox import i18n
from sealbox.i18n import _
from sealbox.i18n_en import EN

PACKAGE = Path(sealbox.__file__).parent


def _template(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in node.values)
    return None


def marked_texts() -> dict[str, str]:
    """Map each ``_("...")`` / ``N_("...")`` string in the source to where it first appears."""
    found: dict[str, str] = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("_", "N_")
                and node.args
            ):
                text = _template(node.args[0])
                if text is not None:
                    found.setdefault(text, f"{path.name}:{node.lineno}")
    return found


def test_every_marked_text_has_english():
    missing = {t: loc for t, loc in marked_texts().items() if t not in EN}
    assert not missing, "İngilizcesi eksik:\n" + "\n".join(
        f"{v}: {k!r}" for k, v in missing.items()
    )


def test_no_stale_translations():
    stale = set(EN) - set(marked_texts())
    assert not stale, f"Kodda artık kullanılmayan çeviriler: {sorted(stale)}"


def test_placeholders_match():
    bad = [k for k, v in EN.items() if k.count("{}") != v.count("{}")]
    assert not bad


@pytest.fixture
def english():
    i18n.set_language("en")
    yield
    i18n.set_language(None)


def test_exact_and_template_translation(english):
    assert _("Dosya bulunamadı") == "File not found"
    assert _("Dosya başka bir işlem tarafından kilitli: src/a.py") == (
        "File is locked by another process: src/a.py"
    )
    assert _("@ali kullanıcısını sahip yapmak") == "Make @ali an owner"
    assert _("çevirisi olmayan metin") == "çevirisi olmayan metin"


def test_turkish_is_default_in_tests():
    assert i18n.language() == "tr"
    assert _("Dosya bulunamadı") == "Dosya bulunamadı"


def test_language_order(monkeypatch):
    monkeypatch.setenv("SEALBOX_LANG", "en")
    assert i18n.language() == "en"
    i18n.set_language("tr")
    try:
        assert i18n.language() == "tr"
    finally:
        i18n.set_language(None)
    monkeypatch.setenv("SEALBOX_LANG", "de")
    monkeypatch.setattr(i18n, "_system_language", lambda: "en")
    assert i18n.language() == "en"


def test_errors_are_translated(english, tmp_path):
    from sealbox.config import SealboxConfig
    from sealbox.core.errors import PathSecurityError
    from sealbox.sealing.file_operations import SafeFS

    with pytest.raises(PathSecurityError, match="Cannot leave the working directory"):
        SafeFS(SealboxConfig(workspace_root=tmp_path)).resolve("../x")
