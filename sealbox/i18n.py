"""User-facing messages in English and Turkish.

Source strings are written in Turkish and marked with ``_("...")``; their English
translations live in ``i18n_en.EN``, keyed by the Turkish text. For strings with variables
the key uses ``{}`` placeholders: at run time ``_(f"Dosya bulunamadı: {name}")`` matches the
template ``"Dosya bulunamadı: {}"``. Module-level constants are marked with ``N_()``, which
only marks them; they are translated with ``_()`` where they are used.

Language order: ``--lang``, then ``SEALBOX_LANG``, then the OS language (English unless the
OS is Turkish). ``tests/test_i18n.py`` fails on any missing or unused translation.
"""

from __future__ import annotations

import locale
import os
import re
import sys
from functools import cache

LANGUAGES = ("tr", "en")
_chosen: str | None = None


def set_language(lang: str | None) -> None:
    global _chosen
    _chosen = lang if lang in LANGUAGES else None


def _system_language() -> str:
    if sys.platform == "win32":
        try:
            import ctypes

            lang_id = ctypes.windll.kernel32.GetUserDefaultUILanguage()
            return "tr" if lang_id & 0x3FF == 0x1F else "en"  # LANG_TURKISH
        except (AttributeError, OSError):
            pass
    name = (locale.getlocale()[0] or os.environ.get("LANG", "")).lower()
    return "tr" if name.startswith(("tr", "turkish")) else "en"


def language() -> str:
    if _chosen:
        return _chosen
    env = os.environ.get("SEALBOX_LANG", "").strip().lower()[:2]
    return env if env in LANGUAGES else _system_language()


@cache
def _templates() -> list[tuple[re.Pattern[str], str]]:
    from sealbox.i18n_en import EN

    out = []
    for tr, en in EN.items():
        if "{}" in tr:
            body = "(.*?)".join(re.escape(part) for part in tr.split("{}"))
            out.append((re.compile(body, re.S), en))
    # Try templates with more fixed text first, so that "{} dosyası var" wins over "{}".
    out.sort(key=lambda p: -len(p[0].pattern))
    return out


def _(text: str) -> str:
    if language() != "en":
        return text
    from sealbox.i18n_en import EN

    exact = EN.get(text)
    if exact is not None:
        return exact
    for pattern, en in _templates():
        m = pattern.fullmatch(text)
        if m:
            return en.format(*m.groups())
    return text


def N_(text: str) -> str:
    """Mark a module-level constant for translation without translating it."""
    return text
