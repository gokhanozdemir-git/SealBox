"""CLI help: localized headings, usage examples and "did you mean" suggestions."""

from __future__ import annotations

import argparse
import difflib
import sys
from typing import Any, NoReturn

from sealbox.i18n import _, language

# argparse translates its own strings through gettext (``argparse._``); we supply Turkish.
_ARGPARSE_TR = {
    "usage: ": "Kullanım: ",
    "positional arguments": "Argümanlar",
    "options": "Seçenekler",
    "show this help message and exit": "Bu yardımı göster",
    "show program's version number and exit": "Sürümü göster",
    "the following arguments are required: %s": "şu argümanlar gerekli: %s",
    "unrecognized arguments: %s": "tanınmayan argümanlar: %s",
    "expected one argument": "bir değer bekleniyor",
    "argument %(argument_name)s: %(message)s": "%(argument_name)s: %(message)s",
    "invalid choice: %(value)r (choose from %(choices)s)": (
        "geçersiz seçim: %(value)r (seçenekler: %(choices)s)"
    ),
    "ambiguous option: %(option)s could match %(matches)s": (
        "belirsiz seçenek: %(option)s şunlardan biri olabilir: %(matches)s"
    ),
}
_argparse_gettext = argparse._  # type: ignore[attr-defined]


def _argparse_text(message: str) -> str:
    if language() == "tr" and message in _ARGPARSE_TR:
        return _ARGPARSE_TR[message]
    return str(_argparse_gettext(message))


argparse._ = _argparse_text  # type: ignore[attr-defined]


class SealboxParser(argparse.ArgumentParser):
    """Parser with examples in help, short error messages and "did you mean" suggestions."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("formatter_class", argparse.RawDescriptionHelpFormatter)
        super().__init__(*args, **kwargs)

    def _check_value(self, action: argparse.Action, value: Any) -> None:
        choices = action.choices
        if choices is not None and value not in choices:
            names = [str(c) for c in choices]
            close = difflib.get_close_matches(str(value), names, n=1, cutoff=0.6)
            if not isinstance(action, argparse._SubParsersAction):
                raise argparse.ArgumentError(
                    action, _(f"geçersiz değer '{value}' (seçenekler: {', '.join(names)})")
                )
            # None keeps argparse from prefixing the message with "argument <command>:".
            if close:
                raise argparse.ArgumentError(
                    None, _(f"'{value}' diye bir komut yok. Bunu mu demek istediniz: {close[0]}?")
                )
            raise argparse.ArgumentError(
                None, _(f"'{value}' diye bir komut yok. Komutlar: {', '.join(names)}")
            )
        super()._check_value(action, value)

    def error(self, message: str) -> NoReturn:
        sys.stderr.write(f"{self.prog}: {_('hata')}: {message}\n")
        sys.stderr.write(_(f"Yardım için: {self.prog} --help") + "\n")
        sys.exit(2)


def examples(*pairs: tuple[str, str]) -> str:
    """Build the "Examples" section of an ``epilog`` from ``(command, description)`` pairs."""
    width = max(len(cmd) for cmd, _text in pairs)
    body = "\n".join(f"  {cmd.ljust(width)}  # {text}" for cmd, text in pairs)
    return f"{_('Örnekler')}:\n{body}"
