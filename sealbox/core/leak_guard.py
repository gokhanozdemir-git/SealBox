"""Hiding secrets in program output and log records.

When a program runs under ``exec``, every vault value (and its common encodings) in its
output is replaced with ``[REDACTED:CATEGORY]`` (``[GİZLİ:...]`` in Turkish).
"""

from __future__ import annotations

import base64
import json
import logging
import urllib.parse
from collections.abc import Callable, Iterable
from typing import Any

from sealbox.core.redaction import literal_pattern
from sealbox.core.scanner import Scanner
from sealbox.core.tokenization import TokenVault
from sealbox.i18n import N_, _

REDACTED = N_("GİZLİ")


def _variants(value: str) -> set[str]:
    """Common encodings under which a value may appear in output."""
    out = {value, json.dumps(value)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1]}
    if len(value) >= 6:
        out.add(base64.b64encode(value.encode()).decode().rstrip("="))
        quoted = urllib.parse.quote(value, safe="")
        out.add(quoted)
    return {v for v in out if v}


class LeakGuard:
    def __init__(self, scanner: Scanner, vault: TokenVault) -> None:
        self.scanner = scanner
        self.vault = vault

    def _iter_needles(self) -> Iterable[tuple[str, str]]:
        for ph, value in self.vault.iter_plain_values():
            if not value:
                continue
            for form in _variants(value):
                yield form, f"vault:{self.vault.category_of(ph).value}"

    def redact(self, text: str) -> str:
        """Replace known and detected secrets in ``text`` with ``[REDACTED:CATEGORY]``."""
        mark = _(REDACTED)
        for needle, label in sorted(self._iter_needles(), key=lambda x: -len(x[0])):
            text = literal_pattern(needle).sub(f"[{mark}:{label}]", text)
        dets = self.scanner.scan(text, "")
        for d in reversed(dets):
            text = text[: d.start] + f"[{mark}:{d.category.value}]" + text[d.end :]
        return text

    def known_value_redactor(self) -> Callable[[str], str]:
        """Return a fast, precompiled function that hides only the known vault values.

        Meant for streaming program output: regex scanning would produce false positives
        there, and recompiling patterns for every line would be slow.
        """
        mark = _(REDACTED)
        rules = [
            (literal_pattern(needle), f"[{mark}:{label}]")
            for needle, label in sorted(self._iter_needles(), key=lambda x: -len(x[0]))
        ]

        def redact(text: str) -> str:
            for pattern, repl in rules:
                text = pattern.sub(repl, text)
            return text

        return redact


class RedactingLogFilter(logging.Filter):
    """Attached to the root logger; formats each record and scrubs it with LeakGuard."""

    def __init__(self, guard_getter: Any) -> None:
        super().__init__()
        self._guard_getter = guard_getter

    def filter(self, record: logging.LogRecord) -> bool:
        guard: LeakGuard | None = self._guard_getter()
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            message = str(record.msg)
        if guard is not None:
            message = guard.redact(message)
        record.msg = message
        record.args = None
        # Exception text may contain secrets: keep only the type name, never the traceback.
        if record.exc_info and record.exc_info[1] is not None:
            record.msg = f"{message} [{type(record.exc_info[1]).__name__}]"
            record.exc_info = None
            record.exc_text = None
        return True
