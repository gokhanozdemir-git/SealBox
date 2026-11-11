"""The only language-specific part: the "read an environment variable" expression.

Supported: Python, JavaScript/TypeScript and Java. Adding a language takes one entry in
``LANGUAGES``. A rewrite happens only when an entire string literal is the secret; in every
other case the file is left untouched and the user is warned.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True)
class Language:
    name: str
    env_expr: Callable[[str], str]
    comment_markers: tuple[str, ...]
    # Prefixes allowed in front of a literal (for example, Python's r"...").
    literal_prefixes: str
    quotes: str
    ensure_imports: Callable[[str], str] | None = None


_IMPORT_OS_RE = re.compile(r"(?m)^\s*import\s+(?:[\w.]+\s*,\s*)*os(?:\s*,|\s*$|\s+as\s)")


def _python_ensure_os(text: str) -> str:
    """Add ``import os`` if missing, after the module docstring and ``__future__`` imports."""
    if re.search(r"(?m)^\s*import\s+os\s*$", text) or _IMPORT_OS_RE.search(text):
        return text
    lines = text.splitlines(keepends=True)
    insert_at = 0
    try:
        tree = ast.parse(text)
    except SyntaxError:
        tree = None
    if tree is not None:
        for node in tree.body:
            is_doc = (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and node is tree.body[0]
            )
            is_future = isinstance(node, ast.ImportFrom) and node.module == "__future__"
            if is_doc or is_future:
                insert_at = node.end_lineno or insert_at
            else:
                break
    else:
        while insert_at < len(lines) and lines[insert_at].startswith("#"):
            insert_at += 1
    newline = "\r\n" if "\r\n" in text else "\n"
    lines.insert(insert_at, f"import os{newline}")
    return "".join(lines)


PYTHON = Language(
    name="Python",
    env_expr=lambda n: f'os.environ["{n}"]',
    comment_markers=("#",),
    literal_prefixes="rRuU",
    quotes="\"'",
    ensure_imports=_python_ensure_os,
)

JAVASCRIPT = Language(
    name="JavaScript/TypeScript",
    env_expr=lambda n: f"process.env.{n}",
    comment_markers=("//",),
    literal_prefixes="",
    quotes="\"'`",
)

# System lives in java.lang, so no import is needed. '...' is a single char and cannot be a
# secret; """ text blocks are already rejected by literal_bounds.
JAVA = Language(
    name="Java",
    env_expr=lambda n: f'System.getenv("{n}")',
    comment_markers=("//", "/*"),
    literal_prefixes="",
    quotes='"',
)

LANGUAGES: dict[str, Language] = {
    ".py": PYTHON,
    ".js": JAVASCRIPT,
    ".mjs": JAVASCRIPT,
    ".cjs": JAVASCRIPT,
    ".jsx": JAVASCRIPT,
    ".ts": JAVASCRIPT,
    ".tsx": JAVASCRIPT,
    ".java": JAVA,
}


def language_for(path: str) -> Language | None:
    return LANGUAGES.get(PurePosixPath(path).suffix.lower())


def literal_bounds(text: str, start: int, end: int, lang: Language) -> tuple[int, int] | None:
    """Return the literal's bounds if ``[start, end)`` is the whole content of a string literal.

    Triple quotes, escape sequences, template expressions and f/b-prefixed literals are not
    supported, because their value may not map one-to-one to an environment variable.
    """
    if start < 1 or end >= len(text):
        return None
    q = text[start - 1]
    if q not in lang.quotes or text[end] != q:
        return None
    if start >= 2 and text[start - 2] == q:  # triple quote or empty literal
        return None
    if end + 1 < len(text) and text[end + 1] == q:
        return None
    value = text[start:end]
    if "\\" in value or "\n" in value or (q == "`" and "${" in value):
        return None
    lit_start = start - 1
    prefix_start = lit_start
    while prefix_start > 0 and text[prefix_start - 1].isalpha():
        prefix_start -= 1
    prefix = text[prefix_start:lit_start]
    if prefix and (len(prefix) > 2 or any(c not in lang.literal_prefixes for c in prefix)):
        return None
    return prefix_start, end + 1


def in_comment(text: str, offset: int, lang: Language) -> bool:
    line_start = text.rfind("\n", 0, offset) + 1
    before = text[line_start:offset]
    return any(m in before for m in lang.comment_markers)


_ASSIGN_RE = re.compile(r"[\"']?([A-Za-z_$][\w$]*)[\"']?\s*(?::=|=>|[:=])\s*$")


def to_env_name(identifier: str) -> str:
    """``dbPass`` -> ``DB_PASS``, ``api-key`` -> ``API_KEY``."""
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", identifier)
    s = re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_").upper()
    if not s or s[0].isdigit():
        return ""
    return s


def env_name_hint(text: str, lit_start: int) -> str:
    """Derive an environment variable name from the assignment or key left of the literal."""
    line_start = text.rfind("\n", 0, lit_start) + 1
    m = _ASSIGN_RE.search(text[line_start:lit_start])
    return to_env_name(m.group(1)) if m else ""
