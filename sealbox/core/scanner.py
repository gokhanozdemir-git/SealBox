"""Rule-based secret scanner.

Regular expressions are only the first layer; every match is confirmed by a second check
in ``validators``. Person names cannot be found reliably with a generic regex, so only the
names listed explicitly in the configuration are matched, plus any optional ``Detector``
plugins (for example, an NER model).

``Detection`` carries the secret value. Its ``repr`` hides the value, and detections are
never written to logs or shown in the UI.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Protocol

from sealbox.config import ScannerConfig
from sealbox.core import validators as v
from sealbox.models.enums import SecretCategory

# Same placeholder format as in tokenization: the scanner must not flag its own
# placeholders as secrets.
PLACEHOLDER_RE = re.compile(r"__SECURE_[A-Z]+_[0-9a-f]{32}__")

KV_FILE_GLOBS = (
    "*.env*",
    "*.ini",
    "*.cfg",
    "*.conf",
    "*.properties",
    "*.yaml",
    "*.yml",
    "*.toml",
    "Dockerfile",
    "*.sh",
    "*.bash",
    "*.ps1",
    "*.txt",
    "*.md",
)

_CRED_NAME = (
    # optional prefix: db_password / db.password / dbPassword (camelCase is case-sensitive)
    r"(?:[A-Za-z0-9_.-]*?[_.-]|(?-i:[A-Za-z0-9]*[a-z0-9](?=[A-Z])))?"
    r"(?:password|passwd|pwd|passphrase|secret|secret[_-]?key|token|access[_-]?token|"
    r"refresh[_-]?token|auth[_-]?token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
    r"client[_-]?secret|credentials?|auth[_-]?key|session[_-]?key|signing[_-]?key|"
    r"encryption[_-]?key|sifre|parola)"
)


@dataclass(frozen=True)
class Detection:
    category: SecretCategory
    rule_id: str
    start: int
    end: int
    value: str = field(repr=False)
    priority: int = 50


class Detector(Protocol):
    """Optional plugin interface (for example, NER-based name detection)."""

    def detect(self, text: str, path: str) -> Iterable[Detection]: ...


Validator = Callable[[str], bool]


@dataclass(frozen=True)
class Rule:
    id: str
    category: SecretCategory
    pattern: re.Pattern[str]
    group: int | str = 0
    validator: Validator | None = None
    priority: int = 50
    file_globs: tuple[str, ...] = ()

    def applies_to(self, path: str) -> bool:
        if not self.file_globs:
            return True
        name = PurePosixPath(path).name
        return any(fnmatch.fnmatch(name, g) for g in self.file_globs)


def _r(p: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(p, flags)


def builtin_rules() -> list[Rule]:
    c = SecretCategory
    return [
        Rule(
            "private_key_block",
            c.PRIVATE_KEY,
            _r(
                r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]+?"
                r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
            ),
            priority=100,
        ),
        Rule("anthropic_key", c.API_KEY, _r(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), priority=95),
        Rule(
            "openai_key", c.API_KEY, _r(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}"), priority=90
        ),
        Rule("aws_access_key_id", c.API_KEY, _r(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), priority=90),
        Rule(
            "github_token",
            c.TOKEN,
            _r(
                r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|"
                r"github_pat_[A-Za-z0-9_]{60,})\b"
            ),
            priority=90,
        ),
        Rule(
            "google_api_key",
            c.API_KEY,
            _r(r"\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])"),
            priority=90,
        ),
        Rule("slack_token", c.TOKEN, _r(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), priority=90),
        Rule("stripe_key", c.API_KEY, _r(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"), priority=90),
        Rule(
            "jwt",
            c.TOKEN,
            _r(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
            priority=85,
        ),
        Rule(
            "url_credentials",
            c.PASSWORD,
            _r(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@'\"]+:(?P<v>[^\s@/'\"]+)@"),
            group="v",
            priority=85,
        ),
        Rule(
            "bearer_token",
            c.TOKEN,
            _r(r"\b[Bb]earer\s+(?P<v>[A-Za-z0-9\-._~+/]{16,}=*)"),
            group="v",
            priority=80,
        ),
        # password = "..." / "password": "..." / password='...' (any file)
        Rule(
            "credential_field_quoted",
            c.PASSWORD,
            _r(
                rf"(?i)(?<![A-Za-z0-9]){_CRED_NAME}(?![A-Za-z0-9])[\"']?\s*(?::=|=>|[:=])\s*"
                r"[bru]{0,2}(?P<q>[\"'`])(?P<v>(?:\\.|(?!(?P=q)).)+?)(?P=q)"
            ),
            group="v",
            priority=70,
        ),
        # PASSWORD=hunter2 / password: hunter2 (key-value files only)
        Rule(
            "credential_field_bare",
            c.PASSWORD,
            _r(
                rf"(?im)(?:^|(?<=\s)|(?<=export\s)){_CRED_NAME}(?![A-Za-z0-9])\s*[:=]\s*"
                r"(?P<v>[^\s\"'`#;,]{3,})"
            ),
            group="v",
            priority=65,
            file_globs=KV_FILE_GLOBS,
        ),
        Rule(
            "email",
            c.EMAIL,
            _r(
                r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*"
                r"\.[A-Za-z]{2,}(?![A-Za-z0-9-])"
            ),
            validator=v.is_valid_email,
            priority=60,
        ),
        Rule(
            "iban",
            c.IBAN,
            _r(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"),
            validator=v.is_valid_iban,
            priority=58,
        ),
        Rule(
            "tckn",
            c.TC_KIMLIK,
            _r(r"(?<![\d.])[1-9]\d{10}(?![\d])"),
            validator=v.is_valid_tckn,
            priority=57,
        ),
        Rule(
            "credit_card",
            c.CREDIT_CARD,
            _r(r"(?<![\d])(?:\d[ -]?){12,18}\d(?![\d])"),
            validator=v.luhn_ok,
            priority=55,
        ),
        Rule(
            "phone_tr",
            c.PHONE,
            _r(
                r"(?<![\w+])(?:\+90[\s.-]?|0)?\(?[2-5]\d{2}\)?[\s.-]?\d{3}[\s.-]?\d{2}"
                r"[\s.-]?\d{2}(?![\d])"
            ),
            validator=v.is_plausible_phone,
            priority=54,
        ),
        Rule(
            "phone_intl",
            c.PHONE,
            _r(r"(?<![\w+])\+\d{1,3}(?:[\s.-]?\(?\d{1,4}\)?){2,5}(?![\d])"),
            validator=v.is_plausible_phone,
            priority=53,
        ),
    ]


class Scanner:
    def __init__(
        self,
        config: ScannerConfig | None = None,
        extra_detectors: Iterable[Detector] = (),
    ) -> None:
        self.config = config or ScannerConfig()
        disabled = set(self.config.disabled_rules)
        self.rules: list[Rule] = [r for r in builtin_rules() if r.id not in disabled]
        for cr in self.config.custom_rules:
            flags = re.IGNORECASE if cr.flags_ignorecase else 0
            self.rules.append(
                Rule(
                    f"custom:{cr.id}",
                    cr.category,
                    re.compile(cr.pattern, flags),
                    group=cr.group,
                    priority=75,
                    file_globs=tuple(cr.file_globs),
                )
            )
        names = sorted(
            {n.strip() for n in self.config.person_names if n.strip()}, key=len, reverse=True
        )
        if names:
            alt = "|".join(re.escape(n) for n in names)
            self.rules.append(
                Rule(
                    "person_name",
                    SecretCategory.PERSON_NAME,
                    re.compile(rf"(?<!\w)(?:{alt})(?!\w)", re.IGNORECASE),
                    priority=40,
                )
            )
        self._allow_values = set(self.config.allow_values)
        self._allow_patterns = [re.compile(p) for p in self.config.allow_value_patterns]
        self._detectors = list(extra_detectors)

    def _allowed(self, value: str) -> bool:
        if value in self._allow_values or PLACEHOLDER_RE.fullmatch(value):
            return True
        return any(p.search(value) for p in self._allow_patterns)

    def scan(self, text: str, path: str = "") -> list[Detection]:
        """Return non-overlapping detections, chosen by priority."""
        placeholder_spans = [(m.start(), m.end()) for m in PLACEHOLDER_RE.finditer(text)]
        candidates: list[Detection] = []
        for rule in self.rules:
            if not rule.applies_to(path):
                continue
            for m in rule.pattern.finditer(text):
                try:
                    start, end = m.span(rule.group)
                except IndexError:
                    continue
                if start < 0 or end <= start:
                    continue
                value = text[start:end]
                if self._allowed(value):
                    continue
                if rule.validator is not None and not rule.validator(value):
                    continue
                candidates.append(
                    Detection(rule.category, rule.id, start, end, value, rule.priority)
                )
        for det in self._detectors:
            candidates.extend(det.detect(text, path))

        # Higher priority wins, then the longer match; overlapping candidates are dropped.
        candidates.sort(key=lambda d: (-d.priority, -(d.end - d.start), d.start))
        taken: list[Detection] = []
        occupied: list[tuple[int, int]] = list(placeholder_spans)
        for d in candidates:
            if any(d.start < e and s < d.end for s, e in occupied):
                continue
            taken.append(d)
            occupied.append((d.start, d.end))
        taken.sort(key=lambda d: d.start)
        return taken


def line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    col = offset - (text.rfind("\n", 0, offset) + 1) + 1
    return line, col
