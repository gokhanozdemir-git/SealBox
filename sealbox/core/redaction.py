"""Finding a known value inside text."""

from __future__ import annotations

import re


def literal_pattern(value: str) -> re.Pattern[str]:
    """Match ``value`` literally without matching inside a longer alphanumeric word."""
    pre = r"(?<![A-Za-z0-9])" if value[:1].isalnum() else ""
    post = r"(?![A-Za-z0-9])" if value[-1:].isalnum() else ""
    return re.compile(pre + re.escape(value) + post)
