"""Format validators: a second filter applied to regex matches."""

from __future__ import annotations

import math
import re
from collections import Counter

_EMAIL_LOCAL = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$")
_EMAIL_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def is_valid_tckn(value: str) -> bool:
    """Checksum validation for Turkish national ID numbers (T.C. Kimlik No).

    Rules: 11 digits, the first digit is not 0;
    digit 10 = ((sum of digits 1, 3, 5, 7, 9) * 7 - (sum of digits 2, 4, 6, 8)) mod 10;
    digit 11 = (sum of the first 10 digits) mod 10.
    """
    if len(value) != 11 or not value.isascii() or not value.isdigit() or value[0] == "0":
        return False
    d = [int(c) for c in value]
    odd = d[0] + d[2] + d[4] + d[6] + d[8]
    even = d[1] + d[3] + d[5] + d[7]
    if (odd * 7 - even) % 10 != d[9]:
        return False
    return sum(d[:10]) % 10 == d[10]


def is_valid_email(value: str) -> bool:
    if value.count("@") != 1 or len(value) > 254:
        return False
    local, domain = value.split("@")
    if not local or len(local) > 64 or local.startswith(".") or local.endswith("."):
        return False
    if ".." in local or not _EMAIL_LOCAL.match(local):
        return False
    labels = domain.split(".")
    if len(labels) < 2 or not all(_EMAIL_LABEL.match(lbl) for lbl in labels):
        return False
    tld = labels[-1]
    return tld.isalpha() and len(tld) >= 2


def digits_only(value: str) -> str:
    return "".join(c for c in value if c.isdigit())


def is_plausible_phone(value: str) -> bool:
    """Digit count and prefix check for Turkish and E.164 phone numbers."""
    digits = digits_only(value)
    if value.strip().startswith("+"):
        if not 10 <= len(digits) <= 15:
            return False
        if digits.startswith("90"):
            return len(digits) == 12 and digits[2] in "2345"
        return True
    if digits.startswith("0"):
        return len(digits) == 11 and digits[1] in "2345"
    return len(digits) == 10 and digits[0] == "5"


def luhn_ok(value: str) -> bool:
    digits = digits_only(value)
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def is_valid_iban(value: str) -> bool:
    compact = value.replace(" ", "").upper()
    if not 15 <= len(compact) <= 34 or not compact[:2].isalpha():
        return False
    if compact.startswith("TR") and len(compact) != 26:
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        numeric = "".join(str(int(c, 36)) for c in rearranged)
    except ValueError:
        return False
    return int(numeric) % 97 == 1


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def looks_random_token(value: str, min_len: int = 20, min_entropy: float = 3.5) -> bool:
    return len(value) >= min_len and shannon_entropy(value) >= min_entropy
