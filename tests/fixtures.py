"""Fake test data. Contains no real personal data and no real API keys."""

from __future__ import annotations


def make_tckn(first9: str) -> str:
    d = [int(c) for c in first9]
    d10 = ((d[0] + d[2] + d[4] + d[6] + d[8]) * 7 - (d[1] + d[3] + d[5] + d[7])) % 10
    d11 = (sum(d) + d10) % 10
    return f"{first9}{d10}{d11}"


def make_tr_iban(bban: str) -> str:
    """BBAN: 5-digit bank code + 1 reserve digit + 16-digit account number (22 digits)."""
    numeric = "".join(str(int(c, 36)) for c in bban + "TR00")
    check = 98 - int(numeric) % 97
    return f"TR{check:02d}{bban}"


FAKE_TCKN = make_tckn("123456789")  # 12345678950
INVALID_TCKN = "12345678951"
FAKE_EMAIL = "ayse.yilmaz@example.com"
FAKE_PHONE = "0532 123 45 67"
FAKE_PHONE_INTL = "+90 532 123 45 67"
FAKE_CARD = "4111 1111 1111 1111"
FAKE_IBAN = make_tr_iban("0006100519786457841326")
FAKE_ANTHROPIC = "sk-ant-api03-FAKEfakeFAKEfakeFAKEfake1234"
FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"
FAKE_GH = "ghp_" + "Ab3" * 12
FAKE_PASSWORD = "Tr0ub4dor&3-fake"
FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)
FAKE_PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
    "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n"
    "-----END RSA PRIVATE KEY-----"
)

CONFIG_PY = f'''"""Uygulama yapılandırması."""
import os

DB_HOST = "db.internal"
DB_PASSWORD = "{FAKE_PASSWORD}"
ADMIN_EMAIL = "{FAKE_EMAIL}"
SUPPORT_PHONE = "{FAKE_PHONE}"
OWNER_TCKN = "{FAKE_TCKN}"
ANTHROPIC_API_KEY = "{FAKE_ANTHROPIC}"
AWS_KEY_ID = "{FAKE_AWS}"
API_TOKEN = os.environ.get("API_TOKEN")
MAX_TOKENS = 1024


def connect():
    # parola tekrar: {FAKE_PASSWORD}
    return f"postgres://admin:{{DB_PASSWORD}}@{{DB_HOST}}/app"
'''

ALL_CONFIG_SECRETS = [
    FAKE_PASSWORD,
    FAKE_EMAIL,
    FAKE_PHONE,
    FAKE_TCKN,
    FAKE_ANTHROPIC,
    FAKE_AWS,
]
