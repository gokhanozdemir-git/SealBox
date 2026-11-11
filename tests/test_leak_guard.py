import base64
import logging

import pytest

from sealbox.core.errors import safe_error_message
from sealbox.core.leak_guard import LeakGuard, RedactingLogFilter
from sealbox.core.scanner import Scanner
from sealbox.core.tokenization import TokenVault
from sealbox.models.enums import SecretCategory
from tests.fixtures import FAKE_EMAIL, FAKE_PASSWORD


@pytest.fixture
def guard():
    vault = TokenVault()
    vault.placeholder_for(FAKE_PASSWORD, SecretCategory.PASSWORD)
    vault.placeholder_for(FAKE_EMAIL, SecretCategory.EMAIL)
    return LeakGuard(Scanner(), vault)


def test_redact(guard):
    out = guard.redact(f"failed for {FAKE_EMAIL} with {FAKE_PASSWORD}")
    assert FAKE_EMAIL not in out and FAKE_PASSWORD not in out
    assert "[GİZLİ:" in out


def test_known_value_redactor_catches_encoded_forms(guard):
    redact = guard.known_value_redactor()
    encoded = base64.b64encode(FAKE_PASSWORD.encode()).decode().rstrip("=")
    out = redact(f"pw={FAKE_PASSWORD} b64={encoded}")
    assert FAKE_PASSWORD not in out and encoded not in out


def test_logging_filter(guard, caplog):
    logger = logging.getLogger("secure-test")
    logger.addFilter(RedactingLogFilter(lambda: guard))
    caplog.set_level(logging.INFO)
    logger.info("value=%s", FAKE_PASSWORD)
    try:
        raise ValueError(FAKE_EMAIL)
    except ValueError:
        logger.exception("boom")
    assert FAKE_PASSWORD not in caplog.text
    assert FAKE_EMAIL not in caplog.text


def test_safe_error_message_hides_foreign_exceptions():
    try:
        FAKE_PASSWORD.encode("ascii", "strict")
        b"\xff" + FAKE_PASSWORD.encode()
        (b"\xff" + FAKE_PASSWORD.encode()).decode("utf-8")
    except UnicodeDecodeError as e:
        msg = safe_error_message(e)
        assert FAKE_PASSWORD not in msg
        assert "UnicodeDecodeError" in msg
