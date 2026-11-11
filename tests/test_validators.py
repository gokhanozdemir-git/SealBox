import pytest

from sealbox.core import validators as v
from tests.fixtures import FAKE_IBAN, FAKE_TCKN, INVALID_TCKN, make_tckn


def test_tckn_valid():
    assert FAKE_TCKN == "12345678950"
    assert v.is_valid_tckn(FAKE_TCKN)
    assert v.is_valid_tckn(make_tckn("987654321"))


@pytest.mark.parametrize(
    "value",
    [
        INVALID_TCKN,
        "02345678950",
        "1234567895",
        "123456789500",
        "1234567895a",
        "１２３４５６７８９５０",
    ],
)
def test_tckn_invalid(value):
    assert not v.is_valid_tckn(value)


@pytest.mark.parametrize("value", ["a@b.co", "first.last+tag@sub.example.com.tr"])
def test_email_valid(value):
    assert v.is_valid_email(value)


@pytest.mark.parametrize(
    "value", ["a@b", "a..b@c.com", ".a@c.com", "a@-c.com", "a@c.c0m", "a@@c.com"]
)
def test_email_invalid(value):
    assert not v.is_valid_email(value)


@pytest.mark.parametrize(
    "value",
    ["0532 123 45 67", "+90 532 123 45 67", "5321234567", "(0212) 555 12 34", "+1 415 555 2671"],
)
def test_phone_plausible(value):
    assert v.is_plausible_phone(value)


@pytest.mark.parametrize("value", ["0132 123 45 67", "+90 132 123 45 67", "12345", "6321234567"])
def test_phone_implausible(value):
    assert not v.is_plausible_phone(value)


def test_luhn():
    assert v.luhn_ok("4111 1111 1111 1111")
    assert not v.luhn_ok("4111 1111 1111 1112")
    assert not v.luhn_ok("0000 0000 0000 0000")


def test_iban():
    assert v.is_valid_iban(FAKE_IBAN)
    broken = FAKE_IBAN[:-1] + ("1" if FAKE_IBAN[-1] != "1" else "2")
    assert not v.is_valid_iban(broken)


def test_entropy():
    assert v.shannon_entropy("aaaa") == 0
    assert v.looks_random_token("q8ZrT2mX9vLk4PwN7sB1cY6h")
    assert not v.looks_random_token("aaaaaaaaaaaaaaaaaaaaaaaa")
