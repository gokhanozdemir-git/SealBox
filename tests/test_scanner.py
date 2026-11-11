import pytest

from sealbox.config import CustomRule, ScannerConfig
from sealbox.core.scanner import Scanner
from sealbox.models.enums import SecretCategory as C
from tests.fixtures import (
    CONFIG_PY,
    FAKE_ANTHROPIC,
    FAKE_AWS,
    FAKE_CARD,
    FAKE_EMAIL,
    FAKE_GH,
    FAKE_IBAN,
    FAKE_JWT,
    FAKE_PASSWORD,
    FAKE_PHONE,
    FAKE_PHONE_INTL,
    FAKE_PRIVATE_KEY,
    FAKE_TCKN,
    INVALID_TCKN,
)


def found(text, path="x.py", **kw):
    return {(d.category, d.value) for d in Scanner(ScannerConfig(**kw)).scan(text, path)}


@pytest.mark.parametrize(
    "text,cat,value",
    [
        (f"mail me: {FAKE_EMAIL}.", C.EMAIL, FAKE_EMAIL),
        (f"id={FAKE_TCKN}", C.TC_KIMLIK, FAKE_TCKN),
        (f"tel: {FAKE_PHONE}", C.PHONE, FAKE_PHONE),
        (f"tel: {FAKE_PHONE_INTL}", C.PHONE, FAKE_PHONE_INTL),
        (f"card {FAKE_CARD}", C.CREDIT_CARD, FAKE_CARD),
        (f"iban {FAKE_IBAN}", C.IBAN, FAKE_IBAN),
        (f"k = {FAKE_ANTHROPIC}", C.API_KEY, FAKE_ANTHROPIC),
        (f"k = {FAKE_AWS}", C.API_KEY, FAKE_AWS),
        (f"t = {FAKE_GH}", C.TOKEN, FAKE_GH),
        (f"Authorization: Bearer {FAKE_JWT}", C.TOKEN, FAKE_JWT),
        (FAKE_PRIVATE_KEY, C.PRIVATE_KEY, FAKE_PRIVATE_KEY),
        (f'password = "{FAKE_PASSWORD}"', C.PASSWORD, FAKE_PASSWORD),
        (f'{{"client_secret": "{FAKE_PASSWORD}"}}', C.PASSWORD, FAKE_PASSWORD),
        (f"connect(passwd='{FAKE_PASSWORD}')", C.PASSWORD, FAKE_PASSWORD),
        (f"url = 'postgres://bob:{FAKE_PASSWORD}@db/x'", C.PASSWORD, FAKE_PASSWORD),
    ],
)
def test_detects(text, cat, value):
    assert (cat, value) in found(text)


def test_bare_kv_only_in_kv_files():
    text = f"DB_PASSWORD={FAKE_PASSWORD}\n"
    assert (C.PASSWORD, FAKE_PASSWORD) in found(text, ".env.example")
    assert (C.PASSWORD, FAKE_PASSWORD) in found(f"password: {FAKE_PASSWORD}\n", "app.yaml")
    assert not found(text, "main.py")


def test_invalid_tckn_rejected():
    assert not any(c == C.TC_KIMLIK for c, _ in found(f"id={INVALID_TCKN}"))


@pytest.mark.parametrize(
    "text",
    [
        'password = "${DB_PASSWORD}"',
        'password = "<your-password>"',
        'token = os.environ["TOKEN"]',
        "max_tokens = 1024",
        'tokenizer = "bert-base"',
        "version = 1.2.3",
        "timestamp = 1700000000000",
    ],
)
def test_no_false_positive(text):
    assert found(text) == set()


def test_allow_values():
    assert found(f"x {FAKE_EMAIL}", allow_values=[FAKE_EMAIL]) == set()


def test_disabled_rules():
    assert found(f"x {FAKE_EMAIL}", disabled_rules=["email"]) == set()


def test_custom_rule():
    rule = CustomRule(id="proj", pattern=r"PRJ-\d{6}")
    assert (C.CUSTOM, "PRJ-123456") in found("code PRJ-123456", custom_rules=[rule])


def test_person_names_unicode():
    res = found(
        "Yazar: Ayşe Yılmaz, gözden geçiren: ÇAĞLA ÖZ", person_names=["Ayşe Yılmaz", "Çağla Öz"]
    )
    assert (C.PERSON_NAME, "Ayşe Yılmaz") in res
    assert (C.PERSON_NAME, "ÇAĞLA ÖZ") in res


def test_names_not_detected_without_config():
    assert found("Yazar: Ayşe Yılmaz") == set()


def test_overlap_resolution_prefers_specific():
    # An e-mail as a password field's value: one detection, no overlap.
    dets = Scanner().scan(f'password = "{FAKE_EMAIL}"', "a.py")
    assert len(dets) == 1


def test_crlf_and_escapes():
    text = f'a = 1\r\nsecret = "ab\\"c{FAKE_PASSWORD}"\r\nmail = "{FAKE_EMAIL}"\r\n'
    res = found(text)
    assert (C.PASSWORD, f'ab\\"c{FAKE_PASSWORD}') in res
    assert (C.EMAIL, FAKE_EMAIL) in res


def test_existing_placeholders_not_rescanned():
    text = 'password = "__SECURE_PASSWORD_0123456789abcdef0123456789abcdef__"'
    assert found(text) == set()


def test_config_file_fixture():
    res = {v for _, v in found(CONFIG_PY)}
    for secret in [FAKE_PASSWORD, FAKE_EMAIL, FAKE_PHONE, FAKE_TCKN, FAKE_ANTHROPIC, FAKE_AWS]:
        assert secret in res


def test_env_variable_reads_are_not_secrets():
    text = 'DB_PASSWORD = os.environ["DB_PASSWORD"]\nAPI_TOKEN=process.env.API_TOKEN\n'
    assert Scanner().scan(text, "README.md") == []
