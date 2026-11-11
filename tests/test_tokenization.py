import pytest

from sealbox.core.crypto import generate_key
from sealbox.core.errors import CryptoError
from sealbox.core.tokenization import PLACEHOLDER_RE, TokenVault
from sealbox.models.enums import SecretCategory
from tests.fixtures import FAKE_PASSWORD


def test_placeholders_are_random_and_formatted():
    v1, v2 = TokenVault(), TokenVault()
    p1 = v1.placeholder_for("x@y.com", SecretCategory.EMAIL)
    p2 = v2.placeholder_for("x@y.com", SecretCategory.EMAIL)
    assert p1 != p2
    assert PLACEHOLDER_RE.fullmatch(p1)


def test_vault_export_import_roundtrip():
    key = generate_key()
    v = TokenVault(key)
    ph = v.placeholder_for(FAKE_PASSWORD, SecretCategory.PASSWORD)
    blob = v.export_encrypted()
    assert FAKE_PASSWORD.encode() not in blob
    v2 = TokenVault.from_encrypted(blob, key)
    assert v2.reveal(ph) == FAKE_PASSWORD
    assert v2.placeholder_for(FAKE_PASSWORD, SecretCategory.PASSWORD) == ph
    with pytest.raises(CryptoError):
        TokenVault.from_encrypted(blob, generate_key())


def test_vault_repr_and_close():
    v = TokenVault()
    v.placeholder_for(FAKE_PASSWORD, SecretCategory.PASSWORD)
    assert FAKE_PASSWORD not in repr(v)
    v.close()
    assert len(v) == 0
