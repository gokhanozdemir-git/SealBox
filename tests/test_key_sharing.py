import itertools
import logging

import pytest

from sealbox.core.crypto import generate_key
from sealbox.core.errors import KeySharingError
from sealbox.core.key_sharing import (
    SHARE_COUNT,
    THRESHOLD,
    KeyShare,
    combine_shares,
    split_key,
)


@pytest.fixture(scope="module")
def key_and_shares():
    key = bytes(generate_key())
    return key, split_key(key)


def test_is_3_of_5(key_and_shares):
    _, shares = key_and_shares
    assert THRESHOLD == 3 and SHARE_COUNT == 5
    assert len(shares) == 5
    assert len({s.mnemonic for s in shares}) == 5


def test_any_three_shares_recover(key_and_shares):
    key, shares = key_and_shares
    for combo in itertools.combinations(shares, 3):
        assert combine_shares(list(combo)) == key


def test_four_and_five_shares_recover(key_and_shares):
    key, shares = key_and_shares
    assert combine_shares(shares[:4]) == key
    assert combine_shares(shares) == key


def test_two_shares_rejected(key_and_shares):
    _, shares = key_and_shares
    for combo in itertools.combinations(shares, 2):
        with pytest.raises(KeySharingError):
            combine_shares(list(combo))


def test_duplicate_shares_do_not_count(key_and_shares):
    _, shares = key_and_shares
    with pytest.raises(KeySharingError):
        combine_shares([shares[0], shares[0], shares[1]])


def test_corrupted_share_rejected(key_and_shares):
    _, shares = key_and_shares
    words = shares[2].mnemonic.split()
    words[5] = "academic" if words[5] != "academic" else "acid"
    bad = KeyShare(index=3, mnemonic=" ".join(words))
    with pytest.raises(KeySharingError):
        combine_shares([shares[0], shares[1], bad])


def test_shares_from_different_keys_rejected(key_and_shares):
    _, shares = key_and_shares
    other = split_key(bytes(generate_key()))
    with pytest.raises(KeySharingError):
        combine_shares([shares[0], shares[1], other[2]])


def test_garbage_rejected():
    with pytest.raises(KeySharingError):
        combine_shares(["not a share", "also not", "nope nope"])


def test_error_messages_do_not_contain_share_material(key_and_shares):
    _, shares = key_and_shares
    try:
        combine_shares(shares[:2])
    except KeySharingError as e:
        for s in shares:
            assert s.mnemonic not in str(e)
            for w in s.mnemonic.split()[3:6]:
                assert w not in str(e)


def test_repr_and_str_hide_mnemonic(key_and_shares, caplog):
    _, shares = key_and_shares
    caplog.set_level(logging.DEBUG)
    logging.getLogger("t").info("share %s %r", shares[0], shares[0])
    assert shares[0].mnemonic not in caplog.text
    assert shares[0].mnemonic not in repr(shares)
