import json
import re
import shutil

import pytest

from sealbox.core.errors import ApprovalDeniedError
from sealbox.core.key_sharing import code_to_share, share_to_code
from sealbox.core.tokenization import PLACEHOLDER_RE
from sealbox.recovery import (
    RecoveryError,
    export_kit,
    make_shares,
    parse_recovery_input,
    restore,
    setup_recovery,
)
from sealbox.vaultstore import KeyMissingError
from tests.vault_helpers import Asker, Shower, User, seal_with


@pytest.fixture
def me(tmp_path):
    return User("me", tmp_path / "me")


@pytest.fixture
def sealed(workspace, config, me):
    store = me.store(workspace)
    seal_with(store, config)
    return store


def values(store):
    vault = store.open()
    try:
        return {ph: vault.reveal(ph) for ph in vault.placeholders}
    finally:
        vault.close()


def setup(store, me):
    shower = Shower()
    setup_recovery(store, me.recovery, shower)
    (display,) = shower.shown
    return display.secret


def lose_key(me):
    me.keystore.data.clear()  # Windows kimlik deposu silindi


def test_setup_shows_code_only_in_window(sealed, me, capsys):
    code = setup(sealed, me)
    out = capsys.readouterr()
    assert code not in out.out + out.err
    meta = json.loads(me.recovery.meta_path.read_text(encoding="utf-8"))
    assert meta["kdf"] == "argon2id"
    assert meta["params"] == {"memory_kib": 65536, "iterations": 3, "lanes": 4}
    assert code.replace("-", "") not in json.dumps(meta)
    assert me.recovery.protects(sealed.project_id())


def test_cancelled_setup_writes_nothing(sealed, me):
    with pytest.raises(ApprovalDeniedError):
        setup_recovery(sealed, me.recovery, Shower(answer=False))
    assert not me.recovery.is_set_up()


def test_lost_key_comes_back_with_code(sealed, me, workspace):
    before = values(sealed)
    code = setup(sealed, me)
    lose_key(me)
    with pytest.raises(KeyMissingError, match="recovery restore"):
        me.store(workspace).open()
    assert restore(me.store(workspace), me.recovery, Asker(code)) == len(before)
    assert values(me.store(workspace)) == before


def test_wrong_code_and_typo(sealed, me, workspace):
    setup(sealed, me)
    other = User("other", workspace.parent / "other")
    other_code = setup(None, other)
    lose_key(me)
    with pytest.raises(RecoveryError, match="ait değil"):
        restore(me.store(workspace), me.recovery, Asker(other_code))
    with pytest.raises(Exception, match="kod"):
        restore(me.store(workspace), me.recovery, Asker("AAAA-BBBB"))


def test_two_of_three_shares(sealed, me, workspace):
    before = values(sealed)
    code = setup(sealed, me)
    shower = Shower()
    make_shares(me.recovery, Asker(code), shower)
    shares = [d.secret for d in shower.shown]
    # Code-style character groups instead of words: 10 groups of 4.
    assert len(shares) == 3
    assert all(re.fullmatch(r"[0-9A-Z]{4}(-[0-9A-Z]{4}){9}", s) for s in shares)
    lose_key(me)
    # Any 2 shares are enough.
    restore(me.store(workspace), me.recovery, Asker(f"{shares[2]}\n{shares[0]}"))
    assert values(me.store(workspace)) == before
    lose_key(me)
    with pytest.raises(RecoveryError, match="En az 2"):
        restore(me.store(workspace), me.recovery, Asker(shares[1]))
    with pytest.raises(RecoveryError, match="En az 2"):
        restore(me.store(workspace), me.recovery, Asker(f"{shares[1]}\n{shares[1]}"))


def test_shares_are_forgiving_to_type(sealed, me, workspace):
    """Line breaks, dashes, lower case and O/0 mix-ups are ignored; typos are caught."""
    code = setup(sealed, me)
    shower = Shower()
    make_shares(me.recovery, Asker(code), shower)
    a, b = shower.shown[0].secret, shower.shown[1].secret
    messy = a.replace("-", " ").lower() + "  " + b.replace("-", "\n").replace("0", "O")
    assert parse_recovery_input(messy) == parse_recovery_input(code)
    bad = ("1" if a[0] != "1" else "2") + a[1:]
    with pytest.raises(RecoveryError, match=r"1\. parçada yazım hatası"):
        parse_recovery_input(f"{bad}\n{b}")


def test_old_word_shares_still_work(sealed, me):
    code = setup(sealed, me)
    shower = Shower()
    make_shares(me.recovery, Asker(code), shower)
    a, c = (code_to_share(d.secret) for d in (shower.shown[0], shower.shown[2]))
    assert len(a.split()) == 20
    # Shares written as SLIP-39 words are accepted, even on a single line.
    assert parse_recovery_input(f"{a} {c}") == parse_recovery_input(code)
    assert share_to_code(a) == shower.shown[0].secret


def test_shares_need_correct_code(sealed, me):
    setup(sealed, me)
    from sealbox.core.envelope import encode_code, new_code_secret

    with pytest.raises(RecoveryError, match="yanlış"):
        make_shares(me.recovery, Asker(encode_code(new_code_secret())), Shower())


def test_new_projects_are_protected_automatically(sealed, me, tmp_path, config):
    setup(sealed, me)
    other = tmp_path / "other"
    (other / "src").mkdir(parents=True)
    shutil.copy(config.workspace_root / "src" / "config.py", other / "src" / "config.py")
    from sealbox.config import SealboxConfig

    store = me.store(other)
    seal_with(store, SealboxConfig(workspace_root=other.resolve()))
    assert me.recovery.protects(store.project_id())


def test_kit_restores_deleted_vault_on_new_machine(sealed, me, workspace, tmp_path):
    before = values(sealed)
    code = setup(sealed, me)
    kit = tmp_path / "usb" / "proje.sealkit"
    export_kit(sealed, me.recovery, kit)
    kit_text = kit.read_text(encoding="utf-8")
    for value in before.values():
        assert value not in kit_text
    # Disk wiped: both the vault folder and the recovery folder are gone.
    shutil.rmtree(workspace / ".sealbox")
    fresh = User("me2", tmp_path / "newpc")
    store = fresh.store(workspace)
    restore(store, fresh.recovery, Asker(code), kit)
    assert values(fresh.store(workspace)) == before


def test_vault_reset_keeps_old_vault_aside(sealed, me, workspace):
    lose_key(me)
    store = me.store(workspace)
    old_pid = store.project_id()
    lost = store.reset()
    assert "DB_PASSWORD" in lost
    assert any(PLACEHOLDER_RE.fullmatch(x) for x in lost)
    aside = list((workspace / ".sealbox").glob("lost-*"))
    assert len(aside) == 1 and (aside[0] / "project.vault").is_file()
    assert (aside[0] / "project.id").read_text(encoding="ascii") == old_pid
    assert store.project_id() != old_pid
    assert len(store.open()) == 0
