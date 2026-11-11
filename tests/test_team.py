import json
import shutil
import subprocess

import pytest

from sealbox.core.errors import ApprovalDeniedError
from sealbox.core.tokenization import TokenVault
from sealbox.team import (
    OWNER,
    TeamError,
    TeamFile,
    check_user,
    parse_public_key,
    sharing_warning,
    team_add,
    team_init,
    team_members,
    team_promote,
    team_remove,
)
from sealbox.vaultstore import KeyMissingError
from tests.fixtures import ALL_CONFIG_SECRETS
from tests.vault_helpers import Approvals, FakeGitHub, User, seal_with


@pytest.fixture
def alice(tmp_path):
    return User("alice", tmp_path / "alice")


@pytest.fixture
def bob(tmp_path):
    return User("bob", tmp_path / "bob", kind="rsa", passphrase="bob-pw")


@pytest.fixture
def github(alice, bob):
    return FakeGitHub(alice, bob)


@pytest.fixture
def team(workspace, config, alice, bob, github):
    """Alice creates the vault, starts a team and adds Bob (the repo is a shared folder)."""
    store = alice.store(workspace)
    seal_with(store, config)
    team_init(store, "alice", Approvals(), store.identity, github)
    team_add(store, "bob", Approvals(), alice.identity(), github)
    return store


def values(store):
    vault = store.open()
    try:
        return {ph: vault.reveal(ph) for ph in vault.placeholders}
    finally:
        vault.close()


def test_friend_opens_vault_with_own_ssh_key_after_pull(team, workspace, bob):
    text = team.team_path.read_text(encoding="utf-8")
    for secret in ALL_CONFIG_SECRETS:
        assert secret not in text
    bob_store = bob.store(workspace)
    assert values(bob_store) == values(team)
    # Cached in Bob's credential store, so the second open asks for no passphrase.
    assert bob.keystore.data
    again = bob.store(workspace, None)
    assert values(again) == values(team)


def test_non_member_cannot_open(team, workspace, tmp_path):
    carol = User("carol", tmp_path / "carol")
    with pytest.raises(KeyMissingError, match="Ekipteysen"):
        carol.store(workspace).open()


def test_member_cannot_add_people(team, workspace, bob, tmp_path):
    carol = User("carol", tmp_path / "carol")
    with pytest.raises(TeamError, match="sahipler"):
        team_add(bob.store(workspace), "carol", Approvals(), bob.identity(), FakeGitHub(carol))


def test_remove_rotates_key_and_locks_out_member(team, workspace, alice, bob):
    bob_store = bob.store(workspace)
    before = values(bob_store)
    files_before = (workspace / "src" / "config.py").read_text(encoding="utf-8")
    old_vault = team.vault_path.read_bytes()

    seen = team_remove(team, "bob", Approvals(), alice.identity())
    assert "DB_PASSWORD" in seen
    # Same placeholders: files untouched, Alice still sees the same values.
    assert (workspace / "src" / "config.py").read_text(encoding="utf-8") == files_before
    assert values(team) == before
    assert team.vault_path.read_bytes() != old_vault
    assert [m[0] for m in team_members(team)] == ["alice"]
    # Bob's cached old key is useless now, and SSH cannot get him the new one.
    with pytest.raises(KeyMissingError):
        bob.store(workspace).open()
    # Backups were re-encrypted with the new key.
    vault = team.open()
    try:
        from sealbox.core.crypto import AesGcmCipher

        cipher = AesGcmCipher(vault.key)
        backups = team._backups()
        assert backups
        for path, aad in backups:
            cipher.decrypt(path.read_bytes(), aad)
    finally:
        vault.close()


def test_other_owner_picks_up_rotated_key(workspace, config, alice, bob, github, tmp_path):
    carol = User("carol", tmp_path / "carol")
    github.keys["carol"] = [carol.pub]
    store = alice.store(workspace)
    seal_with(store, config)
    team_init(store, "alice", Approvals(), store.identity, github)
    team_add(store, "bob", Approvals(), alice.identity(), github, role=OWNER)
    team_add(store, "carol", Approvals(), alice.identity(), github)
    bob_store = bob.store(workspace)
    values(bob_store)  # Bob's cache still holds the old key
    team_remove(store, "carol", Approvals(), alice.identity())
    # After Bob pulls, the stale cache is rejected and the new key is unlocked via SSH.
    assert values(bob.store(workspace)) == values(store)


def test_forged_team_entry_is_rejected(team, workspace, bob):
    data = json.loads(team.team_path.read_text(encoding="utf-8"))
    data["members"]["bob"]["role"] = OWNER  # attempt to promote a role without a valid MAC
    team.team_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(TeamError, match="doğrulanamadı"):
        bob.store(workspace).open()


def test_unencrypted_ssh_key_is_refused(workspace, config, tmp_path):
    lazy = User("lazy", tmp_path / "lazy", passphrase="")
    store = lazy.store(workspace)
    seal_with(store, config)
    with pytest.raises(TeamError, match="şifresiz"):
        team_init(store, "lazy", Approvals(), store.identity, FakeGitHub(lazy))


def test_wrong_passphrase_and_cancel(team, workspace, bob):
    with pytest.raises(TeamError, match="3 kez"):
        bob.store(workspace, "x", "y", "z").open()
    with pytest.raises(ApprovalDeniedError):
        bob.store(workspace, None).open()


def test_init_requires_this_machines_key_on_github(workspace, config, alice, bob):
    store = alice.store(workspace)
    seal_with(store, config)
    impostor = FakeGitHub(bob)
    impostor.keys["alice"] = [bob.pub]
    with pytest.raises(TeamError, match="GitHub hesabında yok"):
        team_init(store, "alice", Approvals(), store.identity, impostor)


def test_denied_approval_changes_nothing(workspace, config, alice, github):
    store = alice.store(workspace)
    seal_with(store, config)
    with pytest.raises(ApprovalDeniedError):
        team_init(store, "alice", Approvals(answer=False), store.identity, github)
    assert not store.team_path.exists()


def test_last_owner_cannot_be_removed_and_promote(team, workspace, alice, bob):
    with pytest.raises(TeamError, match="Son sahip"):
        team_remove(team, "alice", Approvals(), alice.identity())
    team_promote(team, "bob", Approvals(), alice.identity())
    assert dict((u, r) for u, r, _ in team_members(team))["bob"] == OWNER
    TeamFile.load(team.team_path).verify(team.project_id(), team.open().key)
    team_remove(team, "alice", Approvals(), bob.identity())
    assert [m[0] for m in team_members(team)] == ["bob"]


def test_rotation_refreshes_recovery_copy(team, alice):
    from sealbox.recovery import setup_recovery
    from tests.vault_helpers import Shower

    setup_recovery(team, alice.recovery, Shower())
    pid = team.project_id()
    old_vault = team.open()
    old_key = old_vault.key
    old_vault.close()
    assert alice.recovery.protects(pid, old_key)
    team_remove(team, "bob", Approvals(), alice.identity())
    new_vault = team.open()
    try:
        assert alice.recovery.protects(pid, new_vault.key)
        assert TokenVault.from_encrypted(team.vault_path.read_bytes(), new_vault.key)
    finally:
        new_vault.close()


def test_public_key_parsing_and_usernames():
    assert parse_public_key("ecdsa-sha2-nistp256 AAAA") is None
    assert parse_public_key("ssh-ed25519 not-base64!!") is None
    assert parse_public_key("") is None
    assert check_user("@Some-User") == "Some-User"
    for bad in ("-x", "a--b", "a b", "../etc", "x" * 40):
        with pytest.raises(TeamError):
            check_user(bad)


@pytest.mark.skipif(shutil.which("git") is None, reason="git yok")
def test_sharing_warning_when_state_dir_is_gitignored(team, workspace):
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)  # noqa: S607
    assert sharing_warning(team) is None
    (workspace / ".gitignore").write_text(".sealbox/\n", encoding="utf-8")
    assert "gitignore" in sharing_warning(team)
    # The vault's own .gitignore keeps backups and locks out of git.
    assert "backups/" in (workspace / ".sealbox" / ".gitignore").read_text(encoding="utf-8")
