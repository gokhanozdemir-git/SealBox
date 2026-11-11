"""On-disk names, format versioning and large projects."""

import json
from pathlib import Path

import pytest

from sealbox.core.crypto import AesGcmCipher, generate_key
from sealbox.core.errors import NewerFormatError
from sealbox.core.names import home_dir
from sealbox.core.tokenization import _EXPORT_AAD, TokenVault
from sealbox.sealing.sealer import Sealer
from tests.fixtures import FAKE_PASSWORD
from tests.vault_helpers import User, seal_with


def test_new_project_uses_sealbox_folder(workspace, config, tmp_path):
    me = User("me", tmp_path / "me")
    seal_with(me.store(workspace), config)
    assert (workspace / ".sealbox" / "project.vault").is_file()


def test_home_dir_is_dot_sealbox():
    assert home_dir() == Path.home() / ".sealbox"


def test_vault_from_newer_version_gives_clear_error():
    key = generate_key()
    blob = AesGcmCipher(key).encrypt(
        json.dumps({"version": 99, "records": {}}).encode(), _EXPORT_AAD
    )
    with pytest.raises(NewerFormatError, match="daha yeni bir sürümüyle"):
        TokenVault.from_encrypted(blob, key)


def test_many_files_are_all_scanned(workspace, config):
    for i in range(60):
        (workspace / "src" / f"m{i}.py").write_text(
            f'db_password = "{FAKE_PASSWORD}{i}"\n', "utf-8"
        )
    report = Sealer(config, TokenVault()).plan(["."])
    moved = {f.path for f in report.files if f.moved}
    assert {f"src/m{i}.py" for i in range(60)} <= moved
    assert not [s for s in report.skipped if "sınır" in s.reason]
