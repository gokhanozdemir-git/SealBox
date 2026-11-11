from __future__ import annotations

from pathlib import Path

import pytest

from sealbox.config import SealboxConfig
from tests.fixtures import CONFIG_PY


@pytest.fixture(autouse=True)
def isolated_home(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Keep tests away from the real ~/.sealbox (recovery) and ~/.ssh folders."""
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return home


@pytest.fixture(autouse=True)
def turkish(monkeypatch: pytest.MonkeyPatch) -> None:
    """Message assertions use the Turkish source text; the OS language must not matter."""
    monkeypatch.setenv("SEALBOX_LANG", "tr")


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    (root / "src").mkdir(parents=True)
    (root / "src" / "config.py").write_bytes(CONFIG_PY.encode("utf-8"))
    (root / "src" / "util.py").write_bytes(b"def add(a, b):\n    return a + b\n")
    (root / ".env").write_bytes(b"SECRET=topsecretvalue\n")
    (root / "image.bin").write_bytes(b"\x89PNG\x00\x00binary")
    return root


@pytest.fixture
def config(workspace: Path) -> SealboxConfig:
    return SealboxConfig(workspace_root=workspace.resolve())
