"""Names that appear on disk and in the OS credential store."""

from __future__ import annotations

from pathlib import Path

STATE_DIR = ".sealbox"
KEYRING_SERVICE = "sealbox"
CONFIG_FILES = ("sealbox.toml",)


def state_dir(root: Path) -> Path:
    """The project's vault folder."""
    return root / STATE_DIR


def has_vault(root: Path) -> bool:
    return (state_dir(root) / "project.id").is_file()


def home_dir() -> Path:
    """Per-user state folder (recovery data)."""
    return Path.home() / STATE_DIR
