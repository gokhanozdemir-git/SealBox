"""Configuration with safe defaults.

Settings can be read from a TOML file (``sealbox.toml``). That file never holds secrets.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sealbox.core.errors import SealboxError
from sealbox.core.names import state_dir
from sealbox.i18n import _
from sealbox.models.enums import SecretCategory

DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.env",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.kdbx",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    "credentials",
    "credentials.*",
    ".git/**",
    ".hg/**",
    ".svn/**",
    ".venv/**",
    "venv/**",
    "env/**",
    "node_modules/**",
    "__pycache__/**",
    "build/**",
    "dist/**",
    ".mypy_cache/**",
    ".pytest_cache/**",
    ".ruff_cache/**",
    ".tox/**",
    ".aws/**",
    ".ssh/**",
    ".gnupg/**",
    ".sealbox/**",
)


class CustomRule(BaseModel):
    """User-defined regex rule."""

    model_config = ConfigDict(extra="forbid")

    id: str
    category: SecretCategory = SecretCategory.CUSTOM
    pattern: str
    group: int = 0
    file_globs: list[str] = Field(default_factory=list)
    flags_ignorecase: bool = False


class ScannerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disabled_rules: list[str] = Field(default_factory=list)
    custom_rules: list[CustomRule] = Field(default_factory=list)
    # Names cannot be detected reliably with regex, so they must be listed explicitly.
    person_names: list[str] = Field(default_factory=list)
    # Exact values to ignore, to silence false positives (for example, a sample e-mail).
    allow_values: list[str] = Field(default_factory=list)
    # Values matching any of these patterns are never treated as secrets.
    allow_value_patterns: list[str] = Field(
        default_factory=lambda: [
            r"^\$\{[^}]*\}$",  # ${ENV_VAR}
            r"^\$[A-Z_][A-Z0-9_]*$",  # $ENV_VAR
            r"^<[^>]*>$",  # <placeholder>
            r"^\{\{.*\}\}$",  # {{ template }}
            r"^\{[A-Za-z_][A-Za-z0-9_.\[\]'\"]*\}$",  # f-string / format field
            r"^%\([^)]*\)s$",
            r"^\*+$",
            r"^(?i:none|null|nil|true|false|undefined|changeme_placeholder)$",
            # Code that reads an environment variable, e.g. `PASSWORD = os.environ[...]` in docs.
            r"^(?:os\.environ|os\.getenv|process\.env|System\.getenv)\b",
        ]
    )


class SealboxConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workspace_root: Path = Field(default_factory=Path.cwd)
    max_file_bytes: int = 512 * 1024
    excludes: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    # Lets the user explicitly override a default exclude (for example, ".env.example").
    explicit_includes: list[str] = Field(default_factory=list)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)

    @property
    def state_dir(self) -> Path:
        return state_dir(self.workspace_root)


def load_config(path: Path | None, workspace_root: Path | None = None) -> SealboxConfig:
    """Read the TOML configuration, or return the safe defaults when there is none."""
    data: dict[str, object] = {}
    if path is not None:
        try:
            # utf-8-sig accepts the BOM that some Windows editors add.
            data = tomllib.loads(path.read_bytes().decode("utf-8-sig"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            line = getattr(e, "lineno", "?")
            raise SealboxError(_(f"Yapılandırma dosyası okunamadı (satır {line})")) from None
    if workspace_root is not None:
        data["workspace_root"] = workspace_root
    try:
        cfg = SealboxConfig.model_validate(data)
    except ValidationError as e:
        fields = ", ".join(".".join(str(p) for p in err["loc"]) for err in e.errors())
        raise SealboxError(_(f"Yapılandırma geçersiz: {fields}")) from None
    cfg.workspace_root = cfg.workspace_root.resolve()
    return cfg
