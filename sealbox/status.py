"""``sealbox status`` / ``sealbox init``: the project's health, with a fix for each problem.

Read-only: changes nothing, opens no dialog and never opens the vault (reads no values).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from sealbox.config import SealboxConfig
from sealbox.core.tokenization import TokenVault
from sealbox.history import hook_installed, is_git_repo
from sealbox.i18n import _
from sealbox.recovery import RecoveryStore
from sealbox.sealing.sealer import Sealer
from sealbox.team import sharing_warning, team_members
from sealbox.vaultstore import _STATE_GITIGNORE, ProjectVault

OK, INFO, WARN, FAIL = "ok", "info", "warn", "fail"
ICONS = {OK: "✓", INFO: "·", WARN: "⚠", FAIL: "✗"}


@dataclass(frozen=True)
class Check:
    level: str
    text: str
    hint: str = ""  # command to run, or what to do next

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _secrets_on_disk(cfg: SealboxConfig) -> Check:
    vault = TokenVault()
    try:
        report = Sealer(cfg, vault).plan(["."])
    finally:
        vault.close()
    files = [f for f in report.files if f.changed or f.issues]
    if report.clean and not files:
        return Check(OK, _("Diskte açık sır yok"))
    if report.clean:
        return Check(INFO, _(f"{len(files)} dosyada bilgi notu var"), "sealbox seal --check")
    if not report.changed:
        # 'seal' cannot move these (e.g. a password inside a URL), so keep reminding.
        n = len(report.blocking_issues)
        return Check(WARN, _(f"{n} sır dosyada AÇIK kaldı, elle taşınmalı"), "sealbox seal --check")
    return Check(WARN, _(f"{len(files)} dosyada açık sır var"), "sealbox seal")


def project_checks(cfg: SealboxConfig, rec: RecoveryStore | None = None) -> list[Check]:
    rec = rec or RecoveryStore.default()
    store = ProjectVault(cfg.workspace_root, recovery=rec)
    checks: list[Check] = []
    if not store.exists():
        checks.append(Check(WARN, _("Bu projede henüz kasa yok"), "sealbox seal"))
    else:
        names, masked = store.names(), store.masked()
        checks.append(
            Check(
                OK,
                _(
                    f"Kasa: {len(names)} değişken, {len(masked)} karalanmış veri "
                    f"({store.state_dir.name})"
                ),
            )
        )
        team = team_members(store)
        if store.has_cached_key():
            checks.append(Check(OK, _("Kasa anahtarı bu bilgisayarda")))
        elif team:
            checks.append(
                Check(
                    WARN,
                    _("Kasa anahtarı bu bilgisayarda yok; ilk açılışta SSH şifren sorulacak"),
                    "sealbox vault list",
                )
            )
        else:
            checks.append(
                Check(FAIL, _("Kasa anahtarı bu bilgisayarda yok"), "sealbox recovery restore")
            )
        if team:
            checks.append(Check(OK, _(f"Ekip: {len(team)} kişi")))
            warning = sharing_warning(store)
            if warning:
                checks.append(Check(WARN, warning))
        else:
            checks.append(
                Check(INFO, _("Ekip kurulmamış (tek kişi)"), "sealbox team init --github <ad>")
            )
        if is_git_repo(store.root):
            if hook_installed(store.root):
                checks.append(Check(OK, _("Commit kancası kurulu")))
            else:
                checks.append(
                    Check(
                        WARN,
                        _("Commit kancası yok: kasadaki bir değer yanlışlıkla commit edilebilir"),
                        "sealbox hook install",
                    )
                )
        ignore = store.state_dir / ".gitignore"
        lines = ignore.read_text(encoding="utf-8").splitlines() if ignore.is_file() else []
        if any(line not in lines for line in _STATE_GITIGNORE):
            checks.append(
                Check(WARN, _("Kasa klasörünün .gitignore dosyası eksik"), "sealbox seal")
            )
    if not rec.is_set_up():
        checks.append(
            Check(
                WARN,
                _("Kurtarma kodu yok: anahtar kaybolursa kasa açılamaz"),
                "sealbox recovery setup",
            )
        )
    elif store.exists() and not rec.protects(store.project_id()):
        checks.append(
            Check(
                WARN,
                _("Kurtarma kurulu ama bu proje henüz ona kilitlenmedi"),
                "sealbox vault list",
            )
        )
    else:
        checks.append(Check(OK, _("Kurtarma kodu kurulu")))
    checks.append(_secrets_on_disk(cfg))
    return checks


def next_steps(checks: list[Check]) -> list[str]:
    """The commands from warnings and failures, in order and without duplicates."""
    steps: list[str] = []
    for c in checks:
        if c.level in (WARN, FAIL) and c.hint and c.hint not in steps:
            steps.append(c.hint)
    return steps
