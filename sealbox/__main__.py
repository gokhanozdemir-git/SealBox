"""Command-line entry point. Commands and their help texts are defined in ``build_parser``.

The VS Code extension calls these commands by name (``vscode-extension/src/extension.ts``);
when renaming a command, update the extension as well.
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

from sealbox import __version__
from sealbox.cli_help import SealboxParser, examples
from sealbox.config import SealboxConfig, load_config
from sealbox.core.errors import SealboxError, safe_error_message
from sealbox.core.leak_guard import RedactingLogFilter
from sealbox.core.names import CONFIG_FILES
from sealbox.i18n import LANGUAGES, _, set_language

if TYPE_CHECKING:
    from sealbox.history import Hit
    from sealbox.sealing.sealer import SealIssue, SealReport
    from sealbox.status import Check


def _install_safety_nets() -> None:
    """Make sure log records and uncaught exceptions cannot leak secrets."""
    root = logging.getLogger()
    if not root.handlers:
        root.addHandler(logging.NullHandler())
    flt = RedactingLogFilter(lambda: None)
    for h in root.handlers:
        h.addFilter(flt)

    def hook(exc_type: type[BaseException], exc: BaseException, tb: object) -> None:
        print(_(f"Beklenmeyen hata: {safe_error_message(exc)}"), file=sys.stderr)

    sys.excepthook = hook
    # Legacy Windows consoles (cp1252/cp857) cannot print characters such as "→"; print "?"
    # instead of crashing.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="replace")


def _take_language(argv: list[str]) -> list[str]:
    """Accept ``--lang tr|en`` anywhere; it is read before the help texts are built."""
    out: list[str] = []
    it = iter(argv)
    for arg in it:
        if arg == "--":
            out.append(arg)
            out.extend(it)  # leave the arguments of the command passed to exec alone
            break
        if arg == "--lang" or arg.startswith("--lang="):
            value = arg.partition("=")[2] if "=" in arg else next(it, "")
            if value not in LANGUAGES:
                print(f"sealbox: --lang {'|'.join(LANGUAGES)}", file=sys.stderr)
                raise SystemExit(2)
            set_language(value)
            continue
        out.append(arg)
    return out


def _config(args: argparse.Namespace) -> SealboxConfig:
    cfg_path: Path | None = getattr(args, "config", None)
    ws = Path(args.workspace).resolve() if args.workspace else None
    if cfg_path is None:
        base = ws or Path.cwd()
        cfg_path = next((base / n for n in CONFIG_FILES if (base / n).is_file()), None)
    return load_config(cfg_path, ws)


def _project_root(args: argparse.Namespace) -> Path:
    from sealbox.vaultstore import find_project_root

    if args.workspace:
        return Path(args.workspace).resolve()
    found = find_project_root(Path.cwd())
    if found is None:
        raise SealboxError(_("Bu klasörde veya üstünde kasa yok; önce 'seal' çalıştırın"))
    return found


def _seal_json(report: SealReport, written: list[str]) -> dict[str, object]:
    """Machine-readable report for the editor extension. Contains no secret values."""
    return {
        "clean": report.clean,
        "written": written,
        "files": [
            {
                "path": f.path,
                "output_path": f.output_path,
                "changed": f.changed,
                "moved": f.moved,
                "masked": f.masked,
                "spans": [asdict(s) for s in f.spans],
                "issues": [asdict(i) for i in f.issues],
            }
            for f in report.files
            if f.changed or f.issues
        ],
        "skipped": [{"path": s.path, "reason": s.reason} for s in report.skipped],
    }


# --- Commands -------------------------------------------------------------------------


def cmd_seal(args: argparse.Namespace) -> int:
    from sealbox.core.tokenization import TokenVault
    from sealbox.sealing.sealer import Sealer
    from sealbox.vaultstore import ProjectVault, parent_project_hint

    cfg = _config(args)
    # Without -w the command may have been run from the wrong folder (e.g. inside src).
    hint = None if args.workspace else parent_project_hint(cfg.workspace_root)
    if hint is not None:
        raise SealboxError(
            _(
                f"Üst klasörde {hint[1]}: {hint[0]}\n"
                "Proje kökü orası gibi görünüyor; komutu o klasörden çalıştırın. "
                "Bu klasörü bilerek seçiyorsanız: -w ."
            )
        )
    store = ProjectVault(cfg.workspace_root)
    # --check never touches the vault and needs no key: it only asks "are secrets on disk?".
    vault = TokenVault() if args.check else store.open(create=True)
    started = time.monotonic()
    try:
        sealer = Sealer(cfg, vault)
        report = sealer.plan(args.paths or ["."])
        if args.json:
            written = [] if args.check else sealer.apply(report, store)
            print(json.dumps(_seal_json(report, written)))
            return 0 if report.clean or (written and not report.blocking_issues) else 1
        for f in report.files:
            if not f.changed and not f.issues:
                continue
            parts = []
            if f.moved:
                parts.append(_(f"{len(f.moved)} değer kasaya taşındı ({', '.join(f.moved)})"))
            if f.masked:
                parts.append(_(f"{f.masked} değer karalandı"))
            target = f" → {f.output_path}" if f.output_path != f.path else ""
            print(f"{f.path}{target}: {'; '.join(parts) or _('değişiklik yok')}")
            for i in f.issues:
                mark = "!" if i.blocking else "i"
                print(_(f"  [{mark}] satır {i.line} ({i.category}): {i.message}"))
        took = time.monotonic() - started
        print(_(f"{len(report.files)} dosya tarandı ({took:.1f} sn)."))
        if args.check:
            if report.clean:
                print(_("Temiz: diskte karalanmamış sır bulunmadı."))
                return 0
            if report.changed:
                print(_("Diskte karalanmamış sır var. 'sealbox seal' çalıştırın."))
            _print_left_open(report.blocking_issues)
            return 1
        written = sealer.apply(report, store)
        if written:
            print(_(f"Tamam: {len(written)} dosya yazıldı. Kasa: {store.vault_path}"))
            print(_("Programı artık şöyle çalıştırın: sealbox exec -- <komut>"))
        elif not report.blocking_issues:
            print(_("Taşınacak sır bulunamadı."))
        _print_left_open(report.blocking_issues)
        return 1 if report.blocking_issues else 0
    finally:
        vault.close()


def _print_left_open(issues: list[SealIssue]) -> None:
    """Secrets that could not be moved, boxed at the end so they do not get lost in the list."""
    if not issues:
        return
    print()
    print("┌─ " + _(f"DİKKAT: {len(issues)} sır dosyada AÇIK kaldı ") + "─" * 20)
    for i in issues:
        print(f"│ {i.path}:{i.line}  ({i.category})  {i.message}")
    print("│")
    print("│ " + _("Ajan bu dosyaları okursa bu değerleri görür. Ne yapmalı:"))
    print("│ " + _("  - Metnin içindeyse (ör. URL'deki parola): sırrı ayrı bir değişkene al,"))
    print("│ " + _("    metni o değişkenle kur. Örnek (Python):"))
    print('│     DB_PASSWORD = os.environ["DB_PASSWORD"]')
    print('│     url = f"postgres://admin:{DB_PASSWORD}@host/db"')
    print("│ " + _("    Sonra değeri kasaya ekle: sealbox vault set DB_PASSWORD"))
    print(
        "│ " + _("  - Desteklenmeyen dosyadaysa: değeri sil, aynı yolla ortam değişkeninden oku.")
    )
    print("└" + "─" * 60)


def cmd_exec(args: argparse.Namespace) -> int:
    from sealbox.approval import tk_approver
    from sealbox.runner import run_command

    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    return run_command(_project_root(args), command, tk_approver)


def cmd_vault(args: argparse.Namespace) -> int:
    import getpass

    from sealbox.approval import tk_approver
    from sealbox.runner import (
        expose_value,
        remove_values,
        requested_names,
        reveal_value,
        set_value,
    )
    from sealbox.vaultstore import ProjectVault

    root = _project_root(args)
    if args.vault_cmd == "list":
        store = ProjectVault(root)
        kinds = store.names()
        for name in requested_names(store):
            print(f"{name}  ({kinds.get(name, '.env')})")
        masked = store.masked()
        if masked:
            print(_("\nKaralanmış veriler (bakmak için: vault reveal <etiket>):"))
            for ph, kind in masked.items():
                print(f"{ph}  ({kind})")
        return 0
    if args.vault_cmd == "reveal":
        print(reveal_value(root, args.name, tk_approver))
        return 0
    cfg = _config(argparse.Namespace(config=None, workspace=str(root)))
    if args.vault_cmd == "expose":
        name, written = expose_value(cfg, args.name, args.as_name)
        print(_(f"Tamam: değer artık çalışırken {name} olarak verilecek."))
        for rel in written:
            print(_(f"  {rel}: etiket {name} okumasına çevrildi"))
        return 0
    if args.vault_cmd == "remove":
        if not args.names and not args.unused:
            raise SealboxError(_("Silinecek adı/etiketi yazın ya da --unused kullanın"))
        removed = remove_values(cfg, args.names, tk_approver, unused=args.unused, force=args.force)
        if not removed:
            print(_("Silinecek kullanılmayan kayıt yok."))
        for label in removed:
            print(_(f"Silindi: {label}"))
        return 0
    if args.vault_cmd == "reset":
        return _vault_reset(root)
    value = getpass.getpass(_(f"{args.name} için yeni değer (ekranda görünmez): "))
    created = set_value(root, args.name, value, tk_approver)
    print(_(f"{args.name} eklendi.") if created else _(f"{args.name} güncellendi."))
    return 0


def _vault_reset(root: Path) -> int:
    from sealbox.approval import ApprovalRequest, require_approval, tk_approver
    from sealbox.vaultstore import ProjectVault

    store = ProjectVault(root)
    require_approval(
        tk_approver,
        ApprovalRequest(
            _(
                "Kasayı sıfırlamak (eski kasa silinmez, kenara kaldırılır; "
                "değerleri yeniden girersin)"
            ),
            "vault reset",
            str(store.root),
            [*sorted(store.names()), _(f"{len(store.masked())} karalanmış veri")],
        ),
    )
    names, masked = store.names(), store.masked()
    store.reset()
    folder = store.state_dir.name
    print(_(f"Yeni boş kasa açıldı. Eski kasa {folder}/lost-<tarih>/ içinde duruyor."))
    if names:
        print(_("\nDeğeri kaybolan değişkenler (servis panelinden yeni değer alıp gir):"))
        for name in sorted(names):
            print(f"  sealbox vault set {name}")
    if masked:
        print(
            _(
                "\nDeğeri kaybolan karalanmış veriler (asıl kaynağından al, dosyada etiketin "
                "yerine yaz ve tekrar 'seal' çalıştır):"
            )
        )
        for ph, kind in sorted(masked.items()):
            print(f"  {ph}  ({kind})")
    print(_("\nKurtarma kodu kuruluysa yeni kasa ona kendiliğinden kilitlendi."))
    return 0


def cmd_team(args: argparse.Namespace) -> int:
    from sealbox import team as t
    from sealbox.approval import tk_approver
    from sealbox.vaultstore import ProjectVault

    store = ProjectVault(_project_root(args))
    if args.team_cmd == "list":
        members = t.team_members(store)
        if not members:
            print(_("Bu projede ekip kurulmamış. Kurmak için: team init --github <kullanıcı adın>"))
        for user, role, fps in members:
            print(f"@{user}  ({_(t.ROLE_LABELS[role])})  {', '.join(fps)}")
        return 0
    if args.team_cmd == "init":
        pubs = t.team_init(store, args.github, tk_approver, store.identity)
        user = t.check_user(args.github)
        print(_(f"Ekip kuruldu: @{user} sahip ({len(pubs)} SSH anahtarı)."))
    elif args.team_cmd == "add":
        role = t.OWNER if args.owner else t.MEMBER
        pubs = t.team_add(store, args.user, tk_approver, store.identity, role=role)
        user = t.check_user(args.user)
        print(_(f"@{user} eklendi ({_(t.ROLE_LABELS[role])}, {len(pubs)} SSH anahtarı)."))
        print(_(f"Şimdi commit + push et; @{user} pull edince kasayı kendi SSH anahtarıyla açar."))
    elif args.team_cmd == "promote":
        t.team_promote(store, args.user, tk_approver, store.identity)
        print(_(f"@{t.check_user(args.user)} artık sahip. Commit + push et."))
    else:
        seen = t.team_remove(store, args.user, tk_approver, store.identity)
        user = t.check_user(args.user)
        print(_(f"@{user} çıkarıldı ve kasa anahtarı yenilendi. Commit + push et."))
        if seen:
            print(
                _(f"@{user} bunları daha önce görmüş olabilir; mümkünse servislerinden yenileyin:")
            )
            for label in seen:
                print(f"  {label}")
    warning = t.sharing_warning(store)
    if warning:
        print(_(f"Uyarı: {warning}"), file=sys.stderr)
    return 0


def cmd_recovery(args: argparse.Namespace) -> int:
    from sealbox import recovery as r
    from sealbox.approval import tk_ask_secret, tk_show_secret
    from sealbox.vaultstore import ProjectVault, find_project_root

    rec = r.RecoveryStore.default()
    found = Path(args.workspace).resolve() if args.workspace else find_project_root(Path.cwd())
    store = ProjectVault(found) if found else None
    if args.recovery_cmd == "status":
        protected = bool(store and store.exists() and rec.protects(store.project_id()))
        if args.json:
            print(json.dumps({"set_up": rec.is_set_up(), "protected": protected}))
        elif not rec.is_set_up():
            print(_("Kurtarma kurulmamış: kasa anahtarı kaybolursa kasalar açılamaz."))
            print(_("Kurmak için: sealbox recovery setup"))
        elif protected:
            print(_("Kurtarma kurulu. Bu proje korunuyor."))
        else:
            print(_("Kurtarma kurulu."))
        return 0
    if args.recovery_cmd == "setup":
        r.setup_recovery(store, rec, tk_show_secret, replace=args.new)
        print(_("Kurtarma kuruldu. Kod yalnızca pencerede gösterildi."))
        if store is not None and store.exists():
            print(_("Bu proje kurtarma koduna kilitlendi; diğer projeler açıldıkça kilitlenir."))
        return 0
    if args.recovery_cmd == "shares":
        r.make_shares(rec, tk_ask_secret, tk_show_secret)
        print(
            _(
                f"{r.SHARE_COUNT} parça gösterildi; herhangi {r.SHARE_THRESHOLD} tanesi "
                "kodun yerini tutar."
            )
        )
        return 0
    if args.recovery_cmd == "restore":
        target = store or ProjectVault(Path(args.workspace or ".").resolve())
        count = r.restore(target, rec, tk_ask_secret, Path(args.kit) if args.kit else None)
        print(
            _(f"Kasa geri geldi ({count} kayıt). Anahtar bu bilgisayarın kimlik deposuna yazıldı.")
        )
        return 0
    if store is None:
        raise SealboxError(_("Bu klasörde veya üstünde kasa yok"))
    r.export_kit(store, rec, Path(args.path))
    print(_(f"Kurtarma kiti yazıldı: {args.path}"))
    print(_("Kit kurtarma kodu olmadan açılmaz; USB'ye ya da buluta koyabilirsin."))
    return 0


def _print_history(hits: list[Hit]) -> None:
    for h in hits:
        where = _("uzak sunucuya gönderilmiş") if h.pushed else _("yalnızca bu bilgisayarda")
        print(_(f"  ⚠ {h.label}: {h.count} commit'te açık — {where}"))
        print(_(f"      ilk: {h.commit} {h.date}, {h.path}"))
        if h.named:
            print(_(f"      → servisinden yenile, sonra: sealbox vault set {h.label}"))
        else:
            print(_("      → kişisel veri: geçmişten temizlemeyi düşün (git filter-repo)"))
    if hits:
        print(_("  Dosyayı temizlemek geçmişi silmez: bu değerler eski commit'lerde okunabilir."))
    else:
        print(_("  ✓ Kasadaki değerlerin hiçbiri git geçmişinde yok"))


def cmd_history(args: argparse.Namespace) -> int:
    from sealbox.history import is_git_repo, scan_history
    from sealbox.vaultstore import ProjectVault

    root = _project_root(args)
    git = is_git_repo(root)
    hits: list[Hit] = []
    if git:
        vault = ProjectVault(root).open()
        try:
            hits = scan_history(root, vault)
        finally:
            vault.close()
    if args.json:  # for the editor extension; contains no values
        print(json.dumps({"git": git, "hits": [asdict(h) for h in hits]}))
        return 1 if hits else 0
    if not git:
        print(_("Bu klasör bir git deposu değil; taranacak geçmiş yok."))
        return 0
    print(_("Git geçmişi:"))
    _print_history(hits)
    return 1 if hits else 0


def cmd_hook(args: argparse.Namespace) -> int:
    from sealbox import history as h

    root = _project_root(args)
    if args.hook_cmd == "status":
        git, installed = h.is_git_repo(root), h.hook_installed(root)
        if args.json:
            print(json.dumps({"git": git, "installed": installed}))
        elif not git:
            print(_("Bu klasör bir git deposu değil"))
        else:
            print(_("Commit kancası kurulu") if installed else _("Commit kancası kurulu değil"))
        return 0
    if args.hook_cmd == "install":
        path = h.install_hook(root)
        print(_(f"Kanca kuruldu: {path}"))
        print(_("Kasadaki bir değer commit'e girmeye çalışırsa commit durdurulur."))
        return 0
    if args.hook_cmd == "uninstall":
        print(
            _("Kanca kaldırıldı.") if h.uninstall_hook(root) else _("Kurulu sealbox kancası yok.")
        )
        return 0
    return _hook_run(root)


def _hook_run(root: Path) -> int:
    """Pre-commit: stop the commit (exit code 1) if a vault value is being committed."""
    from sealbox.history import scan_staged, scan_staged_generic
    from sealbox.vaultstore import ProjectVault

    store = ProjectVault(root)
    if not store.exists():
        return 0
    try:
        # Without a cached key, fall back to a generic scan instead of asking for SSH.
        vault = store.open() if store.has_cached_key() else None
    except SealboxError:
        vault = None
    if vault is None:
        # Do not block anyone's work because the vault could not be opened; just warn.
        print(
            _("sealbox: kasa anahtarı yok; commit yalnızca genel kurallarla tarandı"),
            file=sys.stderr,
        )
        for path, line, category in scan_staged_generic(root):
            print(_(f"  ⚠ {path}:{line}  olası sır ({category})"), file=sys.stderr)
        return 0
    try:
        hits = scan_staged(root, vault)
    finally:
        vault.close()
    if not hits:
        return 0
    print(
        _("✗ sealbox: commit durduruldu, kasadaki değerler bu commit'e giriyor:"), file=sys.stderr
    )
    for hit in hits:
        print(f"    {hit.path}:{hit.line}  {hit.label}", file=sys.stderr)
    print(
        _("  Değeri dosyadan çıkar (sealbox seal), 'git add' ile güncelle ve tekrar dene."),
        file=sys.stderr,
    )
    return 1


def _status_config(args: argparse.Namespace) -> SealboxConfig:
    """Without -w, find the parent folder that has a vault (so subfolders work too)."""
    from sealbox.vaultstore import find_project_root

    if not args.workspace:
        found = find_project_root(Path.cwd())
        if found is not None:
            args.workspace = str(found)
    return _config(args)


def _print_checks(checks: list[Check]) -> None:
    from sealbox.status import ICONS, OK

    for c in checks:
        line = f"  {ICONS[c.level]} {c.text}"
        if c.hint and c.level != OK:
            line += f"  → {c.hint}"
        print(line)


def cmd_status(args: argparse.Namespace) -> int:
    from sealbox.status import FAIL, project_checks

    cfg = _status_config(args)
    checks = project_checks(cfg)
    failed = any(c.level == FAIL for c in checks)
    if args.json:
        print(
            json.dumps(
                {
                    "root": str(cfg.workspace_root),
                    "ok": not failed,
                    "checks": [c.as_dict() for c in checks],
                }
            )
        )
        return 1 if failed else 0
    print(_(f"Proje: {cfg.workspace_root}"))
    _print_checks(checks)
    return 1 if failed else 0


def cmd_init(args: argparse.Namespace) -> int:
    from sealbox.status import next_steps, project_checks
    from sealbox.vaultstore import ProjectVault, parent_project_hint

    cfg = _status_config(args)
    root = cfg.workspace_root
    print(_(f"sealbox {__version__} · proje: {root}"))
    hint = None if args.workspace else parent_project_hint(root)
    if hint is not None:
        print(_(f"⚠ Üst klasörde {hint[1]}: {hint[0]} — proje kökü orası olabilir (cd ile geç)."))
    print()
    checks = project_checks(cfg)
    _print_checks(checks)
    _init_history(root)
    steps = next_steps(checks)
    print()
    if not steps:
        print(_("Her şey hazır. Programını çalıştırmak için: sealbox exec -- <komut>"))
        return 0
    print(_("Sıradaki adımlar:"))
    for i, step in enumerate(steps, start=1):
        print(f"  {i}) {step}")
    folder = ProjectVault(root).state_dir.name
    print(_(f"Sonra kasayı repoya ekle: git add {folder} && git commit"))
    print(_("Her komutun ayrıntısı: sealbox help <komut>"))
    return 0


def _init_history(root: Path) -> None:
    """Also scan git history if the key is cached (no dialog, no SSH passphrase prompt)."""
    from sealbox.history import is_git_repo, scan_history
    from sealbox.vaultstore import ProjectVault

    store = ProjectVault(root)
    try:
        if not (store.exists() and is_git_repo(root) and store.has_cached_key()):
            return
        vault = store.open()
    except SealboxError:
        return
    try:
        hits = scan_history(root, vault)
    finally:
        vault.close()
    print()
    print(_("Git geçmişi:"))
    _print_history(hits)


# --- Command and help definitions -------------------------------------------------------------


def _groups() -> list[tuple[str, list[tuple[str, str]]]]:
    return [
        (
            _("Başlarken"),
            [
                ("init", _("Projeyi kontrol et, ne yapman gerektiğini adım adım söyle")),
                ("status", _("Kasa, anahtar, kurtarma ve ekip durumu")),
            ],
        ),
        (
            _("Günlük kullanım"),
            [
                ("seal", _("Dosyalardaki sırları kasaya taşı (mühürle)")),
                ("exec", _("Programı sırlarla çalıştır (her seferinde onay)")),
                ("vault", _("Kasadaki değerleri listele, göster, değiştir, sil")),
            ],
        ),
        (
            _("Git"),
            [
                ("history", _("Kasadaki değerler eski commit'lerde açık mı?")),
                ("hook", _("Kasadaki bir değer commit'e girmesin (pre-commit kancası)")),
            ],
        ),
        (_("Ekip"), [("team", _("Kasayı GitHub SSH anahtarlarıyla arkadaşlarınla paylaş"))]),
        (
            _("Kurtarma"),
            [("recovery", _("Anahtar kaybolursa kasayı geri açan kurtarma kodu"))],
        ),
    ]


def _overview() -> str:
    lines = [
        _(
            "Sırları dosyalardan çıkarıp şifreli bir kasaya mühürler: yapay zekâ ajanları\n"
            "dosyalarını okusa da şifre göremez. Program çalışırken sırlar onaylı verilir."
        ),
        "",
    ]
    for title, commands in _groups():
        lines.append(f"{title}:")
        lines.extend(f"  {name:<10}  {text}" for name, text in commands)
        lines.append("")
    return "\n".join(lines).rstrip()


def _footer() -> str:
    return _(
        "Bir komutun ayrıntısı ve örnekleri: sealbox help <komut>  (ya da sealbox <komut> --help)\n"
        "Dil: --lang tr|en ya da SEALBOX_LANG ortam değişkeni."
    )


def build_parser() -> argparse.ArgumentParser:
    p = SealboxParser(
        prog="sealbox",
        usage=_("sealbox [--lang tr|en] <komut> [seçenekler]"),
        description=_overview(),
        epilog=_footer(),
    )
    p.add_argument("-V", "--version", action="version", version=f"sealbox {__version__}")
    p.add_argument(
        "--lang", choices=LANGUAGES, help=_("Mesaj dili (varsayılan: bilgisayarın dili)")
    )
    folder, file, user = _("KLASÖR"), _("DOSYA"), _("KULLANICI")
    common = SealboxParser(add_help=False)
    common.add_argument(
        "--workspace", "-w", metavar=folder, help=_("Proje kökü (varsayılan: bulunduğun klasör)")
    )
    common.add_argument("--config", "-c", type=Path, metavar=file, help=_("sealbox.toml yolu"))
    # Allow -w after the subcommand too (vault list -w DIR); SUPPRESS keeps one from
    # overwriting the other.
    ws = SealboxParser(add_help=False)
    ws.add_argument(
        "--workspace", "-w", metavar=folder, default=argparse.SUPPRESS, help=_("Proje kökü")
    )
    sub = p.add_subparsers(
        dest="command", prog="sealbox", metavar=_("<komut>"), help=argparse.SUPPRESS
    )

    def command(
        name: str,
        description: str,
        *ex: tuple[str, str],
        parents: list[SealboxParser] | None = None,
    ) -> SealboxParser:
        return sub.add_parser(
            name,
            description=description,
            epilog=examples(*ex) if ex else None,
            parents=parents or [],
        )

    # --- Getting started ---
    it = command(
        "init",
        _(
            "Projeyi kontrol eder ve sıradaki adımları sırayla söyler. Hiçbir dosyayı\n"
            "değiştirmez; yeni bir projede ilk çalıştırılacak komuttur."
        ),
        ("sealbox init", _("bulunduğun klasördeki projeyi kontrol et")),
        ("sealbox init -w C:\\projem", _("başka bir klasördeki projeyi kontrol et")),
        parents=[common],
    )
    it.set_defaults(func=cmd_init)
    st = command(
        "status",
        _(
            "Kasanın, anahtarın, kurtarma kodunun ve ekibin durumunu gösterir. Sorun olan\n"
            "her satırın yanında ne yapman gerektiği yazar. Bir şey açılamıyorsa çıkış kodu 1."
        ),
        ("sealbox status", _("durumu göster")),
        ("sealbox status --json", _("betikler ve CI için makine okunur çıktı")),
        parents=[common],
    )
    st.add_argument("--json", action="store_true", help=_("Raporu JSON bas"))
    st.set_defaults(func=cmd_status)

    # --- Everyday use ---
    se = command(
        "seal",
        _(
            "Dosyalardaki parola, token, API anahtarı ve kişisel verileri bulur:\n"
            "  - kod içindeki sırları kasaya taşır, yerine ortam değişkeni okuması yazar\n"
            "    (Python os.environ, JS/TS process.env, Java System.getenv),\n"
            "  - e-posta, TCKN gibi verileri __SECURE_..__ etiketiyle karalar,\n"
            "  - .env dosyasını kasaya alır, yerine .env.sealed bırakır.\n"
            "Yazmadan önce bakmak için --check kullan."
        ),
        ("sealbox seal --check", _("yalnızca bak: diskte açık sır var mı?")),
        ("sealbox seal", _("tüm projedeki sırları kasaya taşı")),
        ("sealbox seal src/config.py", _("yalnızca bir dosya")),
        parents=[common],
    )
    se.add_argument("paths", nargs="*", help=_("Dosya/klasör (varsayılan: tüm proje)"))
    se.add_argument("--check", action="store_true", help=_("Yazma; sır varsa çıkış kodu 1"))
    se.add_argument("--json", action="store_true", help=_("Raporu JSON bas (editör eklentisi)"))
    se.set_defaults(func=cmd_seal)

    ex = command(
        "exec",
        _(
            "Programını kasadaki sırlarla çalıştırır. Önce hangi değerlerin verileceğini\n"
            "gösteren bir onay penceresi açılır; sırlar yalnızca bu çalıştırmaya ortam\n"
            "değişkeni olarak verilir. Programın çıktısındaki sırlar [GİZLİ:..] olarak basılır."
        ),
        ("sealbox exec -- python app.py", "Python"),
        ("sealbox exec -- npm start", "Node.js"),
        ("sealbox exec -- java Main.java", "Java"),
        ("sealbox exec -- mvn spring-boot:run", _("Maven / Gradle da olur")),
    )
    ex.add_argument(
        "--workspace",
        "-w",
        metavar=folder,
        help=_("Proje kökü (varsayılan: kasası olan üst klasör)"),
    )
    ex.add_argument("command", nargs=argparse.REMAINDER, help=_("-- ardından çalıştırılacak komut"))
    ex.set_defaults(func=cmd_exec)

    va = command(
        "vault",
        _(
            "Kasadaki kayıtları yönetir. Değerler hiçbir zaman terminale kendiliğinden\n"
            "yazılmaz; göstermek ve değiştirmek onay ister."
        ),
        ("sealbox vault list", _("değişken adları ve etiketler (değer yok)")),
        ("sealbox vault reveal DB_PASSWORD", _("bir değeri göster (onay ister)")),
        ("sealbox vault set DB_PASSWORD", _("değeri değiştir ya da ekle")),
        ("sealbox vault remove --unused", _("hiçbir dosyanın kullanmadığı kayıtları sil")),
    )
    va.add_argument("--workspace", "-w", metavar=folder, help=_("Proje kökü"))
    vsub = va.add_subparsers(dest="vault_cmd", required=True, metavar=_("<işlem>"))
    vsub.add_parser("list", parents=[ws], help=_("Değişken adları (değer göstermez)"))
    for name, text in (
        ("reveal", _("Değeri göster (onay ister)")),
        ("set", _("Değeri değiştir/ekle")),
    ):
        vsub.add_parser(name, parents=[ws], help=text).add_argument("name", metavar=_("AD"))
    vx = vsub.add_parser(
        "expose",
        parents=[ws],
        help=_("Karalanmış veriyi programa çalışırken ver (TCKN, e-posta...)"),
    )
    vx.add_argument("name", help=_("Dosyadaki __SECURE_..__ etiketi"))
    vx.add_argument("--as", dest="as_name", help=_("Ortam değişkeni adı (varsayılan: atamadan)"))
    vr = vsub.add_parser("remove", parents=[ws], help=_("Kasadan kayıt sil (onay ister)"))
    vr.add_argument("names", nargs="*", help=_("Değişken adı veya __SECURE_..__ etiketi"))
    vr.add_argument(
        "--unused", action="store_true", help=_("Hiçbir dosyanın kullanmadığı kayıtlar")
    )
    vr.add_argument("--force", action="store_true", help=_("Dosyada kullanılıyor olsa da sil"))
    vsub.add_parser(
        "reset",
        parents=[ws],
        help=_("Anahtar kayıpsa: yeni boş kasa aç (eskisi kenara kaldırılır)"),
    )
    va.set_defaults(func=cmd_vault)

    # --- Git ---
    hi = command(
        "history",
        _(
            "Kasadaki değerleri git geçmişinin tamamında arar. Kasaya taşınmadan önce commit\n"
            "edilmiş bir sır eski commit'lerde okunabilir; bulunursa o sırrı servisinden\n"
            "yenile. Değerler ekrana yazılmaz, yalnızca ad, commit ve dosya. Bulursa çıkış kodu 1."
        ),
        ("sealbox history", _("geçmişi tara")),
    )
    hi.add_argument("--workspace", "-w", metavar=folder, help=_("Proje kökü"))
    hi.add_argument("--json", action="store_true", help=_("Raporu JSON bas (editör eklentisi)"))
    hi.set_defaults(func=cmd_history)
    ho = command(
        "hook",
        _(
            "Git'e bir pre-commit kancası kurar: kasadaki bir değer commit'e girmeye çalışırsa\n"
            "commit durdurulur. Kazaya karşı emniyet kemeridir; 'git commit --no-verify'\n"
            "onu atlar. Kanca repoya girmez; ekipteki herkes kendi bilgisayarında kurar."
        ),
        ("sealbox hook install", _("kancayı kur")),
        ("sealbox hook uninstall", _("kancayı kaldır")),
    )
    ho.add_argument("--workspace", "-w", metavar=folder, help=_("Proje kökü"))
    hsub = ho.add_subparsers(dest="hook_cmd", required=True, metavar=_("<işlem>"))
    hsub.add_parser("install", parents=[ws], help=_("Pre-commit kancasını kur"))
    hsub.add_parser("uninstall", parents=[ws], help=_("SealBox kancasını kaldır"))
    hsub.add_parser("run", parents=[ws], help=_("Kancanın çalıştırdığı kontrol (elle de olur)"))
    hst = hsub.add_parser("status", parents=[ws], help=_("Kanca kurulu mu"))
    hst.add_argument("--json", action="store_true", help=_("Raporu JSON bas"))
    ho.set_defaults(func=cmd_hook)

    # --- Team ---
    te = command(
        "team",
        _(
            "Kasayı arkadaşlarınla paylaşır. Kasa repoya girer; değerleri yalnızca ekipteki\n"
            "GitHub hesaplarının SSH anahtarları açabilir. Değişiklikten sonra commit + push et."
        ),
        ("sealbox team init --github benim-adim", _("ekibi kur (sen sahip olursun)")),
        ("sealbox team add arkadasim", _("github.com/arkadasim.keys ile erişim ver")),
        ("sealbox team add arkadasim --owner", _("sahip olarak ekle")),
        ("sealbox team remove arkadasim", _("çıkar; kasa anahtarı yenilenir")),
        ("sealbox team list", _("üyeler")),
    )
    te.add_argument("--workspace", "-w", metavar=folder, help=_("Proje kökü"))
    tsub = te.add_subparsers(dest="team_cmd", required=True, metavar=_("<işlem>"))
    ti = tsub.add_parser("init", parents=[ws], help=_("Ekibi kur (sen sahip olursun)"))
    ti.add_argument("--github", required=True, help=_("Senin GitHub kullanıcı adın"))
    ta = tsub.add_parser("add", parents=[ws], help=_("GitHub kullanıcısına erişim ver"))
    ta.add_argument("user", metavar=user)
    ta.add_argument("--owner", action="store_true", help=_("Sahip olarak ekle"))
    for name, text in (
        ("remove", _("Ekipten çıkar (kasa anahtarı yenilenir)")),
        ("promote", _("Sahip yap")),
    ):
        tsub.add_parser(name, parents=[ws], help=text).add_argument("user", metavar=user)
    tsub.add_parser("list", parents=[ws], help=_("Üyeler ve SSH parmak izleri"))
    te.set_defaults(func=cmd_team)

    # --- Recovery ---
    rv = command(
        "recovery",
        _(
            "Kasa anahtarı kaybolursa (Windows sıfırlama, yeni bilgisayar) kasayı geri açan\n"
            "kurtarma kodu. Kod ve parçalar yalnızca pencerede gösterilir, terminale yazılmaz."
        ),
        ("sealbox recovery setup", _("kurtarma kodunu üret (bir kez)")),
        ("sealbox recovery shares", _("kodu 3 parçaya böl; herhangi 2'si yeter")),
        ("sealbox recovery export D:\\proje.sealkit", _("kurtarma kiti (USB / bulut için)")),
        ("sealbox recovery restore", _("kod ya da 2 parçayla anahtarı geri getir")),
        ("sealbox recovery restore --kit D:\\proje.sealkit", _("kasa klasörü de gittiyse")),
    )
    rv.add_argument("--workspace", "-w", metavar=folder, help=_("Proje kökü"))
    rsub = rv.add_subparsers(dest="recovery_cmd", required=True, metavar=_("<işlem>"))
    rs = rsub.add_parser("setup", parents=[ws], help=_("Kurtarma kodu üret (pencerede gösterilir)"))
    rs.add_argument("--new", action="store_true", help=_("Var olan kodu yenisiyle değiştir"))
    rsub.add_parser("shares", parents=[ws], help=_("Kodu 2-of-3 parçaya böl"))
    rr = rsub.add_parser(
        "restore", parents=[ws], help=_("Kod ya da parçalarla anahtarı geri getir")
    )
    rr.add_argument(
        "--kit", metavar=file, help=_("Kurtarma kiti dosyası (yeni bilgisayar / silinmiş kasa)")
    )
    re_ = rsub.add_parser("export", parents=[ws], help=_("Kurtarma kiti dosyası yaz (USB/bulut)"))
    re_.add_argument("path", metavar=file)
    rst = rsub.add_parser("status", parents=[ws], help=_("Kurtarma kurulu mu"))
    rst.add_argument("--json", action="store_true", help=_("Raporu JSON bas"))
    rv.set_defaults(func=cmd_recovery)
    return p


def main(argv: list[str] | None = None) -> int:
    _install_safety_nets()
    set_language(None)
    args_in = _take_language(list(sys.argv[1:] if argv is None else argv))
    if args_in[:1] == ["help"]:  # like npm/git: sealbox help seal
        args_in = [*args_in[1:], "--help"]
    parser = build_parser()
    args = parser.parse_args(args_in)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 0
    try:
        return int(func(args))
    except SealboxError as e:
        print(_(f"Durduruldu: {safe_error_message(e)}"), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
