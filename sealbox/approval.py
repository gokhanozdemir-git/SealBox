"""User approval before the vault is opened.

The dialog always opens on top and "Deny" is the default button. If the dialog cannot be
shown (no display, no tkinter) or is closed, the result counts as a denial (fail closed).
Agents cannot click this dialog; only the user can approve.

There is deliberately no flag or environment variable that skips approval: an agent can
run the same command line, so any such bypass would work for the agent too.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sealbox.core.errors import ApprovalDeniedError
from sealbox.i18n import _

if TYPE_CHECKING:
    from sealbox.changes import ChangeReport

_MAX_LISTED_NAMES = 12
_MAX_RISK_FILES = 8
_MAX_RISK_LINES = 4
# With risky changes, "Allow" stays disabled for a few seconds so it is not clicked by habit.
ALLOW_DELAY_SECONDS = 3


@dataclass(frozen=True)
class ApprovalRequest:
    action: str  # e.g. "Run program", "Show value"
    command: str
    cwd: str
    names: list[str] = field(default_factory=list)  # names only, never values
    changes: ChangeReport | None = None  # risky lines changed since the last approval


Approver = Callable[[ApprovalRequest], bool]


def _names_text(names: list[str]) -> str:
    if not names:
        return "—"
    shown = ", ".join(names[:_MAX_LISTED_NAMES])
    rest = len(names) - _MAX_LISTED_NAMES
    return shown + (_(f" (+{rest} tane daha)") if rest > 0 else "")


def _kind_text(kind: str, strong: bool) -> str:
    if kind == "send":
        return _("dışarı gönderiyor")
    if kind == "write":
        return _("dosyaya yazıyor")
    return _("dönüştürüp yazdırıyor") if strong else _("yazdırıyor")


def changes_summary(report: ChangeReport) -> tuple[str, str]:
    """``(title, color)`` for the heading of the dialog's changes section."""
    if report.first_run:
        return _("İlk çalıştırma: bundan sonra, değişen riskli satırlar burada gösterilir."), ""
    if not report.files:
        return _("Son onaydan beri sırları dışarı çıkarabilecek bir değişiklik yok."), "#2a6"
    if report.strong:
        return _(f"⚠ Son onaydan beri {len(report.files)} dosyada riskli değişiklik var:"), "#a33"
    return _(f"Son onaydan beri {len(report.files)} dosyada sır yazdıran satır eklendi:"), "#a60"


def changes_lines(report: ChangeReport) -> list[str]:
    """List of risky lines: file, line number, what the line does, and the code itself."""
    out: list[str] = []
    for f in report.files[:_MAX_RISK_FILES]:
        out.append(f.path)
        for r in f.lines[:_MAX_RISK_LINES]:
            out.append(f"  {r.line:>4}  {_kind_text(r.kind, r.strong)}: {r.code}")
        if len(f.lines) > _MAX_RISK_LINES:
            out.append(_(f"        (+{len(f.lines) - _MAX_RISK_LINES} satır daha)"))
    rest = len(report.files) - _MAX_RISK_FILES
    if rest > 0:
        out.append(_(f"(+{rest} dosya daha)"))
    return out


def tk_approver(req: ApprovalRequest) -> bool:
    try:
        import tkinter as tk
    except ImportError:
        return False
    try:
        root = tk.Tk()
    except tk.TclError:
        return False

    result = {"ok": False}

    def allow() -> None:
        result["ok"] = True
        root.destroy()

    def deny() -> None:
        root.destroy()

    root.title("SealBox — " + _("kasa onayı"))
    root.attributes("-topmost", True)
    root.resizable(False, False)
    root.protocol("WM_DELETE_WINDOW", deny)

    def label(
        text: str, top: int = 4, bottom: int = 4, font: str = "TkDefaultFont", fg: str = ""
    ) -> None:
        widget = tk.Label(root, text=text, wraplength=520, justify="left", font=font)
        if fg:
            widget.configure(fg=fg)
        widget.pack(padx=14, pady=(top, bottom), anchor="w")

    label(
        _(f"{req.action} için kasadaki gizli değerler isteniyor."),
        top=14,
        bottom=6,
        font="{Segoe UI} 11 bold",
    )
    label(_("Komut:"))
    cmd = tk.Text(root, height=3, width=70, wrap="word", font=("Consolas", 10))
    cmd.insert("1.0", req.command)
    cmd.configure(state="disabled")
    cmd.pack(padx=14, pady=2)
    label(_(f"Klasör: {req.cwd}"))
    label(_(f"Verilecek değerler: {_names_text(req.names)}"))
    changes = req.changes
    if changes is not None:
        title, color = changes_summary(changes)
        bold = "{Segoe UI} 10 bold" if changes.files else "TkDefaultFont"
        label(title, top=8, font=bold, fg=color)
        lines = changes_lines(changes)
        if lines:
            box = tk.Text(
                root, height=min(len(lines), 10), width=100, wrap="none", font=("Consolas", 9)
            )
            box.insert("1.0", "\n".join(lines))
            box.configure(state="disabled")
            box.pack(padx=14, pady=2)
            label(
                _(
                    "Ağa gönderilen veya dosyaya yazılan değeri SealBox gizleyemez. Ekrana "
                    "yazılanı gizler, ama dönüştürülmüşse (base64, ters çevrilmiş) tanımayabilir. "
                    "Bu değişiklikleri siz yapmadıysanız Reddet'e basıp dosyalara bakın."
                ),
                fg="#a33" if changes.strong else "",
            )
    label(_("Bu komutu siz başlatmadıysanız Reddet'e basın."), top=6, fg="#a33")
    buttons = tk.Frame(root)
    buttons.pack(padx=14, pady=(6, 14), anchor="e")
    allow_btn = tk.Button(buttons, text=_("İzin ver"), width=12, command=allow)
    allow_btn.pack(side="left", padx=4)
    deny_btn = tk.Button(buttons, text=_("Reddet"), width=12, command=deny, default="active")
    deny_btn.pack(side="left", padx=4)

    def on_return(_e: object) -> None:
        # Enter presses only the focused button; anything but a focused "Allow" denies.
        ready = str(allow_btn["state"]) != "disabled"
        (allow if ready and root.focus_get() is allow_btn else deny)()

    root.bind("<Escape>", lambda _e: deny())
    root.bind("<Return>", on_return)
    if changes is not None and changes.strong:
        allow_btn.configure(state="disabled")

        def countdown(left: int) -> None:
            if left <= 0:
                allow_btn.configure(state="normal", text=_("İzin ver"))
                return
            allow_btn.configure(text=f"{_('İzin ver')} ({left})")
            root.after(1000, countdown, left - 1)

        countdown(ALLOW_DELAY_SECONDS)
    root.after(50, root.focus_force)
    root.after(60, deny_btn.focus_set)
    root.mainloop()
    return result["ok"]


def require_approval(approver: Approver, req: ApprovalRequest) -> None:
    try:
        ok = approver(req)
    except Exception:
        ok = False
    if not ok:
        raise ApprovalDeniedError(_("Kullanıcı onay vermedi; kasa açılmadı"))


# --- Dialogs that show or ask for secrets ---------------------------------------
# Recovery codes, Shamir shares and SSH passphrases never pass through the terminal: an
# agent can read and write the terminal, but it cannot reach these dialogs.


@dataclass(frozen=True)
class SecretDisplay:
    title: str
    intro: str
    secret: str = field(repr=False)
    # (question, expected answer) pairs that prove the user really saved the code.
    checks: list[tuple[str, str]] = field(default_factory=list, repr=False)


@dataclass(frozen=True)
class SecretPrompt:
    title: str
    prompt: str
    multiline: bool = False


SecretShower = Callable[[SecretDisplay], bool]
SecretAsker = Callable[[SecretPrompt], "str | None"]

try:
    import tkinter
except ImportError:  # pragma: no cover - Python built without tkinter
    tkinter = None  # type: ignore[assignment]


def _new_window(title: str) -> tkinter.Tk | None:
    try:
        root = tkinter.Tk()
    except tkinter.TclError:
        return None
    root.title(f"SealBox — {title}")
    root.attributes("-topmost", True)
    root.resizable(False, False)
    return root


def tk_show_secret(d: SecretDisplay) -> bool:
    if tkinter is None or (root := _new_window(d.title)) is None:
        return False
    result = {"ok": False}
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    tkinter.Label(root, text=d.intro, wraplength=560, justify="left").pack(
        padx=14, pady=(14, 6), anchor="w"
    )
    box = tkinter.Text(root, height=4, width=64, wrap="word", font=("Consolas", 13))
    box.insert("1.0", d.secret)
    box.configure(state="disabled")
    box.pack(padx=14, pady=4)
    entries: list[tuple[tkinter.Entry, str]] = []
    if d.checks:
        tkinter.Label(root, text=_("Kaydettiğini doğrulamak için:"), justify="left").pack(
            padx=14, pady=(8, 2), anchor="w"
        )
    for question, expected in d.checks:
        row = tkinter.Frame(root)
        row.pack(padx=14, pady=2, anchor="w")
        tkinter.Label(row, text=question, width=34, anchor="w").pack(side="left")
        entry = tkinter.Entry(row, width=24, font=("Consolas", 11))
        entry.pack(side="left")
        entries.append((entry, expected))
    error = tkinter.Label(root, text="", fg="#a33")
    error.pack(padx=14, anchor="w")

    def done() -> None:
        for entry, expected in entries:
            if entry.get().strip().upper() != expected.strip().upper():
                error.configure(text=_("Yazdığın, gösterilenle uyuşmuyor. Tekrar bak."))
                return
        result["ok"] = True
        root.destroy()

    buttons = tkinter.Frame(root)
    buttons.pack(padx=14, pady=(6, 14), anchor="e")
    tkinter.Button(buttons, text=_("Kaydettim"), width=12, command=done).pack(side="left", padx=4)
    tkinter.Button(buttons, text=_("Vazgeç"), width=12, command=root.destroy).pack(
        side="left", padx=4
    )
    root.after(50, root.focus_force)
    root.mainloop()
    return result["ok"]


def tk_ask_secret(p: SecretPrompt) -> str | None:
    if tkinter is None or (root := _new_window(p.title)) is None:
        return None
    result: dict[str, str | None] = {"value": None}
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    tkinter.Label(root, text=p.prompt, wraplength=520, justify="left").pack(
        padx=14, pady=(14, 6), anchor="w"
    )
    if p.multiline:
        text = tkinter.Text(root, height=6, width=64, wrap="word", font=("Consolas", 11))
        text.pack(padx=14, pady=4)
        text.focus_set()

        def read() -> str:
            return text.get("1.0", "end")
    else:
        entry = tkinter.Entry(root, width=48, show="•", font=("Consolas", 11))
        entry.pack(padx=14, pady=4)
        entry.focus_set()

        def read() -> str:
            return entry.get()

    def ok(_e: object = None) -> None:
        result["value"] = read()
        root.destroy()

    buttons = tkinter.Frame(root)
    buttons.pack(padx=14, pady=(6, 14), anchor="e")
    tkinter.Button(buttons, text=_("Tamam"), width=12, command=ok).pack(side="left", padx=4)
    tkinter.Button(buttons, text=_("Vazgeç"), width=12, command=root.destroy).pack(
        side="left", padx=4
    )
    if not p.multiline:
        root.bind("<Return>", ok)
    root.bind("<Escape>", lambda _e: root.destroy())
    root.after(50, root.focus_force)
    root.mainloop()
    return result["value"]
