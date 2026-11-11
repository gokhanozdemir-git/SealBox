// SealBox for VS Code. All the real work is done by the `sealbox` command-line engine; this
// extension wires editor features to it. Secret values only pass through the extension after
// an explicit "Show value" approval, stay in memory briefly, and are never logged.

import { execFile } from "child_process";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";
import {
  envRefAt,
  findProjectRoot,
  historyLines,
  isInside,
  isKeyMissing,
  isOlder,
  manualHelp as manualHelpText,
  MIN_ENGINE_VERSION,
  missingVaultVar,
  parseEngineVersion,
  parseHistory,
  parseReport,
  placeholderAt,
  problemsFromReport,
  readTeam,
  readVaultIndex,
  recoveryState,
  resolveExecutable,
  SealReport,
  setTranslator,
  splitArgs,
  STATE_DIR,
  stateDir,
  t,
} from "./core";

const SOURCE = "sealbox";
const CLIPBOARD_CLEAR_MS = 30_000;
const TERMINAL_NAME = "SealBox";

let diagnostics: vscode.DiagnosticCollection;
let output: vscode.OutputChannel;
let status: vscode.StatusBarItem;
let lastCommand = "";
let engineChecked = false;
let installOffered = false;

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

class ExecutableMissing extends Error {}

// --- Helpers -------------------------------------------------------------------

function setting<T>(key: string, fallback: T): T {
  return vscode.workspace.getConfiguration("sealbox").get<T>(key, fallback);
}

/** Ask the engine to answer in the same language as VS Code. */
function engineLanguage(): string {
  return vscode.env.language.toLowerCase().startsWith("tr") ? "tr" : "en";
}

/** Project root for a file: the nearest folder with a vault, else its workspace folder. */
function rootFor(uri?: vscode.Uri): string | undefined {
  const target = uri ?? vscode.window.activeTextEditor?.document.uri;
  const folder = target
    ? vscode.workspace.getWorkspaceFolder(target)
    : vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    return undefined;
  }
  if (!target || target.scheme !== "file") {
    return folder.uri.fsPath;
  }
  return findProjectRoot(path.dirname(target.fsPath), folder.uri.fsPath);
}

function executable(root: string): string {
  const dirs = [root, ...(vscode.workspace.workspaceFolders ?? []).map((f) => f.uri.fsPath)];
  return resolveExecutable(setting<string>("executable", ""), dirs);
}

function run(root: string, args: string[]): Promise<RunResult> {
  const exe = executable(root);
  return new Promise((resolve, reject) => {
    execFile(
      exe,
      args,
      {
        cwd: root,
        env: { ...process.env, PYTHONIOENCODING: "utf-8", SEALBOX_LANG: engineLanguage() },
        windowsHide: true, // no console window; the engine's approval dialog still shows
        maxBuffer: 16 * 1024 * 1024,
      },
      (err, stdout, stderr) => {
        if (err && (err as NodeJS.ErrnoException).code === "ENOENT") {
          reject(new ExecutableMissing(exe));
          return;
        }
        const code = err ? (typeof err.code === "number" ? err.code : 1) : 0;
        resolve({ code, stdout, stderr });
      },
    );
  });
}

/** The engine's error message (the engine never prints secret values in errors). */
function errorText(res: RunResult): string {
  const line = res.stderr.trim().split(/\r?\n/).pop() ?? "";
  return line.replace(/^(Durduruldu|Stopped):\s*/, "").replace(/^\w+Error:\s*/, "") || t("exit code {0}", res.code);
}

async function handleError(err: unknown): Promise<void> {
  output.appendLine(`Error: ${err instanceof Error ? `${err.name}: ${err.message}` : String(err)}`);
  if (err instanceof Error && isKeyMissing(err.message)) {
    await keyMissing();
    return;
  }
  if (err instanceof ExecutableMissing) {
    await offerInstall(err.message);
    return;
  }
  void vscode.window.showErrorMessage(`SealBox: ${err instanceof Error ? err.message : String(err)}`);
}

function relPath(root: string, uri: vscode.Uri): string {
  return path.relative(root, uri.fsPath).split(path.sep).join("/");
}

function shouldCheck(doc: vscode.TextDocument): boolean {
  if (doc.uri.scheme !== "file" || !vscode.workspace.getWorkspaceFolder(doc.uri)) {
    return false;
  }
  const parts = doc.uri.fsPath.split(path.sep);
  return ![STATE_DIR, "node_modules", ".git"].some((p) => parts.includes(p));
}

// --- Engine installation and version ----------------------------------------------

function setupTerminal(command: string): void {
  const term = vscode.window.createTerminal({ name: t("SealBox setup") });
  term.show();
  term.sendText(command);
}

/** Offer to install the engine; only once per session unless the user asked for a check. */
async function offerInstall(exe: string, force = false): Promise<void> {
  if (installOffered && !force) {
    return;
  }
  installOffered = true;
  const pipx = t("Install with pipx");
  const pip = t("Install with pip");
  const locate = t("Set path…");
  const pick = await vscode.window.showErrorMessage(
    t("The SealBox engine was not found ({0}). SealBox needs its Python command-line tool (Python 3.12+).", exe),
    pipx,
    pip,
    locate,
  );
  if (pick === pipx) {
    setupTerminal("pipx install sealbox");
  } else if (pick === pip) {
    setupTerminal(process.platform === "win32" ? "py -m pip install --user sealbox" : "python3 -m pip install --user sealbox");
  } else if (pick === locate) {
    void vscode.commands.executeCommand("workbench.action.openSettings", "sealbox.executable");
    return;
  } else {
    return;
  }
  const retry = t("Check again");
  const again = await vscode.window.showInformationMessage(
    t('When the installation finishes, click "Check again". If SealBox is still not found, restart VS Code so it picks up the new PATH.'),
    retry,
  );
  if (again === retry) {
    await checkEngine(true);
  }
}

/** Verify the engine is installed and new enough; runs once per session unless forced. */
async function checkEngine(force = false): Promise<void> {
  if (engineChecked && !force) {
    return;
  }
  const root = rootFor();
  if (!root) {
    return;
  }
  engineChecked = true;
  let res: RunResult;
  try {
    res = await run(root, ["--version"]);
  } catch (err) {
    if (err instanceof ExecutableMissing) {
      await offerInstall(err.message, force);
    }
    return;
  }
  const version = parseEngineVersion(res.stdout + res.stderr);
  output.appendLine(`Engine: ${executable(root)} (${version ? version.join(".") : "unknown version"})`);
  if (version && isOlder(version, MIN_ENGINE_VERSION)) {
    const upgrade = t("Upgrade");
    const pick = await vscode.window.showWarningMessage(
      t("The SealBox engine is out of date ({0}); this extension needs {1} or newer.", version.join("."), MIN_ENGINE_VERSION),
      upgrade,
    );
    if (pick === upgrade) {
      setupTerminal("pipx upgrade sealbox");
    }
  } else if (force && version) {
    void vscode.window.showInformationMessage(t("SealBox engine {0} is ready.", version.join(".")));
  }
}

// --- Exposed secret warnings -----------------------------------------------------

/** Warning counts: fixable by "Move to vault", and those that must be moved by hand. */
interface Counts {
  fixable: number;
  manual: number;
}

const MANUAL = "manual"; // Diagnostic.code: "Move to vault" cannot fix this one

function applyReport(root: string, report: SealReport, checked: vscode.Uri[]): Counts {
  for (const uri of checked) {
    diagnostics.delete(uri);
  }
  const counts: Counts = { fixable: 0, manual: 0 };
  for (const [rel, problems] of problemsFromReport(report)) {
    const uri = vscode.Uri.file(path.join(root, rel));
    const list = problems.map((p) => {
      const d = new vscode.Diagnostic(
        new vscode.Range(p.line, p.col, p.endLine, p.endCol),
        p.message,
        p.severity === "warning" ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Information,
      );
      d.source = SOURCE;
      if (p.manual) {
        d.code = MANUAL;
        counts.manual++;
      } else if (p.severity === "warning") {
        counts.fixable++;
      }
      return d;
    });
    diagnostics.set(uri, list);
  }
  return counts;
}

async function manualHelp(): Promise<void> {
  await vscode.window.showWarningMessage(t("This secret must be moved by hand"), { modal: true, detail: manualHelpText() });
}

const pending = new Map<string, NodeJS.Timeout>();

function scheduleCheck(doc: vscode.TextDocument): void {
  if (!setting<boolean>("checkOnSave", true) || !shouldCheck(doc)) {
    return;
  }
  const key = doc.uri.toString();
  clearTimeout(pending.get(key));
  pending.set(
    key,
    setTimeout(() => {
      pending.delete(key);
      void checkFile(doc.uri).catch(handleError);
    }, 300),
  );
}

async function checkFile(uri: vscode.Uri): Promise<void> {
  const root = rootFor(uri);
  if (!root || !isInside(uri.fsPath, root)) {
    return;
  }
  output.appendLine(`Check: ${relPath(root, uri)} (root: ${root}, engine: ${executable(root)})`);
  const res = await run(root, ["seal", "--check", "--json", "-w", root, relPath(root, uri)]);
  if (res.code > 1) {
    output.appendLine(`Check failed (${relPath(root, uri)}): ${errorText(res)}`);
    return;
  }
  const counts = applyReport(root, parseReport(res.stdout), [uri]);
  output.appendLine(`  -> ${counts.fixable} exposed, ${counts.manual} to move by hand`);
  notifyIfNew(uri, counts);
}

// Squiggles are easy to miss, so notify when a file gains new secrets (the count goes up),
// but do not nag on every save while the count stays the same.
const lastCount = new Map<string, number>();

function notifyIfNew(uri: vscode.Uri, counts: Counts): void {
  const key = uri.toString();
  const count = counts.fixable + counts.manual;
  const before = lastCount.get(key) ?? 0;
  lastCount.set(key, count);
  if (count <= before) {
    return;
  }
  // If every secret must be moved by hand, "Move to vault" would do nothing; offer help instead.
  const moveLabel = t("Move to vault");
  const helpLabel = t("How do I fix this?");
  const showLabel = t("Show");
  const action = counts.fixable ? moveLabel : helpLabel;
  const manualNote = counts.manual ? t(" {0} of them cannot be moved automatically and must be fixed by hand.", counts.manual) : "";
  void vscode.window
    .showWarningMessage(
      t("🔓 {0}: {1} exposed secret(s). AI coding agents that read this file can see them.", path.basename(uri.fsPath), count) +
        manualNote,
      action,
      showLabel,
    )
    .then(async (pick) => {
      if (pick === moveLabel) {
        await safe(sealFile)(uri);
      } else if (pick === helpLabel) {
        await manualHelp();
      } else if (pick === showLabel) {
        await vscode.commands.executeCommand("workbench.actions.view.problems");
      }
    });
}

async function checkProject(): Promise<void> {
  const root = rootFor();
  if (!root) {
    void vscode.window.showWarningMessage(t("Open a folder first."));
    return;
  }
  // Only the scan runs inside the progress notification. If the result message were awaited
  // there too, the spinner would keep turning until the user clicked it.
  const res = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: t("Looking for exposed secrets…") },
    () => run(root, ["seal", "--check", "--json", "-w", root]),
  );
  if (res.code > 1) {
    throw new Error(errorText(res));
  }
  diagnostics.clear();
  const { fixable, manual } = applyReport(root, parseReport(res.stdout), []);
  if (fixable + manual === 0) {
    void vscode.window.showInformationMessage(t("All clear: no exposed secrets on disk. 🔒"));
    return;
  }
  const moveAll = t("Move all to vault");
  const helpLabel = t("How do I fix this?");
  const manualNote = manual ? t(" {0} of them cannot be moved automatically and must be fixed by hand.", manual) : "";
  const pick = await vscode.window.showWarningMessage(
    t("Found {0} exposed secret(s).", fixable + manual) + manualNote + t(" Details are in the Problems panel."),
    ...(fixable ? [moveAll] : []),
    ...(manual ? [helpLabel] : []),
  );
  if (pick === moveAll) {
    await sealProject(true);
  } else if (pick === helpLabel) {
    await manualHelp();
  }
}

// --- Sealing ---------------------------------------------------------------------

function sealSummary(report: SealReport): string {
  const moved = [...new Set(report.files.flatMap((f) => f.moved))];
  const masked = report.files.reduce((n, f) => n + f.masked, 0);
  const parts: string[] = [];
  if (moved.length) {
    parts.push(t("{0} value(s) moved to the vault ({1})", moved.length, moved.join(", ")));
  }
  if (masked) {
    parts.push(t("{0} value(s) redacted", masked));
  }
  return parts.join(", ") || t("nothing to move");
}

/** Rewriting a file on disk while it has unsaved edits would lose one of the two versions. */
async function saveDirty(root: string): Promise<void> {
  for (const doc of vscode.workspace.textDocuments) {
    if (doc.isDirty && doc.uri.scheme === "file" && isInside(doc.uri.fsPath, root)) {
      await doc.save();
    }
  }
}

async function seal(root: string, targets: string[]): Promise<void> {
  await saveDirty(root);
  const res = await run(root, ["seal", "--json", "-w", root, ...targets]);
  if (res.code > 1) {
    throw new Error(errorText(res));
  }
  const report = parseReport(res.stdout);
  const checked = report.files.map((f) => vscode.Uri.file(path.join(root, f.path)));
  applyReport(root, { ...report, files: report.files.filter((f) => f.issues.some((i) => i.blocking)) }, checked);
  const left = report.files.flatMap((f) => f.issues.filter((i) => i.blocking));
  const msg = `SealBox: ${sealSummary(report)}.`;
  if (left.length) {
    const helpLabel = t("How do I fix this?");
    const showLabel = t("Show");
    void vscode.window
      .showWarningMessage(
        msg +
          " " +
          t("⚠ {0} secret(s) are still EXPOSED in the file: they could not be moved automatically and must be fixed by hand.", left.length),
        helpLabel,
        showLabel,
      )
      .then(async (pick) => {
        if (pick === helpLabel) {
          await manualHelp();
        } else if (pick === showLabel) {
          await vscode.commands.executeCommand("workbench.actions.view.problems");
        }
      });
  } else {
    void vscode.window.showInformationMessage(
      report.written.length ? msg + " " + t('From now on, start the program with "Run with Vault".') : msg,
    );
  }
  refreshStatus();
  if (!hookState.has(root)) {
    void refreshHook(root); // the first seal may have just created the vault
  }
}

async function sealFile(uri?: vscode.Uri): Promise<void> {
  const target = uri ?? vscode.window.activeTextEditor?.document.uri;
  const root = target && rootFor(target);
  if (!target || !root) {
    return;
  }
  await seal(root, [relPath(root, target)]);
}

async function sealProject(confirmed = false): Promise<void> {
  const root = rootFor();
  if (!root) {
    return;
  }
  if (!confirmed) {
    const move = t("Move to vault");
    const ok = await vscode.window.showWarningMessage(
      t("Every secret in the project will be taken out of its file and moved to the vault:\n{0}", root),
      { modal: true },
      move,
    );
    if (!ok) {
      return;
    }
  }
  await seal(root, []);
}

// --- Revealing a value -------------------------------------------------------------

async function reveal(arg?: { name?: string; root?: string }): Promise<void> {
  const root = arg?.root ?? rootFor();
  if (!root) {
    return;
  }
  let name = arg?.name;
  if (!name) {
    name = await pickVaultEntry(root);
    if (!name) {
      return;
    }
  }
  // The engine opens the approval dialog; if the user denies, the value never arrives.
  const res = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: t("Approval dialog is open, waiting…") },
    () => run(root, ["vault", "reveal", name!, "-w", root]),
  );
  if (res.code !== 0) {
    void vscode.window.showWarningMessage(t("Not shown: {0}", errorText(res)));
    return;
  }
  let value = res.stdout.replace(/\r?\n$/, "");
  const label = name.startsWith("__SECURE_") ? t("Value") : name;
  const copy = t("Copy");
  const pick = await vscode.window.showInformationMessage(`${label}: ${value}`, { modal: true }, copy);
  if (pick === copy) {
    await vscode.env.clipboard.writeText(value);
    const copied = value;
    setTimeout(async () => {
      if ((await vscode.env.clipboard.readText()) === copied) {
        await vscode.env.clipboard.writeText("");
      }
    }, CLIPBOARD_CLEAR_MS);
    void vscode.window.showInformationMessage(t("Copied; the clipboard will be cleared in 30 seconds."));
  }
  value = "";
}

async function pickVaultEntry(root: string): Promise<string | undefined> {
  const index = readVaultIndex(root);
  if (!index) {
    void vscode.window.showInformationMessage(t("This project has no vault yet. Move its secrets to the vault first."));
    return undefined;
  }
  const items: vscode.QuickPickItem[] = [
    ...Object.entries(index.names).map(([n, c]) => ({ label: n, description: c })),
    ...Object.entries(index.masked).map(([ph, c]) => ({ label: ph, description: t("{0} (redacted)", c) })),
  ];
  const pick = await vscode.window.showQuickPick(items, { placeHolder: t("Which value should be shown? (approval required)") });
  return pick?.label;
}

// --- Exposing redacted data at run time / cleaning the vault ----------------------------

async function expose(arg?: { name?: string; root?: string }): Promise<void> {
  const root = arg?.root ?? rootFor();
  const index = root ? readVaultIndex(root) : undefined;
  if (!root || !index) {
    return;
  }
  let ph = arg?.name;
  if (!ph) {
    const items = Object.entries(index.masked).map(([p, c]) => ({ label: p, description: c }));
    if (!items.length) {
      void vscode.window.showInformationMessage(t("There is no redacted data."));
      return;
    }
    ph = (await vscode.window.showQuickPick(items, { placeHolder: t("Which data does the program use?") }))?.label;
    if (!ph) {
      return;
    }
  }
  const give = t("Pass at run time");
  const ok = await vscode.window.showWarningMessage(
    t("This data ({0}) will be passed to the program at run time.", index.masked[ph] ?? t("data")),
    {
      modal: true,
      detail: t(
        'The placeholder in the file is turned into an environment variable read. The value still never sits in the file; it is only passed to the program after a "Run with Vault" approval.',
      ),
    },
    give,
  );
  if (!ok) {
    return;
  }
  await saveDirty(root);
  const res = await run(root, ["vault", "expose", ph, "-w", root]);
  if (res.code !== 0) {
    throw new Error(errorText(res));
  }
  void vscode.window.showInformationMessage(`SealBox: ${res.stdout.trim().split(/\r?\n/)[0]}`);
  refreshStatus();
}

async function prune(): Promise<void> {
  const root = rootFor();
  if (!root || !readVaultIndex(root)) {
    void vscode.window.showInformationMessage(t("This project has no vault yet."));
    return;
  }
  // The engine's approval dialog lists the records that would be deleted.
  const res = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: t("Looking for unused records…") },
    () => run(root, ["vault", "remove", "--unused", "-w", root]),
  );
  if (res.code !== 0) {
    void vscode.window.showWarningMessage(t("Nothing deleted: {0}", errorText(res)));
    return;
  }
  const removed = res.stdout.split(/\r?\n/).filter((l) => /^(Silindi|Deleted): /.test(l)).length;
  void vscode.window.showInformationMessage(
    removed ? t("Deleted {0} unused record(s) from the vault.", removed) : t("The vault has no unused records."),
  );
  refreshStatus();
}

// --- Team and recovery ----------------------------------------------------------------
// Recovery codes, shares and SSH passphrases are shown or asked for in the engine's own
// dialogs; they never pass through the extension or the terminal.

const GITHUB_USER_RE = /^@?[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;

/** Run an engine command that opens dialogs, and surface the engine's warnings. */
async function cli(root: string, args: string[], title: string): Promise<string> {
  const res = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title },
    () => run(root, [...args, "-w", root]),
  );
  refreshStatus();
  output.appendLine(`> sealbox ${args.join(" ")}`);
  output.append(res.stdout);
  if (res.code !== 0) {
    throw new Error(errorText(res));
  }
  for (const line of res.stderr.split(/\r?\n/).filter((l) => /^(Uyarı|Warning):/.test(l))) {
    void vscode.window.showWarningMessage(`SealBox: ${line.replace(/^(Uyarı|Warning):\s*/, "")}`);
  }
  return res.stdout.trim();
}

function firstLine(text: string): string {
  return text.split(/\r?\n/)[0] ?? "";
}

async function askGithubUser(prompt: string): Promise<string | undefined> {
  const user = await vscode.window.showInputBox({
    prompt,
    placeHolder: t("@username"),
    ignoreFocusOut: true,
    validateInput: (v) => (GITHUB_USER_RE.test(v.trim()) ? undefined : t("Enter a valid GitHub username")),
  });
  return user?.trim().replace(/^@/, "");
}

function roleLabel(role: "owner" | "member"): string {
  return role === "owner" ? t("owner") : t("member");
}

async function pickMember(root: string, placeHolder: string, filter: "all" | "member" = "all"): Promise<string | undefined> {
  const members = readTeam(root).filter((m) => filter === "all" || m.role === "member");
  if (!members.length) {
    void vscode.window.showInformationMessage(t("There are no team members to choose from."));
    return undefined;
  }
  const pick = await vscode.window.showQuickPick(
    members.map((m) => ({ label: `@${m.user}`, description: roleLabel(m.role), user: m.user })),
    { placeHolder },
  );
  return pick?.user;
}

async function teamInit(root: string): Promise<void> {
  const me = await askGithubUser(t("Your GitHub username (this computer's SSH key must be on that account)"));
  if (!me) {
    return;
  }
  const out = await cli(root, ["team", "init", "--github", me], t("Setting up the team… (SSH passphrase and approval dialogs will open)"));
  void vscode.window.showInformationMessage(`SealBox: ${firstLine(out)} ` + t('Add teammates with "Add teammate".'));
}

async function teamAdd(arg?: { root?: string }): Promise<void> {
  const root = arg?.root ?? rootFor();
  if (!root) {
    return;
  }
  if (!readTeam(root).length) {
    await teamInit(root);
    return;
  }
  const user = await askGithubUser(t("GitHub user to give vault access to"));
  if (!user) {
    return;
  }
  const role = await vscode.window.showQuickPick(
    [
      { label: t("Member"), description: t("uses the vault (showing values and running still need approval)"), owner: false },
      { label: t("Owner"), description: t("can also add and remove people"), owner: true },
    ],
    { placeHolder: t("Which role should @{0} get?", user) },
  );
  if (!role) {
    return;
  }
  const out = await cli(
    root,
    ["team", "add", user, ...(role.owner ? ["--owner"] : [])],
    t("Fetching @{0}'s GitHub keys… (an approval dialog will open)", user),
  );
  void vscode.window.showInformationMessage(`SealBox: ${out.split(/\r?\n/).join(" ")}`);
}

async function teamRemove(root: string): Promise<void> {
  const user = await pickMember(root, t("Who should be removed from the team?"));
  if (!user) {
    return;
  }
  const remove = t("Remove");
  const ok = await vscode.window.showWarningMessage(
    t("Remove @{0} from the team?", user),
    {
      modal: true,
      detail: t(
        "The vault key will be rotated, so @{0} cannot open the new vault. They may still remember values they have seen: if possible, rotate those passwords and keys at their providers.",
        user,
      ),
    },
    remove,
  );
  if (!ok) {
    return;
  }
  await cli(root, ["team", "remove", user], t("Removing @{0} and rotating the vault key…", user));
  output.show(true);
  void vscode.window.showInformationMessage(
    t("SealBox: @{0} was removed. Commit and push. The values worth rotating are listed in the Output panel.", user),
  );
}

async function teamPromote(root: string): Promise<void> {
  const user = await pickMember(root, t("Who should become an owner?"), "member");
  if (user) {
    const out = await cli(root, ["team", "promote", user], t("Making @{0} an owner…", user));
    void vscode.window.showInformationMessage(`SealBox: ${firstLine(out)}`);
  }
}

async function recoverySetup(arg?: { root?: string; renew?: boolean }): Promise<void> {
  const root = arg?.root ?? rootFor();
  if (!root) {
    return;
  }
  const showCode = t("Show the code");
  const ok = await vscode.window.showInformationMessage(
    arg?.renew ? t("Create a new recovery code?") : t("Create a recovery code?"),
    {
      modal: true,
      detail:
        t(
          "If your vault key is ever lost (Windows reset, new computer), this code reopens your vaults. It is shown once, in a separate window: write it down or save it in your password manager. The code is stored neither on this computer nor by us.",
        ) + (arg?.renew ? " " + t("The old code stops working as the vaults on this computer are opened.") : ""),
    },
    showCode,
  );
  if (!ok) {
    return;
  }
  const out = await cli(root, ["recovery", "setup", ...(arg?.renew ? ["--new"] : [])], t("Recovery code window is open…"));
  const more = await vscode.window.showInformationMessage(`SealBox: ${firstLine(out)}`, t("Also split it into 3 shares (any 2 work)"));
  if (more) {
    await recoveryShares(root);
  }
}

async function recoveryShares(root: string): Promise<void> {
  const out = await cli(root, ["recovery", "shares"], t("Recovery shares window is open…"));
  void vscode.window.showInformationMessage(`SealBox: ${firstLine(out)}`);
}

async function recoveryRestore(arg?: { root?: string; kit?: boolean }): Promise<void> {
  const root = arg?.root ?? rootFor();
  if (!root) {
    return;
  }
  const args = ["recovery", "restore"];
  if (arg?.kit) {
    const kitLabel = t("Recovery kit");
    const picked = await vscode.window.showOpenDialog({
      title: kitLabel,
      filters: { [kitLabel]: ["sealkit", "json"] },
      canSelectMany: false,
    });
    if (!picked?.length) {
      return;
    }
    args.push("--kit", picked[0].fsPath);
  }
  const out = await cli(root, args, t("Recovery window is open… (enter the code or 2 shares there)"));
  void vscode.window.showInformationMessage(`SealBox: ${firstLine(out)}`);
}

async function recoveryExport(root: string): Promise<void> {
  const kitLabel = t("Recovery kit");
  const dest = await vscode.window.showSaveDialog({
    title: t("Where should the recovery kit be saved? (USB stick or cloud folder)"),
    defaultUri: vscode.Uri.file(path.join(os.homedir(), `${path.basename(root)}.sealkit`)),
    filters: { [kitLabel]: ["sealkit"] },
  });
  if (dest) {
    const out = await cli(root, ["recovery", "export", dest.fsPath], t("Writing the recovery kit…"));
    void vscode.window.showInformationMessage(`SealBox: ${out.split(/\r?\n/).join(" ")}`);
  }
}

async function vaultReset(root: string): Promise<void> {
  const reset = t("Reset");
  const ok = await vscode.window.showWarningMessage(
    t("Reset the vault?"),
    {
      modal: true,
      detail: t(
        "Only use this if the key is completely lost (no recovery code, kit or team access). The old vault is not deleted; it is moved to {0}/lost-<date>. A new empty vault is created, and the values that were lost are listed in the Output panel so you can enter them again.",
        path.basename(stateDir(root)),
      ),
    },
    reset,
  );
  if (!ok) {
    return;
  }
  await cli(root, ["vault", "reset"], t("Resetting the vault… (an approval dialog will open)"));
  output.show(true);
  void vscode.window.showInformationMessage(t("SealBox: a new vault was created. The lost values are listed in the Output panel."));
}

async function keyMissing(): Promise<void> {
  const root = rootFor();
  if (!root) {
    return;
  }
  const inTeam = readTeam(root).length > 0;
  const hasCopy = recoveryState(root, os.homedir()) === "protected";
  const enterCode = t("Enter recovery code");
  const fromKit = t("Load from recovery kit");
  const reset = t("Reset vault");
  const pick = await vscode.window.showErrorMessage(
    t("SealBox: this project's vault key is not on this computer."),
    {
      modal: true,
      detail:
        (hasCopy
          ? t("This computer has a recovery copy for this project: reopen it with your recovery code or 2 shares.")
          : t("If you have your recovery code and recovery kit, you can reopen the vault.")) +
        (inTeam
          ? " " + t('If you are on the team: add this computer\'s SSH key to your GitHub account and ask an owner to add you with "Add teammate".')
          : "") +
        " " +
        t("If you have none of these, reset the vault and enter the values again."),
    },
    ...(hasCopy ? [enterCode] : []),
    fromKit,
    reset,
  );
  if (pick === enterCode) {
    await recoveryRestore({ root });
  } else if (pick === fromKit) {
    await recoveryRestore({ root, kit: true });
  } else if (pick === reset) {
    await vaultReset(root);
  }
}

// --- Plain run warning --------------------------------------------------------------
// Running `python x.py` with the ▶ button passes no vault values, so it fails with a
// KeyError. Only the variable name is searched for in the terminal output; nothing is kept.

async function watchPlainRun(e: vscode.TerminalShellExecutionStartEvent): Promise<void> {
  if (e.terminal.name === TERMINAL_NAME) {
    return;
  }
  const cwd = e.execution.cwd?.fsPath;
  const root = cwd ? rootFor(vscode.Uri.file(path.join(cwd, "x"))) : rootFor();
  const index = root ? readVaultIndex(root) : undefined;
  if (!root || !index || !Object.keys(index.names).length) {
    return;
  }
  let text = "";
  for await (const chunk of e.execution.read()) {
    text = (text + chunk).slice(-64 * 1024);
  }
  const name = missingVaultVar(text.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, ""), index.names);
  if (!name) {
    return;
  }
  const command = e.execution.commandLine.value.trim().replace(/^&\s+/, "");
  const runWith = t("Run with Vault");
  const pick = await vscode.window.showWarningMessage(
    t("The program expects {0} from the vault, but it was run without it.", name),
    { detail: t('Vault values are only passed through "Run with Vault" (after your approval).') },
    runWith,
  );
  if (pick) {
    await execProgram(command);
  }
}

// --- Running the program ---------------------------------------------------------

async function execProgram(prefill?: string): Promise<void> {
  const root = rootFor();
  if (!root) {
    return;
  }
  const cmd = await vscode.window.showInputBox({
    prompt: t("Command to run with the vault's secrets (approval is asked on every run)"),
    value: prefill || lastCommand || defaultCommand(),
    ignoreFocusOut: true,
  });
  if (!cmd?.trim()) {
    return;
  }
  let args: string[];
  try {
    args = splitArgs(cmd);
  } catch (e) {
    void vscode.window.showErrorMessage(t("Could not parse the command: {0}", (e as Error).message));
    return;
  }
  lastCommand = cmd;
  // The engine starts the command directly, without a shell: no quoting surprises and no
  // way to inject a second command.
  const term = vscode.window.createTerminal({
    name: TERMINAL_NAME,
    cwd: root,
    env: { SEALBOX_LANG: engineLanguage() },
    shellPath: executable(root),
    shellArgs: ["exec", "-w", root, "--", ...args],
  });
  term.show();
}

function defaultCommand(): string {
  const doc = vscode.window.activeTextEditor?.document;
  if (!doc) {
    return "";
  }
  const file = path.basename(doc.fileName);
  if (doc.languageId === "python") {
    return `python ${file}`;
  }
  if (["javascript", "typescript"].includes(doc.languageId)) {
    return `node ${file}`;
  }
  if (doc.languageId === "java") {
    return `java ${file}`; // Java 11+ runs a single source file without compiling
  }
  return "";
}

// --- Hover ---------------------------------------------------------------------------

const hovers: vscode.HoverProvider = {
  provideHover(doc, pos) {
    const root = rootFor(doc.uri);
    const index = root && readVaultIndex(root);
    if (!root || !index) {
      return undefined;
    }
    const line = doc.lineAt(pos.line).text;
    const ph = placeholderAt(line, pos.character);
    const ref = ph ? undefined : envRefAt(line, pos.character);
    const hit = ph ?? ref;
    if (!hit) {
      return undefined;
    }
    const category = ph ? ph.category : index.names[hit.text];
    if (ref && !category) {
      return undefined; // an ordinary environment variable, not one from the vault
    }
    const args = encodeURIComponent(JSON.stringify([{ name: hit.text, root }]));
    const md = new vscode.MarkdownString(
      ph
        ? t("🔒 **Stored in the vault** ({0})\n\nThe real value is not in this file; it is in the encrypted vault.", category ?? "")
        : t('🔒 **{0}** comes from the vault ({1})\n\nIt is passed when you start the program with "Run with Vault".', hit.text, category ?? ""),
    );
    md.appendMarkdown(`\n\n[${t("Show value")}](command:sealbox.reveal?${args}) _${t("(approval required)")}_`);
    if (ph && index.masked[ph.text]) {
      md.appendMarkdown(` · [${t("The program uses this: pass it at run time")}](command:sealbox.expose?${args})`);
    }
    md.isTrusted = { enabledCommands: ["sealbox.reveal", "sealbox.expose"] };
    return new vscode.Hover(md, new vscode.Range(pos.line, hit.start, pos.line, hit.end));
  },
};

// --- Quick fixes ---------------------------------------------------------------------

const quickFix: vscode.CodeActionProvider = {
  provideCodeActions(doc, range, ctx) {
    const root = rootFor(doc.uri);
    const ph = placeholderAt(doc.lineAt(range.start.line).text, range.start.character);
    if (root && ph && readVaultIndex(root)?.masked[ph.text]) {
      const action = new vscode.CodeAction(t("▶ The program uses this data: pass it at run time"), vscode.CodeActionKind.QuickFix);
      action.command = { command: "sealbox.expose", title: action.title, arguments: [{ name: ph.text, root }] };
      return [action];
    }
    const ours = ctx.diagnostics.filter((d) => d.source === SOURCE);
    const manual = ours.filter((d) => d.code === MANUAL);
    const fixable = ours.filter((d) => d.code !== MANUAL);
    const actions: vscode.CodeAction[] = [];
    if (fixable.length) {
      const action = new vscode.CodeAction(t("🔒 Move this file's secrets to the vault"), vscode.CodeActionKind.QuickFix);
      action.command = { command: "sealbox.sealFile", title: action.title, arguments: [doc.uri] };
      action.diagnostics = fixable;
      action.isPreferred = true;
      actions.push(action);
    }
    if (manual.length) {
      const action = new vscode.CodeAction(t("❓ This secret must be moved by hand: how do I fix it?"), vscode.CodeActionKind.QuickFix);
      action.command = { command: "sealbox.manualHelp", title: action.title };
      action.diagnostics = manual;
      actions.push(action);
    }
    return actions;
  },
};

// --- Git history and commit hook -------------------------------------------------------

/** Project root -> hook state. The status bar refreshes on every editor change, so the
 *  engine is only asked at startup and after installing, never on each refresh. */
const hookState = new Map<string, { git: boolean; installed: boolean }>();

async function refreshHook(root: string | undefined): Promise<void> {
  if (!root || !readVaultIndex(root)) {
    return;
  }
  try {
    const res = await run(root, ["hook", "status", "--json", "-w", root]);
    if (res.code === 0) {
      hookState.set(root, JSON.parse(res.stdout) as { git: boolean; installed: boolean });
      refreshStatus();
    }
  } catch {
    // a missing engine is reported by checkEngine and by the other commands
  }
}

async function gitHistory(arg?: { root?: string }): Promise<void> {
  const root = arg?.root ?? rootFor();
  if (!root) {
    return;
  }
  const res = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: t("Scanning git history…") },
    () => run(root, ["history", "--json", "-w", root]),
  );
  if (res.code > 1) {
    throw new Error(errorText(res));
  }
  const report = parseHistory(res.stdout);
  if (!report.git) {
    void vscode.window.showInformationMessage(t("This project is not a git repository; there is no history to scan."));
    return;
  }
  if (!report.hits.length) {
    void vscode.window.showInformationMessage(t("All clear: none of the vault values appear in git history. 🔒"));
    return;
  }
  const lines = historyLines(report.hits);
  output.appendLine("Git history:");
  lines.forEach((l) => output.appendLine(`  ${l}`));
  const pushed = report.hits.filter((h) => h.pushed).length;
  const labels = report.hits.map((h) => h.label).join(", ");
  const what = t("What should I do?");
  const pick = await vscode.window.showWarningMessage(
    t("⚠ {0} secret(s) exposed in git history", report.hits.length) +
      (pushed ? t(" ({0} pushed to a remote)", pushed) : "") +
      `: ${labels}. ` +
      t("Cleaning the file does not erase history."),
    what,
  );
  if (pick) {
    await vscode.window.showWarningMessage(t("Secrets exposed in git history"), {
      modal: true,
      detail: [
        ...lines,
        "",
        t(
          "Anyone who reads the old commits can see these values. A pushed secret may already be in someone else's hands: rewriting history is not enough, rotate the secret at its provider (Stripe, the AWS console…).",
        ),
      ].join("\n"),
    });
  }
}

async function hookInstall(arg?: { root?: string }): Promise<void> {
  const root = arg?.root ?? rootFor();
  if (!root) {
    return;
  }
  await cli(root, ["hook", "install"], t("Installing the commit hook…"));
  void vscode.window.showInformationMessage(t("Commit hook installed: a commit that contains a vault value will be stopped."));
  await refreshHook(root);
}

// --- Status bar -------------------------------------------------------------------------

function refreshStatus(): void {
  const root = rootFor();
  const index = root ? readVaultIndex(root) : undefined;
  if (!root) {
    status.hide();
    return;
  }
  if (!index) {
    status.text = "$(unlock) " + t("No vault");
    status.tooltip = t("SealBox: this project has no vault yet. Click for the menu.");
  } else {
    const names = Object.keys(index.names).length;
    const masked = Object.keys(index.masked).length;
    const team = readTeam(root).length;
    const backedUp = recoveryState(root, os.homedir()) === "protected";
    const hook = hookState.get(root);
    const noHook = hook?.git === true && !hook.installed;
    status.text =
      "$(lock) " +
      t("{0} in vault", names) +
      (masked ? " · " + t("{0} redacted", masked) : "") +
      (team ? " · $(organization) " + t("{0} people", team) : "") +
      (backedUp ? "" : " · $(warning) " + t("no backup")) +
      (noHook ? " · $(git-commit) " + t("no hook") : "");
    const tips = [
      backedUp ? "" : t("The vault key has no backup: if the key is lost, the vault cannot be opened. Create a recovery code from the menu."),
      noHook ? t("No commit hook: a vault value could be committed by accident. Install it from the menu.") : "",
    ].filter(Boolean);
    status.tooltip = tips.length ? tips.join("\n") : t("SealBox menu");
  }
  status.show();
}

async function menu(): Promise<void> {
  const root = rootFor();
  if (!root) {
    return;
  }
  const actions: (vscode.QuickPickItem & { run?: () => Promise<void> })[] = [
    { label: "$(play) " + t("Run program with the vault…"), run: () => execProgram() },
    { label: "$(search) " + t("Scan project (any exposed secrets?)"), run: checkProject },
    { label: "$(lock) " + t("Move all project secrets to the vault"), run: () => sealProject() },
  ];
  const index = readVaultIndex(root);
  if (index) {
    actions.push({ label: t("In the vault (select to show; approval required)"), kind: vscode.QuickPickItemKind.Separator });
    for (const [n, c] of Object.entries(index.names)) {
      actions.push({ label: n, description: c, run: () => reveal({ name: n, root }) });
    }
    for (const [ph, c] of Object.entries(index.masked)) {
      actions.push({ label: ph, description: t("{0} (redacted)", c), run: () => reveal({ name: ph, root }) });
    }
    actions.push({ label: t("Vault maintenance"), kind: vscode.QuickPickItemKind.Separator });
    if (Object.keys(index.masked).length) {
      actions.push({ label: "$(debug-start) " + t("Pass redacted data to the program at run time…"), run: () => expose({ root }) });
    }
    actions.push({ label: "$(trash) " + t("Delete unused records from the vault"), run: prune });

    const hook = hookState.get(root);
    if (hook?.git !== false) {
      actions.push({ label: "Git", kind: vscode.QuickPickItemKind.Separator });
      actions.push({ label: "$(git-commit) " + t("Any exposed secrets in git history?"), run: () => gitHistory({ root }) });
      if (!hook?.installed) {
        actions.push({
          label: "$(shield) " + t("Install the commit hook (recommended)"),
          description: t("keeps vault values out of commits"),
          run: () => hookInstall({ root }),
        });
      }
    }

    const team = readTeam(root);
    actions.push({
      label: team.length
        ? t("Team: {0}", team.map((m) => `@${m.user}${m.role === "owner" ? ` (${t("owner")})` : ""}`).join(", "))
        : t("Team"),
      kind: vscode.QuickPickItemKind.Separator,
    });
    if (!team.length) {
      actions.push({ label: "$(organization) " + t("Set up a team (share the vault via GitHub accounts)…"), run: () => teamInit(root) });
    } else {
      actions.push({ label: "$(person-add) " + t("Add teammate (@GitHub user)…"), run: () => teamAdd({ root }) });
      actions.push({ label: "$(person) " + t("Remove from team (rotates the vault key)…"), run: () => teamRemove(root) });
      actions.push({ label: "$(star) " + t("Make owner…"), run: () => teamPromote(root) });
    }

    const rec = recoveryState(root, os.homedir());
    actions.push({ label: t("Recovery"), kind: vscode.QuickPickItemKind.Separator });
    if (rec === "none") {
      actions.push({ label: "$(key) " + t("Create a recovery code (recommended)"), run: () => recoverySetup({ root }) });
    } else {
      actions.push({ label: "$(split-horizontal) " + t("Split the recovery code into 3 shares (any 2 work)"), run: () => recoveryShares(root) });
      actions.push({ label: "$(export) " + t("Export a recovery kit (USB/cloud)…"), run: () => recoveryExport(root) });
      actions.push({ label: "$(key) " + t("Renew the recovery code…"), run: () => recoverySetup({ root, renew: true }) });
    }
    actions.push({ label: "$(history) " + t("Reopen the vault with a recovery code…"), run: () => recoveryRestore({ root }) });
    actions.push({ label: "$(debug-restart) " + t("Reset the vault (only if the key is completely lost)…"), run: () => vaultReset(root) });
  } else {
    actions.push({ label: t("Recovery"), kind: vscode.QuickPickItemKind.Separator });
    actions.push({ label: "$(history) " + t("Restore the vault from a recovery kit…"), run: () => recoveryRestore({ root, kit: true }) });
  }
  const pick = await vscode.window.showQuickPick(actions, { placeHolder: `SealBox — ${root}` });
  await pick?.run?.();
}

// --- Activation ----------------------------------------------------------------------

function safe<A extends unknown[]>(fn: (...args: A) => Promise<void>): (...args: A) => Promise<void> {
  return async (...args: A) => {
    try {
      await fn(...args);
    } catch (e) {
      await handleError(e);
    }
  };
}

export function activate(context: vscode.ExtensionContext): void {
  setTranslator(vscode.l10n.t);
  diagnostics = vscode.languages.createDiagnosticCollection(SOURCE);
  output = vscode.window.createOutputChannel("SealBox");
  status = vscode.window.createStatusBarItem("sealbox.status", vscode.StatusBarAlignment.Left, 50);
  status.name = "SealBox";
  status.command = "sealbox.menu";
  lastCommand = context.workspaceState.get<string>("lastCommand", "");

  const watcher = vscode.workspace.createFileSystemWatcher(`**/${STATE_DIR}/{project.vault,project.names,project.masked,team.json}`);
  watcher.onDidChange(refreshStatus);
  watcher.onDidCreate(refreshStatus);
  watcher.onDidDelete(refreshStatus);

  context.subscriptions.push(
    diagnostics,
    output,
    status,
    watcher,
    vscode.commands.registerCommand("sealbox.menu", safe(menu)),
    vscode.commands.registerCommand("sealbox.checkProject", safe(checkProject)),
    vscode.commands.registerCommand("sealbox.sealFile", safe(sealFile)),
    vscode.commands.registerCommand("sealbox.sealProject", safe(() => sealProject())),
    vscode.commands.registerCommand(
      "sealbox.exec",
      safe(async () => {
        await execProgram();
        await context.workspaceState.update("lastCommand", lastCommand);
      }),
    ),
    vscode.commands.registerCommand("sealbox.reveal", safe(reveal)),
    vscode.commands.registerCommand("sealbox.expose", safe(expose)),
    vscode.commands.registerCommand("sealbox.prune", safe(prune)),
    vscode.commands.registerCommand("sealbox.teamAdd", safe(teamAdd)),
    vscode.commands.registerCommand("sealbox.recoverySetup", safe(recoverySetup)),
    vscode.commands.registerCommand("sealbox.recoveryRestore", safe(recoveryRestore)),
    vscode.commands.registerCommand("sealbox.manualHelp", safe(manualHelp)),
    vscode.commands.registerCommand("sealbox.history", safe(gitHistory)),
    vscode.commands.registerCommand("sealbox.hookInstall", safe(hookInstall)),
    vscode.commands.registerCommand("sealbox.checkInstallation", safe(() => checkEngine(true))),
    vscode.window.onDidStartTerminalShellExecution((e) => void watchPlainRun(e).catch(() => undefined)),
    vscode.languages.registerHoverProvider({ scheme: "file" }, hovers),
    vscode.languages.registerCodeActionsProvider({ scheme: "file" }, quickFix, {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }),
    vscode.workspace.onDidSaveTextDocument(scheduleCheck),
    vscode.workspace.onDidOpenTextDocument(scheduleCheck),
    vscode.workspace.onDidCloseTextDocument((doc) => diagnostics.delete(doc.uri)),
    vscode.window.onDidChangeActiveTextEditor(refreshStatus),
  );
  output.appendLine(`SealBox started (${vscode.workspace.workspaceFolders?.length ?? 0} folder(s) open)`);
  void checkEngine().catch(handleError);
  vscode.workspace.textDocuments.forEach(scheduleCheck);
  void refreshHook(rootFor());
  refreshStatus();
}

export function deactivate(): void {
  for (const timer of pending.values()) {
    clearTimeout(timer);
  }
}
