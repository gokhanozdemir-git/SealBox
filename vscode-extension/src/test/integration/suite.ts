// End-to-end test that runs inside a real VS Code instance (started by runner.ts).
import * as assert from "assert";
import * as path from "path";
import * as vscode from "vscode";

const SOURCE = "sealbox";

async function waitFor<T>(what: string, fn: () => T | undefined | false, ms = 30_000): Promise<T> {
  const until = Date.now() + ms;
  for (;;) {
    const v = fn();
    if (v) {
      return v;
    }
    if (Date.now() > until) {
      throw new Error(`Timed out waiting for ${what}`);
    }
    await new Promise((r) => setTimeout(r, 200));
  }
}

function ours(uri: vscode.Uri): vscode.Diagnostic[] {
  return vscode.languages.getDiagnostics(uri).filter((d) => d.source === SOURCE);
}

async function hoverText(uri: vscode.Uri, pos: vscode.Position): Promise<string> {
  const hovers = await vscode.commands.executeCommand<vscode.Hover[]>("vscode.executeHoverProvider", uri, pos);
  return hovers
    .flatMap((h) => h.contents)
    .map((c) => (typeof c === "string" ? c : "value" in c ? c.value : ""))
    .join("\n");
}

export async function run(): Promise<void> {
  const ws = vscode.workspace.workspaceFolders![0].uri.fsPath;
  const file = vscode.Uri.file(path.join(ws, "src", "config.py"));
  const doc = await vscode.workspace.openTextDocument(file);
  await vscode.window.showTextDocument(doc);

  const diags = await waitFor("exposed secret diagnostics", () => (ours(file).length ? ours(file) : undefined));
  console.log(`[e2e] diagnostics: ${diags.length}`);
  const pw = diags.find((d) => d.message.includes("PASSWORD"));
  assert.ok(pw, "no PASSWORD diagnostic");
  assert.equal(doc.getText(pw.range), "Tr0ub4dor&3-fake", "diagnostic marks the wrong range");

  const actions = await vscode.commands.executeCommand<vscode.CodeAction[]>(
    "vscode.executeCodeActionProvider",
    file,
    pw.range,
  );
  assert.ok(actions.some((a) => a.title.includes("Move this file's secrets to the vault")), "no move-to-vault quick fix");

  await vscode.commands.executeCommand("sealbox.sealFile", file);
  await waitFor("the file to be rewritten", () => doc.getText().includes('os.environ["DB_PASSWORD"]'));
  await waitFor("diagnostics to clear", () => ours(file).length === 0);
  console.log("[e2e] sealed, diagnostics cleared");

  const lines = doc.getText().split(/\r?\n/);
  const envLine = lines.findIndex((l) => l.includes('os.environ["DB_PASSWORD"]'));
  const envCol = lines[envLine].indexOf("DB_PASSWORD", lines[envLine].indexOf("os.environ"));
  const envHover = await hoverText(file, new vscode.Position(envLine, envCol + 2));
  assert.ok(envHover.includes("comes from the vault"), `no hover on the env read: ${envHover}`);

  const phLine = lines.findIndex((l) => l.includes("__SECURE_EMAIL_"));
  const phHover = await hoverText(file, new vscode.Position(phLine, lines[phLine].indexOf("__SECURE_") + 5));
  assert.ok(phHover.includes("Stored in the vault") && phHover.includes("Show value"), `no hover on the placeholder: ${phHover}`);
  assert.ok(phHover.includes("pass it at run time"), `no "pass it at run time" link: ${phHover}`);
  console.log("[e2e] hovers work");

  const phPos = new vscode.Position(phLine, lines[phLine].indexOf("__SECURE_") + 5);
  const fixes = await vscode.commands.executeCommand<vscode.CodeAction[]>(
    "vscode.executeCodeActionProvider",
    file,
    new vscode.Range(phPos, phPos),
  );
  assert.ok(fixes.some((a) => a.title.includes("pass it at run time")), "no quick fix on the placeholder");
  console.log("[e2e] pass-at-run-time quick fix present");

  const commands = await vscode.commands.getCommands(true);
  for (const c of [
    "sealbox.teamAdd",
    "sealbox.recoverySetup",
    "sealbox.recoveryRestore",
    "sealbox.manualHelp",
    "sealbox.history",
    "sealbox.hookInstall",
  ]) {
    assert.ok(commands.includes(c), `command ${c} is not registered`);
  }
  // The vault's own .gitignore keeps backups out of git; the vault and team.json are committed.
  const ignore = await vscode.workspace.fs.readFile(vscode.Uri.file(path.join(ws, ".sealbox", ".gitignore")));
  assert.ok(Buffer.from(ignore).toString("utf-8").includes("backups/"), "missing .sealbox/.gitignore");
  console.log("[e2e] team and recovery commands registered");
}
