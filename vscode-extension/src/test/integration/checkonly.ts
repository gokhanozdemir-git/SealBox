// Read-only smoke test: opens SEALBOX_TEST_FILE and waits for diagnostics. Never edits the file.
import * as assert from "assert";
import * as vscode from "vscode";

export async function run(): Promise<void> {
  const file = vscode.Uri.file(process.env.SEALBOX_TEST_FILE!);
  await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(file));
  const until = Date.now() + 30_000;
  let count = 0;
  while (Date.now() < until) {
    count = vscode.languages.getDiagnostics(file).filter((d) => d.source === "sealbox").length;
    if (count) {
      break;
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  console.log(`[smoke] diagnostics: ${count}`);
  assert.ok(count > 0, "no diagnostics appeared");
}
