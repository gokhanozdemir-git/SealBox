// Usage: node out/test/integration/runner.js <workspace folder> <temporary profile folder>
// Set VSCODE_EXE to use an installed VS Code instead of downloading one.
import * as path from "path";
import { runTests } from "@vscode/test-electron";

async function main(): Promise<void> {
  const [workspace, profile] = process.argv.slice(2);
  await runTests({
    vscodeExecutablePath: process.env.VSCODE_EXE,
    extensionDevelopmentPath: path.resolve(__dirname, "../../.."),
    extensionTestsPath: path.resolve(__dirname, process.env.SEALBOX_TEST_FILE ? "checkonly" : "suite"),
    launchArgs: [
      workspace,
      "--locale=en",
      "--disable-extensions",
      "--disable-workspace-trust",
      "--skip-welcome",
      `--user-data-dir=${path.join(profile, "data")}`,
      `--extensions-dir=${path.join(profile, "ext")}`,
    ],
  });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
