import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import {
  envRefAt,
  findProjectRoot,
  historyLines,
  isKeyMissing,
  isOlder,
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
  splitArgs,
  stateDir,
} from "../core";

const PH = "__SECURE_TCKN_c3dc0fb3c82d96b59d28f8cf35b4e8dc__";
const EXTENSION_ROOT = path.resolve(__dirname, "../..");

test("finds the placeholder under the cursor", () => {
  const line = `TCKN = "${PH}"`;
  const hit = placeholderAt(line, line.indexOf(PH) + 5);
  assert.equal(hit?.text, PH);
  assert.equal(hit?.category, "TCKN");
  assert.equal(placeholderAt(line, 1), undefined);
});

test("recognizes environment variable reads", () => {
  const cases: [string, string][] = [
    ['DB = os.environ["DB_PASSWORD"]', "DB_PASSWORD"],
    ["x = os.environ.get('API_KEY', '')", "API_KEY"],
    ['x = os.getenv("TOKEN")', "TOKEN"],
    ["const k = process.env.STRIPE_SECRET;", "STRIPE_SECRET"],
    ['const k = process.env["DB_PASS"];', "DB_PASS"],
    ['String p = System.getenv("DB_PASSWORD");', "DB_PASSWORD"],
  ];
  for (const [line, name] of cases) {
    assert.equal(envRefAt(line, line.indexOf(name))?.text, name, line);
  }
  assert.equal(envRefAt("print(environ)", 7), undefined);
});

test("splits a command line, keeping quoted parts together", () => {
  assert.deepEqual(splitArgs('python -c "import config as c; print(c.X)"'), [
    "python",
    "-c",
    "import config as c; print(c.X)",
  ]);
  assert.deepEqual(splitArgs("npm  run   dev"), ["npm", "run", "dev"]);
  assert.deepEqual(splitArgs(`node -e 'console.log("a b")' ""`), ["node", "-e", 'console.log("a b")', ""]);
  assert.throws(() => splitArgs('python "unclosed'));
});

function tmpProject(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sealbox-ext-"));
  fs.mkdirSync(path.join(root, "app", "src"), { recursive: true });
  return root;
}

test("project root is the nearest folder with a vault, else the workspace", () => {
  const ws = tmpProject();
  const src = path.join(ws, "app", "src");
  assert.equal(findProjectRoot(src, ws), path.resolve(ws));
  fs.mkdirSync(path.join(ws, "app", ".sealbox"));
  fs.writeFileSync(path.join(ws, "app", ".sealbox", "project.id"), "x");
  assert.equal(findProjectRoot(src, ws), path.join(ws, "app"));
  assert.equal(stateDir(path.join(ws, "app")), path.join(ws, "app", ".sealbox"));
});

test("looks for the engine in .venv before PATH", () => {
  const ws = tmpProject();
  assert.equal(resolveExecutable("", [ws], "linux"), "sealbox");
  const bin = path.join(ws, ".venv", "bin");
  fs.mkdirSync(bin, { recursive: true });
  fs.writeFileSync(path.join(bin, "sealbox"), "");
  assert.equal(resolveExecutable("", [path.join(ws, "app", "src")], "linux"), path.join(bin, "sealbox"));
  assert.equal(resolveExecutable(" C:/tools/sealbox.exe ", [ws]), "C:/tools/sealbox.exe");
});

test("parses and compares the engine version", () => {
  assert.deepEqual(parseEngineVersion("sealbox 0.3.0\n"), [0, 3, 0]);
  assert.equal(parseEngineVersion("python: can't open file"), undefined);
  assert.equal(isOlder([0, 2, 9], "0.3.0"), true);
  assert.equal(isOlder([0, 3, 0], "0.3.0"), false);
  assert.equal(isOlder([1, 0, 0], "0.3.0"), false);
});

test("turns a seal report into diagnostics", () => {
  const report = parseReport(
    JSON.stringify({
      clean: false,
      written: [],
      skipped: [],
      files: [
        {
          path: "src/config.py",
          output_path: "src/config.py",
          changed: true,
          moved: ["DB_PASSWORD"],
          masked: 0,
          spans: [{ line: 3, col: 16, end_line: 3, end_col: 32, category: "PASSWORD" }],
          issues: [
            { path: "src/config.py", line: 3, category: "PASSWORD", message: "same line", blocking: false },
            { path: "src/config.py", line: 9, category: "TOKEN", message: "Must be moved by hand", blocking: true },
          ],
        },
      ],
    }),
  );
  const problems = problemsFromReport(report).get("src/config.py")!;
  assert.equal(problems.length, 2);
  assert.deepEqual([problems[0].line, problems[0].col, problems[0].endCol], [2, 15, 31]);
  assert.equal(problems[0].severity, "warning");
  assert.equal(problems[1].line, 8);
  assert.equal(problems[0].manual, false);
  assert.equal(problems[1].manual, true); // "Move to vault" cannot fix this one
  assert.ok(problems[1].message.includes("own environment variable"));
  assert.throws(() => parseReport('{"x": 1}'));
});

test("password inside a URL: one diagnostic, marked manual, no move suggestion", () => {
  // The engine sends both a span and a blocking issue for this line.
  const report = parseReport(
    JSON.stringify({
      clean: false,
      written: [],
      skipped: [],
      files: [
        {
          path: "db.py",
          output_path: "db.py",
          changed: true,
          moved: ["KEY"],
          masked: 0,
          spans: [
            { line: 1, col: 26, end_line: 1, end_col: 42, category: "PASSWORD" },
            { line: 2, col: 8, end_line: 2, end_col: 49, category: "APIKEY" },
          ],
          issues: [{ path: "db.py", line: 1, category: "PASSWORD", message: "Must be moved by hand (part of a text)", blocking: true }],
        },
      ],
    }),
  );
  const problems = problemsFromReport(report).get("db.py")!;
  assert.equal(problems.length, 2);
  assert.equal(problems[0].manual, true);
  assert.ok(!problems[0].message.includes("Move it to the vault."));
  assert.ok(problems[0].message.includes("Must be moved by hand (part of a text)"));
  assert.equal(problems[1].manual, false);
});

test("turns the git history report into lines without values", () => {
  const report = parseHistory(
    JSON.stringify({
      git: true,
      hits: [
        { label: "DB_PASSWORD", named: true, path: "src/config.py", line: 0, commit: "a1b2c3d", date: "2026-10-12", count: 2, pushed: true },
        { label: "__SECURE_EMAIL_x__", named: false, path: "a.py", line: 0, commit: "b2c3d4e", date: "2026-10-13", count: 1, pushed: false },
      ],
    }),
  );
  const lines = historyLines(report.hits);
  assert.ok(lines[0].includes("DB_PASSWORD: exposed in 2 commit(s), pushed to a remote"));
  assert.ok(lines[0].includes("sealbox vault set DB_PASSWORD"));
  assert.ok(lines[1].includes("personal data"));
  assert.throws(() => parseHistory('{"git": true}'));
});

test("reads the vault index from files that hold no values", () => {
  const ws = tmpProject();
  assert.equal(readVaultIndex(ws), undefined);
  const dir = path.join(ws, ".sealbox");
  fs.mkdirSync(dir);
  fs.writeFileSync(path.join(dir, "project.vault"), "encrypted");
  fs.writeFileSync(path.join(dir, "project.names"), JSON.stringify({ DB_PASSWORD: "PASSWORD" }));
  assert.deepEqual(readVaultIndex(ws), { names: { DB_PASSWORD: "PASSWORD" }, masked: {} });
});

test("reads team members and recovery state from files that hold no values", () => {
  const ws = tmpProject();
  const home = tmpProject();
  assert.deepEqual(readTeam(ws), []);
  const dir = path.join(ws, ".sealbox");
  fs.mkdirSync(dir);
  const pid = "a".repeat(32);
  fs.writeFileSync(path.join(dir, "project.id"), pid);
  fs.writeFileSync(
    path.join(dir, "team.json"),
    JSON.stringify({ members: { zoe: { role: "member" }, alice: { role: "owner" } } }),
  );
  assert.deepEqual(readTeam(ws), [
    { user: "alice", role: "owner" },
    { user: "zoe", role: "member" },
  ]);
  assert.equal(recoveryState(ws, home), "none");
  const rdir = path.join(home, ".sealbox");
  fs.mkdirSync(path.join(rdir, "recovery"), { recursive: true });
  fs.writeFileSync(path.join(rdir, "recovery.json"), JSON.stringify({ pub: "P1" }));
  assert.equal(recoveryState(ws, home), "unprotected");
  fs.writeFileSync(path.join(rdir, "recovery", `${pid}.json`), JSON.stringify({ pub: "P1" }));
  assert.equal(recoveryState(ws, home), "protected");
  fs.writeFileSync(path.join(rdir, "recovery.json"), JSON.stringify({ pub: "P2" }));
  assert.equal(recoveryState(ws, home), "unprotected"); // code renewed, copy is stale
});

test("recognizes KeyError only for vault variables", () => {
  const tb = ["Traceback...", '    "api_key": os.environ["API_KEY"],', "KeyError: 'API_KEY'", ""].join("\n");
  assert.equal(missingVaultVar(tb, { API_KEY: "APIKEY" }), "API_KEY");
  assert.equal(missingVaultVar(tb, { OTHER: "APIKEY" }), undefined);
  assert.equal(missingVaultVar("KeyError: 'HOME'", { API_KEY: "APIKEY" }), undefined);
});

test("recognizes the missing-key message in both languages", () => {
  assert.equal(isKeyMissing("Durduruldu: KeyMissingError: Kasa anahtarı bu bilgisayarın kimlik deposunda bulunamadı."), true);
  assert.equal(isKeyMissing("Stopped: KeyMissingError: The vault key was not found in this computer's credential store."), true);
  assert.equal(isKeyMissing("Stopped: some other error"), false);
});

// --- Localization completeness ------------------------------------------------------

function sourceStrings(): Set<string> {
  const out = new Set<string>();
  // t("...") / t('...') with a single literal first argument.
  const call = /\bt\(\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')/g;
  for (const file of ["extension.ts", "core.ts"]) {
    const text = fs.readFileSync(path.join(EXTENSION_ROOT, "src", file), "utf-8");
    for (const m of text.matchAll(call)) {
      out.add(JSON.parse(`"${(m[1] ?? m[2]).replace(/\\'/g, "'").replace(/(?<!\\)"/g, '\\"')}"`));
    }
  }
  return out;
}

test("every UI string has a Turkish translation, and none is unused", () => {
  const bundle = JSON.parse(fs.readFileSync(path.join(EXTENSION_ROOT, "l10n", "bundle.l10n.tr.json"), "utf-8"));
  const used = sourceStrings();
  const missing = [...used].filter((s) => !(s in bundle));
  const unused = Object.keys(bundle).filter((k) => !used.has(k));
  assert.deepEqual(missing, [], "missing in l10n/bundle.l10n.tr.json");
  assert.deepEqual(unused, [], "unused in l10n/bundle.l10n.tr.json");
});

test("package.nls.tr.json has the same keys as package.nls.json", () => {
  const en = JSON.parse(fs.readFileSync(path.join(EXTENSION_ROOT, "package.nls.json"), "utf-8"));
  const tr = JSON.parse(fs.readFileSync(path.join(EXTENSION_ROOT, "package.nls.tr.json"), "utf-8"));
  assert.deepEqual(Object.keys(tr).sort(), Object.keys(en).sort());
});
