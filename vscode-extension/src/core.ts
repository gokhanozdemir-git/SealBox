// Helpers that do not depend on the VS Code API, so they can be unit tested on their own.
// Nothing in this file ever holds a secret value: only names, placeholders and positions.

import * as fs from "fs";
import * as path from "path";

// --- Localization -------------------------------------------------------------

/** Translates a message; ``{0}``, ``{1}``... are replaced with ``args``. */
export type Translate = (message: string, ...args: (string | number | boolean)[]) => string;

function format(message: string, ...args: (string | number | boolean)[]): string {
  return message.replace(/\{(\d+)\}/g, (m, i: string) => (Number(i) < args.length ? String(args[Number(i)]) : m));
}

let translate: Translate = format;

/** The extension plugs in ``vscode.l10n.t``; tests keep the English source strings. */
export function setTranslator(fn: Translate): void {
  translate = fn;
}

export function t(message: string, ...args: (string | number | boolean)[]): string {
  return translate(message, ...args);
}

// --- Placeholders and environment variable reads ---------------------------------

/** Same as ``PLACEHOLDER_RE`` in the Python engine. */
export const PLACEHOLDER_RE = /__SECURE_([A-Z]+)_([0-9a-f]{32})__/g;

const NAME = "([A-Za-z_][A-Za-z0-9_]*)";
/** Ways code reads an environment variable: the forms `seal` writes plus common ones. */
const ENV_REF_PATTERNS = [
  new RegExp(`os\\.environ\\[\\s*["']${NAME}["']\\s*\\]`, "g"),
  new RegExp(`os\\.environ\\.get\\(\\s*["']${NAME}["']`, "g"),
  new RegExp(`os\\.getenv\\(\\s*["']${NAME}["']`, "g"),
  new RegExp(`process\\.env\\.${NAME}`, "g"),
  new RegExp(`process\\.env\\[\\s*["']${NAME}["']\\s*\\]`, "g"),
  new RegExp(`System\\.getenv\\(\\s*"${NAME}"\\s*\\)`, "g"),
];

export interface Hit {
  text: string; // placeholder or variable name
  category?: string; // placeholder category (TCKN, EMAIL...)
  start: number; // 0-based column
  end: number;
}

function hitsIn(line: string, re: RegExp, group: number): Hit[] {
  const out: Hit[] = [];
  for (const m of line.matchAll(new RegExp(re.source, "g"))) {
    out.push({ text: m[group], category: group === 0 ? m[1] : undefined, start: m.index!, end: m.index! + m[0].length });
  }
  return out;
}

/** The ``__SECURE_..__`` placeholder under the cursor. */
export function placeholderAt(line: string, col: number): Hit | undefined {
  return hitsIn(line, PLACEHOLDER_RE, 0).find((h) => h.start <= col && col <= h.end);
}

/** The ``os.environ["X"]`` / ``process.env.X`` / ``System.getenv("X")`` read under the cursor. */
export function envRefAt(line: string, col: number): Hit | undefined {
  for (const re of ENV_REF_PATTERNS) {
    const hit = hitsIn(line, re, 1).find((h) => h.start <= col && col <= h.end);
    if (hit) {
      return hit;
    }
  }
  return undefined;
}

/** Split a command line into arguments, keeping single- and double-quoted parts together. */
export function splitArgs(cmd: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: string | null = null;
  let started = false;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (quote) {
      if (c === "\\" && quote === '"' && cmd[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (c === quote) {
        quote = null;
      } else {
        cur += c;
      }
    } else if (c === '"' || c === "'") {
      quote = c;
      started = true;
    } else if (/\s/.test(c)) {
      if (started) {
        out.push(cur);
        cur = "";
        started = false;
      }
    } else {
      cur += c;
      started = true;
    }
  }
  if (quote) {
    throw new Error(t("Unclosed quote"));
  }
  if (started) {
    out.push(cur);
  }
  return out;
}

// --- Project layout (mirrors sealbox/core/names.py) --------------------------------

export const STATE_DIR = ".sealbox";

/** The project's vault folder. */
export function stateDir(root: string): string {
  return path.join(root, STATE_DIR);
}

/** Per-user recovery folder. */
export function homeStateDir(home: string): string {
  return path.join(home, STATE_DIR);
}

/** Walk up from ``fileDir`` to the nearest folder with a vault, never leaving ``stopAt``. */
export function findProjectRoot(fileDir: string, stopAt: string): string {
  const stop = path.resolve(stopAt);
  let dir = path.resolve(fileDir);
  for (;;) {
    if (fs.existsSync(path.join(stateDir(dir), "project.id"))) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (dir === stop || parent === dir || !isInside(parent, stop)) {
      return stop;
    }
    dir = parent;
  }
}

export function isInside(child: string, parent: string): boolean {
  const rel = path.relative(path.resolve(parent), path.resolve(child));
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

export const EXECUTABLE = "sealbox";

/** With no setting: the engine in the nearest ``.venv`` above the project, else ``sealbox`` on PATH. */
export function resolveExecutable(setting: string, startDirs: string[], platform = process.platform): string {
  if (setting.trim()) {
    return setting.trim();
  }
  const rel =
    platform === "win32" ? path.join(".venv", "Scripts", `${EXECUTABLE}.exe`) : path.join(".venv", "bin", EXECUTABLE);
  for (const start of startDirs) {
    let dir = path.resolve(start);
    for (;;) {
      const candidate = path.join(dir, rel);
      if (fs.existsSync(candidate)) {
        return candidate;
      }
      const parent = path.dirname(dir);
      if (parent === dir) {
        break;
      }
      dir = parent;
    }
  }
  return EXECUTABLE;
}

// --- Engine version ------------------------------------------------------------------

/** Oldest engine release whose CLI and JSON output this extension understands. */
export const MIN_ENGINE_VERSION = "0.3.0";

/** ``"sealbox 0.3.1"`` -> ``[0, 3, 1]``; undefined if the output is not a version line. */
export function parseEngineVersion(output: string): number[] | undefined {
  const m = /\bsealbox\s+(\d+)\.(\d+)\.(\d+)/.exec(output);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : undefined;
}

export function isOlder(version: number[], than: string): boolean {
  const min = than.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((version[i] ?? 0) !== (min[i] ?? 0)) {
      return (version[i] ?? 0) < (min[i] ?? 0);
    }
  }
  return false;
}

// --- `sealbox seal --json` output ---------------------------------------------------

export interface SecretSpan {
  line: number; // 1-based
  col: number; // 1-based
  end_line: number;
  end_col: number;
  category: string;
}

export interface SealIssue {
  path: string;
  line: number;
  category: string;
  message: string;
  blocking: boolean;
}

export interface SealFile {
  path: string;
  output_path: string;
  changed: boolean;
  moved: string[];
  masked: number;
  spans: SecretSpan[];
  issues: SealIssue[];
}

export interface SealReport {
  clean: boolean;
  written: string[];
  files: SealFile[];
  skipped: { path: string; reason: string }[];
}

export function parseReport(stdout: string): SealReport {
  const data = JSON.parse(stdout) as SealReport;
  if (typeof data !== "object" || data === null || !Array.isArray(data.files)) {
    throw new Error(t("Unexpected report format"));
  }
  return data;
}

export type Severity = "warning" | "info";

export interface Problem {
  line: number; // 0-based
  col: number;
  endLine: number;
  endCol: number;
  message: string;
  severity: Severity;
  /** "Move to vault" cannot fix this one (e.g. a password inside a URL); the user must. */
  manual: boolean;
}

/** Short fix appended to warnings about secrets that must be moved by hand. */
export function manualHint(): string {
  return t(
    'Move to vault cannot fix this: put the secret in its own environment variable and build the text from it (e.g. f"postgres://admin:{DB_PASSWORD}@host/db").',
  );
}

/** Body of the "How do I fix this?" dialog. */
export function manualHelp(): string {
  return [
    t(
      "These secrets are part of a larger text (for example, a password inside a connection URL) or in a file type SealBox cannot rewrite automatically. They are still exposed: AI coding agents that read the file can see them.",
    ),
    "",
    t("1) Take the secret out of the text and read it from an environment variable. Python example:"),
    '     DB_PASSWORD = os.environ["DB_PASSWORD"]',
    '     url = f"postgres://admin:{DB_PASSWORD}@host/db"',
    '   (JS/TS: process.env.DB_PASSWORD, Java: System.getenv("DB_PASSWORD"))',
    "",
    t("2) Add the value to the vault (in a terminal; the value is not echoed):"),
    "     sealbox vault set DB_PASSWORD",
    "",
    t('3) Start the program with "Run with Vault"; the value is passed at run time.'),
  ].join("\n");
}

/** Diagnostics to show for each file in the report, keyed by relative path. */
export function problemsFromReport(report: SealReport): Map<string, Problem[]> {
  const out = new Map<string, Problem[]>();
  for (const f of report.files) {
    const list: Problem[] = [];
    const manualLines = new Map(f.issues.filter((i) => i.blocking).map((i) => [i.line, i]));
    const seenLines = new Set<number>();
    for (const s of f.spans) {
      seenLines.add(s.line);
      const manual = manualLines.get(s.line);
      list.push({
        line: s.line - 1,
        col: s.col - 1,
        endLine: s.end_line - 1,
        endCol: s.end_col - 1,
        message: manual
          ? t("Exposed secret ({0}) that could not be moved automatically: {1}. {2}", s.category, manual.message, manualHint())
          : t("Exposed secret ({0}): AI coding agents that read this file can see it. Move it to the vault.", s.category),
        severity: "warning",
        manual: manual !== undefined,
      });
    }
    for (const i of f.issues) {
      if (seenLines.has(i.line)) {
        continue; // this line already has a diagnostic; a manual note was merged into it
      }
      list.push({
        line: Math.max(0, i.line - 1),
        col: 0,
        endLine: Math.max(0, i.line - 1),
        endCol: Number.MAX_SAFE_INTEGER,
        message: i.blocking ? `${i.message} (${i.category}). ${manualHint()}` : `${i.message} (${i.category})`,
        severity: i.blocking ? "warning" : "info",
        manual: i.blocking,
      });
    }
    out.set(f.path, list);
  }
  return out;
}

// --- Git history -------------------------------------------------------------------

export interface HistoryHit {
  label: string;
  named: boolean;
  path: string;
  commit: string;
  date: string;
  count: number;
  pushed: boolean;
}

export interface HistoryReport {
  git: boolean;
  hits: HistoryHit[];
}

export function parseHistory(stdout: string): HistoryReport {
  const data = JSON.parse(stdout) as HistoryReport;
  if (typeof data !== "object" || data === null || !Array.isArray(data.hits)) {
    throw new Error(t("Unexpected report format"));
  }
  return data;
}

/** One line per finding, with what to do about it (never includes the value). */
export function historyLines(hits: HistoryHit[]): string[] {
  return hits.map((h) => {
    const where = h.pushed ? t("pushed to a remote") : t("only on this computer");
    const todo = h.named
      ? t("rotate it at the provider, then run: sealbox vault set {0}", h.label)
      : t("personal data: consider rewriting history");
    return t("• {0}: exposed in {1} commit(s), {2} (first: {3} {4}, {5}) → {6}", h.label, h.count, where, h.commit, h.date, h.path, todo);
  });
}

// --- Vault index (files without values) ------------------------------------------

export interface VaultIndex {
  names: Record<string, string>; // variable name -> category
  masked: Record<string, string>; // placeholder -> category
}

function readMap(file: string): Record<string, string> {
  try {
    const data = JSON.parse(fs.readFileSync(file, "utf-8"));
    return typeof data === "object" && data !== null ? data : {};
  } catch {
    return {};
  }
}

export function readVaultIndex(root: string): VaultIndex | undefined {
  const dir = stateDir(root);
  if (!fs.existsSync(path.join(dir, "project.vault"))) {
    return undefined;
  }
  return { names: readMap(path.join(dir, "project.names")), masked: readMap(path.join(dir, "project.masked")) };
}

// --- Team and recovery (files without values) --------------------------------------

/** The engine's ``KEY_MISSING`` message (Turkish and English): no vault key on this computer. */
export const KEY_MISSING = [
  "Kasa anahtarı bu bilgisayarın kimlik deposunda bulunamadı",
  "The vault key was not found in this computer's credential store",
];

export function isKeyMissing(message: string): boolean {
  return KEY_MISSING.some((text) => message.includes(text));
}

export interface TeamMember {
  user: string;
  role: "owner" | "member";
}

/** Members listed in ``.sealbox/team.json`` (unverified; for display only). */
export function readTeam(root: string): TeamMember[] {
  try {
    const data = JSON.parse(fs.readFileSync(path.join(stateDir(root), "team.json"), "utf-8"));
    return Object.entries(data.members ?? {})
      .map(([user, m]) => ({ user, role: (m as { role?: string }).role === "owner" ? "owner" : "member" }) as TeamMember)
      .sort((a, b) => a.user.localeCompare(b.user));
  } catch {
    return [];
  }
}

/**
 * Whether this project is locked to a recovery code: ``none`` (recovery never set up),
 * ``unprotected`` (set up, but no current copy for this project) or ``protected``.
 */
export function recoveryState(root: string, home: string): "none" | "unprotected" | "protected" {
  const dir = homeStateDir(home);
  try {
    const meta = JSON.parse(fs.readFileSync(path.join(dir, "recovery.json"), "utf-8"));
    try {
      const pid = fs.readFileSync(path.join(stateDir(root), "project.id"), "ascii").trim();
      if (!/^[0-9a-f]{32}$/.test(pid)) {
        return "unprotected";
      }
      const rec = JSON.parse(fs.readFileSync(path.join(dir, "recovery", `${pid}.json`), "utf-8"));
      return rec.pub === meta.pub ? "protected" : "unprotected";
    } catch {
      return "unprotected";
    }
  } catch {
    return "none";
  }
}

/** ``KeyError: 'API_KEY'`` in Python output: a vault variable was not passed to the program. */
export function missingVaultVar(text: string, names: Record<string, string>): string | undefined {
  for (const m of text.matchAll(/KeyError: '([A-Za-z_][A-Za-z0-9_]*)'/g)) {
    if (m[1] in names) {
      return m[1];
    }
  }
  return undefined;
}
