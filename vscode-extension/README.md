# SealBox: Secret Vault for AI Coding

**Keep passwords, API keys and personal data out of your source files, so AI coding agents
like GitHub Copilot, Claude Code and Cursor never see them.**

AI agents read your files straight from disk and send what they read to a cloud model.
SealBox moves every secret out of your files into an encrypted, per-project vault and rewrites
your code to read an environment variable instead. Your program gets the real values only when
you run it through SealBox, and only after you approve.

<!-- Screenshot: docs/images/hero.gif
![Sealing a file in VS Code](https://raw.githubusercontent.com/gokhanozdemir-git/SealBox/main/docs/images/hero.gif)
-->

## Features

| | |
|---|---|
| **Exposed secret warnings** | Files are checked when you open or save them. Secrets are underlined and listed in the Problems panel. |
| **One-click fix** | Lightbulb → *Move this file's secrets to the vault*. `DB_PASSWORD = "…"` becomes `os.environ["DB_PASSWORD"]`. |
| **Hover to reveal** | Hover a `__SECURE_…__` placeholder or an `os.environ["X"]` / `process.env.X` / `System.getenv("X")` read to see where it comes from, and show the value after approval. |
| **Run with Vault** | Starts your program with the secrets as environment variables. Known values are hidden in the output. |
| **Plain-run hint** | Ran `python app.py` with ▶ and got a `KeyError` for a vault variable? SealBox offers to run it with the vault. |
| **Status bar** | `🔒 3 in vault · 👥 2 people`, with a warning when there is no recovery code or commit hook. Click it for the full menu. |
| **Team sharing** | Share the vault with teammates through their GitHub SSH keys. No server, no extra account. |
| **Recovery** | Create a one-time recovery code, split it into 2-of-3 shares, export a recovery kit. |
| **Git protection** | Scan git history for secrets that were committed before sealing, and install a pre-commit hook. |

<!-- Screenshots: docs/images/diagnostics.png, docs/images/hover.png, docs/images/approval.png
![Exposed secret warning and quick fix](https://raw.githubusercontent.com/gokhanozdemir-git/SealBox/main/docs/images/diagnostics.png)
![Hover over a vault value](https://raw.githubusercontent.com/gokhanozdemir-git/SealBox/main/docs/images/hover.png)
![Approval dialog](https://raw.githubusercontent.com/gokhanozdemir-git/SealBox/main/docs/images/approval.png)
-->

Works with Python, JavaScript/TypeScript and Java code, `.env` files and JSON/YAML/TOML
configuration. Detects passwords, tokens, API keys (OpenAI, Anthropic, AWS, GitHub, Stripe,
Google, Slack…), private keys, JWTs, credentials in URLs, e-mail addresses, phone numbers,
IBANs, credit card numbers and Turkish national IDs.

## Requirements

SealBox uses a small Python command-line engine (Python 3.12 or newer). The extension offers
to install it for you; to do it yourself:

```sh
pipx install sealbox
```

The extension looks for the engine in the project's `.venv` first, then on `PATH`. If it is
somewhere else, set **SealBox: Executable**.

## Getting started

1. Open a project and run **SealBox: Scan Project for Exposed Secrets** from the Command Palette.
2. Click a warning's lightbulb, or run **SealBox: Move All Project Secrets to the Vault**.
3. Start your program with **SealBox: Run with Vault** and approve the dialog.
4. Create a recovery code from the status bar menu, in case the vault key is ever lost.

A step-by-step walkthrough is available under **Help → Welcome → Get Started with SealBox**.

## Commands

| Command | What it does |
|---|---|
| `SealBox: Menu` | Everything in one place (also on the status bar) |
| `SealBox: Scan Project for Exposed Secrets` | Scan without changing anything |
| `SealBox: Move This File's Secrets to the Vault` | Seal the current file (also in the editor and Explorer context menus) |
| `SealBox: Move All Project Secrets to the Vault` | Seal the whole project |
| `SealBox: Run with Vault` | Run a command with the vault's secrets |
| `SealBox: Show a Value from the Vault` | Reveal one value after approval |
| `SealBox: Add Teammate (GitHub User)` | Share the vault with a GitHub user |
| `SealBox: Create Recovery Code` | One-time code to recover a lost key |
| `SealBox: Scan Git History for Exposed Secrets` | Find vault values in old commits |
| `SealBox: Install Commit Hook` | Stop vault values from being committed |
| `SealBox: Check Engine Installation` | Verify the engine is installed and up to date |

## Settings

| Setting | Default | Description |
|---|---|---|
| `sealbox.executable` | `""` | Path to the `sealbox` engine. Empty: the project's `.venv`, then `PATH`. |
| `sealbox.checkOnSave` | `true` | Check files for exposed secrets when they are opened or saved. |

## Privacy and security

- Secret values never pass through the extension, except right after you approve **Show
  value**. They are never logged. A copied value is cleared from the clipboard after 30 seconds.
- Recovery codes, shares and SSH passphrases are shown or asked for only in the engine's own
  dialogs, never in the editor or the terminal.
- The vault key is stored in your OS credential store, not in the project.
- SealBox runs the engine from your workspace's `.venv`, so it is disabled in untrusted
  workspaces (Restricted Mode).
- No telemetry. SealBox only talks to the network when you add a teammate (to fetch their
  public SSH keys from `github.com/<user>.keys`).

## Language

The interface follows your VS Code display language: English, or Turkish.

## Links

- [Source code and full documentation](https://github.com/gokhanozdemir-git/SealBox)
- [Python engine on PyPI](https://pypi.org/project/sealbox/)
- [Report an issue](https://github.com/gokhanozdemir-git/SealBox/issues)
- [Security policy](https://github.com/gokhanozdemir-git/SealBox/blob/main/SECURITY.md)

## License

[FSL-1.1-ALv2](https://github.com/gokhanozdemir-git/SealBox/blob/main/LICENSE): free to use,
modify and share for any purpose except a competing commercial product. Each release becomes
Apache-2.0 two years after it is published.
