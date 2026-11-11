# Changelog

All notable changes to SealBox are documented in this file. The Python engine (`sealbox` on
PyPI) and the VS Code extension share version numbers.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-11-12

First public release.

### Engine (`sealbox` on PyPI)

- `sealbox seal` moves passwords, tokens and API keys out of Python, JavaScript/TypeScript and
  Java files into an AES-256-GCM vault and rewrites the code to read environment variables.
  Personal data (e-mail, phone, IBAN, credit card, Turkish national ID, listed names) is
  replaced with placeholders. `.env` files become `.env.sealed`.
- `sealbox exec` runs any command with the vault's secrets as environment variables, after an
  approval dialog that highlights risky lines changed since the last approval. Known values
  are redacted in the program's output as `[REDACTED:…]`.
- Vault commands: `vault list`, `reveal`, `set`, `expose`, `remove`, `reset`.
- Team sharing through GitHub SSH keys (`team init`, `add`, `remove`, `promote`, `list`), with
  key rotation on removal.
- Recovery code with optional 2-of-3 Shamir shares and exportable recovery kits.
- `sealbox history` scans git history for vault values; `sealbox hook install` adds a
  pre-commit hook.
- `sealbox init` and `sealbox status` report the project's health with a fix for each problem.
- English and Turkish output, following the OS language (`--lang` / `SEALBOX_LANG` to override).

### VS Code extension

- Exposed secret diagnostics on open and save, with quick fixes.
- Hovers on placeholders and environment variable reads, with approval-gated reveal.
- **Run with Vault**, status bar item and a menu for vault, team, recovery and git features.
- Offers to install or upgrade the engine when it is missing or outdated.
- **Get Started** walkthrough.
- English and Turkish interface.
- Disabled in untrusted workspaces, because it runs the engine from the workspace's `.venv`.

[Unreleased]: https://github.com/gokhanozdemir-git/SealBox/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/gokhanozdemir-git/SealBox/releases/tag/v0.3.0
