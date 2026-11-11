# Contributing to SealBox

Thanks for your interest in improving SealBox! Bug reports, feature ideas and pull requests
are all welcome. For security issues, please follow [SECURITY.md](SECURITY.md) instead.

## Development setup

You need Python 3.12+, Node.js 22+ and git.

```sh
git clone https://github.com/gokhanozdemir-git/SealBox.git
cd SealBox
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
```

Checks that CI runs on every push:

```sh
ruff check sealbox tests
ruff format --check sealbox tests
mypy sealbox
pytest -q

cd vscode-extension
npm ci
npm test
```

To try the extension, open the repository in VS Code and press **F5** (*Run Extension*). It
uses the engine from the repository's `.venv`.

All test data is fake (see `tests/fixtures.py`). Never commit a real secret, even in a test.

## Project layout

```
sealbox/
├── __main__.py             CLI: commands, help texts and examples (build_parser)
├── cli_help.py             Help infrastructure: localized headings, "did you mean"
├── i18n.py, i18n_en.py     Message translation: _("...") and the English table
├── status.py               init / status checklist (read-only)
├── config.py               Configuration with safe defaults (TOML, pydantic)
├── vaultstore.py           Project vault: unlocking via credential store, SSH or recovery
├── runner.py               exec and vault reveal/set/expose/remove
├── team.py                 Team sharing through GitHub SSH keys (team.json)
├── recovery.py             Recovery code, 2-of-3 shares, recovery kit
├── approval.py             Approval and secret dialogs (tkinter)
├── changes.py              Risky lines changed since the last approval
├── history.py              Git history scan and pre-commit hook
├── sealing/
│   ├── sealer.py           Plans and applies moving secrets to the vault
│   ├── rewriters.py        Per-language "read an environment variable" rewrites
│   └── file_operations.py  SafeFS: path safety, locks, atomic writes, rollback
├── models/enums.py         Secret categories
└── core/
    ├── scanner.py          Detection rules, priorities and overlap resolution
    ├── validators.py       Checksums: national ID, e-mail, phone, Luhn, IBAN, entropy
    ├── tokenization.py     __SECURE_<CATEGORY>_<128 bits>__ placeholders, encrypted vault
    ├── crypto.py           AES-256-GCM with nonce reuse protection
    ├── envelope.py         Key wrapping: Argon2id, X25519, SSH ed25519/RSA, recovery code
    ├── key_sharing.py      SLIP-39 secret sharing (shamir-mnemonic)
    ├── leak_guard.py       Redaction of program output and log records
    ├── redaction.py        Literal value matching
    ├── names.py            On-disk and credential-store names
    ├── fsutil.py           Atomic file writes
    └── errors.py           Error types whose messages never contain secrets
vscode-extension/           VS Code extension (TypeScript)
tests/                      Engine tests
```

## Guidelines

- **Never let a secret value reach a log, an exception message, the terminal or a file.**
  Errors raised to the user must be `SealboxError` subclasses built from fixed text; see
  `sealbox/core/errors.py`.
- Keep changes focused, add tests for new behavior, and update `CHANGELOG.md` under
  *Unreleased*.
- Commit messages: short imperative summary line (for example, "Add Go rewriter").

## Translations

The engine's messages are written in Turkish in the source and translated through a table:

1. Wrap the message in `_("...")` (or `N_("...")` for module-level constants).
2. Add the English text to `sealbox/i18n_en.py`, keyed by the Turkish source.

`tests/test_i18n.py` fails on missing or unused translations.

The extension's UI strings are written in English and wrapped in `t("...")`. Add the Turkish
text to `vscode-extension/l10n/bundle.l10n.tr.json`; command titles and settings live in
`package.nls.json` and `package.nls.tr.json`. `npm test` fails on missing or unused entries.

## Releasing (maintainers)

1. Update the version in `sealbox/__init__.py` and `vscode-extension/package.json`, and move
   the *Unreleased* changelog entries under the new version.
2. Commit, then tag: `git tag v0.3.1 && git push origin v0.3.1`.
3. The **release** workflow tests everything, then publishes the engine to PyPI and the
   extension to the VS Code Marketplace and Open VSX, and creates a GitHub release.
