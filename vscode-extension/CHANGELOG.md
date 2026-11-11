# Changelog

The extension and the [`sealbox` engine](https://pypi.org/project/sealbox/) share version
numbers. The full history of both lives in the
[project changelog](https://github.com/gokhanozdemir-git/SealBox/blob/main/CHANGELOG.md).

## 0.3.0 - 2026-11-12

First public release.

- Exposed secret diagnostics on open and save, with quick fixes.
- Hovers on `__SECURE_…__` placeholders and environment variable reads, with approval-gated reveal.
- **Run with Vault**, status bar item and a menu for vault, team, recovery and git features.
- Offers to install or upgrade the engine when it is missing or outdated.
- **Get Started** walkthrough.
- English and Turkish interface.
- Disabled in untrusted workspaces, because it runs the engine from the workspace's `.venv`.
