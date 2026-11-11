# Security Policy

SealBox exists to protect secrets, so security reports are the most important bug reports we
receive. Thank you for taking the time to report responsibly.

## Supported versions

Security fixes are released for the latest minor version of the `sealbox` engine and the VS
Code extension.

| Version | Supported |
|---|---|
| 0.3.x | Yes |
| < 0.3 | No |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub:
[**Report a vulnerability**](https://github.com/gokhanozdemir-git/SealBox/security/advisories/new)
(Security tab → *Report a vulnerability*).

Please include:

- the SealBox version (`sealbox -V`) and, if relevant, the extension version;
- your operating system and Python version;
- steps to reproduce, or a proof of concept;
- the impact you expect (for example: a secret value is written to disk, logged, or exposed
  without approval).

Never include real secrets in a report; use made-up values.

## What to expect

- An acknowledgement within **3 working days**.
- An initial assessment within **10 working days**.
- A fix and a coordinated disclosure date agreed with you. Reporters are credited in the
  release notes unless they prefer otherwise.

## Scope

In scope, for example:

- a secret value written to disk in plain text, logged, or printed without approval;
- bypassing the approval dialog;
- weaknesses in the vault, key wrapping, recovery or team-sharing cryptography;
- path traversal, symlink or race issues in file rewriting;
- the VS Code extension executing untrusted code.

Out of scope: the limits documented in the README's *Security model* section, such as a
deliberately malicious process running under your own user account and reading the OS
credential store.
