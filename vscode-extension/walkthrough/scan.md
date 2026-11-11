# Scan your project

SealBox looks for secrets that are sitting in plain text on disk:

- passwords, tokens and API keys (OpenAI, Anthropic, AWS, GitHub, Stripe, Google, Slack…)
- private keys, JWTs, credentials inside URLs
- personal data: e-mail addresses, phone numbers, IBANs, credit card numbers

Every hit is underlined in the editor and listed in the **Problems** panel. Files are also
checked automatically when you open or save them.

Scanning never changes a file and never opens the vault.
