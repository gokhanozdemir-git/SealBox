# Run with Vault

Start your program with **SealBox: Run with Vault** (or `sealbox exec -- python app.py`).

1. An approval dialog shows the command and which variables it will receive. It also
   highlights lines changed since your last approval that could leak a secret.
2. After you click **Allow**, secrets are passed as environment variables, only to that
   process.
3. Known secret values in the program's output are replaced with `[REDACTED:…]`.

There is deliberately no flag that skips the approval: an AI agent could use it too.
