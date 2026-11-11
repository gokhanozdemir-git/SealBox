# Demo project

A tiny project full of **fake** secrets for trying SealBox safely.

```sh
cd examples/demo_project
sealbox seal --check     # list what would be moved (changes nothing)
sealbox seal             # move the secrets into .sealbox/project.vault
sealbox vault list       # names and placeholders only, never values
sealbox exec -- python -c "import os; print(os.environ['DB_PASSWORD'])"
```

To reset the demo afterwards, restore the files with `git checkout -- .` and delete
`.sealbox/` and `.env.sealed`.
