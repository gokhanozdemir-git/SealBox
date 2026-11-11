# Move secrets to the vault

For each secret, SealBox:

1. stores the value in `.sealbox/project.vault`, encrypted with AES-256-GCM;
2. rewrites the code to read an environment variable instead:

```python
# before
DB_PASSWORD = "Tr0ub4dor&3"

# after
DB_PASSWORD = os.environ["DB_PASSWORD"]
```

Personal data that the program does not need at run time is replaced with a placeholder
such as `__SECURE_EMAIL_…__`. `.env` files become `.env.sealed`.

The vault key lives in your operating system's credential store, never on disk.
