"""Demo app configuration. Every secret below is fake; try `sealbox seal` on this folder."""
import os

DB_HOST = "db.internal"
DB_PASSWORD = "Tr0ub4dor&3-fake"
ADMIN_EMAIL = "ayse.yilmaz@example.com"
SUPPORT_PHONE = "0532 123 45 67"
OWNER_TCKN = "12345678950"
AWS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
API_TOKEN = os.environ.get("API_TOKEN")
MAX_TOKENS = 1024


def connect():
    # password repeated in a comment: Tr0ub4dor&3-fake
    return f"postgres://admin:{DB_PASSWORD}@{DB_HOST}/app"
