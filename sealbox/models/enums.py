from __future__ import annotations

from enum import StrEnum


class SecretCategory(StrEnum):
    EMAIL = "EMAIL"
    TC_KIMLIK = "TCKN"
    PHONE = "PHONE"
    PASSWORD = "PASSWORD"
    TOKEN = "TOKEN"
    API_KEY = "APIKEY"
    PRIVATE_KEY = "PRIVKEY"
    CREDIT_CARD = "CARD"
    IBAN = "IBAN"
    PERSON_NAME = "NAME"
    CUSTOM = "CUSTOM"
