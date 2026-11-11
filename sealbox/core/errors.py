"""Error types whose messages never contain secrets.

Every exception in this module is built from fixed text and numbers only, so its
message is safe to show or log. Exceptions from third-party libraries are reduced
to their type name by ``safe_error_message``.
"""

from __future__ import annotations

from sealbox.i18n import _


class SealboxError(Exception):
    """Base error whose message is safe to show to the user."""


class CryptoError(SealboxError):
    pass


class KeySharingError(SealboxError):
    pass


class PathSecurityError(SealboxError):
    pass


class ConflictError(SealboxError):
    pass


class ApprovalDeniedError(SealboxError):
    pass


class NewerFormatError(SealboxError):
    pass


def require_version(found: object, supported: int, what: str) -> None:
    """Stop with a clear message if a file was written by a newer, unknown format version."""
    if isinstance(found, int) and found > supported:
        raise NewerFormatError(
            _(
                f"Bu {what} sealbox'ın daha yeni bir sürümüyle yazılmış; sealbox'ı güncelleyin "
                "(pipx upgrade sealbox)"
            )
        )


def safe_error_message(exc: BaseException) -> str:
    """Turn an exception into text that is safe to log.

    Only messages of this package's own error types are trusted. The ``str()`` of any
    other exception is never used, because it may carry raw data (for example,
    ``UnicodeDecodeError`` includes the offending bytes).
    """
    if isinstance(exc, SealboxError):
        return f"{type(exc).__name__}: {exc}"
    return _(f"{type(exc).__name__} (ayrıntılar güvenlik nedeniyle gizlendi)")
