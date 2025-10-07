import json
import logging
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)
_FERNET: Fernet | None = None
_INVALID_TOKEN_WARNING_EMITTED = False


def _get_cipher() -> Fernet:
    global _FERNET
    if _FERNET is not None:
        return _FERNET
    key = getattr(settings, "DEVICE_DATA_ENCRYPTION_KEY", None)
    if not key:
        raise ImproperlyConfigured("DEVICE_DATA_ENCRYPTION_KEY is not configured")
    if isinstance(key, str):
        key = key.encode("utf-8")
    try:
        _FERNET = Fernet(key)
    except (TypeError, ValueError) as exc:
        raise ImproperlyConfigured(
            "DEVICE_DATA_ENCRYPTION_KEY must be a 32-byte urlsafe base64 value"
        ) from exc
    return _FERNET


def encrypt_payload(value: Any) -> str:
    if value is None:
        return ""
    data = json.dumps(value).encode("utf-8")
    return _get_cipher().encrypt(data).decode("utf-8")


def decrypt_payload(token: str | bytes):
    if not token:
        return None
    if isinstance(token, str):
        token = token.encode("utf-8")
    try:
        decrypted = _get_cipher().decrypt(token)
    except InvalidToken as exc:
        global _INVALID_TOKEN_WARNING_EMITTED
        if not _INVALID_TOKEN_WARNING_EMITTED:
            logger.error("Failed to decrypt device payload: %s", exc)
            _INVALID_TOKEN_WARNING_EMITTED = True
        raise ValueError("Unable to decrypt device payload") from exc
    return json.loads(decrypted.decode("utf-8"))
