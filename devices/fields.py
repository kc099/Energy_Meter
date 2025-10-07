import json

from django.db import models

from .encryption import decrypt_payload, encrypt_payload


class EncryptedJSONField(models.JSONField):
    description = "JSONField that stores values encrypted with Fernet"

    def get_prep_value(self, value):
        if value in (None, ""):
            return None
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            try:
                decrypt_payload(value)
                return value
            except ValueError:
                try:
                    decoded = json.loads(value)
                    if isinstance(decoded, (dict, list)):
                        value = decoded
                except (TypeError, ValueError):
                    value = value
        if isinstance(value, (dict, list)):
            return encrypt_payload(value)
        return encrypt_payload(value)

    def from_db_value(self, value, expression, connection):
        if value in (None, ""):
            return None
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, (dict, list)):
            return value
        if isinstance(value, str):
            try:
                return decrypt_payload(value)
            except ValueError:
                try:
                    return json.loads(value)
                except (TypeError, ValueError):
                    return value
        return value

    def to_python(self, value):
        if value in (None, ""):
            return value
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, (dict, list)):
            return value
        if isinstance(value, str):
            try:
                return decrypt_payload(value)
            except ValueError:
                try:
                    return json.loads(value)
                except (TypeError, ValueError):
                    return value
        return super().to_python(value)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        path = "devices.fields.EncryptedJSONField"
        return name, path, args, kwargs
