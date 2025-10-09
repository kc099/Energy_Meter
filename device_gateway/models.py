from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.crypto import constant_time_compare


class Device(models.Model):
    """Minimal representation of a provisioned edge device."""

    name = models.CharField(max_length=100)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="gateway_devices",
    )
    source_device = models.OneToOneField(
        "devices.Device",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="gateway_device",
        help_text="Link back to the primary devices.Device entry when available.",
    )
    location = models.CharField(max_length=200, blank=True)
    latest_payload = models.JSONField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)

    device_secret = models.CharField(
        max_length=128,
        null=True,
        blank=True,
        help_text="Last issued device credential in plain text (optional).",
    )
    device_secret_hash = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        editable=False,
        help_text="SHA-256 hash of the active device credential.",
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["owner", "created_at"]),
        ]

    def __str__(self) -> str:  # pragma: no cover - human readable only
        if self.source_device:
            return f"{self.source_device}"
        return f"{self.name} ({self.owner})"

    # Credential helpers -----------------------------------------------------

    def issue_api_secret(self) -> str:
        """Generate and persist a new bearer token, returning the plain value."""

        token = secrets.token_urlsafe(32)
        token_hash = self._hash(token)
        self.device_secret = token
        self.device_secret_hash = token_hash
        self.last_seen = timezone.now()
        self.save(update_fields=["device_secret", "device_secret_hash", "last_seen"])
        return token

    def clear_api_secret(self) -> None:
        self.device_secret = None
        self.device_secret_hash = None
        self.save(update_fields=["device_secret", "device_secret_hash"])

    def validate_api_secret(self, candidate: str) -> bool:
        if not candidate or not self.device_secret_hash:
            return False
        candidate_hash = self._hash(candidate)
        return constant_time_compare(candidate_hash, self.device_secret_hash)

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()


class DeviceProvisioningToken(models.Model):
    """One-time token issued by operators to bootstrap a device."""

    DEFAULT_LIFETIME = None

    device = models.ForeignKey(
        Device,
        on_delete=models.CASCADE,
        related_name="provisioning_tokens",
    )
    token_hash = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    used_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    issued_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="issued_gateway_tokens",
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["device", "expires_at"]),
        ]

    def __str__(self) -> str:  # pragma: no cover - human readable only
        state = "used" if self.used_at else "pending"
        return f"Token<{self.device_id}> ({state})"

    # Token lifecycle --------------------------------------------------------

    @classmethod
    def issue(
        cls,
        *,
        device: Device,
        issued_by=None,
        lifetime: timedelta | None = None,
        metadata: dict | None = None,
    ) -> tuple[str, "DeviceProvisioningToken"]:
        if lifetime is None:
            lifetime = cls.DEFAULT_LIFETIME
        plain = secrets.token_urlsafe(32)
        token_obj = cls.objects.create(
            device=device,
            issued_by=issued_by,
            expires_at=(timezone.now() + lifetime) if lifetime is not None else None,
            token_hash=cls._hash(plain),
            metadata=metadata or {},
        )
        return plain, token_obj

    @classmethod
    def find_active(cls, token: str) -> "DeviceProvisioningToken | None":
        candidate = cls.objects.filter(token_hash=cls._hash(token)).select_related("device").first()
        if not candidate:
            return None
        if candidate.used_at:
            return None
        if candidate.expires_at is not None and candidate.expires_at <= timezone.now():
            return None
        return candidate

    def mark_used(self) -> None:
        self.used_at = timezone.now()
        self.save(update_fields=["used_at"])

    def update_metadata(self, **kwargs) -> None:
        info = self.metadata or {}
        info.update({k: v for k, v in kwargs.items() if v is not None})
        self.metadata = info
        self.save(update_fields=["metadata"])

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()


class DeviceTelemetry(models.Model):
    """Captured telemetry samples per device."""

    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="telemetry")
    payload = models.JSONField()
    received_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-received_at"]
        indexes = [models.Index(fields=["device", "-received_at"])]

    def __str__(self) -> str:  # pragma: no cover - human readable only
        return f"Telemetry<{self.device_id}> @ {self.received_at:%Y-%m-%d %H:%M:%S}"
