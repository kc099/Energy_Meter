from django.db import models
from django.db.models import Q
from django.conf import settings
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password, check_password
from datetime import timedelta
import base64
import logging
import requests
import json
import secrets
import hashlib
import uuid
import re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .fields import EncryptedJSONField, EncryptedCharField


logger = logging.getLogger(__name__)

IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

class Shift(models.Model):
    name = models.CharField(max_length=50)  # e.g., "Morning Shift", "Night Shift"
    start_time = models.TimeField()
    end_time = models.TimeField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'shifts'
        ordering = ['start_time']

    def __str__(self):
        start = self.start_time.strftime('%I:%M %p').lstrip('0').lower()
        end = self.end_time.strftime('%I:%M %p').lstrip('0').lower()
        return f"{self.name} ({start} - {end})"
        
    @classmethod
    def get_current_shift(cls):
        current_time = timezone.localtime().time()
        active_shifts = cls.objects.filter(is_active=True)
        
        for shift in active_shifts:
            # Handle shifts that cross midnight
            if shift.start_time >= shift.end_time:
                # If shift crosses midnight (e.g., 22:00 to 06:00)
                if current_time >= shift.start_time or current_time < shift.end_time:
                    return shift
            else:
                # Regular shift (e.g., 09:00 to 17:00)
                if shift.start_time <= current_time < shift.end_time:
                    return shift
        return None

    def clean(self):
        if not (self.start_time and self.end_time):
            return

        # For shifts crossing midnight (e.g., 22:00 to 06:00)
        crosses_midnight = self.start_time >= self.end_time
        
        # Check for overlapping shifts
        other_shifts = Shift.objects.exclude(id=self.id).filter(is_active=True)
        
        for other in other_shifts:
            # For shifts crossing midnight
            other_crosses_midnight = other.start_time >= other.end_time
            
            if crosses_midnight and other_crosses_midnight:
                # Both shifts cross midnight - they must not overlap at all
                if not (self.end_time <= other.start_time or other.end_time <= self.start_time):
                    raise ValidationError(f'This shift overlaps with {other.name} ({other.start_time.strftime("%H:%M")} - {other.end_time.strftime("%H:%M")})')
            elif crosses_midnight:
                # Current shift crosses midnight, other doesn't
                if not (self.end_time <= other.start_time and other.end_time <= self.start_time):
                    raise ValidationError(f'This shift overlaps with {other.name} ({other.start_time.strftime("%H:%M")} - {other.end_time.strftime("%H:%M")})')
            elif other_crosses_midnight:
                # Other shift crosses midnight, current doesn't
                if not (other.end_time <= self.start_time and self.end_time <= other.start_time):
                    raise ValidationError(f'This shift overlaps with {other.name} ({other.start_time.strftime("%H:%M")} - {other.end_time.strftime("%H:%M")})')
            else:
                # Neither shift crosses midnight - simple comparison
                if not (self.end_time <= other.start_time or other.end_time <= self.start_time):
                    raise ValidationError(f'This shift overlaps with {other.name} ({other.start_time.strftime("%H:%M")} - {other.end_time.strftime("%H:%M")})')

class ShiftReport(models.Model):
    shift = models.ForeignKey(Shift, on_delete=models.CASCADE, related_name='reports')
    device = models.ForeignKey('Device', on_delete=models.CASCADE, related_name='shift_reports')
    date = models.DateField()
    min_power_factor = models.FloatField()
    max_power_factor = models.FloatField()
    min_power_factor_time = models.DateTimeField()
    max_power_factor_time = models.DateTimeField()
    avg_power_factor = models.FloatField()
    total_kwh = models.FloatField()
    min_current = models.FloatField(default=0)
    max_current = models.FloatField(default=0)
    avg_current = models.FloatField(default=0)
    min_current_time = models.DateTimeField(null=True, blank=True)
    max_current_time = models.DateTimeField(null=True, blank=True)
    min_voltage = models.FloatField(default=0)
    max_voltage = models.FloatField(default=0)
    avg_voltage = models.FloatField(default=0)
    min_voltage_time = models.DateTimeField(null=True, blank=True)
    max_voltage_time = models.DateTimeField(null=True, blank=True)
    data_points = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'shift_reports'
        ordering = ['-date', 'shift__start_time']
        unique_together = ['shift', 'device', 'date']

    def __str__(self):
        return f"{self.device} - {self.shift} - {self.date}"

class Device(models.Model):
    class ProvisioningState(models.TextChoices):
        ACTIVE = 'active', 'Active'
        PENDING = 'pending', 'Pending Claim'

    DEVICE_TYPE_CHOICES = [
        ('meter', 'Energy Meter'),
        ('gas_monitor', 'Gas Monitor'),
        ('andon', 'Andon Station'),
    ]

    ADDRESS_TYPE_CHOICES = [
        ('ip', 'IP Address'),
        ('api', 'API Endpoint'),
    ]

    device_type = models.CharField(max_length=50, choices=DEVICE_TYPE_CHOICES)
    duid = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        editable=False,
        null=True,  # Temporarily allow null for migration
        help_text="Device universal identifier used for cross-system correlation",
    )
    device_owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='devices')
    located_at = models.CharField(max_length=100)
    device_address = EncryptedCharField(max_length=500, help_text="Device IP address or API endpoint URL (encrypted)")
    address_type = models.CharField(max_length=3, choices=ADDRESS_TYPE_CHOICES, default='ip')
    latest_value = EncryptedJSONField(null=True, blank=True, help_text="Latest data received from device (encrypted)")
    last_updated = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    device_secret = EncryptedJSONField(
        null=True,
        blank=True,
        help_text="Encrypted API credential shared with the device",
    )
    device_secret_hash = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        editable=False,
        help_text="SHA-256 hash of the active device credential",
    )
    encryption_key_b64 = EncryptedCharField(
        max_length=256,
        null=True,
        blank=True,
        help_text="Base64 encoded AES key issued to the device",
    )
    provisioning_state = models.CharField(
        max_length=20,
        choices=ProvisioningState.choices,
        default=ProvisioningState.ACTIVE,
        help_text="Tracks whether the device has completed credential provisioning",
    )
    polling_interval = models.FloatField(default=0.5, help_text="Polling interval in seconds", editable=False)
    shared_with = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='shared_devices',
        through='DeviceShare',
        blank=True,
        help_text="Users who have been granted access to this device",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'device'
        ordering = ['-created_at']
        unique_together = ['device_owner', 'device_address']

    def __str__(self):
        return f"{self.device_type} at {self.located_at}"

    def format_reading(self, data):
        """
        Format the data into a structured reading
        """
        try:
            # Handle string input
            if isinstance(data, str):
                # Remove curly braces and split by comma
                data = data.strip('{}').split(',')
            
            if len(data) != 5:
                raise ValueError(f"Expected 5 values, got {len(data)}")
                
            # Clean and convert each value - strip whitespace and convert to float
            data = [float(str(val).strip()) for val in data]
            
            # Format power factor to 3 decimal places
            power_factor = round(data[2], 3)
            
            return {
                'voltage': data[0],
                'current': data[1],
                'power_factor': power_factor,
                'kwh': data[3],
                'kwah': data[4]
            }
        except (IndexError, ValueError) as e:
            print(f"Error formatting reading: {str(e)}")  # Debug print
            return None

    def get_data_url(self):
        """
        Get the appropriate URL for data polling based on address type
        """
        if self.address_type == 'ip':
            return f"http://{self.device_address}/data"
        else:
            # For API endpoint, use the address as is
            return self.device_address

    def issue_api_secret(self) -> str:
        """Generate, store, and return a new device API credential."""
        secret = secrets.token_urlsafe(32)
        self.device_secret = secret
        self.device_secret_hash = self._hash_secret(secret)
        self.provisioning_state = self.ProvisioningState.ACTIVE
        self.is_active = True
        self.save(update_fields=['device_secret', 'device_secret_hash', 'provisioning_state', 'is_active'])
        return secret

    def get_or_create_encryption_key(self) -> str:
        """Return the device AES key, generating and persisting it when missing."""
        if not self.encryption_key_b64:
            key_bytes = secrets.token_bytes(32)
            self.encryption_key_b64 = base64.b64encode(key_bytes).decode('ascii')
            self.save(update_fields=['encryption_key_b64'])
        return self.encryption_key_b64

    def get_encryption_key_bytes(self) -> bytes:
        """Return the AES key in bytes, ensuring it exists."""
        key_b64 = self.get_or_create_encryption_key()
        return base64.b64decode(key_b64)

    def clear_api_secret(self):
        """Remove the stored API credential."""
        self.device_secret = None
        self.device_secret_hash = None
        self.provisioning_state = self.ProvisioningState.PENDING
        self.is_active = False
        self.save(update_fields=['device_secret', 'device_secret_hash', 'provisioning_state', 'is_active'])

    def validate_api_secret(self, candidate: str) -> bool:
        """Check whether the provided secret matches the stored credential."""
        if not candidate or not self.device_secret_hash:
            return False
        return constant_time_compare(self.device_secret_hash, self._hash_secret(candidate))

    @staticmethod
    def _hash_secret(value: str) -> str:
        return hashlib.sha256(value.encode('utf-8')).hexdigest()

    def poll_device(self):
        """
        Poll the device for new data
        """
        logger.warning("Starting to poll device device_id=%s", self.id)
        try:
            # Prepare URL
            url = self.device_address
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            logger.warning("Requesting device data device_id=%s", self.id)

            # Make request with longer timeout
            response = requests.get(url, timeout=10)
            logger.warning("Device response status device_id=%s status=%s", self.id, response.status_code)
            logger.warning("Device response bundle=%s", self._log_bundle_for_log(response.text))
            response.raise_for_status()
            
            # Try parsing response data
            try:
                data = response.json()
                logger.warning("Parsed JSON bundle=%s", self._log_bundle_for_log(data))
            except json.JSONDecodeError:
                logger.warning("Response not JSON device_id=%s", self.id)
                data = response.text.strip()
            
            # Handle different response formats
            formatted_data = None
            if isinstance(data, dict):
                formatted_data = data
            else:
                formatted_data = self.format_reading(data)
                
            if not formatted_data:
                raise ValueError(f"Could not format data: {data}")

            logger.warning("Formatted reading bundle=%s", self._log_bundle_for_log(formatted_data))
            
            # Update device state
            self.latest_value = formatted_data
            self.last_updated = timezone.now()
            self.is_active = True
            self.save()
            
            # Store in historical data
            DeviceData.objects.create(device=self, value=formatted_data)
            
            logger.warning("Successfully stored device data device_id=%s", self.id)
            return True, formatted_data
            
        except requests.exceptions.RequestException as e:
            masked_error = self._redact_ip_addresses(str(e))
            logger.warning("Request error device_id=%s error=%s", self.id, masked_error)
            self.is_active = False
            self.save()
            return False, f"Connection error: {str(e)}"
        except json.JSONDecodeError as e:
            masked_error = self._redact_ip_addresses(str(e))
            logger.warning("JSON parsing error device_id=%s error=%s", self.id, masked_error)
            self.is_active = False
            self.save()
            return False, f"Data format error: {str(e)}"
        except Exception as e:
            masked_error = self._redact_ip_addresses(str(e))
            logger.warning("Unexpected error device_id=%s error=%s", self.id, masked_error)
            self.is_active = False
            self.save()
            return False, str(e)

    def _encrypt_value_for_log(self, value) -> str:
        """Encrypt a JSON-serialisable value with the device AES key."""

        key_bytes = self.get_encryption_key_bytes()
        nonce = secrets.token_bytes(12)
        serialized = json.dumps(value, default=str).encode("utf-8")
        ciphertext = AESGCM(key_bytes).encrypt(nonce, serialized, None)
        return base64.b64encode(nonce + ciphertext).decode("ascii")

    @staticmethod
    def _redact_ip_addresses(value) -> str:
        """Replace IPv4 addresses in the provided value with a redacted token."""

        if value is None:
            return ""
        text = value if isinstance(value, str) else str(value)
        return IPV4_PATTERN.sub("<redacted-ip>", text)

    def _log_bundle_for_log(self, payload) -> str:
        """Return logging structure with encrypted uid and payload."""

        try:
            uid = str(self.duid or self.id)
            bundle = {
                "uid": self._encrypt_value_for_log(uid),
                "payload": self._encrypt_value_for_log(payload),
            }
            return json.dumps(bundle)
        except Exception as exc:  # pragma: no cover - logging safeguard
            masked_error = self._redact_ip_addresses(str(exc))
            logger.warning("Failed to build log bundle device_id=%s error=%s", self.id, masked_error)
            return json.dumps({"uid": "<unable>", "payload": "<unable>"})

    def has_active_provisioning_window(self) -> bool:
        """Return True if there is an unexpired provisioning token for this device."""
        now = timezone.now()
        return self.provisioning_tokens.filter(used_at__isnull=True).filter(
            Q(expires_at__isnull=True) | Q(expires_at__gt=now)
        ).exists()

    @classmethod
    def purge_expired_pending(cls, owner=None) -> int:
        """Remove pending devices whose provisioning window has fully expired."""
        now = timezone.now()
        queryset = cls.objects.filter(provisioning_state=cls.ProvisioningState.PENDING)
        if owner is not None:
            queryset = queryset.filter(device_owner=owner)

        pending_devices = list(queryset.only('id', 'created_at'))
        if not pending_devices:
            return 0

        pending_ids = [device.id for device in pending_devices]
        active_expiries = (
            DeviceProvisioningToken.objects.filter(
                device_id__in=pending_ids,
                used_at__isnull=True,
            )
            .values('device_id')
            .annotate(latest_expiry=models.Max('expires_at'))
        )
        expiry_map = {row['device_id']: row['latest_expiry'] for row in active_expiries}

        lifetime_window = DeviceProvisioningToken.DEFAULT_LIFETIME
        default_cutoff = None
        if lifetime_window is not None:
            default_cutoff = now - lifetime_window
        stale_ids: list[int] = []
        for device in pending_devices:
            latest_expiry = expiry_map.get(device.id)
            if latest_expiry and latest_expiry > now:
                continue
            created_at = device.created_at
            if default_cutoff is None:
                continue
            if created_at and created_at > default_cutoff:
                continue
            stale_ids.append(device.id)

        if not stale_ids:
            return 0

        cls.objects.filter(id__in=stale_ids).delete()
        return len(stale_ids)


class DeviceProvisioningToken(models.Model):
    DEFAULT_LIFETIME = None

    device = models.ForeignKey('Device', on_delete=models.CASCADE, related_name='provisioning_tokens')
    token_hash = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='issued_device_tokens',
    )
    metadata = models.JSONField(null=True, blank=True, help_text="Additional context captured during provisioning")

    class Meta:
        db_table = 'device_provisioning_tokens'
        ordering = ['-created_at']

    def __str__(self):
        status = 'used' if self.used_at else 'pending'
        return f"Token for {self.device_id} ({status})"

    @classmethod
    def issue(
        cls,
        device,
        created_by=None,
        lifetime: timedelta | None = None,
        metadata: dict | None = None,
    ) -> tuple[str, "DeviceProvisioningToken"]:
        token = secrets.token_urlsafe(32)
        if lifetime is None:
            lifetime = cls.DEFAULT_LIFETIME

        if lifetime is None:
            expires_at = None
        else:
            expires_at = timezone.now() + lifetime
        token_obj = cls.objects.create(
            device=device,
            token_hash=cls._hash(token),
            expires_at=expires_at,
            created_by=created_by,
            metadata=metadata or {},
        )
        return token, token_obj

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode('utf-8')).hexdigest()

    @classmethod
    def find_active(cls, token: str):
        token_hash = cls._hash(token)
        try:
            candidate = cls.objects.select_related('device').get(token_hash=token_hash)
        except cls.DoesNotExist:
            return None
        if not candidate.is_valid():
            return None
        return candidate

    def mark_used(self):
        self.used_at = timezone.now()
        self.save(update_fields=['used_at'])

    def update_metadata(self, **kwargs):
        metadata = self.metadata or {}
        metadata.update({k: v for k, v in kwargs.items() if v is not None})
        self.metadata = metadata
        self.save(update_fields=['metadata'])

    def is_valid(self) -> bool:
        if self.used_at is not None:
            return False
        if self.expires_at is None:
            return True
        return timezone.now() < self.expires_at


class DeviceTokenAccessOTP(models.Model):
    device = models.ForeignKey(
        'Device',
        on_delete=models.CASCADE,
        related_name='token_access_otps',
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='device_token_otps',
    )
    code_hash = models.CharField(max_length=128)
    expires_at = models.DateTimeField()
    verified_at = models.DateTimeField(null=True, blank=True)
    attempt_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    MAX_ATTEMPTS = 5
    DEFAULT_TTL = timedelta(minutes=2)

    class Meta:
        indexes = [
            models.Index(fields=['device', 'user', 'expires_at']),
        ]
        ordering = ['-created_at']

    @classmethod
    def issue(
        cls,
        device,
        user,
        *,
        ttl: timedelta | None = None,
    ) -> tuple[str, 'DeviceTokenAccessOTP']:
        now = timezone.now()
        cls.objects.filter(
            device=device,
            user=user,
            verified_at__isnull=True,
            expires_at__lte=now,
        ).delete()
        cls.objects.filter(
            device=device,
            user=user,
            verified_at__isnull=True,
            expires_at__gt=now,
        ).update(expires_at=now)
        ttl = ttl or cls.DEFAULT_TTL
        raw_code = f"{secrets.randbelow(1_000_000):06d}"
        otp = cls.objects.create(
            device=device,
            user=user,
            code_hash=make_password(raw_code),
            expires_at=now + ttl,
        )
        return raw_code, otp

    def is_expired(self) -> bool:
        return timezone.now() > self.expires_at

    def mark_verified(self) -> None:
        if not self.verified_at:
            self.verified_at = timezone.now()
            self.save(update_fields=['verified_at', 'attempt_count'])

    def register_failure(self) -> None:
        self.attempt_count += 1
        updates = ['attempt_count']
        if self.attempt_count >= self.MAX_ATTEMPTS:
            self.expires_at = timezone.now()
            updates.append('expires_at')
        self.save(update_fields=updates)

    def validate_code(self, raw_code: str) -> bool:
        return check_password(raw_code, self.code_hash)


class DeviceShare(models.Model):
    class AccessLevel(models.TextChoices):
        VIEWER = 'viewer', 'Data Viewer'
        INSPECTOR = 'inspector', 'Configuration Viewer'
        MANAGER = 'manager', 'Device Manager'

    ROLE_DESCRIPTIONS = {
        AccessLevel.VIEWER.value: 'View dashboards and history only',
        AccessLevel.INSPECTOR.value: 'View device data and configuration details',
        AccessLevel.MANAGER.value: 'Full management access (poll, configure, remove)',
    }

    device = models.ForeignKey('Device', on_delete=models.CASCADE, related_name='device_shares')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='device_shares')
    role = models.CharField(max_length=20, choices=AccessLevel.choices, default=AccessLevel.VIEWER)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'device_shares'
        unique_together = ('device', 'user')
        ordering = ['user__username']

    def __str__(self):
        return f"{self.user} → {self.device} ({self.get_role_display()})"

    @classmethod
    def role_options(cls):
        return [
            {
                'value': choice.value,
                'label': choice.label,
                'description': cls.ROLE_DESCRIPTIONS.get(choice.value, ''),
            }
            for choice in cls.AccessLevel
        ]

    @classmethod
    def default_role(cls):
        return cls.AccessLevel.VIEWER

    def description(self):
        return self.ROLE_DESCRIPTIONS.get(self.role, '')


class DeviceData(models.Model):
    """
    Historical data from devices
    """
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='historical_data')
    value = EncryptedJSONField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'device_data'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['device', '-timestamp']),
        ]
     

    def __str__(self):
        return f"Data from {self.device} at {self.timestamp}"
