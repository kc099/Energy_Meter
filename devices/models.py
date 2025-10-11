from django.db import models
from django.db.models import Q
from django.conf import settings
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from django.core.exceptions import ValidationError
from datetime import timedelta
import requests
import json
import secrets
import hashlib
from .fields import EncryptedJSONField

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
        ('sensor', 'Sensor'),
        ('monitor', 'Power Monitor'),
        ('andon', 'Andon Station'),
    ]

    ADDRESS_TYPE_CHOICES = [
        ('ip', 'IP Address'),
        ('api', 'API Endpoint'),
    ]

    device_type = models.CharField(max_length=50, choices=DEVICE_TYPE_CHOICES)
    device_owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='devices')
    located_at = models.CharField(max_length=100)
    device_address = models.CharField(max_length=200, help_text="Device IP address or API endpoint URL")
    address_type = models.CharField(max_length=3, choices=ADDRESS_TYPE_CHOICES, default='ip')
    latest_value = models.JSONField(null=True, blank=True, help_text="Latest data received from device")
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
        print(f"Starting to poll device at URL: {self.device_address}")  # Debug print
        try:
            # Prepare URL
            url = self.device_address
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            print(f"Requesting data from: {url}")  # Debug print

            # Make request with longer timeout
            response = requests.get(url, timeout=10)
            print(f"Response status code: {response.status_code}")  # Debug print
            print(f"Response content: {response.text}")  # Debug print
            response.raise_for_status()
            
            # Try parsing response data
            try:
                data = response.json()
                print(f"Parsed JSON data: {data}")  # Debug print
            except json.JSONDecodeError as e:
                print(f"Not JSON data, using raw text: {response.text}")  # Debug print
                data = response.text.strip()
            
            # Handle different response formats
            formatted_data = None
            if isinstance(data, dict):
                print("Data is already in dictionary format")  # Debug print
                formatted_data = data
            else:
                print(f"Attempting to format data: {data}")  # Debug print
                formatted_data = self.format_reading(data)
                
            if not formatted_data:
                raise ValueError(f"Could not format data: {data}")

            print(f"Successfully formatted data: {formatted_data}")  # Debug print
            
            # Update device state
            self.latest_value = formatted_data
            self.last_updated = timezone.now()
            self.is_active = True
            self.save()
            
            # Store in historical data
            DeviceData.objects.create(device=self, value=formatted_data)
            
            print("Successfully updated device and stored historical data")  # Debug print
            return True, formatted_data
            
        except requests.exceptions.RequestException as e:
            print(f"Request error: {str(e)}")  # Debug print
            self.is_active = False
            self.save()
            return False, f"Connection error: {str(e)}"
        except json.JSONDecodeError as e:
            print(f"JSON parsing error: {str(e)}")  # Debug print
            self.is_active = False
            self.save()
            return False, f"Data format error: {str(e)}"
        except Exception as e:
            print(f"Unexpected error: {str(e)}")  # Debug print
            self.is_active = False
            self.save()
            return False, str(e)

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
