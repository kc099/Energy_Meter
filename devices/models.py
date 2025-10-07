from django.db import models
from django.conf import settings
from django.utils import timezone
from django.core.exceptions import ValidationError
import requests
import json

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
        return f"{self.name} ({self.start_time.strftime('%H:%M')} - {self.end_time.strftime('%H:%M')})"
        
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
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'shift_reports'
        ordering = ['-date', 'shift__start_time']
        unique_together = ['shift', 'device', 'date']

    def __str__(self):
        return f"{self.device} - {self.shift} - {self.date}"

class Device(models.Model):
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
    value = models.JSONField()
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'device_data'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['device', '-timestamp']),
        ]

    def __str__(self):
        return f"Data from {self.device} at {self.timestamp}"
