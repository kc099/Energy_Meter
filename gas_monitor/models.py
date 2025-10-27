from __future__ import annotations

from datetime import timedelta

from django.db import models
from django.utils import timezone

from devices.models import Device


class GasMonitorDevice(models.Model):
    """Extended metadata for devices of type `gas_monitor`."""

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        INACTIVE = "inactive", "Inactive"
        MAINTENANCE = "maintenance", "Maintenance"
        FAULT = "fault", "Fault"

    device = models.OneToOneField(
        Device,
        on_delete=models.CASCADE,
        related_name="gas_monitor",
        help_text="Link to the core devices.Device entry.",
    )
    location = models.CharField(max_length=200)
    installation_date = models.DateField(null=True, blank=True)
    last_maintenance_date = models.DateField(null=True, blank=True)
    status = models.CharField(
        max_length=12,
        choices=Status.choices,
        default=Status.ACTIVE,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Gas Monitor"
        verbose_name_plural = "Gas Monitors"
        ordering = ["-installation_date", "-created_at"]
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["location"]),
        ]

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"Gas Monitor {self.device.located_at or self.device.name}"

    @classmethod
    def active_devices(cls):
        return cls.objects.filter(status=cls.Status.ACTIVE)

    @classmethod
    def devices_needing_maintenance(cls, *, days_threshold: int):
        if days_threshold <= 0:
            return cls.objects.none()
        threshold_date = timezone.now().date() - timedelta(days=days_threshold)
        return cls.objects.filter(last_maintenance_date__lt=threshold_date)

    @classmethod
    def by_location(cls, location: str):
        return cls.objects.filter(location__iexact=location)


class GasMonitorTelemetry(models.Model):
    """Telemetry readings captured from a gas monitor."""

    device = models.ForeignKey(
        GasMonitorDevice,
        on_delete=models.CASCADE,
        related_name="telemetry",
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    gas_level = models.FloatField()
    unit = models.CharField(max_length=20, default="ppm")

    class Meta:
        verbose_name = "Gas Monitor Reading"
        verbose_name_plural = "Gas Monitor Readings"
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["timestamp"]),
            models.Index(fields=["device", "timestamp"]),
        ]

    def __str__(self) -> str:  # pragma: no cover - display helper
        return (
            f"{self.device} - {self.gas_level} {self.unit} "
            f"@ {self.timestamp:%Y-%m-%d %H:%M:%S}"
        )

    @classmethod
    def recent(cls, *, hours: int = 24):
        if hours <= 0:
            return cls.objects.none()
        time_threshold = timezone.now() - timedelta(hours=hours)
        return cls.objects.filter(timestamp__gte=time_threshold)

    @classmethod
    def average_gas_level(cls, *, device_id: int, start_time, end_time):
        return (
            cls.objects.filter(device_id=device_id, timestamp__range=(start_time, end_time))
            .aggregate(avg=models.Avg("gas_level"))
            .get("avg")
        )
