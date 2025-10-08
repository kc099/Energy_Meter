from django.contrib import admin

from .models import Device, DeviceProvisioningToken, DeviceTelemetry


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "last_seen", "source_device")
    search_fields = ("name", "owner__username", "owner__email")
    readonly_fields = ("device_secret", "device_secret_hash", "last_seen", "created_at", "source_device")


@admin.register(DeviceProvisioningToken)
class DeviceProvisioningTokenAdmin(admin.ModelAdmin):
    list_display = ("device", "expires_at", "used_at")
    search_fields = ("device__name",)
    readonly_fields = ("token_hash", "created_at")


@admin.register(DeviceTelemetry)
class DeviceTelemetryAdmin(admin.ModelAdmin):
    list_display = ("device", "received_at")
    search_fields = ("device__name",)
    readonly_fields = ("payload", "received_at")
    ordering = ("-received_at",)
