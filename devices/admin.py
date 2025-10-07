from django.contrib import admin

from .models import Device, DeviceProvisioningToken


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'device_type',
        'located_at',
        'device_owner',
        'provisioning_state',
        'is_active',
        'device_secret_hash',
        'created_at',
    )
    list_filter = ('device_type', 'is_active', 'provisioning_state')
    search_fields = ('located_at', 'device_address', 'device_owner__username')


@admin.register(DeviceProvisioningToken)
class DeviceProvisioningTokenAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'device',
        'created_at',
        'expires_at',
        'used_at',
        'created_by',
    )
    list_filter = ('created_at', 'expires_at', 'used_at')
    search_fields = ('device__located_at', 'device__device_address', 'created_by__username')
