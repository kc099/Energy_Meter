"""Lightweight serializers that expose template context as JSON."""
from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from django.utils import timezone
from django.utils.timesince import timesince

from accounts.models import User
from devices.models import Device, DeviceData, DeviceShare, Shift, ShiftReport


def _isoformat(dt):
    if not dt:
        return None
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, timezone.get_current_timezone())
    return timezone.localtime(dt).isoformat()


def _time_string(value):
    if value is None:
        return None
    return value.strftime("%H:%M")


def _timestamp_label(dt):
    if not dt:
        return None
    return timesince(dt) + " ago"


def _coerce_float(value):
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return value


def serialize_user_brief(user: Optional[User]) -> Optional[Dict[str, Any]]:
    if not user:
        return None
    return {
        "id": user.id,
        "username": user.username,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
    }


def serialize_shift(shift: Shift) -> Dict[str, Any]:
    return {
        "id": shift.id,
        "name": shift.name,
        "start_time": _time_string(shift.start_time),
        "end_time": _time_string(shift.end_time),
        "is_active": shift.is_active,
    }


def serialize_shift_full(shift: Shift) -> Dict[str, Any]:
    payload = serialize_shift(shift)
    payload.update(
        {
            "created_at": _isoformat(shift.created_at),
            "updated_at": _isoformat(shift.updated_at),
        }
    )
    return payload


def serialize_device_share(entry: DeviceShare) -> Dict[str, Any]:
    return {
        "id": entry.id,
        "user": serialize_user_brief(entry.user),
        "role": entry.role,
        "role_label": entry.get_role_display(),
        "description": entry.description(),
        "created_at": _isoformat(entry.created_at),
    }


def _device_display_name(device: Device) -> str:
    try:
        return device.get_device_type_display()
    except AttributeError:
        return device.device_type


def serialize_device_summary(device: Device, *, user: User) -> Dict[str, Any]:
    is_owner = device.device_owner_id == getattr(user, "id", None)
    share = None
    if not is_owner and getattr(user, "id", None):
        share = next(
            (item for item in device.device_shares.all() if item.user_id == user.id),
            None,
        )
    access_role = share.role if share else (DeviceShare.AccessLevel.MANAGER if is_owner else None)
    access_label = ""
    if access_role:
        try:
            access_label = DeviceShare.AccessLevel(access_role).label
        except ValueError:
            access_label = ""

    return {
        "id": device.id,
        "name": _device_display_name(device),
        "device_type": device.device_type,
        "located_at": device.located_at,
        "device_address": device.device_address,
        "address_type": device.address_type,
        "is_active": device.is_active,
        "created_at": _isoformat(device.created_at),
        "last_updated": _isoformat(device.last_updated),
        "last_updated_label": _timestamp_label(device.last_updated),
        "latest_value": device.latest_value or {},
        "is_owner": is_owner,
        "access_role": access_role,
        "access_role_label": access_label,
        "polling_interval": device.polling_interval,
        "provisioning_state": device.provisioning_state,
    }


def serialize_device_detail(device: Device, *, user: User) -> Dict[str, Any]:
    base = serialize_device_summary(device, user=user)
    base.update(
        {
            "owner": serialize_user_brief(device.device_owner),
            "provisioning_state": device.provisioning_state,
            "has_secret": bool(device.device_secret_hash),
        }
    )
    return base


def serialize_device_data(entry: DeviceData) -> Dict[str, Any]:
    value = entry.value or {}
    return {
        "id": entry.id,
        "timestamp": _isoformat(entry.timestamp),
        "voltage": value.get("voltage"),
        "current": value.get("current"),
        "power_factor": value.get("power_factor"),
        "kwh": value.get("kwh"),
        "kwah": value.get("kwah"),
    }


def serialize_device_history(entries: Iterable[DeviceData]) -> Iterable[Dict[str, Any]]:
    return [serialize_device_data(item) for item in entries]


def serialize_shift_report(report: ShiftReport) -> Dict[str, Any]:
    return {
        "id": report.id,
        "date": report.date.isoformat(),
        "device": {
            "id": report.device_id,
            "name": _device_display_name(report.device),
            "located_at": report.device.located_at,
        },
        "shift": {
            "id": report.shift_id,
            "name": report.shift.name,
            "start_time": _time_string(report.shift.start_time),
            "end_time": _time_string(report.shift.end_time),
        },
        "total_kwh": report.total_kwh,
        "min_power_factor": report.min_power_factor,
        "min_power_factor_time": _isoformat(report.min_power_factor_time),
        "max_power_factor": report.max_power_factor,
        "max_power_factor_time": _isoformat(report.max_power_factor_time),
        "avg_power_factor": report.avg_power_factor,
        "min_current": report.min_current,
        "min_current_time": _isoformat(report.min_current_time),
        "max_current": report.max_current,
        "max_current_time": _isoformat(report.max_current_time),
        "avg_current": report.avg_current,
        "min_voltage": report.min_voltage,
        "min_voltage_time": _isoformat(report.min_voltage_time),
        "max_voltage": report.max_voltage,
        "max_voltage_time": _isoformat(report.max_voltage_time),
        "avg_voltage": report.avg_voltage,
        "data_points": report.data_points,
        "created_at": _isoformat(report.created_at),
    }


def serialize_role_option(option: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "value": option.get("value"),
        "label": option.get("label"),
        "description": option.get("description"),
    }


def serialize_minmax_stats(stats: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "overall_min": _coerce_float(stats.get("overall_min")),
        "overall_max": _coerce_float(stats.get("overall_max")),
    }
