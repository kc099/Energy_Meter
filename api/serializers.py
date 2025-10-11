from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from django.utils import timezone
from django.utils.timesince import timesince

from accounts.models import User
from devices.models import Device, DeviceData, Shift, ShiftReport


def _isoformat(dt):
    if not dt:
        return None
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, timezone.get_current_timezone())
    return timezone.localtime(dt).isoformat()


def _humanize_timesince(dt):
    if not dt:
        return None
    return f"{timesince(dt)} ago"


def _humanize_timestamp(dt):
    if not dt:
        return None
    return timezone.localtime(dt).strftime("%Y-%m-%d %H:%M:%S")


def serialize_shift(shift: Shift) -> Dict[str, Any]:
    return {
        "id": shift.id,
        "name": shift.name,
        "start_time": shift.start_time.strftime("%H:%M"),
        "end_time": shift.end_time.strftime("%H:%M"),
        "is_active": shift.is_active,
    }


def serialize_user(user: Optional[User], *, include_shift: bool = True) -> Optional[Dict[str, Any]]:
    if not user:
        return None

    data = {
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "date_joined": _isoformat(user.date_joined),
    }

    if include_shift:
        current_shift = Shift.get_current_shift()
        data["current_shift"] = serialize_shift(current_shift) if current_shift else None

    return data


def serialize_device(device: Device, *, include_owner: bool = False) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "id": device.id,
        "device_type": device.device_type,
        "located_at": device.located_at,
        "device_address": device.device_address,
        "address_type": device.address_type,
        "latest_value": device.latest_value or {},
        "is_active": device.is_active,
        "polling_interval": device.polling_interval,
        "created_at": _isoformat(device.created_at),
        "last_updated": _isoformat(device.last_updated),
        "last_updated_human": _humanize_timesince(device.last_updated),
    }

    if include_owner:
        payload["owner"] = {
            "id": device.device_owner_id,
            "email": device.device_owner.email,
        }

    return payload


def serialize_device_history(entries: Iterable[DeviceData]) -> Iterable[Dict[str, Any]]:
    serialized = []
    for entry in entries:
        value = entry.value or {}
        serialized.append(
            {
                "id": entry.id,
                "timestamp": _isoformat(entry.timestamp),
                "timestamp_human": _humanize_timestamp(entry.timestamp),
                "value": {
                    "voltage": value.get("voltage"),
                    "current": value.get("current"),
                    "power_factor": value.get("power_factor"),
                    "kwh": value.get("kwh"),
                    "kwah": value.get("kwah"),
                },
            }
        )
    return serialized


def serialize_shift_report(report: ShiftReport) -> Dict[str, Any]:
    return {
        "id": report.id,
        "date": report.date.isoformat(),
        "shift_id": report.shift_id,
        "shift_name": report.shift.name,
        "device_id": report.device_id,
        "device_name": str(report.device),
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
    }
