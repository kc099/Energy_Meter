from __future__ import annotations

from datetime import datetime

from django.contrib.auth.decorators import login_required
from django.db.models import Min, Max, Q
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_GET

from accounts.models import User
from devices.models import Device, DeviceShare, DeviceData, Shift, ShiftReport
from devices.views import _find_andon_station, _build_andon_snapshot
from EM_main.views import (
    READINGS_SORT_CHOICES,
    MINMAX_SORT_CHOICES,
    _build_preview_data,
    _device_access_q,
    _normalize_dataset,
    _normalize_sort,
    _validated_date_range,
)

from .serializers import (
    _isoformat,
    serialize_device_detail,
    serialize_device_history,
    serialize_device_share,
    serialize_device_summary,
    serialize_minmax_stats,
    serialize_role_option,
    serialize_shift,
    serialize_shift_full,
    serialize_shift_report,
    serialize_user_brief,
)


def _device_role(device: Device, user) -> str | None:
    if not getattr(user, "is_authenticated", False):
        return None
    if device.device_owner_id == getattr(user, "id", None):
        return DeviceShare.AccessLevel.MANAGER
    share = next(
        (entry for entry in device.device_shares.all() if entry.user_id == user.id),
        None,
    )
    return share.role if share else None


def _andon_snapshot_payload(snapshot: dict | None) -> dict | None:
    if not snapshot:
        return None
    return {
        **snapshot,
        "created_at": _isoformat(snapshot.get("created_at")),
        "last_updated": _isoformat(snapshot.get("last_updated")),
        "fault_time": _isoformat(snapshot.get("fault_time")),
        "resolved_time": _isoformat(snapshot.get("resolved_time")),
    }


@login_required
@require_GET
def dashboard_view(request):
    devices_qs = (
        Device.objects.filter(
            Q(device_owner=request.user) | Q(shared_with=request.user)
        )
        .select_related("device_owner")
        .prefetch_related("device_shares__user")
        .order_by("-created_at")
        .distinct()
    )
    devices = list(devices_qs)
    owned_device_ids = {device.id for device in devices if device.device_owner_id == request.user.id}
    config_access_ids = set(owned_device_ids)

    for device in devices:
        role = _device_role(device, request.user)
        if role in (
            DeviceShare.AccessLevel.INSPECTOR,
            DeviceShare.AccessLevel.MANAGER,
        ):
            config_access_ids.add(device.id)

    current_shift = Shift.get_current_shift()

    payload = {
        "devices": [serialize_device_summary(device, user=request.user) for device in devices],
        "device_totals": {
            "total": len(devices),
            "active": sum(1 for device in devices if device.is_active),
            "inactive": sum(1 for device in devices if not device.is_active),
        },
        "owned_device_ids": sorted(owned_device_ids),
        "config_access_ids": sorted(config_access_ids),
        "current_shift": serialize_shift(current_shift) if current_shift else None,
    }
    return JsonResponse(payload)


@login_required
@require_GET
def device_list_view(request):
    owned_ids = set(
        Device.objects.filter(
            device_owner=request.user,
            provisioning_state=Device.ProvisioningState.ACTIVE,
        ).values_list("id", flat=True)
    )
    devices_qs = (
        Device.objects.filter(
            Q(device_owner=request.user) | Q(shared_with=request.user),
            provisioning_state=Device.ProvisioningState.ACTIVE,
        )
        .select_related("device_owner")
        .prefetch_related("device_shares__user")
        .order_by("-created_at")
        .distinct()
    )
    devices = [serialize_device_summary(device, user=request.user) for device in devices_qs]

    payload = {
        "devices": devices,
        "owned_device_ids": sorted(owned_ids),
    }
    return JsonResponse(payload)


@login_required
@require_GET
def device_detail_view(request, device_id: int):
    device = get_object_or_404(
        Device.objects.select_related("device_owner").prefetch_related("device_shares__user"),
        id=device_id,
    )
    is_owner = device.device_owner_id == request.user.id

    if device.provisioning_state != Device.ProvisioningState.ACTIVE and not is_owner:
        raise Http404("Device not found")

    role = _device_role(device, request.user)
    if role is None:
        raise Http404("Device not found")

    accessible_devices = (
        Device.objects.filter(
            Q(device_owner=request.user) | Q(shared_with=request.user),
            provisioning_state=Device.ProvisioningState.ACTIVE,
        )
        .order_by("id")
        .distinct()
    )
    next_device = accessible_devices.filter(id__gt=device_id).order_by("id").first()
    prev_device = accessible_devices.filter(id__lt=device_id).order_by("-id").first()

    history_qs = DeviceData.objects.filter(device=device).order_by("-timestamp")[:100]
    history_entries = list(history_qs)
    chart_history = list(reversed(history_entries))

    chart_payload = {
        "timestamps": [entry.timestamp.strftime("%H:%M:%S") for entry in chart_history],
        "voltage": [entry.value.get("voltage", 0) if isinstance(entry.value, dict) else 0 for entry in chart_history],
        "current": [entry.value.get("current", 0) if isinstance(entry.value, dict) else 0 for entry in chart_history],
        "power_factor": [entry.value.get("power_factor", 0) if isinstance(entry.value, dict) else 0 for entry in chart_history],
        "kwh": [entry.value.get("kwh", 0) if isinstance(entry.value, dict) else 0 for entry in chart_history],
    }

    shared_entries = list(
        device.device_shares.select_related("user").order_by("user__username")
    )

    is_andon = device.device_type == "andon"
    andon_snapshot = None
    if is_andon:
        station = _find_andon_station(device)
        if station:
            andon_snapshot = _build_andon_snapshot(station)

    payload = {
        "device": serialize_device_detail(device, user=request.user),
        "history": list(serialize_device_history(history_entries)),
        "chart_data": chart_payload,
        "navigation": {
            "next_device_id": getattr(next_device, "id", None),
            "prev_device_id": getattr(prev_device, "id", None),
        },
        "permissions": {
            "role": role,
            "can_manage": role == DeviceShare.AccessLevel.MANAGER,
            "can_view_config": role in (
                DeviceShare.AccessLevel.INSPECTOR,
                DeviceShare.AccessLevel.MANAGER,
            ),
            "is_owner": is_owner,
        },
        "shared_entries": [serialize_device_share(entry) for entry in shared_entries],
        "alerts": [
            {
                "level": "info",
                "message": "This device is awaiting provisioning. Share the token to complete setup.",
            }
            for _ in [1]
            if is_owner and device.provisioning_state == Device.ProvisioningState.PENDING
        ],
        "is_andon": is_andon,
        "andon_snapshot": _andon_snapshot_payload(andon_snapshot),
    }
    return JsonResponse(payload)


@login_required
@require_GET
def manage_shifts_view(request):
    shifts = Shift.objects.all().order_by("start_time")
    return JsonResponse({"shifts": [serialize_shift_full(shift) for shift in shifts]})


@login_required
@require_GET
def shift_reports_view(request):
    reports_qs = (
        ShiftReport.objects.filter(
            Q(device__device_owner=request.user) | Q(device__shared_with=request.user)
        )
        .select_related("shift", "device")
        .order_by("-date", "shift__start_time")
        .distinct()
    )

    date_str = request.GET.get("date")
    if date_str:
        try:
            filter_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError as exc:
            return JsonResponse({"error": "Invalid date format."}, status=400)
        reports_qs = reports_qs.filter(date=filter_date)

    payload = {
        "reports": [serialize_shift_report(report) for report in reports_qs],
        "selected_date": date_str,
        "shifts": [serialize_shift(shift) for shift in Shift.objects.all()],
    }
    return JsonResponse(payload)


@login_required
@require_GET
def bulk_share_overview_view(request):
    owned_devices = (
        Device.objects.filter(device_owner=request.user)
        .select_related("device_owner")
        .prefetch_related("device_shares__user")
        .order_by("created_at")
    )
    available_users = (
        User.objects.filter(is_active=True)
        .exclude(id=request.user.id)
        .order_by("username")
    )

    payload = {
        "devices": [
            {
                "device": serialize_device_summary(device, user=request.user),
                "shares": [serialize_device_share(share) for share in device.device_shares.all()],
            }
            for device in owned_devices
        ],
        "available_users": [serialize_user_brief(user) for user in available_users],
        "role_choices": [serialize_role_option(option) for option in DeviceShare.role_options()],
    }
    return JsonResponse(payload)


@login_required
@require_GET
def reports_preview_view(request):
    dataset_raw = request.GET.get("dataset", "")
    export_format = request.GET.get("format", "csv")
    from_value = request.GET.get("from")
    to_value = request.GET.get("to")
    page = request.GET.get("page", "1")
    sort_raw = request.GET.get("sort")

    normalized_dataset = _normalize_dataset(dataset_raw)
    sort_key = _normalize_sort(normalized_dataset, sort_raw)

    minmax_stats = serialize_minmax_stats(
        ShiftReport.objects.filter(_device_access_q(request.user)).aggregate(
            overall_min=Min("min_power_factor"),
            overall_max=Max("max_power_factor"),
        )
    )

    sort_choices = (
        MINMAX_SORT_CHOICES if normalized_dataset == "minmax" else READINGS_SORT_CHOICES
    )
    sort_options = [
        {"value": value, "label": label}
        for value, label in sort_choices
    ]

    preview_data = None
    if dataset_raw and from_value and to_value:
        try:
            start_date, end_date = _validated_date_range(from_value, to_value)
            preview_data = _build_preview_data(
                request.user,
                normalized_dataset,
                start_date,
                end_date,
                page=page,
                sort_key=sort_key,
            )
        except ValueError as exc:
            return JsonResponse({"error": str(exc)}, status=400)

    payload = {
        "form": {
            "dataset": dataset_raw,
            "export_format": export_format,
            "from": from_value,
            "to": to_value,
            "page": page,
            "sort": sort_key,
        },
        "preview": preview_data,
        "minmax_stats": minmax_stats,
        "normalized_dataset": normalized_dataset,
        "sort_choices": sort_options,
    }
    return JsonResponse(payload)
