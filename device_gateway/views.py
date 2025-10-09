from __future__ import annotations

import json
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .auth import bearer_required
from .models import Device, DeviceProvisioningToken, DeviceTelemetry
from devices.models import Device as PortalDevice


def _parse_json_body(request):
    try:
        return json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid JSON body") from exc


@csrf_exempt
@require_http_methods(["POST"])
def issue_provisioning_token_view(request, device_id: int):
    """Create a short-lived provisioning token for the specified device."""

    device = get_object_or_404(Device, id=device_id)
    try:
        payload = _parse_json_body(request)
    except ValueError as exc:
        return JsonResponse({"message": str(exc)}, status=400)

    lifetime_minutes = payload.get("lifetime_minutes")
    lifetime = None
    if lifetime_minutes is not None:
        try:
            minutes = max(1, int(lifetime_minutes))
            lifetime = timedelta(minutes=minutes)
        except (TypeError, ValueError):
            return JsonResponse({"message": "lifetime_minutes must be an integer."}, status=400)

    metadata = payload.get("metadata") or {}
    notes = payload.get("notes")
    if notes:
        metadata["notes"] = notes

    token, token_obj = DeviceProvisioningToken.issue(
        device=device,
        lifetime=lifetime,
        metadata=metadata,
    )

    return JsonResponse(
        {
            "token": token,
            "expires_at": token_obj.expires_at.isoformat() if token_obj.expires_at else None,
            "device_id": device.id,
        },
        status=201,
    )


@csrf_exempt
@require_http_methods(["POST"])
def claim_device_view(request):
    """Exchange a provisioning token for a permanent API key."""

    try:
        payload = _parse_json_body(request)
    except ValueError as exc:
        return JsonResponse({"message": str(exc)}, status=400)

    token = payload.get("token")
    if not token:
        return JsonResponse({"message": "token is required."}, status=400)

    candidate = DeviceProvisioningToken.find_active(token)
    if not candidate:
        return JsonResponse({"message": "Invalid or expired provisioning token."}, status=400)

    device = candidate.device
    api_key = device.issue_api_secret()

    candidate.update_metadata(
        claimed_from_ip=request.META.get("REMOTE_ADDR"),
        claimed_at=timezone.now().isoformat(),
        device_metadata=payload.get("device_metadata"),
    )
    candidate.mark_used()

    ingest_path = reverse("device-gateway:telemetry-ingest")
    ingest_url = request.build_absolute_uri(ingest_path)

    return JsonResponse(
        {
            "device_id": device.id,
            "api_key": api_key,
            "ingest_url": ingest_url,
            "token_expires_at": candidate.expires_at.isoformat() if candidate.expires_at else None,
        },
        status=201,
    )


@csrf_exempt
@bearer_required
@require_http_methods(["POST"])
def telemetry_ingest_view(request):
    """Persist telemetry payloads from authenticated devices."""

    try:
        payload = _parse_json_body(request)
    except ValueError as exc:
        return JsonResponse({"message": str(exc)}, status=400)

    if not isinstance(payload, dict):
        return JsonResponse({"message": "Payload must be a JSON object."}, status=400)

    device: Device = request.device
    DeviceTelemetry.objects.create(device=device, payload=payload)
    device.latest_payload = payload
    device.last_seen = timezone.now()
    device.save(update_fields=["latest_payload", "last_seen"])

    return JsonResponse({"status": "ok"}, status=201)


@csrf_exempt
@require_http_methods(["GET"])
def device_latest_payload_view(request, device_id: int):
    """Simple helper to verify ingestion by returning the last payload."""

    device = get_object_or_404(Device, id=device_id)
    latest = device.telemetry.first()
    if not latest:
        return JsonResponse({"message": "No telemetry stored for this device."}, status=404)

    return JsonResponse(
        {
            "device_id": device.id,
            "received_at": latest.received_at.isoformat(),
            "payload": latest.payload,
        }
    )


@login_required
def device_token_management_view(request):
    """Dashboard for issuing and reviewing provisioning tokens."""

    if request.user.is_staff:
        portal_devices = PortalDevice.objects.all().select_related("device_owner")
    else:
        portal_devices = PortalDevice.objects.filter(device_owner=request.user).select_related("device_owner")

    # Ensure every portal device has a gateway mirror for token handling
    for portal_device in portal_devices:
        defaults = {
            "owner": portal_device.device_owner,
            "name": portal_device.located_at or f"{portal_device.device_type} #{portal_device.id}",
            "location": portal_device.located_at or "",
        }
        Device.objects.get_or_create(
            source_device=portal_device,
            defaults=defaults,
        )

    if request.user.is_staff:
        device_qs = Device.objects.select_related("source_device", "owner")
        token_qs = DeviceProvisioningToken.objects.all()
    else:
        device_qs = Device.objects.select_related("source_device", "owner").filter(owner=request.user)
        token_qs = DeviceProvisioningToken.objects.filter(device__owner=request.user)

    devices = device_qs.order_by("name")
    tokens = (
        token_qs.select_related("device", "device__source_device", "issued_by")
        .order_by("-created_at")[:50]
    )

    issued_token: str | None = None

    if request.method == "POST":
        device_id = request.POST.get("device_id")
        lifetime_minutes = request.POST.get("lifetime_minutes")
        notes = request.POST.get("notes")

        try:
            device = device_qs.get(id=device_id)
        except Device.DoesNotExist:
            messages.error(request, "Unknown device or insufficient permissions.")
            return redirect("device-gateway:token-management")

        lifetime = None
        if lifetime_minutes:
            try:
                minutes = max(1, int(lifetime_minutes))
                lifetime = timedelta(minutes=minutes)
            except (TypeError, ValueError):
                messages.error(request, "Lifetime must be a whole number of minutes.")
                return redirect("device-gateway:token-management")

        token, _ = DeviceProvisioningToken.issue(
            device=device,
            issued_by=request.user,
            lifetime=lifetime,
            metadata={"notes": notes} if notes else None,
        )

        issued_token = token
        messages.success(
            request,
            "Provisioning token created. Copy it now; it cannot be retrieved again.",
        )
        tokens = (
            token_qs.select_related("device", "device__source_device", "issued_by")
            .order_by("-created_at")[:50]
        )

    context = {
        "devices": devices,
        "tokens": tokens,
        "issued_token": issued_token,
        "now": timezone.now(),
    }
    return render(request, "device_gateway/token_management.html", context)
