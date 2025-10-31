from __future__ import annotations

import base64
import json
import logging

from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from api.utils import device_token_required, parse_json_body

from .forms import GasMonitorDeviceForm
from .models import GasMonitorDevice, GasMonitorTelemetry


logger = logging.getLogger(__name__)


def device_list_view(request):
    """Display the registered gas monitor devices."""
    devices = GasMonitorDevice.objects.select_related("device").all()
    return render(request, "gas_monitor/device_list.html", {"devices": devices})


def device_create_view(request):
    """Create a new gas monitor device entry."""
    if request.method == "POST":
        form = GasMonitorDeviceForm(request.POST)
        if form.is_valid():
            gas_monitor = form.save()
            messages.success(request, "Gas monitor device added successfully.")
            return redirect("gas_monitor:device_detail", pk=gas_monitor.pk)
    else:
        form = GasMonitorDeviceForm()

    return render(request, "gas_monitor/device_create.html", {"form": form})


def device_detail_view(request, pk):
    """Show details and recent telemetry for a specific gas monitor device."""

    device = get_object_or_404(
        GasMonitorDevice.objects.select_related("device"), pk=pk
    )

    telemetry_qs = list(device.telemetry.order_by("-timestamp")[:200])
    recent_samples = telemetry_qs[:10]

    if telemetry_qs:
        latest_sample = telemetry_qs[0]
        chronological = list(reversed(telemetry_qs))
        chart_labels = [
            timezone.localtime(sample.timestamp).strftime("%H:%M:%S")
            for sample in chronological
        ]
        chart_values = [sample.gas_level for sample in chronological]
        levels = [sample.gas_level for sample in telemetry_qs]
        summary = {
            "avg": sum(levels) / len(levels),
            "max": max(levels),
            "min": min(levels),
            "unit": latest_sample.unit,
        }
    else:
        latest_sample = None
        chart_labels = []
        chart_values = []
        summary = None

    context = {
        "device": device,
        "latest_sample": latest_sample,
        "recent_samples": recent_samples,
        "chart_labels": json.dumps(chart_labels),
        "chart_values": json.dumps(chart_values),
        "summary": summary,
    }

    return render(request, "gas_monitor/device_detail.html", context)


def device_update_view(request, pk):
    """Update gas monitor metadata."""
    device = get_object_or_404(GasMonitorDevice, pk=pk)

    if request.method == "POST":
        form = GasMonitorDeviceForm(request.POST, instance=device)
        if form.is_valid():
            form.save()
            messages.success(request, "Gas monitor device updated successfully.")
            return redirect("gas_monitor:device_detail", pk=device.pk)
    else:
        form = GasMonitorDeviceForm(instance=device)

    return render(
        request,
        "gas_monitor/device_update.html",
        {"form": form, "device": device},
    )


def device_delete_view(request, pk):
    """Confirm and delete a gas monitor device record."""
    device = get_object_or_404(GasMonitorDevice.objects.select_related("device"), pk=pk)

    if request.method == "POST":
        device.delete()
        messages.success(request, "Gas monitor device removed.")
        return redirect("gas_monitor:device_list")

    return render(request, "gas_monitor/device_delete.html", {"device": device})


def dashboard_view(request):
    """Display a simple dashboard for gas monitor devices."""
    devices = GasMonitorDevice.objects.select_related("device").all()
    return render(request, "gas_monitor/dashboard.html", {"devices": devices})


@csrf_exempt
@require_http_methods(["POST"])
@device_token_required
def telemetry_ingest_view(request, pk):
    """Receive encrypted telemetry payloads for a gas monitor device."""

    monitor = get_object_or_404(
        GasMonitorDevice.objects.select_related("device"), pk=pk
    )

    portal_device = getattr(request, "device", None)
    if not portal_device or portal_device.pk != monitor.device_id:
        return JsonResponse(
            {"detail": "Bearer token does not match gas monitor device."},
            status=403,
        )

    try:
        payload = parse_json_body(request)
    except ValueError as exc:
        return JsonResponse({"detail": str(exc)}, status=400)

    logger.info(
        "Gas monitor telemetry ingest device=%s payload=%s",
        portal_device.id,
        _safe_payload_repr(payload),
    )

    try:
        decoded = _decrypt_payload(portal_device, payload)
    except ValueError as exc:
        return JsonResponse({"detail": str(exc)}, status=400)

    try:
        raw_level = decoded.get("gas_level")
        gas_level = float(raw_level)
    except (TypeError, ValueError):
        return JsonResponse(
            {"detail": "gas_level must be provided as a numeric value."},
            status=400,
        )

    unit = decoded.get("unit", "ppm")
    if not isinstance(unit, str):
        return JsonResponse({"detail": "unit must be a string."}, status=400)
    unit = unit.strip() or "ppm"

    GasMonitorTelemetry.objects.create(device=monitor, gas_level=gas_level, unit=unit)

    monitor.device.latest_value = {"gas_level": gas_level, "unit": unit}
    monitor.device.last_updated = timezone.now()
    monitor.device.save(update_fields=["latest_value", "last_updated"])

    return JsonResponse({"status": "ok"}, status=201)


def _decrypt_payload(device, payload: dict) -> dict:
    if not isinstance(payload, dict):
        return payload
    if payload.get("algorithm") != "AESGCM":
        return payload

    missing = {"nonce", "ciphertext"} - set(payload)
    if missing:
        missing_fields = ", ".join(sorted(missing))
        raise ValueError(f"Encrypted payload missing fields: {missing_fields}")

    try:
        nonce = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["ciphertext"])
        plaintext = AESGCM(device.get_encryption_key_bytes()).decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive encryption guard
        raise ValueError("Unable to decrypt telemetry payload") from exc


def _safe_payload_repr(payload) -> str:
    try:
        return json.dumps(payload)
    except TypeError:
        return "<non-serialisable payload>"
