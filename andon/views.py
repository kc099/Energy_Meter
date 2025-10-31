import base64
import datetime
import json
import logging
from typing import Dict

from django.contrib import messages
from django.core.serializers.json import DjangoJSONEncoder
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from django.templatetags.static import static

from .forms import StationForm
from .models import ShiftConfig, ShiftData, Station, DailyRecord, SectionData
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from api.utils import device_token_required, parse_json_body
from devices.models import Device


logger = logging.getLogger(__name__)


def _address_candidates(raw_address: str | None) -> list[str]:
    if not raw_address:
        return []
    addr = raw_address.strip()
    if not addr:
        return []

    candidates = [addr]
    if '://' not in addr:
        parsed = f'//{addr}'
    else:
        parsed = addr

    head = addr.split('/', 1)[0]
    if head:
        candidates.append(head)
        if ':' in head:
            host, _, port = head.partition(':')
            candidates.append(host)
            if port:
                candidates.append(f"{host}:{port}")

    if addr.startswith('http://') or addr.startswith('https://'):
        without_scheme = addr.split('://', 1)[1]
        candidates.append(without_scheme)

    seen = set()
    unique = []
    for candidate in candidates:
        candidate = candidate.strip()
        if candidate and candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)
    return unique


def _station_matches_device(station: Station, device: Device) -> bool:
    device_addr = device.device_address or ""
    station_addr = station.ip_address or ""
    if not station_addr:
        return False
    station_norm = station_addr.strip().lower()
    for candidate in _address_candidates(device_addr):
        if candidate.lower() == station_norm:
            return True
        if ':' in candidate:
            host = candidate.split(':', 1)[0]
            if host.lower() == station_norm.lower():
                return True
    return False


def _decrypt_payload(device: Device, payload: Dict[str, str]) -> Dict[str, str]:
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
    except Exception as exc:  # pragma: no cover - defensive guard
        raise ValueError("Unable to decrypt telemetry payload") from exc


def _as_float(value) -> float | None:
    try:
        if isinstance(value, str):
            value = value.strip()
        return float(value)
    except (TypeError, ValueError):
        return None


def _current_shift(cfg: ShiftConfig | None, *, now=None) -> tuple[int | None, str | None]:
    now = now or timezone.localtime()
    if not cfg:
        return None, None

    def _in_range(start, end):
        start_dt = datetime.datetime.combine(now.date(), start)
        end_dt = datetime.datetime.combine(now.date(), end)
        if start_dt <= end_dt:
            return start_dt.time() <= now.time() <= end_dt.time()
        return now.time() >= start_dt.time() or now.time() <= end_dt.time()

    shift_number = None
    if _in_range(cfg.shift1_start, cfg.shift1_end):
        shift_number = 1
    elif _in_range(cfg.shift2_start, cfg.shift2_end):
        shift_number = 2
    else:
        shift_number = 3

    if cfg.display_format == "numeric":
        shift_label = str(shift_number)
    else:
        shift_label = "ABC"[shift_number - 1]
    return shift_number, shift_label


def station_add(request):
    """Create a new Andon station."""

    form = StationForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Station created.")
        return redirect("andon:station_list")

    return render(request, "andon/station_form.html", {"form": form})


def station_list(request):
    stations = Station.objects.order_by("name")
    return render(request, "andon/station_list.html", {"stations": stations})


def station_detail(request, pk):
    station = get_object_or_404(Station, pk=pk)
    recent_shift = (
        ShiftData.objects.filter(station=station).order_by("-date", "-id").first()
    )
    return render(
        request,
        "andon/station_detail.html",
        {
            "station": station,
            "recent_shift": recent_shift,
        },
    )


def station_edit(request, pk):
    """Update an existing station."""

    station = get_object_or_404(Station, pk=pk)
    form = StationForm(request.POST or None, instance=station)

    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Station updated.")
        return redirect("andon:station_detail", pk=station.pk)

    return render(
        request,
        "andon/station_form.html",
        {
            "form": form,
            "station": station,
        },
    )


def station_delete(request, pk):
    station = get_object_or_404(Station, pk=pk)

    if request.method == "POST":
        station.delete()
        messages.success(request, "Station deleted.")
        return redirect("andon:station_list")

    return render(request, "andon/station_confirm_delete.html", {"station": station})


@csrf_exempt
@require_http_methods(["POST"])
@device_token_required
def telemetry_ingest_view(request, pk):
    station = get_object_or_404(Station, pk=pk)
    portal_device = getattr(request, "device", None)
    if portal_device is None:
        return JsonResponse({"detail": "Missing device context."}, status=403)
    if portal_device.device_type != "andon":
        return JsonResponse({"detail": "Bearer token is not associated with an Andon device."}, status=403)
    if not _station_matches_device(station, portal_device):
        return JsonResponse({"detail": "Bearer token does not match this station."}, status=403)

    try:
        payload = parse_json_body(request)
    except ValueError as exc:
        return JsonResponse({"detail": str(exc)}, status=400)

    logger.info(
        "Andon telemetry ingest device=%s station=%s payload=%s",
        portal_device.id,
        station.id,
        json.dumps(payload) if isinstance(payload, dict) else payload,
    )

    try:
        decoded = _decrypt_payload(portal_device, payload)
    except ValueError as exc:
        return JsonResponse({"detail": str(exc)}, status=400)

    actual = _as_float(decoded.get("actual"))
    if actual is None:
        return JsonResponse({"detail": "actual must be numeric."}, status=400)
    plan = _as_float(decoded.get("plan"))
    downtime = _as_float(decoded.get("downtime_min"))

    timestamp = timezone.now()
    station.actual_count = int(round(actual))
    if downtime is not None:
        station.total_downtime_min = float(downtime)
    station.last_ping = timestamp
    station.is_alive = True
    update_fields = ["actual_count", "last_ping", "is_alive"]
    if downtime is not None:
        update_fields.append("total_downtime_min")
    station.save(update_fields=update_fields)

    device_payload = {
        "actual": int(round(actual)),
        "unit": decoded.get("unit", "units"),
    }
    if plan is not None:
        device_payload["plan"] = int(round(plan))
    if downtime is not None:
        device_payload["downtime_min"] = float(downtime)

    portal_device.latest_value = device_payload
    portal_device.last_updated = timestamp
    portal_device.is_active = True
    portal_update_fields = ["latest_value", "last_updated", "is_active"]
    portal_device.save(update_fields=portal_update_fields)

    cfg = ShiftConfig.objects.first()
    shift_number, shift_label = _current_shift(cfg, now=timestamp)
    if shift_label is None:
        shift_label = "1"
    sd, _ = ShiftData.objects.get_or_create(
        station=station,
        date=timestamp.date(),
        shift=shift_label,
    )
    if plan is not None:
        sd.plan = int(round(plan))
    elif shift_number:
        sd.plan = station.current_plan(shift_number)
    sd.actual = int(round(actual))
    if downtime is not None:
        sd.downtime_min = float(downtime)
    sd.save()

    dr, _ = DailyRecord.objects.get_or_create(station=station, date=timestamp.date())
    if plan is not None:
        dr.plan = int(round(plan))
    elif dr.plan == 0:
        dr.plan = station.plan_shift1 + station.plan_shift2 + station.plan_shift3
    dr.actual_count = max(dr.actual_count, int(round(actual)))
    if dr.plan:
        dr.efficiency = round((dr.actual_count / dr.plan) * 100, 2)
    dr.save()

    return JsonResponse({"status": "ok"}, status=201)


def dashboard(request):
    cfg = ShiftConfig.objects.first()
    today = timezone.localdate()

    shift_number, shift_label = _current_shift(cfg)

    station_cards = []
    for s in Station.objects.order_by("name"):
        shift_snapshot = (
            ShiftData.objects
            .filter(station=s, date=today)
            .order_by("-id")
            .first()
        )
        section_snapshot = (
            SectionData.objects
            .filter(station=s)
            .order_by("-date", "-id")
            .first()
        )

        calltype = section_snapshot.calltype if section_snapshot else ""
        fault_time = section_snapshot.fault_time if section_snapshot else None
        resolved_time = section_snapshot.resolved_time if section_snapshot else None

        station_cards.append({
            "id": s.id,
            "name": s.name,
            "plan": (shift_snapshot.plan if shift_snapshot else 0),
            "actual": (shift_snapshot.actual if shift_snapshot else 0),
            "downtime_min": (shift_snapshot.downtime_min if shift_snapshot else 0.0),
            "fault_time": fault_time,
            "resolved_time": resolved_time,
            "calltype": calltype,
            "ip": s.ip_address,
            "created_at": s.created_at,
            "last_updated": s.last_ping,
            "is_active": (s.is_active and s.is_alive),
        })

    context = {
        "stations": station_cards,
        "left_logo_url": static("images/RBA_logo.jpeg"),
        "right_logo_url": static("images/RBA_logo.jpeg"),
        "stations_json": json.dumps(station_cards, cls=DjangoJSONEncoder),
        "current_shift_label": shift_label,
    }
    return render(request, "andon/dashboard.html", context)
