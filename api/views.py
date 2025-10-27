from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta
from typing import Any, Dict

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.tokens import default_token_generator
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.urls import reverse

from accounts.models import User
from devices.forms import DeviceForm
from devices.models import Device, DeviceData, DeviceProvisioningToken, Shift, ShiftReport
from devices.tasks import poll_device_task
from devices.views import generate_shift_reports_for_date
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .serializers import (
    serialize_device,
    serialize_device_history,
    serialize_shift,
    serialize_shift_report,
    serialize_user,
)
from .utils import (
    allow_cors,
    cors_json_response,
    device_token_required,
    login_required_json,
    parse_json_body,
)

try:  # pragma: no cover - optional dependencies
    from celery.exceptions import CeleryError
    from kombu.exceptions import OperationalError
except ModuleNotFoundError:  # pragma: no cover - fallback when Celery is absent
    class CeleryError(Exception):
        pass

    class OperationalError(Exception):
        pass


def _parse_time(value: str):
    try:
        return datetime.strptime(value, "%H:%M").time()
    except (TypeError, ValueError) as exc:
        raise ValueError("Time values must be in HH:MM format") from exc


def _form_error_messages(form):
    errors = {}
    for field, messages in form.errors.get_json_data().items():
        errors[field] = [item.get("message") for item in messages]
    return errors


def _decrypt_device_payload(device: Device, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return plaintext telemetry, transparently handling AES-GCM envelopes."""

    if not isinstance(payload, dict):
        return payload

    if payload.get("algorithm") != "AESGCM":
        return payload

    required_fields = {"nonce", "ciphertext"}
    if not required_fields.issubset(payload):
        missing = ", ".join(sorted(required_fields - set(payload)))
        raise ValueError(f"Encrypted payload missing fields: {missing}")

    key_bytes = device.get_encryption_key_bytes()
    try:
        nonce = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["ciphertext"])
        plaintext = AESGCM(key_bytes).decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Unable to decrypt telemetry payload") from exc


@allow_cors
@require_http_methods(["GET"])
def session_view(request):
    user = request.user if request.user.is_authenticated else None
    payload = {
        "authenticated": bool(user),
        "user": serialize_user(user),
    }
    return cors_json_response(request, payload)


@allow_cors
@csrf_exempt
@require_http_methods(["POST"])
def login_view(request):
    try:
        data = parse_json_body(request)
    except ValueError as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)

    identifier = (data.get("email") or "").strip()
    password = data.get("password")

    if not identifier or not password:
        return cors_json_response(
            request,
            {"message": "Email or username and password are required."},
            status=400,
        )

    user = authenticate(request, username=identifier, password=password)

    if not user:
        try:
            user_obj = User.objects.get(email__iexact=identifier)
        except User.DoesNotExist:
            user_obj = None
        if user_obj:
            user = authenticate(request, username=user_obj.email, password=password)
            if not user:
                user = authenticate(request, username=user_obj.username, password=password)

    if not user:
        try:
            user_obj = User.objects.get(username__iexact=identifier)
        except User.DoesNotExist:
            user_obj = None
        if user_obj:
            user = authenticate(request, username=user_obj.email, password=password)
            if not user:
                user = authenticate(request, username=user_obj.username, password=password)

    if not user:
        return cors_json_response(
            request,
            {"message": "Invalid credentials."},
            status=400,
        )

    login(request, user)
    return cors_json_response(
        request,
        {"message": "Login successful", "user": serialize_user(user)},
    )


@allow_cors
@csrf_exempt
@require_http_methods(["POST"])
def logout_view(request):
    logout(request)
    return cors_json_response(request, {"message": "Logged out"})


@allow_cors
@csrf_exempt
@require_http_methods(["POST"])
def register_view(request):
    try:
        data = parse_json_body(request)
    except ValueError as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)

    required_fields = ["username", "email", "password"]
    missing = [field for field in required_fields if not data.get(field)]
    if missing:
        return cors_json_response(
            request,
            {"message": f"Missing fields: {', '.join(missing)}"},
            status=400,
        )

    email = data["email"].strip().lower()
    username = data["username"].strip()

    if User.objects.filter(email=email).exists():
        return cors_json_response(
            request,
            {"message": "An account with this email already exists."},
            status=400,
        )
    if User.objects.filter(username=username).exists():
        return cors_json_response(
            request,
            {"message": "Username is already taken."},
            status=400,
        )

    try:
        user = User.objects.create_user(
            email=email,
            username=username,
            first_name=data.get("first_name", ""),
            last_name=data.get("last_name", ""),
            password=data["password"],
        )
    except Exception as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)

    return cors_json_response(
        request,
        {
            "message": "Account created successfully.",
            "user": serialize_user(user),
        },
        status=201,
    )


@allow_cors
@csrf_exempt
@require_http_methods(["POST"])
def forgot_password_view(request):
    try:
        data = parse_json_body(request)
    except ValueError as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)

    email = (data.get("email") or "").strip().lower()
    if not email:
        return cors_json_response(request, {"message": "Email is required."}, status=400)

    user = User.objects.filter(email=email).first()
    if user:
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        response_payload: Dict[str, Any] = {
            "message": "Password reset instructions have been sent if the email exists.",
        }
        if settings.DEBUG:
            response_payload["debug"] = {
                "uid": uid,
                "token": token,
            }
        return cors_json_response(request, response_payload)

    return cors_json_response(
        request,
        {"message": "Password reset instructions have been sent if the email exists."},
    )


@allow_cors
@csrf_exempt
@require_http_methods(["POST"])
def reset_password_view(request):
    try:
        data = parse_json_body(request)
    except ValueError as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)

    uid = data.get("uid")
    token = data.get("token")
    new_password = data.get("password")

    if not all([uid, token, new_password]):
        return cors_json_response(
            request,
            {"message": "uid, token, and password are required."},
            status=400,
        )

    try:
        user_id = force_str(urlsafe_base64_decode(uid))
        user = User.objects.get(pk=user_id)
    except (ValueError, User.DoesNotExist, TypeError):
        return cors_json_response(request, {"message": "Invalid reset link."}, status=400)

    if not default_token_generator.check_token(user, token):
        return cors_json_response(request, {"message": "Invalid or expired token."}, status=400)

    user.set_password(new_password)
    user.save()

    return cors_json_response(request, {"message": "Password updated successfully."})


@allow_cors
@csrf_exempt
@login_required_json
@require_http_methods(["GET", "POST"])
def devices_view(request):
    if request.method == "GET":
        devices = Device.objects.filter(device_owner=request.user).order_by("-created_at")
        data = [serialize_device(device) for device in devices]
        return cors_json_response(request, data, status=200)

    try:
        payload = parse_json_body(request)
    except ValueError as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)

    form_data = {
        "device_type": payload.get("device_type"),
        "located_at": payload.get("located_at"),
        "address_type": payload.get("address_type", "ip"),
        "device_address": payload.get("device_address"),
    }

    form = DeviceForm(form_data)
    if not form.is_valid():
        return cors_json_response(request, {"errors": _form_error_messages(form)}, status=400)

    device = form.save(commit=False)
    device.device_owner = request.user
    polling_interval = payload.get("polling_interval")
    if polling_interval:
        try:
            device.polling_interval = max(5, int(polling_interval))
        except (TypeError, ValueError):
            pass
    device.save()

    connection_message = "Device added successfully."
    for attempt in range(3):
        success, data = device.poll_device()
        if success:
            connection_message = "Device added successfully and connected."
            break
        if attempt == 2:
            connection_message = (
                "Device saved but connection could not be established yet."
            )

    return cors_json_response(
        request,
        {
            "message": connection_message,
            "device": serialize_device(device),
        },
        status=201,
    )


@allow_cors
@csrf_exempt
@login_required_json
@require_http_methods(["GET", "PUT", "DELETE"])
def device_detail_view(request, device_id: int):
    device = get_object_or_404(Device, id=device_id, device_owner=request.user)

    if request.method == "GET":
        next_device = (
            Device.objects.filter(device_owner=request.user, id__gt=device.id)
            .order_by("id")
            .first()
        )
        previous_device = (
            Device.objects.filter(device_owner=request.user, id__lt=device.id)
            .order_by("-id")
            .first()
        )

        historical_entries = list(
            device.historical_data.all().order_by("-timestamp")[:100]
        )
        historical_entries.reverse()
        historical_serialized = list(serialize_device_history(historical_entries))

        timestamps = [entry["timestamp_human"] for entry in historical_serialized]
        voltage = [entry["value"].get("voltage") for entry in historical_serialized]
        current = [entry["value"].get("current") for entry in historical_serialized]
        power_factor = [entry["value"].get("power_factor") for entry in historical_serialized]
        kwh = [entry["value"].get("kwh") for entry in historical_serialized]

        response_payload = {
            "device": serialize_device(device),
            "historical_data": historical_serialized,
            "chart_data": {
                "timestamps": timestamps,
                "voltage": voltage,
                "current": current,
                "power_factor": power_factor,
                "kwh": kwh,
            },
            "next_device": serialize_device(next_device) if next_device else None,
            "previous_device": serialize_device(previous_device) if previous_device else None,
        }
        return cors_json_response(request, response_payload)

    if request.method == "DELETE":
        device.delete()
        return cors_json_response(request, {"message": "Device removed."})

    try:
        payload = parse_json_body(request)
    except ValueError as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)

    form_data = {
        "device_type": payload.get("device_type", device.device_type),
        "located_at": payload.get("located_at", device.located_at),
        "address_type": payload.get("address_type", device.address_type),
        "device_address": payload.get("device_address", device.device_address),
    }

    form = DeviceForm(form_data, instance=device)
    if not form.is_valid():
        return cors_json_response(request, {"errors": _form_error_messages(form)}, status=400)

    updated_device = form.save(commit=False)
    polling_interval = payload.get("polling_interval")
    if polling_interval:
        try:
            updated_device.polling_interval = max(5, int(polling_interval))
        except (TypeError, ValueError):
            pass
    updated_device.device_owner = request.user
    updated_device.save()

    return cors_json_response(
        request,
        {
            "message": "Device updated successfully.",
            "device": serialize_device(updated_device),
        },
    )


@allow_cors
@csrf_exempt
@login_required_json
@require_http_methods(["POST"])
def device_poll_view(request, device_id: int):
    device = get_object_or_404(Device, id=device_id, device_owner=request.user)

    try:
        poll_device_task.delay(device.id, force=True)
        return cors_json_response(
            request,
            {"status": "queued", "message": "Polling scheduled."},
        )
    except (CeleryError, OperationalError):
        success, payload = device.poll_device()
        if success:
            return cors_json_response(
                request,
                {"status": "success", "data": payload},
            )
        return cors_json_response(
            request,
            {"status": "error", "message": str(payload)},
            status=400,
        )


@allow_cors
@csrf_exempt
@login_required_json
@require_http_methods(["POST"])
def device_provision_view(request, device_id: int):
    device = get_object_or_404(Device, id=device_id, device_owner=request.user)

    try:
        payload = parse_json_body(request)
    except ValueError as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)

    lifetime_minutes = payload.get("lifetime_minutes")
    lifetime = None
    if lifetime_minutes is not None:
        try:
            minutes = max(1, int(lifetime_minutes))
            lifetime = timedelta(minutes=minutes)
        except (TypeError, ValueError):
            return cors_json_response(
                request,
                {"message": "lifetime_minutes must be an integer value."},
                status=400,
            )

    metadata = {
        "notes": payload.get("notes"),
        "issued_from_ip": request.META.get("REMOTE_ADDR"),
        "user_agent": request.META.get("HTTP_USER_AGENT"),
    }
    token, token_obj = DeviceProvisioningToken.issue(
        device,
        created_by=request.user,
        lifetime=lifetime,
        metadata={k: v for k, v in metadata.items() if v},
    )

    response_payload = {
        "token": token,
        "expires_at": (
            timezone.localtime(token_obj.expires_at).isoformat()
            if token_obj.expires_at
            else None
        ),
        "device": {
            "id": device.id,
            "located_at": device.located_at,
            "device_type": device.device_type,
        },
    }
    return cors_json_response(request, response_payload, status=201)


@allow_cors
@csrf_exempt
@require_http_methods(["POST"])
def device_claim_view(request):
    try:
        payload = parse_json_body(request)
    except ValueError as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)

    token = payload.get("token")
    if not token:
        return cors_json_response(
            request,
            {"message": "token is required."},
            status=400,
        )

    candidate = DeviceProvisioningToken.find_active(token)
    if not candidate:
        return cors_json_response(
            request,
            {"message": "Invalid or expired provisioning token."},
            status=400,
        )

    device = candidate.device
    api_key = device.issue_api_secret()
    encryption_key_b64 = device.get_or_create_encryption_key()
    device.last_updated = timezone.now()
    device.save(update_fields=["last_updated"])

    candidate.update_metadata(
        claimed_from_ip=request.META.get("REMOTE_ADDR"),
        claimed_at=timezone.now().isoformat(),
        device_metadata=payload.get("device_metadata"),
    )
    candidate.mark_used()

    ingest_path = reverse("api:device-data-ingest")
    ingest_url = request.build_absolute_uri(ingest_path)

    response_payload = {
        "device_id": device.id,
        "api_key": api_key,
        "encryption_key_b64": encryption_key_b64,
        "ingest_url": ingest_url,
        "token_expires_at": (
            timezone.localtime(candidate.expires_at).isoformat()
            if candidate.expires_at
            else None
        ),
    }
    return cors_json_response(request, response_payload, status=201)


@allow_cors
@csrf_exempt
@device_token_required
@require_http_methods(["POST"])
def device_data_ingest_view(request):
    try:
        payload = parse_json_body(request)
    except ValueError as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)

    if not isinstance(payload, dict):
        return cors_json_response(
            request,
            {"message": "Payload must be a JSON object."},
            status=400,
        )

    device = getattr(request, "device", None)
    if device is None:
        return cors_json_response(
            request,
            {"message": "Unable to determine device context."},
            status=400,
        )

    try:
        payload = _decrypt_device_payload(device, payload)
    except ValueError as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)

    DeviceData.objects.create(device=device, value=payload)
    device.latest_value = payload
    device.last_updated = timezone.now()
    device.is_active = True
    if device.provisioning_state != Device.ProvisioningState.ACTIVE:
        device.provisioning_state = Device.ProvisioningState.ACTIVE
        device.save(update_fields=["latest_value", "last_updated", "is_active", "provisioning_state"])
    else:
        device.save(update_fields=["latest_value", "last_updated", "is_active"])

    return cors_json_response(request, {"status": "ok"}, status=201)


@allow_cors
@login_required_json
@require_http_methods(["GET"])
def dashboard_overview_view(request):
    devices_qs = Device.objects.filter(device_owner=request.user).order_by("-created_at")
    active = devices_qs.filter(is_active=True).count()
    total_devices = devices_qs.count()
    devices_sample = list(devices_qs[:10])

    window_start = timezone.now() - timedelta(days=30)
    history = DeviceData.objects.filter(
        device__device_owner=request.user,
        timestamp__gte=window_start,
    ).only("value")

    total_kwh = 0.0
    for entry in history:
        try:
            total_kwh += float((entry.value or {}).get("kwh", 0) or 0)
        except (TypeError, ValueError):
            continue

    recent_reports_qs = (
        ShiftReport.objects.select_related("shift", "device")
        .filter(device__device_owner=request.user)
        .order_by("-date", "-id")[:10]
    )

    response_payload = {
        "totals": {
            "activeDevices": active,
            "inactiveDevices": max(total_devices - active, 0),
            "totalKwhLast30Days": total_kwh,
        },
        "devices": [serialize_device(device) for device in devices_sample],
        "recentReports": [serialize_shift_report(report) for report in recent_reports_qs],
    }
    return cors_json_response(request, response_payload)


@allow_cors
@csrf_exempt
@login_required_json
@require_http_methods(["GET", "POST"])
def shifts_view(request):
    if request.method == "GET":
        shifts = Shift.objects.all().order_by("start_time")
        return cors_json_response(request, [serialize_shift(shift) for shift in shifts])

    try:
        payload = parse_json_body(request)
    except ValueError as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)

    try:
        shift = Shift(
            name=payload.get("name"),
            start_time=_parse_time(payload.get("start_time")),
            end_time=_parse_time(payload.get("end_time")),
        )
        shift.full_clean()
        shift.save()
    except ValueError as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)
    except Exception as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)

    return cors_json_response(
        request,
        {"message": "Shift created successfully.", "shift": serialize_shift(shift)},
        status=201,
    )


@allow_cors
@csrf_exempt
@login_required_json
@require_http_methods(["PUT", "PATCH"])
def shift_detail_view(request, shift_id: int):
    shift = get_object_or_404(Shift, id=shift_id)

    try:
        payload = parse_json_body(request)
    except ValueError as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)

    if "name" in payload:
        shift.name = payload["name"]
    if "start_time" in payload:
        try:
            shift.start_time = _parse_time(payload["start_time"])
        except ValueError as exc:
            return cors_json_response(request, {"message": str(exc)}, status=400)
    if "end_time" in payload:
        try:
            shift.end_time = _parse_time(payload["end_time"])
        except ValueError as exc:
            return cors_json_response(request, {"message": str(exc)}, status=400)

    try:
        shift.full_clean()
        shift.save()
    except Exception as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)

    return cors_json_response(
        request,
        {"message": "Shift updated successfully.", "shift": serialize_shift(shift)},
    )


@allow_cors
@csrf_exempt
@login_required_json
@require_http_methods(["POST"])
def shift_toggle_view(request, shift_id: int):
    shift = get_object_or_404(Shift, id=shift_id)
    shift.is_active = not shift.is_active
    shift.save(update_fields=["is_active"])
    return cors_json_response(
        request,
        {"message": "Shift updated.", "shift": serialize_shift(shift)},
    )


@allow_cors
@login_required_json
@require_http_methods(["GET"])
def shift_reports_view(request):
    reports = ShiftReport.objects.select_related("shift", "device").filter(
        device__device_owner=request.user
    )

    date_str = request.GET.get("date")
    if date_str:
        try:
            target_date = datetime.strptime(date_str, "%Y-%m-%d").date()
            reports = reports.filter(date=target_date)
        except ValueError:
            return cors_json_response(request, {"message": "Invalid date format."}, status=400)

    reports = reports.order_by("-date", "shift__start_time")
    return cors_json_response(
        request,
        [serialize_shift_report(report) for report in reports],
    )


@allow_cors
@csrf_exempt
@login_required_json
@require_http_methods(["POST"])
def shift_reports_generate_view(request):
    try:
        payload = parse_json_body(request)
    except ValueError as exc:
        return cors_json_response(request, {"message": str(exc)}, status=400)

    date_str = payload.get("date")
    if not date_str:
        return cors_json_response(request, {"message": "Date is required."}, status=400)

    try:
        target_date = datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        return cors_json_response(request, {"message": "Invalid date format."}, status=400)

    generated = generate_shift_reports_for_date(target_date)
    return cors_json_response(
        request,
        {"message": f"Generated {generated} reports for {target_date}."},
    )
