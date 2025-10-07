from __future__ import annotations

import json
from typing import Any, Callable, Dict

from django.conf import settings
from django.http import HttpResponse, JsonResponse
from functools import wraps
import hashlib

from devices.models import Device

ALLOWED_ORIGINS = getattr(settings, "API_ALLOWED_ORIGINS", ["http://localhost:3000"])
DEFAULT_ALLOW_METHODS = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
DEFAULT_ALLOW_HEADERS = "Content-Type, X-CSRFToken, Authorization"


def _origin_allowed(origin: str | None) -> bool:
    if not origin:
        return False
    if not ALLOWED_ORIGINS:
        return False
    if '*' in ALLOWED_ORIGINS:
        return True
    return origin in ALLOWED_ORIGINS


def apply_cors(response: HttpResponse, request) -> HttpResponse:
    origin = request.headers.get("Origin")
    if origin and _origin_allowed(origin):
        response["Access-Control-Allow-Origin"] = origin
        response["Access-Control-Allow-Credentials"] = "true"
        vary = response.get("Vary", "")
        if "Origin" not in vary:
            vary = f"{vary}, Origin" if vary else "Origin"
            response["Vary"] = vary
    return response


def cors_json_response(request, data: Any, *, status: int = 200) -> JsonResponse:
    safe = isinstance(data, dict)
    response = JsonResponse(data, status=status, safe=safe)
    return apply_cors(response, request)


def cors_response(request, *, status: int = 204) -> HttpResponse:
    response = HttpResponse(status=status)
    return apply_cors(response, request)


def parse_json_body(request) -> Dict[str, Any]:
    if not request.body:
        return {}
    try:
        body = request.body.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Invalid payload encoding")
    try:
        return json.loads(body) if body else {}
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON payload") from exc


def allow_cors(view_func: Callable):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.method == "OPTIONS":
            response = HttpResponse(status=204)
            response["Access-Control-Allow-Methods"] = DEFAULT_ALLOW_METHODS
            response["Access-Control-Allow-Headers"] = DEFAULT_ALLOW_HEADERS
            return apply_cors(response, request)
        response = view_func(request, *args, **kwargs)
        return apply_cors(response, request)

    if hasattr(view_func, "csrf_exempt"):
        wrapper.csrf_exempt = view_func.csrf_exempt

    return wrapper


def login_required_json(view_func: Callable):
    from functools import wraps

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return cors_json_response(
                request,
                {"detail": "Authentication credentials were not provided."},
                status=401,
            )
        return view_func(request, *args, **kwargs)

    return wrapper


def device_token_required(view_func: Callable):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return cors_json_response(
                request,
                {"detail": "Device token missing."},
                status=401,
            )
        token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return cors_json_response(
                request,
                {"detail": "Device token missing."},
                status=401,
            )
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        device = Device.objects.filter(device_secret_hash=token_hash).select_related("device_owner").first()
        if not device or not device.validate_api_secret(token):
            return cors_json_response(
                request,
                {"detail": "Invalid or expired device token."},
                status=401,
            )
        request.device = device
        return view_func(request, *args, **kwargs)

    return wrapper
