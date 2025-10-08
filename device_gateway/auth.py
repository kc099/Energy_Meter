from __future__ import annotations

import hashlib
from functools import wraps

from django.http import JsonResponse

from .models import Device


def bearer_required(view_func):
    """Authenticate requests using the device bearer token."""

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return JsonResponse({"detail": "Device token missing."}, status=401)

        token = header.split(" ", 1)[1].strip()
        if not token:
            return JsonResponse({"detail": "Device token missing."}, status=401)

        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        device = (
            Device.objects.filter(device_secret_hash=token_hash)
            .select_related("owner")
            .first()
        )
        if not device or not device.validate_api_secret(token):
            return JsonResponse({"detail": "Invalid or expired device token."}, status=401)

        request.device = device
        return view_func(request, *args, **kwargs)

    return wrapper
