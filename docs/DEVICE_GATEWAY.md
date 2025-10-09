# Device Gateway API

This lightweight app exposes the endpoints the ESP32 firmware expects:

| Endpoint | Method | Description |
| --- | --- | --- |
| `/gateway/devices/<id>/provision` | POST | Issue a short-lived provisioning token. |
| `/gateway/devices/claim` | POST | Exchange a provisioning token for a permanent API key. |
| `/gateway/device-data/ingest` | POST | Ingest telemetry using `Authorization: Bearer <api_key>`. |
| `/gateway/devices/<id>/telemetry/latest` | GET | Fetch the most recent stored payload (debug helper). |

All responses are JSON.

## Setup

1. Ensure the app is installed:
   - `INSTALLED_APPS` includes `"device_gateway"`.
   - Root URLs include `path("gateway/", include("device_gateway.urls", namespace="device-gateway"))`.
2. Apply migrations:

   ```bash
   python manage.py migrate device_gateway
   ```

3. Create devices (via Django admin or shell). Only three fields are required:

   ```python
   from django.contrib.auth import get_user_model
   from device_gateway.models import Device

   owner = get_user_model().objects.first()
   device = Device.objects.create(name="Factory Meter 1", owner=owner, location="Line A")
   ```

4. (Optional) Use the in-app UI: authenticated users will find a **Device Token Management** option in the menu (three-line button). The page automatically mirrors devices you already manage under **Devices** and lets you issue new tokens or review the last 50 claims without touching curl.

## Provisioning Flow (manual test)

1. Issue a provisioning token:

   ```bash
   curl -X POST http://localhost:8000/gateway/devices/1/provision \
        -H "Content-Type: application/json" \
        -d '{"notes": "Line A ESP32"}'
   ```

   Response:

   ```json
   {
     "token": "<one-time-token>",
     "expires_at": null,
     "device_id": 1
   }
   ```

2. Claim the token (simulates the ESP32 setup call):

   ```bash
   curl -X POST http://localhost:8000/gateway/devices/claim \
        -H "Content-Type: application/json" \
        -d '{"token": "<one-time-token>", "device_metadata": {"fw": "1.0.0"}}'
   ```

   Response:

   ```json
   {
     "device_id": 1,
     "api_key": "<bearer-token>",
     "ingest_url": "http://localhost:8000/gateway/device-data/ingest",
     "token_expires_at": null
   }
   ```

3. Send dummy telemetry using the returned API key:

   ```bash
   curl -X POST http://localhost:8000/gateway/device-data/ingest \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer <bearer-token>" \
        -d '{"voltage": 228.4, "current": 3.2, "power_factor": 0.97, "kwh": 1234.5}'
   ```

   Response: `{ "status": "ok" }`

4. Verify the payload was stored:

   ```bash
   curl http://localhost:8000/gateway/devices/1/telemetry/latest
   ```

   Response contains the last payload and timestamp.

## Notes

- Provisioning tokens never expire by default. Supply `lifetime_minutes` when issuing if you need an automatic timeout.
- Issuing a new API key overwrites the previous credential; devices must use the fresh key.
- The app stores the last payload on the `Device` record for quick debugging and keeps a history in `DeviceTelemetry`.
- Admin screens (`/admin/`) provide read-only access to issued tokens, credentials, and telemetry samples.

## ESP32 Client Configuration Tips

- For local/staging servers that expose only `http://` (for example `http://192.168.0.159:8000`), set `USE_TLS = false`, `API_PORT = 8000`, and `API_HOST` to the server IP in `clientside_authentication_program.ino`. Reflash the board so it uses plain HTTP while you are testing.
- Once the Django server is running behind HTTPS (port 443 with a certificate whose CN/SAN matches your hostname), switch `USE_TLS = true`, paste the CA certificate into `SERVER_CA_PEM`, adjust `API_PORT` accordingly, recompile, and flash again. The ESP32 will then validate the TLS handshake and continue with bearer-token authentication.
