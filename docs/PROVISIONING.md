# Device Provisioning Overview

This document explains how device owners issue provisioning tokens, how ESP32 edge devices claim credentials, and how authenticated telemetry reaches the server.

## 1. Owner Workflow

1. Use **Devices → Add Device** to register metadata (type, location, address). Newly added devices remain hidden until claimed.
2. After saving, the app redirects to the provisioning console with a one-time token already generated for you. Copy it securely; the device is still pending.
3. On the provisioning page you can:
   - Leave lifetime blank for a token that never expires, or provide minutes if you need an expiry window.
   - Click **Generate Token** to mint another token (only displayed once).
   - Revoke the current credential if you need to force the device back to pending state (password required).
4. Share the token with the technician flashing the ESP32. Tokens are single-use and only expire if you specified a lifetime.

Devices move from *Pending claim* to *Active* as soon as the ESP32 calls the claim endpoint. Owners can always revisit the provisioning page to audit token history (pending, claimed, expired).

## 2. API Endpoints

| Purpose | Method & URL | Auth | Notes |
| --- | --- | --- | --- |
| Issue token programmatically | `POST /api/devices/<id>/provision` | Session cookie | Returns `{token, expires_at}` if caller owns the device. `expires_at` is `null` for non-expiring tokens. Optional `lifetime_minutes` and `notes` body fields. |
| Claim token from ESP32 | `POST /api/devices/claim` | none | Body: `{"token": "..."}`. Returns `{device_id, api_key, ingest_url}`. Token is immediately marked used. |
| Send telemetry | `POST /api/device-data/ingest` | Bearer token | Header: `Authorization: Bearer <api_key>`. Body is JSON payload stored as historical data. |

### Example: Claim Request

```http
POST /api/devices/claim HTTP/1.1
Content-Type: application/json

{"token": "<value from owner>"}
```

Response:

```json
{
  "device_id": 17,
  "api_key": "mhd6wOnL6mYk4...",
  "ingest_url": "https://example.com/api/device-data/ingest",
  "token_expires_at": null
}
```

### Example: Telemetry Upload

```http
POST /api/device-data/ingest HTTP/1.1
Content-Type: application/json
Authorization: Bearer mhd6wOnL6mYk4...

{
  "voltage": 228.4,
  "current": 4.8,
  "power_factor": 0.94,
  "kwh": 1261.3,
  "timestamp": "2025-10-07T10:33:00Z"
}
```

Successful requests return `201` with `{ "status": "ok" }`.

## 3. ESP32 Integration Checklist

1. Store the provisioning token securely (e.g., Serial input → NVS flash).
2. Connect to Wi-Fi using `WiFiClientSecure` and pin the server CA certificate.
3. Claim the token:
   - Build a JSON body with the token (and any optional metadata).
   - POST to `/api/devices/claim`.
   - Persist the returned API key in NVS.
4. Replace the token with the permanent API key for all subsequent requests.
5. Send telemetry to `/api/device-data/ingest` with the `Authorization` header.
6. Handle `401` responses by halting transmission and requesting a new provisioning token from the owner.

## 4. Secret Rotation

- Owners can revoke the current device credential from the provisioning UI (the device must perform the claim step again).
- Programmatic rotation can issue a new provisioning token; the act of claiming generates a fresh API key, superseding the previous hash stored on the device record.

## 5. Data Handling Notes

- Incoming telemetry is stored in `DeviceData.value` using the existing Fernet encryption layer (`EncryptedJSONField`).
- Device state (`latest_value`, `last_updated`, `is_active`) is refreshed whenever ingestion succeeds.
- Device credentials are stored hashed (`device_secret_hash`) and encrypted (`device_secret`) for single-display convenience. The hash is used for constant-time token validation.

Keep this document alongside firmware instructions so both cloud and edge engineers share a common handshake process.
