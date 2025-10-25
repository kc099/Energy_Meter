# UUID Validation Test Flow

This document explains how to test the new UUID-based authentication and data validation flow.

## Overview

The new flow works as follows:

1. **Server generates Token + UUID** for the client device
2. **Client authenticates** with the token and receives both API key and device UUID
3. **Client sends data** in format: `{uuid: "...", data: [field1, field2, ..., field7]}`
4. **Server validates** that the UUID exists in the database before saving data
5. **Server prints** all received data to console for debugging

## Files Created

### Server Side
- **`device_gateway/views.py`** - Added `telemetry_ingest_test_view()` function (line 133-197)
  - New test endpoint at `/api/device-data/ingest-test`
  - Validates UUID against `devices.Device.duid` field
  - Prints all data to console with colored output
  - Returns detailed JSON response

- **`device_gateway/views.py`** - Modified `claim_device_view()` (line 99-102)
  - Now returns `device_uuid` in the claim response
  - Client receives and stores this UUID

- **`device_gateway/urls.py`** - Added test endpoint routes (line 12, 19)
  - `/gateway/device-data/ingest-test`
  - `/api/device-data/ingest-test` (compatibility alias)

### Client Side
- **`test_client_with_uuid.ino`** - Complete test client
  - Authenticates and receives UUID from server
  - Stores UUID in NVS (non-volatile storage)
  - Sends 8-field array: `[voltage, current, pf, kwh, kwah, temp, humidity]`
  - Sends to TEST endpoint for validation

## Testing Steps

### 1. Prepare the Server

```bash
# Make sure your Django server is running
python manage.py runserver

# The console will show all test endpoint activity
```

### 2. Create a Device with UUID

In Django admin or shell:

```python
from devices.models import Device
from django.contrib.auth import get_user_model

User = get_user_model()
user = User.objects.first()

# Create a device (UUID is auto-generated)
device = Device.objects.create(
    device_type='meter',
    device_owner=user,
    located_at='Test Lab',
    device_address='192.168.1.100'
)

print(f"Device created with UUID: {device.duid}")
```

### 3. Generate Provisioning Token

Go to: `http://your-server/gateway/device-tokens`

1. Select the device you just created
2. Click "Issue Token"
3. Copy the provisioning token

### 4. Configure and Upload Client Code

Edit `test_client_with_uuid.ino`:

```cpp
// Update these values
static const char *WIFI_SSID     = "Your-WiFi-SSID";
static const char *WIFI_PASSWORD = "your-wifi-password";
static const char *API_HOST      = "192.168.1.10";  // Your server IP
static const uint16_t API_PORT   = 8000;
static const bool USE_TLS        = false;  // false for http://

String provisioningToken = "paste-token-here";
```

Upload to your ESP32 and open Serial Monitor (115200 baud).

### 5. Watch the Flow

**Client Serial Monitor will show:**
```
==================================================
Provisioning complete!
==================================================
API Key: xxxx...
Device UUID: 4aab7352-0368-419d-9f64-5a5f95ba1ece
==================================================

==================================================
Sending test data to server:
{"uuid":"4aab7352-0368-419d-9f64-5a5f95ba1ece","data":[230.5,15.2,0.97,1234.5,1456.7,28.3,65.4]}
==================================================

✓ Test data sent successfully!
✓ UUID validated by server!
```

**Server Console will show:**
```
================================================================================
TEST ENDPOINT: Received data from client
================================================================================
Full payload: {
  "uuid": "4aab7352-0368-419d-9f64-5a5f95ba1ece",
  "data": [230.5, 15.2, 0.97, 1234.5, 1456.7, 28.3, 65.4]
}
UUID: 4aab7352-0368-419d-9f64-5a5f95ba1ece
Data array: [230.5, 15.2, 0.97, 1234.5, 1456.7, 28.3, 65.4]
✓ UUID VALIDATED: Found device 'meter at Test Lab' (ID: 5)
  Owner: admin
  Location: Test Lab
✓ DATA SAVED to gateway device 12
================================================================================
```

## Testing Scenarios

### Test 1: Valid UUID
- Use a device UUID that exists in the database
- **Expected**: Data is saved, console shows "✓ UUID VALIDATED"

### Test 2: Invalid UUID
- Modify the client code to send a fake UUID:
  ```cpp
  doc["uuid"] = "00000000-0000-0000-0000-000000000000";
  ```
- **Expected**: Server rejects with 403, console shows "✗ UUID NOT FOUND"

### Test 3: Missing UUID
- Remove the UUID from client payload
- **Expected**: Server returns 400 error "UUID is required"

### Test 4: Wrong Data Array Length
- Send only 5 fields instead of 7
- **Expected**: Server returns 400 error "data must be an array of 7 values"

## Data Format

### Client Sends:
```json
{
  "uuid": "device-uuid-from-claim",
  "data": [
    230.5,   // field1: voltage (V)
    15.2,    // field2: current (A)
    0.97,    // field3: power factor
    1234.5,  // field4: energy (kWh)
    1456.7,  // field5: reactive energy (kVArh)
    28.3,    // field6: temperature (°C) - dummy for now
    65.4     // field7: humidity (%) - dummy for now
  ]
}
```

### Server Response (Success):
```json
{
  "status": "ok",
  "message": "UUID validated and data saved",
  "matched_device_id": 5,
  "matched_device": "meter at Test Lab"
}
```

### Server Response (UUID Not Found):
```json
{
  "status": "rejected",
  "message": "UUID not found in database. Data not saved."
}
```

## Integration into Production

Once testing is complete:

1. **Merge the test endpoint logic** into the regular `telemetry_ingest_view()`
2. **Update the original client** `clientside_authentication_program.ino`:
   - Add UUID storage (already done in test client)
   - Modify `sendTelemetry()` to send UUID + data array format
3. **Keep the test endpoint** for future debugging or remove it
4. **Update existing devices** to have UUIDs (already done via migrations)

## Troubleshooting

### Client doesn't receive UUID
- Check that the gateway device is linked to a portal device with a duid
- Check device_gateway/views.py line 100-102 for the UUID lookup logic

### Server doesn't print to console
- Make sure you're running `python manage.py runserver` (not production WSGI)
- Check that the test endpoint is being hit (check URL path)

### UUID validation always fails
- Verify the UUID format in database (should be hyphenated UUID4)
- Check that devices have non-null duid values: `Device.objects.filter(duid__isnull=True)`

## Next Steps

After successful testing:
- [ ] Test with multiple devices
- [ ] Test network disconnection/reconnection
- [ ] Test token expiration handling
- [ ] Integrate into production code
- [ ] Add proper error handling and retry logic
- [ ] Consider adding data field validation on server
