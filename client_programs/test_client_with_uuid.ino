// TEST CLIENT: ESP32 with UUID validation
// This is a test version to validate the UUID + data array flow
// Once tested, integrate into main clientside_authentication_program.ino

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <ArduinoJson.h>

// ---- User config -----------------------------------------------------------
static const char *WIFI_SSID     = "your-ssid";
static const char *WIFI_PASSWORD = "your-pass";
static const char *API_HOST      = "your-api.example.com"; // no protocol
static const uint16_t API_PORT   = 443;
static const bool USE_TLS        = false;     // set true for https:// production

// Initial provisioning token (get this from Django admin)
String provisioningToken = "paste-one-time-token";

// ---------------------------------------------------------------------------

Preferences prefs;
WiFiClient plainClient;
WiFiClientSecure secureClient;
HTTPClient http;

const char *NAMESPACE_NAME = "energy";
const char *KEY_API_TOKEN  = "apiToken";
const char *KEY_DEVICE_UUID = "deviceUUID";

String apiKey;
String deviceUUID;

void connectWifi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("Connecting to Wi-Fi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print('.');
  }
  Serial.println("\nWi-Fi connected");
  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());
}

bool postJson(const String &path, const String &body, const String &bearer, int &status, String &payload) {
  const char *scheme = USE_TLS ? "https://" : "http://";
  String url = String(scheme) + API_HOST + path;
  bool began = false;
  if (USE_TLS) {
    began = http.begin(secureClient, API_HOST, API_PORT, path, true);
  } else {
    began = http.begin(plainClient, API_HOST, API_PORT, path);
  }
  if (!began) {
    Serial.println("HTTP begin failed");
    return false;
  }
  http.addHeader("Content-Type", "application/json");
  if (bearer.length()) {
    http.addHeader("Authorization", "Bearer " + bearer);
  }
  status = http.POST(body);
  payload = http.getString();
  http.end();
  Serial.printf("POST %s -> %d\n", url.c_str(), status);
  return true;
}

bool claimToken() {
  if (provisioningToken.isEmpty()) {
    Serial.println("No provisioning token available.");
    return false;
  }

  StaticJsonDocument<256> doc;
  doc["token"] = provisioningToken;
  String body;
  serializeJson(doc, body);

  int status = 0;
  String payload;
  if (!postJson("/api/devices/claim", body, "", status, payload)) {
    return false;
  }
  if (status != 200 && status != 201) {
    Serial.printf("Token claim failed: %d %s\n", status, payload.c_str());
    return false;
  }

  Serial.println("Claim response:");
  Serial.println(payload);

  StaticJsonDocument<512> resp;
  DeserializationError err = deserializeJson(resp, payload);
  if (err) {
    Serial.println("Failed to parse claim response");
    return false;
  }

  // Extract API key and UUID from response
  apiKey = resp["api_key"].as<String>();
  deviceUUID = resp["device_uuid"].as<String>();

  // Save to NVS
  prefs.putString(KEY_API_TOKEN, apiKey);
  prefs.putString(KEY_DEVICE_UUID, deviceUUID);
  provisioningToken.clear();

  Serial.println("==================================================");
  Serial.println("Provisioning complete!");
  Serial.println("==================================================");
  Serial.print("API Key: ");
  Serial.println(apiKey);
  Serial.print("Device UUID: ");
  Serial.println(deviceUUID);
  Serial.println("==================================================");

  return true;
}

bool sendTestData() {
  if (apiKey.isEmpty()) {
    Serial.println("No API key; skip telemetry.");
    return false;
  }

  if (deviceUUID.isEmpty()) {
    Serial.println("No device UUID; cannot send data.");
    return false;
  }

  // Create 8-field payload: [uuid, field1, field2, ..., field7]
  // Field mapping example:
  // field1: voltage
  // field2: current
  // field3: power_factor
  // field4: kwh
  // field5: kwah
  // field6: temperature (dummy)
  // field7: humidity (dummy)

  StaticJsonDocument<512> doc;
  doc["uuid"] = deviceUUID;

  JsonArray data = doc.createNestedArray("data");
  data.add(230.5);   // field1: voltage
  data.add(15.2);    // field2: current
  data.add(0.97);    // field3: power_factor
  data.add(1234.5);  // field4: kwh
  data.add(1456.7);  // field5: kwah
  data.add(28.3);    // field6: temperature (dummy)
  data.add(65.4);    // field7: humidity (dummy)

  String body;
  serializeJson(doc, body);

  Serial.println("==================================================");
  Serial.println("Sending test data to server:");
  Serial.println(body);
  Serial.println("==================================================");

  int status = 0;
  String payload;

  // Send to TEST endpoint
  if (!postJson("/api/device-data/ingest-test", body, apiKey, status, payload)) {
    return false;
  }

  Serial.println("Server response:");
  Serial.println(payload);

  if (status == 401) {
    Serial.println("API key rejected; removing stored key.");
    prefs.remove(KEY_API_TOKEN);
    prefs.remove(KEY_DEVICE_UUID);
    apiKey.clear();
    deviceUUID.clear();
    return false;
  }

  if (status == 403) {
    Serial.println("UUID NOT FOUND IN DATABASE!");
    Serial.println("Server rejected the data.");
    return false;
  }

  if (status >= 200 && status < 300) {
    Serial.println("✓ Test data sent successfully!");
    Serial.println("✓ UUID validated by server!");
    return true;
  }

  Serial.printf("Test data failed: %d %s\n", status, payload.c_str());
  return false;
}

void readTokenFromSerial() {
  if (Serial.available()) {
    provisioningToken = Serial.readStringUntil('\n');
    provisioningToken.trim();
    if (provisioningToken.length()) {
      Serial.println("New provisioning token received.");
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("==================================================");
  Serial.println("TEST CLIENT - UUID Validation");
  Serial.println("==================================================");

  prefs.begin(NAMESPACE_NAME, false);

  apiKey = prefs.getString(KEY_API_TOKEN, "");
  deviceUUID = prefs.getString(KEY_DEVICE_UUID, "");

  connectWifi();

  if (apiKey.isEmpty()) {
    Serial.println("No API key found. Attempting to claim token...");
    if (!claimToken()) {
      Serial.println("Claiming token failed. Paste new token via Serial.");
    }
  } else {
    Serial.println("API key loaded from storage.");
    Serial.print("Device UUID: ");
    Serial.println(deviceUUID);
  }
}

unsigned long lastTelemetry = 0;
const unsigned long TELEMETRY_INTERVAL_MS = 10 * 1000; // 10 seconds for testing

void loop() {
  readTokenFromSerial();

  if (WiFi.status() != WL_CONNECTED) {
    connectWifi();
  }

  if (apiKey.isEmpty() && !provisioningToken.isEmpty()) {
    claimToken();
  }

  unsigned long now = millis();
  if (now - lastTelemetry > TELEMETRY_INTERVAL_MS) {
    lastTelemetry = now;
    if (!apiKey.isEmpty() && !deviceUUID.isEmpty()) {
      sendTestData();
    }
  }
}
