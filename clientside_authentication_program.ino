// ESP32 Integration Checklist
// 1. Store the provisioning token securely (e.g., Serial input → NVS flash).
// 2. Connect to Wi-Fi; enable USE_TLS + CA cert only when the server speaks HTTPS.
// 3. Claim the token: build JSON payload, POST to /api/devices/claim, persist returned API key in NVS.
// 4. Replace the token with the permanent API key for all subsequent requests.
// 5. Send telemetry to /api/device-data/ingest with the Authorization header.
// 6. Handle 401 responses by halting transmission and requesting a new provisioning token from the owner.

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
static const bool USE_TLS        = true;     // set false for http:// + WiFiClient

// Paste the PEM for your Django server’s CA cert here (no extra spaces).
static const char SERVER_CA_PEM[] PROGMEM = R"(
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
)";

// Initial provisioning token (overwrite via serial as needed)
String provisioningToken = "paste-one-time-token";

// ---------------------------------------------------------------------------

Preferences prefs;
WiFiClient plainClient;
WiFiClientSecure secureClient;
HTTPClient http;

const char *NAMESPACE_NAME = "energy";
const char *KEY_API_TOKEN  = "apiToken";
const char *KEY_PROV_TOKEN = "provToken";

String apiKey;

void connectWifi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("Connecting to Wi-Fi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print('.');
  }
  Serial.println("\nWi-Fi connected");
}

bool beginSecureClient() {
  if (USE_TLS) {
    secureClient.setCACert(SERVER_CA_PEM);
  }
  return true;
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
  // doc["device_ip"] = WiFi.localIP().toString(); // optional metadata
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

  StaticJsonDocument<256> resp;
  DeserializationError err = deserializeJson(resp, payload);
  if (err) {
    Serial.println("Failed to parse claim response");
    return false;
  }

  apiKey = resp["api_key"].as<String>();
  prefs.putString(KEY_API_TOKEN, apiKey);
  prefs.remove(KEY_PROV_TOKEN);
  provisioningToken.clear();
  Serial.println("Provisioning complete. API key stored.");
  return true;
}

bool sendTelemetry() {
  if (apiKey.isEmpty()) {
    Serial.println("No API key; skip telemetry.");
    return false;
  }

  StaticJsonDocument<256> doc;
  doc["voltage"] = 228.4;
  doc["current"] = 3.2;
  doc["power_factor"] = 0.97;
  doc["kwh"] = 1234.5;

  String body;
  serializeJson(doc, body);

  int status = 0;
  String payload;
  if (!postJson("/api/device-data/ingest", body, apiKey, status, payload)) {
    return false;
  }

  if (status == 401) {
    Serial.println("API key rejected; removing stored key.");
    prefs.remove(KEY_API_TOKEN);
    apiKey.clear();
    return false;
  }

  if (status >= 200 && status < 300) {
    Serial.println("Telemetry sent.");
    return true;
  }

  Serial.printf("Telemetry failed: %d %s\n", status, payload.c_str());
  return false;
}

void readTokenFromSerial() {
  if (Serial.available()) {
    provisioningToken = Serial.readStringUntil('\n');
    provisioningToken.trim();
    if (provisioningToken.length()) {
      prefs.putString(KEY_PROV_TOKEN, provisioningToken);
      Serial.println("New provisioning token saved to NVS.");
    }
  }
}

void setup() {
  Serial.begin(115200);
  prefs.begin(NAMESPACE_NAME, false);

  apiKey = prefs.getString(KEY_API_TOKEN, "");
  provisioningToken = prefs.getString(KEY_PROV_TOKEN, provisioningToken);

  connectWifi();
  beginSecureClient();

  if (apiKey.isEmpty()) {
    if (!claimToken()) {
      Serial.println("Claiming token failed. Awaiting new token...");
    }
  } else {
    Serial.println("API key loaded from NVS.");
  }
}

unsigned long lastTelemetry = 0;
const unsigned long TELEMETRY_INTERVAL_MS = 60 * 1000;

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
    sendTelemetry();
  }
}
