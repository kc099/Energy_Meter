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

const unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000; // 15 seconds

bool connectWifi() {
  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }

  Serial.printf("Connecting to Wi-Fi SSID: %s\n", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true, true);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  unsigned long startAttempt = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - startAttempt < WIFI_CONNECT_TIMEOUT_MS) {
    delay(500);
    Serial.print('.');
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\n==== Wi-Fi connected ====");
    Serial.print("IP Address: ");
    Serial.println(WiFi.localIP());
    Serial.print("Connecting to server: ");
    Serial.print(API_HOST);
    Serial.print(":");
    Serial.println(API_PORT);
    Serial.println("========================");
    return true;
  }

  Serial.printf("\nWi-Fi connect failed (status=%d). Check SSID/password and ensure 2.4 GHz availability.\n", WiFi.status());
  return false;
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

  Serial.printf("Attempting POST to: %s\n", url.c_str());
  Serial.printf("Body: %s\n", body.c_str());

  bool began = false;
  if (USE_TLS) {
    began = http.begin(secureClient, API_HOST, API_PORT, path, true);
  } else {
    began = http.begin(plainClient, API_HOST, API_PORT, path);
  }
  if (!began) {
    Serial.println("ERROR: HTTP begin failed");
    return false;
  }
  http.addHeader("Content-Type", "application/json");
  if (bearer.length()) {
    http.addHeader("Authorization", "Bearer " + bearer);
    Serial.println("Added Authorization header");
  }

  status = http.POST(body);
  payload = http.getString();
  http.end();

  Serial.printf("Response status: %d\n", status);
  Serial.printf("Response payload: %s\n", payload.c_str());

  if (status < 0) {
    Serial.printf("HTTPClient error: %s\n", HTTPClient::errorToString(status).c_str());
  }

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

  // Generate random data for testing
  float voltage = random(2200, 2400) / 10.0;      // 220.0 - 240.0 V
  float current = random(10, 200) / 10.0;         // 1.0 - 20.0 A
  float power_factor = random(800, 1000) / 1000.0; // 0.800 - 1.000
  float kwh = random(10000, 20000) / 10.0;        // 1000.0 - 2000.0 kWh

  StaticJsonDocument<256> doc;
  doc["voltage"] = voltage;
  doc["current"] = current;
  doc["power_factor"] = power_factor;
  doc["kwh"] = kwh;

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
    Serial.printf("Telemetry sent: V=%.1f, I=%.1f, PF=%.3f, kWh=%.1f\n",
                  voltage, current, power_factor, kwh);
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

  if (!connectWifi()) {
    Serial.println("Unable to join Wi-Fi. Re-check credentials via Serial monitor.");
  }
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
const unsigned long TELEMETRY_INTERVAL_MS = 20; // Send every 20ms (50 times per second)

void loop() {
  readTokenFromSerial();

  if (WiFi.status() != WL_CONNECTED) {
    if (!connectWifi()) {
      delay(2000);
      return;
    }
  }

  if (apiKey.isEmpty() && !provisioningToken.isEmpty()) {
    claimToken();
  }

  unsigned long now = millis();
  if (now - lastTelemetry >= TELEMETRY_INTERVAL_MS) {
    lastTelemetry = now;
    if (sendTelemetry()) {
      // Successfully sent data
    } else {
      // Failed to send, wait a bit longer before retrying
      delay(1000);
    }
  }
}
