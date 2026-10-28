// NFC attendance reader: ESP32 + RC522 -> HTTPS -> Supabase Edge Function "punch"
//
// The ESP32 is a thin client: it reads a card UID, sends it to the server, and shows
// the result. All decisions (known card? in or out? too soon?) are made server-side.
//
// Wiring (RC522 -> ESP32): SDA/SS=GPIO5, SCK=18, MOSI=23, MISO=19, RST=22, 3.3V, GND
// Feedback: green LED=GPIO25, red LED=GPIO26, active buzzer=GPIO27 (LEDs via resistors)

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <WiFiManager.h>
#include <LittleFS.h>
#include <SPI.h>
#include <MFRC522.h>
#include <ArduinoJson.h>
#include "secrets.h"

#ifndef TLS_INSECURE_FOR_TESTING
// Mozilla root certificate bundle built into the ESP32 Arduino framework
extern const uint8_t rootca_crt_bundle_start[] asm("_binary_x509_crt_bundle_start");
#endif

// ---------------------------------------------------------------- pins & settings
constexpr uint8_t PIN_SS = 5;
constexpr uint8_t PIN_RST = 22;
constexpr uint8_t PIN_LED_OK = 25;
constexpr uint8_t PIN_LED_ERR = 26;
constexpr uint8_t PIN_BUZZER = 27;
constexpr uint8_t PIN_BOOT = 0;  // BOOT button on most dev boards

constexpr uint32_t LOCAL_DEBOUNCE_MS = 3000;   // ignore the same card re-read within 3 s
constexpr uint32_t HTTP_TIMEOUT_MS = 8000;
constexpr uint32_t HTTP_CONNECT_TIMEOUT_MS = 4000;
constexpr uint32_t QUEUE_BACKOFF_MIN_MS = 5000;
constexpr uint32_t QUEUE_BACKOFF_MAX_MS = 60000;
constexpr uint32_t READER_CHECK_MS = 60000;
constexpr uint32_t WIFI_RETRY_MS = 30000;
constexpr uint32_t PORTAL_HOLD_MS = 5000;      // hold BOOT 5 s to re-open WiFi setup
constexpr size_t QUEUE_MAX = 200;
constexpr uint32_t MIN_VALID_TIME = 1735689600;  // 1 Jan 2025: anything earlier = clock not set

static const char *QUEUE_FILE = "/queue.txt";
static const char *QUEUE_TMP = "/queue.tmp";

MFRC522 rfid(PIN_SS, PIN_RST);

static String lastUid;
static uint32_t lastUidAt = 0;
static size_t queueCount = 0;
static uint32_t nextQueueTry = 0;
static uint32_t queueBackoff = QUEUE_BACKOFF_MIN_MS;
static uint32_t lastReaderCheck = 0;
static uint32_t lastWifiTry = 0;
static uint32_t bootPressedAt = 0;
static char deviceTag[16];

// ---------------------------------------------------------------- feedback (LED + buzzer)
static void pulse(uint8_t led, uint16_t onMs) {
  digitalWrite(led, HIGH);
  digitalWrite(PIN_BUZZER, HIGH);
  delay(onMs);
  digitalWrite(led, LOW);
  digitalWrite(PIN_BUZZER, LOW);
}

static void blink(uint8_t led, uint8_t count, uint16_t onMs, uint16_t offMs) {
  for (uint8_t i = 0; i < count; i++) {
    pulse(led, onMs);
    if (i + 1 < count) delay(offMs);
  }
}

// Both LEDs together = "saved on the reader, will upload when online"
static void signalQueued() {
  digitalWrite(PIN_LED_OK, HIGH);
  digitalWrite(PIN_LED_ERR, HIGH);
  digitalWrite(PIN_BUZZER, HIGH);
  delay(400);
  digitalWrite(PIN_LED_OK, LOW);
  digitalWrite(PIN_LED_ERR, LOW);
  digitalWrite(PIN_BUZZER, LOW);
}

// ---------------------------------------------------------------- time
static bool timeValid() { return (uint32_t)time(nullptr) > MIN_VALID_TIME; }

static String nowText() {
  if (!timeValid()) return "(clock not set)";
  struct tm t;
  time_t n = time(nullptr);
  localtime_r(&n, &t);
  char b[24];
  strftime(b, sizeof b, "%Y-%m-%d %H:%M:%S", &t);
  return String(b);
}

static void syncTime() {
  configTzTime(TZ_INFO, "pool.ntp.org", "time.google.com");
  if (WiFi.status() != WL_CONNECTED) return;
  uint32_t t0 = millis();
  while (!timeValid() && millis() - t0 < 10000) delay(200);
  Serial.printf("Time: %s\n", nowText().c_str());
}

// ---------------------------------------------------------------- ids
// Unique per tap, so a retry of the same tap can never be recorded twice.
static String newPunchId() {
  char b[48];
  snprintf(b, sizeof b, "%s-%08lx%08lx", deviceTag, (unsigned long)esp_random(),
           (unsigned long)esp_random());
  return String(b);
}

static String uidToHex(const MFRC522::Uid &uid) {
  String s;
  for (byte i = 0; i < uid.size; i++) {
    if (uid.uidByte[i] < 0x10) s += "0";
    s += String(uid.uidByte[i], HEX);
  }
  s.toUpperCase();
  return s;
}

// ---------------------------------------------------------------- offline queue (LittleFS)
// One line per punch: punchId,uid,timestamp   (timestamp 0 = clock was not set)
static size_t countQueue() {
  File f = LittleFS.open(QUEUE_FILE, "r");
  if (!f) return 0;
  size_t n = 0;
  while (f.available()) {
    if (f.readStringUntil('\n').length() > 0) n++;
  }
  f.close();
  return n;
}

static bool queuePush(const String &punchId, const String &uid, uint32_t ts) {
  if (queueCount >= QUEUE_MAX) {
    Serial.println("Queue full: punch DROPPED");
    return false;
  }
  File f = LittleFS.open(QUEUE_FILE, "a");
  if (!f) return false;
  f.printf("%s,%s,%lu\n", punchId.c_str(), uid.c_str(), (unsigned long)ts);
  f.close();
  queueCount++;
  Serial.printf("Queued (%u waiting)\n", (unsigned)queueCount);
  return true;
}

static bool queuePeek(String &line) {
  File f = LittleFS.open(QUEUE_FILE, "r");
  if (!f) return false;
  line = f.readStringUntil('\n');
  f.close();
  line.trim();
  return line.length() > 0;
}

static void queuePop() {
  File f = LittleFS.open(QUEUE_FILE, "r");
  if (!f) return;
  f.readStringUntil('\n');  // discard the first line
  String rest = f.readString();
  f.close();
  if (rest.length() == 0) {
    LittleFS.remove(QUEUE_FILE);
  } else {
    // write a temp file then swap, so a power cut can't wipe the queue
    File w = LittleFS.open(QUEUE_TMP, "w");
    if (!w) return;
    w.print(rest);
    w.close();
    LittleFS.remove(QUEUE_FILE);
    LittleFS.rename(QUEUE_TMP, QUEUE_FILE);
  }
  if (queueCount > 0) queueCount--;
}

// ---------------------------------------------------------------- talking to the server
enum class Kind { OK, REJECTED, AUTH_FAIL, RETRY };

struct Reply {
  Kind kind = Kind::RETRY;
  int http = 0;
  String name, action, error;
};

// Sends one punch. Fills in `r`:
//   OK        server recorded it (or already had it)
//   REJECTED  server definitively said no (unknown card, too soon...) - never retry
//   AUTH_FAIL bad/disabled reader token - keep punches, fix the config
//   RETRY     network problem or server fault - try again later
static void sendPunch(const String &uid, const String &punchId, uint32_t ts, Reply &r) {
  r = Reply();

  WiFiClientSecure client;
#ifdef TLS_INSECURE_FOR_TESTING
  client.setInsecure();
#else
  client.setCACertBundle(rootca_crt_bundle_start);
#endif

  HTTPClient http;
  http.setTimeout(HTTP_TIMEOUT_MS);
  http.setConnectTimeout(HTTP_CONNECT_TIMEOUT_MS);
  if (!http.begin(client, FUNCTION_URL)) {
    Serial.println("http.begin failed");
    return;
  }
  http.addHeader("Content-Type", "application/json");
  http.addHeader("Authorization", String("Bearer ") + DEVICE_TOKEN);

  JsonDocument doc;
  doc["uid"] = uid;
  doc["punch_id"] = punchId;
  if (ts > 0) doc["ts"] = ts;
  String body;
  serializeJson(doc, body);

  int code = http.POST(body);
  String payload = code > 0 ? http.getString() : String();
  http.end();

  if (code <= 0) {
    Serial.printf("Network error: %s\n", HTTPClient::errorToString(code).c_str());
    return;  // RETRY
  }
  r.http = code;

  JsonDocument res;
  if (!deserializeJson(res, payload)) {
    r.name = res["name"] | "";
    r.action = res["action"] | "";
    r.error = res["error"] | "";
  }

  if (code >= 200 && code < 300) {
    r.kind = Kind::OK;
  } else if (code == 401) {
    r.kind = Kind::AUTH_FAIL;
  } else if (code == 404 && r.error == "unknown_card") {
    r.kind = Kind::REJECTED;
  } else if (code == 409 || code == 400) {
    r.kind = Kind::REJECTED;
  } else {
    r.kind = Kind::RETRY;  // 408/429/5xx, or a 404 from a wrong URL: don't throw punches away
  }
  Serial.printf("Server: HTTP %d  %s\n", code, payload.c_str());
}

// Shows the outcome of a punch on the LEDs/buzzer.
static void showReply(const Reply &r) {
  switch (r.kind) {
    case Kind::OK:
      if (r.action == "in") {
        Serial.printf("CLOCK IN : %s\n", r.name.c_str());
        blink(PIN_LED_OK, 1, 200, 0);
      } else if (r.action == "out") {
        Serial.printf("CLOCK OUT: %s\n", r.name.c_str());
        blink(PIN_LED_OK, 2, 150, 120);
      } else if (r.action == "enrolled") {
        Serial.printf("CARD ENROLLED for %s\n", r.name.c_str());
        blink(PIN_LED_OK, 3, 100, 80);
      } else {
        blink(PIN_LED_OK, 1, 200, 0);
      }
      break;
    case Kind::REJECTED:
      Serial.printf("Rejected: %s\n", r.error.c_str());
      if (r.error == "unknown_card") blink(PIN_LED_ERR, 1, 700, 0);
      else if (r.error == "card_inactive") blink(PIN_LED_ERR, 2, 250, 150);
      else if (r.error == "too_soon") blink(PIN_LED_ERR, 1, 80, 0);
      else blink(PIN_LED_ERR, 3, 150, 100);
      break;
    case Kind::AUTH_FAIL:
      Serial.println("AUTH FAILED: check DEVICE_TOKEN, or the reader is switched off on the website");
      blink(PIN_LED_ERR, 6, 80, 80);
      break;
    case Kind::RETRY:
      break;  // handled by the caller (queued)
  }
}

// ---------------------------------------------------------------- handling a tap
static void handleCard(const String &uid) {
  String punchId = newPunchId();
  uint32_t ts = timeValid() ? (uint32_t)time(nullptr) : 0;
  Serial.printf("[%s] Card %s\n", nowText().c_str(), uid.c_str());

#ifdef DRY_RUN
  Serial.println("DRY RUN: not sending. UID read OK.");
  blink(PIN_LED_OK, 1, 150, 0);
  (void)punchId;
  (void)ts;
  return;
#else
  // Keep punches in order: if older ones are waiting, this one joins the back of the queue.
  if (queueCount > 0 || WiFi.status() != WL_CONNECTED) {
    if (queuePush(punchId, uid, ts)) signalQueued();
    else blink(PIN_LED_ERR, 4, 100, 80);
    return;
  }

  Reply r;
  sendPunch(uid, punchId, ts, r);
  if (r.kind == Kind::RETRY) {
    if (queuePush(punchId, uid, ts)) signalQueued();
    else blink(PIN_LED_ERR, 4, 100, 80);
    return;
  }
  showReply(r);
#endif
}

// Uploads one waiting punch at a time, backing off while the network is down.
static void processQueue() {
#ifndef DRY_RUN
  if (queueCount == 0 || WiFi.status() != WL_CONNECTED) return;
  if ((int32_t)(millis() - nextQueueTry) < 0) return;

  String line;
  if (!queuePeek(line)) {
    queueCount = 0;
    return;
  }
  int a = line.indexOf(','), b = line.indexOf(',', a + 1);
  if (a < 0 || b < 0) {  // corrupt line: discard
    queuePop();
    return;
  }
  String punchId = line.substring(0, a);
  String uid = line.substring(a + 1, b);
  uint32_t ts = (uint32_t)strtoul(line.substring(b + 1).c_str(), nullptr, 10);

  Reply r;
  sendPunch(uid, punchId, ts, r);
  if (r.kind == Kind::OK || r.kind == Kind::REJECTED) {
    Serial.printf("Queued punch uploaded (%s)\n", r.kind == Kind::OK ? "ok" : r.error.c_str());
    queuePop();
    queueBackoff = QUEUE_BACKOFF_MIN_MS;
    nextQueueTry = millis();  // go straight to the next one
  } else {
    queueBackoff = min(queueBackoff * 2, QUEUE_BACKOFF_MAX_MS);
    nextQueueTry = millis() + queueBackoff;
  }
#endif
}

// ---------------------------------------------------------------- WiFi
static void connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFiManager wm;
  wm.setConfigPortalTimeout(180);  // if nobody sets it up, carry on offline
  wm.setConnectTimeout(20);
  Serial.println("Connecting to WiFi (or opening setup hotspot)...");
  if (wm.autoConnect(PORTAL_AP_NAME, PORTAL_AP_PASS)) {
    Serial.printf("WiFi connected: %s\n", WiFi.localIP().toString().c_str());
  } else {
    Serial.println("No WiFi. Running offline; punches will queue.");
  }
}

static void runConfigPortal() {
  Serial.printf("Setup hotspot '%s' open for 3 minutes...\n", PORTAL_AP_NAME);
  digitalWrite(PIN_LED_OK, HIGH);
  digitalWrite(PIN_LED_ERR, HIGH);
  WiFiManager wm;
  wm.setConfigPortalTimeout(180);
  wm.startConfigPortal(PORTAL_AP_NAME, PORTAL_AP_PASS);
  ESP.restart();
}

static void maintainWiFi() {
#ifndef DRY_RUN
  if (WiFi.status() == WL_CONNECTED) return;
  if (millis() - lastWifiTry < WIFI_RETRY_MS) return;
  lastWifiTry = millis();
  Serial.println("WiFi down, reconnecting...");
  WiFi.reconnect();
#endif
}

// Hold BOOT for 5 s (after the board has started) to change WiFi.
static void handleBootButton() {
  if (digitalRead(PIN_BOOT) == LOW) {
    if (bootPressedAt == 0) bootPressedAt = millis();
    else if (millis() - bootPressedAt >= PORTAL_HOLD_MS) runConfigPortal();
  } else {
    bootPressedAt = 0;
  }
}

// ---------------------------------------------------------------- RC522
static bool readerOk() {
  byte v = rfid.PCD_ReadRegister(MFRC522::VersionReg);
  return v != 0x00 && v != 0xFF;  // 0x00/0xFF = no response (wiring or power fault)
}

// RC522 clone boards sometimes lock up: re-initialise if it stops answering.
static void checkReaderHealth() {
  if (millis() - lastReaderCheck < READER_CHECK_MS) return;
  lastReaderCheck = millis();
  if (!readerOk()) {
    Serial.println("RC522 not responding: re-initialising");
    rfid.PCD_Init();
    if (!readerOk()) blink(PIN_LED_ERR, 2, 300, 200);
  }
}

static void readCard() {
  if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) return;
  String uid = uidToHex(rfid.uid);
  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();

  if (uid == lastUid && millis() - lastUidAt < LOCAL_DEBOUNCE_MS) return;
  lastUid = uid;
  handleCard(uid);
  lastUidAt = millis();  // measured from when feedback finished
}

// ---------------------------------------------------------------- setup / loop
void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("\n=== NFC attendance reader ===");

  pinMode(PIN_LED_OK, OUTPUT);
  pinMode(PIN_LED_ERR, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);
  pinMode(PIN_BOOT, INPUT_PULLUP);

  uint64_t mac = ESP.getEfuseMac();
  snprintf(deviceTag, sizeof deviceTag, "%04X%08X", (uint16_t)(mac >> 32), (uint32_t)mac);
  Serial.printf("Device tag: %s\n", deviceTag);

  SPI.begin();
  rfid.PCD_Init();
  delay(50);
  byte v = rfid.PCD_ReadRegister(MFRC522::VersionReg);
  Serial.printf("RC522 version register: 0x%02X %s\n", v,
                readerOk() ? "(OK)" : "(NO RESPONSE: check wiring and 3.3V)");
  if (!readerOk()) blink(PIN_LED_ERR, 3, 300, 200);

#ifndef DRY_RUN
  if (!LittleFS.begin(true)) Serial.println("LittleFS failed: offline queue unavailable");
  queueCount = countQueue();
  Serial.printf("Punches waiting in queue: %u\n", (unsigned)queueCount);

  connectWiFi();
  syncTime();
#else
  Serial.println("DRY RUN mode: WiFi and server disabled.");
#endif

  blink(PIN_LED_OK, 1, 120, 0);  // ready
  Serial.println("Ready. Tap a card.");
}

void loop() {
  handleBootButton();
  maintainWiFi();
  checkReaderHealth();
  readCard();      // taps first...
  processQueue();  // ...then catch up on any backlog
  delay(10);
}
