// ============================================================
//  PPG_SHA3.ino  —  Level 8: Integrity Implementation
//  Mengganti ASCON Encryption → SHA3-256 Hashing
//  Data ECG dikirim plaintext + hash SHA3 untuk verifikasi integritas
// ============================================================

#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <time.h>
#include <Wire.h>
#include "MAX30105.h"
#include "heartRate.h"
#include <Crypto.h>
#include <SHA3.h>

// --- Konfigurasi Jaringan & MQTT ---
const char* ssid         = "SSID";
const char* password     = "password";
const char* mqtt_server  = "broker.hivemq.com";
const int   mqtt_port    = 1883;
const char* mqtt_topic   = "arsyad/brawijaya_med/sha3_ppg"; // topic baru untuk Level 8
const char* ntpServer    = "pool.ntp.org";

WiFiClient   espClient;
PubSubClient client(espClient);
MAX30105     particleSensor;

// --- Variabel Kalkulasi PPG & HRV ---
long lastBeat = 0;
int  ibi      = 0;
float beatsPerMinute = 0;
int   beatAvg        = 0;

const byte RATE_SIZE = 4;
byte rates[RATE_SIZE];
byte rateSpot = 0;

const byte HRV_SIZE = 10;
int  ibi_array[HRV_SIZE];
byte ibi_spot  = 0;
float hrv_sdnn = 0.0;

// --- Variabel Pengatur Waktu ---
unsigned long lastPublishTime = 0;
const int PUBLISH_INTERVAL    = 200;

// ============================================================
//  FUNGSI HELPER
// ============================================================

// Konversi byte array → hex string (sama seperti sebelumnya)
String toHex(byte* data, int len) {
  String hexStr = "";
  for (int i = 0; i < len; i++) {
    if (data[i] < 0x10) hexStr += "0";
    hexStr += String(data[i], HEX);
  }
  return hexStr;
}

// ============================================================
//  FUNGSI SHA3-256 HASHING  <-- BARU, pengganti ASCON encrypt
//  Input  : string data yang mau di-hash
//  Output : hex string 64 karakter (256 bit / 32 byte)
// ============================================================
// Buat objek SHA3-256 (Kamu juga bisa pakai SHA3_512 jika butuh yang 512-bit)
SHA3_256 sha3;

String hitungSHA3String(String input) {
  byte hash[32]; // SHA3-256 menghasilkan 32 byte
  
  // Proses Hashing
  sha3.reset();
  sha3.update((const uint8_t*)input.c_str(), input.length());
  sha3.finalize(hash, sizeof(hash));
  
  // Ubah hasil byte menjadi teks Hexadecimal agar mudah dibaca
  String hashHex = "";
  for (int i = 0; i < sizeof(hash); i++) {
    if (hash[i] < 0x10) hashHex += "0";
    hashHex += String(hash[i], HEX);
  }
  
  return hashHex;
}

// ============================================================
void setup_wifi() {
  delay(10);
  Serial.print("Connecting to ");
  Serial.println(ssid);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.println("\nWiFi connected");

  configTime(0, 0, ntpServer);
  while (time(nullptr) < 100000) { delay(100); }
}

void reconnect() {
  while (!client.connected()) {
    String clientId = "ESP32S3-SHA3-";
    clientId += String(random(0, 1000));
    if (client.connect(clientId.c_str())) { }
    else { delay(5000); }
  }
}

// ============================================================
void setup() {
  Serial.begin(115200);
  delay(3000);

  Wire.begin(8, 9);
  if (!particleSensor.begin(Wire, I2C_SPEED_FAST)) {
    Serial.println("MAX30102 tidak ditemukan. Cek I2C!");
    while (1);
  }

  particleSensor.setup();
  particleSensor.setPulseAmplitudeRed(0x0A);
  particleSensor.setPulseAmplitudeGreen(0);

  setup_wifi();
  client.setServer(mqtt_server, mqtt_port);
  client.setBufferSize(600); // sedikit lebih besar karena ada field hash (64 char)
}

// ============================================================
void loop() {
  unsigned long loopStartMicros = micros();

  if (!client.connected()) reconnect();
  client.loop();

  long irValue = particleSensor.getIR();
  String sensorStatus = "Good (100%)";

  if (irValue < 50000) {
    sensorStatus = "No Finger Detected";
    beatAvg = 0; ibi = 0; hrv_sdnn = 0.0;
  } else {
    if (checkForBeat(irValue) == true) {
      unsigned long currentTime = millis();
      ibi       = currentTime - lastBeat;
      lastBeat  = currentTime;

      beatsPerMinute = 60 / (ibi / 1000.0);

      if (beatsPerMinute < 255 && beatsPerMinute > 40) {
        rates[rateSpot++] = (byte)beatsPerMinute;
        rateSpot %= RATE_SIZE;
        beatAvg = 0;
        for (byte x = 0; x < RATE_SIZE; x++) beatAvg += rates[x];
        beatAvg /= RATE_SIZE;

        // Kalkulasi HRV (SDNN) — sama seperti sebelumnya
        ibi_array[ibi_spot++] = ibi;
        ibi_spot %= HRV_SIZE;

        float mean_ibi  = 0;
        int valid_count = 0;
        for (byte i = 0; i < HRV_SIZE; i++) {
          if (ibi_array[i] > 0) { mean_ibi += ibi_array[i]; valid_count++; }
        }
        if (valid_count > 0) mean_ibi /= valid_count;

        float variance = 0;
        for (byte i = 0; i < HRV_SIZE; i++) {
          if (ibi_array[i] > 0) variance += pow(ibi_array[i] - mean_ibi, 2);
        }
        if (valid_count > 1) hrv_sdnn = sqrt(variance / (valid_count - 1));
      }
    }
  }

  // Kalkulasi CPU Riil
  unsigned long processingTime = micros() - loopStartMicros;
  float realCpuLoad = ((float)processingTime / (processingTime + 10000.0)) * 100.0;

  if (millis() - lastPublishTime >= PUBLISH_INTERVAL) {
    lastPublishTime = millis();

    Serial.printf("BPM: %d | IBI: %d ms | HRV: %.1f ms | CPU: %.1f%% | IR: %ld\n",
                  beatAvg, ibi, hrv_sdnn, realCpuLoad, irValue);

    uint32_t freeHeap  = ESP.getFreeHeap();
    uint32_t totalHeap = ESP.getHeapSize();
    float memoryUsagePercent = ((float)(totalHeap - freeHeap) / totalHeap) * 100.0;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long long current_epoch_ms =
      (unsigned long long)(tv.tv_sec) * 1000ULL +
      (unsigned long long)(tv.tv_usec) / 1000ULL;

    // -------------------------------------------------------
    //  STEP 1: Buat JSON data PPG (plaintext, tidak disembunyikan)
    // -------------------------------------------------------
    StaticJsonDocument<256> plainDoc;
    plainDoc["ppg"]    = irValue;
    plainDoc["bpm"]    = beatAvg;
    plainDoc["ibi"]    = ibi;
    plainDoc["hrv"]    = hrv_sdnn;
    plainDoc["status"] = sensorStatus;

    String plainTextStr;
    serializeJson(plainDoc, plainTextStr);

    // -------------------------------------------------------
    //  STEP 2: Hitung SHA3-256 dari data PPG
    //  Ukur waktu hashing (dalam mikrodetik) untuk evaluasi Level 9
    // -------------------------------------------------------
    unsigned long startHash = micros();
    String hashResult = hitungSHA3String(plainTextStr);
    unsigned long endHash = micros();

    unsigned long hashingTime = endHash - startHash; // dalam mikrodetik

    // -------------------------------------------------------
    //  STEP 3: Kirim payload = data asli + hash + metadata
    //  (berbeda dengan ASCON yang kirim ciphertext)
    // -------------------------------------------------------
    StaticJsonDocument<512> secureDoc;
    secureDoc["ppg"]              = irValue;       // data asli (terbaca)
    secureDoc["bpm"]              = beatAvg;
    secureDoc["ibi"]              = ibi;
    secureDoc["hrv"]              = hrv_sdnn;
    secureDoc["status"]           = sensorStatus;
    secureDoc["hash"]             = hashResult;    // SHA3-256 hash (64 char hex)
    secureDoc["hash_t"]           = hashingTime;   // hashing time (us) — untuk Level 9
    secureDoc["integrity_valid"]  = true;          // selalu true di sisi pengirim
    secureDoc["cpu"]              = realCpuLoad;
    secureDoc["mem"]              = memoryUsagePercent;
    secureDoc["ts"]               = current_epoch_ms;

    char jsonBuffer[512];
    serializeJson(secureDoc, jsonBuffer);
    client.publish(mqtt_topic, jsonBuffer);

    Serial.printf("Hash: %s | Hash Time: %lu us\n",
                  hashResult.substring(0, 16).c_str(), hashingTime);
  }

  delay(10);
}
