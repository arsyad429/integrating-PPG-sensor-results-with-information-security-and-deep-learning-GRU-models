#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <time.h> 
#include <Wire.h>
#include "MAX30105.h" 
#include "heartRate.h" 
#include <Crypto.h>
#include <Ascon128.h> 
#include <SHA3.h> 

// --- Konfigurasi Jaringan & MQTT ---
const char* ssid = "SamsungS23FE";       
const char* password = "spectercantik";
const char* mqtt_server = "broker.hivemq.com";
const int mqtt_port = 1883;
const char* mqtt_topic = "arsyad/brawijaya_med/secure_ppg"; 
const char* ntpServer = "pool.ntp.org";

WiFiClient espClient;
PubSubClient client(espClient);
MAX30105 particleSensor;

// --- Variabel Keamanan ASCON-128 & SHA3 ---
Ascon128 ascon;
SHA3_256 sha3; 

// Kunci rahasia 16-byte (SAMA dengan di kode Streamlit Anda)
byte secretKey[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
byte nonce[16] = {0}; 

// --- Variabel Kalkulasi PPG & HRV ---
long lastBeat = 0; 
int ibi = 0;       
float beatsPerMinute = 0;
int beatAvg = 0;   

const byte RATE_SIZE = 4;
byte rates[RATE_SIZE];
byte rateSpot = 0;

const byte HRV_SIZE = 10; 
int ibi_array[HRV_SIZE];
byte ibi_spot = 0;
float hrv_sdnn = 0.0;

// --- Variabel Pengatur Waktu ---
unsigned long lastPublishTime = 0;
const int PUBLISH_INTERVAL = 200; 

String toHex(byte* data, int len) {
  String hexStr = "";
  for(int i = 0; i < len; i++) {
    if(data[i] < 0x10) hexStr += "0";
    hexStr += String(data[i], HEX);
  }
  return hexStr;
}

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
    String clientId = "ESP32S3-Secure-";
    clientId += String(random(0, 1000));
    if (client.connect(clientId.c_str())) { } 
    else { delay(5000); }
  }
}

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
  client.setBufferSize(512); 
}

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
      ibi = currentTime - lastBeat; 
      lastBeat = currentTime;

      beatsPerMinute = 60 / (ibi / 1000.0);

      if (beatsPerMinute < 255 && beatsPerMinute > 40) {
        rates[rateSpot++] = (byte)beatsPerMinute;
        rateSpot %= RATE_SIZE;
        beatAvg = 0;
        for (byte x = 0 ; x < RATE_SIZE ; x++) beatAvg += rates[x];
        beatAvg /= RATE_SIZE; 

        // Kalkulasi HRV (SDNN)
        ibi_array[ibi_spot++] = ibi;
        ibi_spot %= HRV_SIZE;

        float mean_ibi = 0;
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

  // Kalkulasi Beban Pemrosesan Utama
  unsigned long processingTime = micros() - loopStartMicros; 
  float realCpuLoad = ((float)processingTime / (processingTime + 10000.0)) * 100.0;

  if (millis() - lastPublishTime >= PUBLISH_INTERVAL) {
    lastPublishTime = millis();

    uint32_t freeHeap = ESP.getFreeHeap();
    uint32_t totalHeap = ESP.getHeapSize();
    float memoryUsagePercent = ((float)(totalHeap - freeHeap) / totalHeap) * 100.0;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long long current_epoch_ms = (unsigned long long)(tv.tv_sec) * 1000ULL + (unsigned long long)(tv.tv_usec) / 1000ULL;

    // 1. Membuat Plaintext JSON Medis
    StaticJsonDocument<256> plainDoc; 
    plainDoc["ppg"] = irValue;     
    plainDoc["bpm"] = beatAvg;
    plainDoc["ibi"] = ibi;         
    plainDoc["hrv"] = hrv_sdnn;
    plainDoc["status"] = sensorStatus;
    
    String plainTextStr;
    serializeJson(plainDoc, plainTextStr);
    int plainLen = plainTextStr.length();

    // 2. Pembuatan Integritas Data via SHA3-256
    byte sha3Hash[32]; 
    sha3.reset();
    sha3.update((const uint8_t*)plainTextStr.c_str(), plainLen);
    sha3.finalize(sha3Hash, 32);

    // 3. Proses Enkripsi ASCON-128 Authenticated Encryption
    nonce[0]++; 
    if(nonce[0] == 0) nonce[1]++; 

    byte ciphertext[plainLen];
    byte tag[16];

    unsigned long startEnc = micros(); 
    ascon.clear();
    ascon.setKey(secretKey, 16);
    ascon.setIV(nonce, 16);
    ascon.encrypt(ciphertext, (const uint8_t*)plainTextStr.c_str(), plainLen);
    ascon.computeTag(tag, 16);
    unsigned long endEnc = micros(); 
    
    unsigned long encryptionTime = endEnc - startEnc;
    int encryptionOverhead = 16; 
    
    // PERBAIKAN FORMAT UNTUK PYTHON: 
    // Pustaka 'ascon' di Python mengharapkan format gabungan [Ciphertext + Tag] 
    // saat menjalankan ascon.decrypt() jika variabel tag tidak dipisah eksplisit.
    byte fullCipher[plainLen + 16];
    memcpy(fullCipher, ciphertext, plainLen);
    memcpy(fullCipher + plainLen, tag, 16);
    
    // 4. Memasukkan ke Payload JSON Utama Jaringan
    StaticJsonDocument<512> secureDoc; 
    secureDoc["ct"] = toHex(fullCipher, plainLen + 16);
    secureDoc["nonce"] = toHex(nonce, 16);
    secureDoc["sha3"] = toHex(sha3Hash, 32); // Untuk verifikasi integritas opsional di sisi server
    secureDoc["enc_t"] = encryptionTime;     
    secureDoc["enc_o"] = encryptionOverhead; 
    secureDoc["cpu"] = realCpuLoad; 
    secureDoc["mem"] = memoryUsagePercent;
    secureDoc["ts"] = current_epoch_ms; // Dibaca Streamlit untuk kalkulasi Latensi

    char jsonBuffer[512];
    serializeJson(secureDoc, jsonBuffer);
    client.publish(mqtt_topic, jsonBuffer);
  }

  delay(10); 
}