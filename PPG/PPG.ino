#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <time.h> 
#include <Wire.h>
#include "MAX30105.h" 
#include "heartRate.h" 

// --- Konfigurasi Jaringan & MQTT ---
const char* ssid = "";       
const char* password = "";
const char* mqtt_server = "broker.hivemq.com";
const int mqtt_port = 1883;
const char* mqtt_topic = "arsyad/brawijaya_med/ppg_sensor_01";
const char* ntpServer = "pool.ntp.org";

WiFiClient espClient;
PubSubClient client(espClient);
MAX30105 particleSensor;

// --- Variabel Kalkulasi PPG ---
long lastBeat = 0; 
int ibi = 0;       
float beatsPerMinute = 0;
int beatAvg = 0;   

const byte RATE_SIZE = 4;
byte rates[RATE_SIZE];
byte rateSpot = 0;

// --- Variabel HRV ---
const byte HRV_SIZE = 10; // Mengambil 10 detak terakhir untuk analisis variabilitas
int ibi_array[HRV_SIZE];
byte ibi_spot = 0;
float hrv_sdnn = 0.0;

// --- Variabel Pengatur Waktu ---
unsigned long lastPublishTime = 0;
const int PUBLISH_INTERVAL = 200; 

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
    String clientId = "ESP32S3-PPG-";
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
  client.setBufferSize(512); // Memastikan ukuran paket MQTT mencukupi
}

void loop() {
  unsigned long loopStartMicros = micros(); // Mulai Stopwatch CPU Riil

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

        // --- Kalkulasi HRV (Metode SDNN) ---
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

  // --- Kalkulasi CPU Riil ---
  unsigned long processingTime = micros() - loopStartMicros; 
  // Loop memakan waktu pemrosesan aktif + delay 10ms (10000 us)
  float realCpuLoad = ((float)processingTime / (processingTime + 10000.0)) * 100.0;

  if (millis() - lastPublishTime >= PUBLISH_INTERVAL) {
    lastPublishTime = millis();

    Serial.printf("BPM: %d | IBI: %d ms | HRV: %.1f ms | CPU: %.1f%% | IR: %ld\n", 
                   beatAvg, ibi, hrv_sdnn, realCpuLoad, irValue);

    uint32_t freeHeap = ESP.getFreeHeap();
    uint32_t totalHeap = ESP.getHeapSize();
    float memoryUsagePercent = ((float)(totalHeap - freeHeap) / totalHeap) * 100.0;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long long current_epoch_ms = (unsigned long long)(tv.tv_sec) * 1000ULL + (unsigned long long)(tv.tv_usec) / 1000ULL;

    StaticJsonDocument<384> doc; 
    doc["ppg"] = irValue;     
    doc["bpm"] = beatAvg;
    doc["ibi"] = ibi;         
    doc["hrv"] = hrv_sdnn;
    doc["status"] = sensorStatus;
    doc["cpu"] = realCpuLoad; 
    doc["mem"] = memoryUsagePercent;
    doc["ts"] = current_epoch_ms; 

    char jsonBuffer[384];
    serializeJson(doc, jsonBuffer);
    client.publish(mqtt_topic, jsonBuffer);
  }

  delay(10); 
}