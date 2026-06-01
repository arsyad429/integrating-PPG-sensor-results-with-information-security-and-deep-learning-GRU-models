#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <time.h> 
#include <Wire.h>
#include "MAX30105.h" 
#include "heartRate.h" 

// --- PUSTAKA TENSORFLOW LITE ---
#include <TensorFlowLite_ESP32.h>
#include "tensorflow/lite/micro/all_ops_resolver.h"
#include "tensorflow/lite/micro/micro_error_reporter.h"
#include "tensorflow/lite/micro/micro_interpreter.h"
#include "tensorflow/lite/schema/schema_generated.h"
#include "model_data.h" // ⚠️ Pastikan file ini ada di folder proyek!

// --- Konfigurasi Jaringan & MQTT ---
const char* ssid = "";       
const char* password = "";
const char* mqtt_server = "broker.hivemq.com";
const int mqtt_port = 1883;
const char* mqtt_topic = "ppg_sensor_01";
const char* ntpServer = "pool.ntp.org";

WiFiClient espClient;
PubSubClient client(espClient);
MAX30105 particleSensor;

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

// --- Variabel Pengatur Waktu & Bendera AI ---
unsigned long lastPublishTime = 0;
const int PUBLISH_INTERVAL = 200; 
bool newBeatDetected = false; // Bendera agar AI tidak membaca duplikat data

// =========================================================
// VARIABEL GLOBAL TENSORFLOW LITE
// =========================================================
const tflite::Model* tfliteModel = nullptr;
tflite::MicroInterpreter* interpreter = nullptr;
tflite::MicroErrorReporter micro_error_reporter;
tflite::ErrorReporter* error_reporter = &micro_error_reporter;

constexpr int kTensorArenaSize = 128 * 1024; // 128KB untuk GRU Model
uint8_t tensor_arena[kTensorArenaSize];

float input_buffer[60];
int data_index = 0;
String current_diagnosis = "Waiting for finger...";

// =========================================================
// FUNGSI HELPER
// =========================================================
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
    String clientId = "ESP32S3-PPG-ML-";
    clientId += String(random(0, 1000));
    if (client.connect(clientId.c_str())) { } 
    else { delay(5000); }
  }
}

// =========================================================
// SETUP
// =========================================================
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

  // Inisialisasi TFLite
  tfliteModel = tflite::GetModel(model_tflite);
  if (tfliteModel->version() != TFLITE_SCHEMA_VERSION) {
    Serial.println("ERROR: Skema TFLite tidak cocok!");
    while (true);
  }

  static tflite::AllOpsResolver resolver;
  static tflite::MicroInterpreter static_interpreter(
      tfliteModel, resolver, tensor_arena, kTensorArenaSize, error_reporter);
  interpreter = &static_interpreter;

  if (interpreter->AllocateTensors() != kTfLiteOk) {
    Serial.println("ERROR: Gagal mengalokasikan memori Tensor Arena!");
    while (true);
  }
  Serial.println("✅ TFLite Model berhasil dimuat!");
}

// =========================================================
// MAIN LOOP
// =========================================================
void loop() {
  unsigned long loopStartMicros = micros(); 

  if (!client.connected()) reconnect();
  client.loop();

  long irValue = particleSensor.getIR();
  String sensorStatus = "Good (100%)";

  // --- CEK JARI & KALKULASI DATA VITAL ---
  if (irValue < 50000) {
    sensorStatus = "No Finger Detected";
    beatAvg = 0; ibi = 0; hrv_sdnn = 0.0;
  } else {
    // Mengecek detak jantung
    if (checkForBeat(irValue) == true) {
      newBeatDetected = true; // BENDERA NYALA: Ada detak baru terdeteksi!

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

  unsigned long processingTime = micros() - loopStartMicros; 
  float realCpuLoad = ((float)processingTime / (processingTime + 10000.0)) * 100.0;

  if (millis() - lastPublishTime >= PUBLISH_INTERVAL) {
    lastPublishTime = millis();

    // --- 1. PENGUMPULAN DATA & INFERENSI ML ---
    // Syarat: Jari menempel DAN Detak sudah masuk akal (> 40 BPM)
    if (irValue > 50000 && beatAvg > 40) {
      
      // SYARAT TAMBAHAN: Eksekusi pengumpulan AI HANYA jika bendera detak baru menyala
      if (newBeatDetected == true) {
        newBeatDetected = false; // Langsung matikan agar tidak duplikat di loop berikutnya
        
        float mean_f1 = 0.7769376f;   float scale_f1 = 0.20464825f;
        float mean_f2 = 82.99367422f; float scale_f2 = 23.88029078f;
        float mean_f3 = 0.09135964f;  float scale_f3 = 0.08498789f;
        
        float feature1_raw = (float)ibi / 1000.0;     
        float feature2_raw = (float)beatAvg;          
        float feature3_raw = hrv_sdnn / 1000.0;       

        float feature1 = (feature1_raw - mean_f1) / scale_f1; 
        float feature2 = (feature2_raw - mean_f2) / scale_f2;   
        float feature3 = (feature3_raw - mean_f3) / scale_f3;      

        if (data_index < 20) {
          input_buffer[data_index * 3 + 0] = feature1;
          input_buffer[data_index * 3 + 1] = feature2;
          input_buffer[data_index * 3 + 2] = feature3;
          data_index++;
          
          if (data_index < 20) {
             current_diagnosis = "Mengumpulkan Data (" + String(data_index) + "/20)...";
          }
        }
      } // Akhir blok newBeatDetected

      // Eksekusi GRU (Di luar dari bendera agar tetap terpanggil saat mencapai 20)
      if (data_index == 20) {
        TfLiteTensor* input = interpreter->input(0);
        for(int i = 0; i < 60; i++) {
          input->data.f[i] = input_buffer[i];
        }

        if (interpreter->Invoke() == kTfLiteOk) {
          TfLiteTensor* output = interpreter->output(0);
          float p_normal      = output->data.f[0];
          float p_arrhythmia  = output->data.f[1];
          float p_tachycardia = output->data.f[2];
          float p_bradycardia = output->data.f[3];

          float max_prob = p_normal; 
          current_diagnosis = "Normal";

          if(p_arrhythmia > max_prob)  { max_prob = p_arrhythmia;  current_diagnosis = "Arrhythmia"; }
          if(p_tachycardia > max_prob) { max_prob = p_tachycardia; current_diagnosis = "Tachycardia"; }
          if(p_bradycardia > max_prob) { max_prob = p_bradycardia; current_diagnosis = "Bradycardia"; }
        }
        data_index = 0; // Reset untuk gelombang observasi medis berikutnya
      }
    } 
    // Jika jari nempel tapi angka BPM masih 0 (sensor belum dapat ritme)
    else if (irValue > 50000 && beatAvg <= 40) {
        data_index = 0; 
        current_diagnosis = "Menunggu detak stabil...";
    } 
    // Jari dilepas sepenuhnya
    else {
        data_index = 0;
        current_diagnosis = "Waiting for finger...";
    }

    // --- 2. PENYIAPAN METADATA & MQTT PUBLISH ---
    uint32_t freeHeap = ESP.getFreeHeap();
    uint32_t totalHeap = ESP.getHeapSize();
    float memoryUsagePercent = ((float)(totalHeap - freeHeap) / totalHeap) * 100.0;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long long current_epoch_ms = (unsigned long long)(tv.tv_sec) * 1000ULL + (unsigned long long)(tv.tv_usec) / 1000ULL;

    StaticJsonDocument<512> doc; 
    doc["ppg"] = irValue;     
    doc["bpm"] = beatAvg;
    doc["ibi"] = ibi;         
    doc["hrv"] = hrv_sdnn;
    doc["status"] = sensorStatus;
    doc["ml_class"] = current_diagnosis; // Klasifikasi dimasukkan ke MQTT JSON
    doc["cpu"] = realCpuLoad; 
    doc["mem"] = memoryUsagePercent;
    doc["ts"] = current_epoch_ms; 

    char jsonBuffer[512];
    serializeJson(doc, jsonBuffer);
    
    Serial.print("Mengirim MQTT (Baseline): ");
    Serial.println(jsonBuffer);
    
    client.publish(mqtt_topic, jsonBuffer);
  }

  delay(10); 
}