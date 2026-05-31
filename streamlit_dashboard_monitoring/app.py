import streamlit as st
import paho.mqtt.client as mqtt
import json
import time
from collections import deque
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os

# --- Konfigurasi Halaman ---
st.set_page_config(page_title="Real-Time PPG Dashboard", layout="wide")
st.title("🩸 Real-Time Photoplethysmography (PPG) Monitor & AI Diagnosis")

# --- KELAS UNTUK SHARED MEMORY & FILTER DATA ---
class SensorData:
    def __init__(self):
        self.ppg_data = deque(maxlen=150)
        self.bpm_data = deque(maxlen=150) 
        self.ibi_data = deque(maxlen=150)
        self.latest_data = {
            "bpm": 0, "ibi": 0, "hrv": 0.0, "status": "Waiting...", 
            "ml_class": "Waiting for finger...",
            "cpu": 0.0, "mem": 0.0, "latency": 0
        }
        self.w = 0.0  

        # --- Variabel Khusus Excel Export ---
        self.export_buffer = []
        self.export_counter = 1
        self.last_export_time = time.time()
        self.is_finger_currently_detected = False

    def filter_dc_removal(self, current_val, alpha=0.95):
        old_w = self.w
        self.w = current_val + alpha * old_w
        return self.w - old_w

@st.cache_resource
def get_data_store():
    return SensorData()

data_store = get_data_store()

# --- Konfigurasi MQTT ---
MQTT_BROKER = "broker.hivemq.com"
MQTT_PORT = 1883
MQTT_TOPIC = "ppg_sensor_01" 

def on_connect(client, userdata, flags, rc, *args):
    print(f"\n[STATUS MQTT] Terhubung ke Broker dengan kode: {rc}")
    client.subscribe(MQTT_TOPIC)

def on_message(client, userdata, msg):
    try:
        raw_payload = msg.payload.decode("utf-8")
        payload = json.loads(raw_payload)
        
        current_time_ms = int(time.time() * 1000)
        esp_ts = payload.get("ts", current_time_ms)
        latency = abs(current_time_ms - esp_ts) 

        bpm_val = payload.get("bpm", 0)
        ibi_val = payload.get("ibi", 0)
        hrv_val = payload.get("hrv", 0.0)
        raw_ppg = payload.get("ppg", 0)
        status_val = payload.get("status", "Unknown")
        ml_class_val = payload.get("ml_class", "Waiting for finger...")

        # Data CPU & MEMORY dari ESP32
        cpu_val = payload.get("cpu", 0.0)
        mem_val = payload.get("mem", 0.0)

        # Logika Filter & Jari
        finger_detected_now = (raw_ppg > 50000)

        if finger_detected_now and not data_store.is_finger_currently_detected:
            data_store.last_export_time = time.time()
            data_store.export_buffer.clear() 

        if finger_detected_now:
            filtered_ppg = data_store.filter_dc_removal(raw_ppg)
            if bpm_val > 0 and ibi_val > 0:
                data_store.export_buffer.append({
                    "Timestamp_PC": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "Timestamp_ESP32": esp_ts,
                    "PPG_Raw": raw_ppg,
                    "PPG_Filtered": round(filtered_ppg, 2),
                    "BPM": bpm_val,
                    "IBI_ms": ibi_val,
                    "HRV_SDNN_ms": round(hrv_val, 2),
                    "Sensor_Status": status_val,
                    "ML_Classification": ml_class_val,
                    "CPU_Load_%": round(cpu_val, 2),
                    "Memory_Used_%": round(mem_val, 2),
                    "Latency_ms": latency
                })
        else:
            filtered_ppg = 0
            data_store.w = 0.0 

        data_store.is_finger_currently_detected = finger_detected_now

        # Update antrean data grafik
        data_store.ppg_data.append(filtered_ppg)
        data_store.bpm_data.append(bpm_val)
        data_store.ibi_data.append(ibi_val)

        data_store.latest_data.update({
            "bpm": bpm_val, "ibi": ibi_val, "hrv": hrv_val,
            "status": status_val, "ml_class": ml_class_val,
            "cpu": cpu_val, "mem": mem_val, "latency": latency
        })

    except Exception as e:
        print(f"❌ Error saat memproses data: {e}")

@st.cache_resource
def init_mqtt():
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    except AttributeError:
        client = mqtt.Client()
        
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.loop_start()
    return client

mqtt_client = init_mqtt()

# --- Navigasi Menggunakan Tabs ---
tab_monitor, tab_ai, tab_telemetry, tab_report = st.tabs([
    "📊 Real-Time Monitoring", 
    "🤖 AI Classification", 
    "⚙️ Telemetry & Hardware",
    "📈 Model Performance Report"
])

# --- DIKONTROL MELALUI PLACEHOLDER DI DALAM TAB ---

# 1. TAB MONITORING
with tab_monitor:
    st.markdown("### 🩺 Vital Signs Real-Time")
    vcol1, vcol2, vcol3 = st.columns(3)
    bpm_placeholder = vcol1.empty()
    ibi_placeholder = vcol2.empty()
    hrv_placeholder = vcol3.empty()
    
    sensor_status_placeholder = st.empty()
    st.markdown("---")
    st.markdown("### 📈 Sinyal Gelombang Detak Jantung (Filtered PPG)")
    chart_placeholder = st.empty()
    
    st.markdown("---")
    st.markdown("### 📊 Tren Stabilitas Jantung")
    tcol1, tcol2 = st.columns(2)
    bpm_chart_placeholder = tcol1.empty()
    ibi_chart_placeholder = tcol2.empty()

# 2. TAB AI CLASSIFICATION
with tab_ai:
    st.markdown("### 🧠 Edge AI Classification Result (On-Device GRU)")
    st.info("Prediksi di bawah ini dieksekusi secara lokal di dalam mikroprosesor ESP32-S3 menggunakan TensorFlow Lite for Microcontrollers.")
    
    ai_status_placeholder = st.empty()
    st.markdown("---")
    st.markdown("#### Panduan Respons Klasifikasi:")
    
    gcol1, gcol2, gcol3, gcol4 = st.columns(4)
    gcol1.success("**Normal**\n\nDetak jantung berada di rentang normal dan ritme teratur.")
    gcol2.warning("**Arrhythmia**\n\nTerdeteksi adanya ketidakteraturan pada ritme detak jantung.")
    gcol3.error("**Tachycardia**\n\nRata-rata detak jantung terlalu cepat (> 100 BPM).")
    gcol4.error("**Bradycardia**\n\nRata-rata detak jantung terlalu lambat (< 60 BPM).")

# 3. TAB TELEMETRY
with tab_telemetry:
    st.markdown("### ⚙️ IoT Device Telemetry (ESP32-S3)")
    sys1, sys2, sys3 = st.columns(3)
    cpu_placeholder = sys1.empty()
    mem_placeholder = sys2.empty()
    lat_placeholder = sys3.empty()

# 4. TAB REPORT PERFORMANCE (Static Report dari Python Training)
with tab_report:
    st.markdown("### 📑 Classification Report (Model Evaluation)")
    st.markdown("Berikut adalah hasil evaluasi model GRU tingkat lanjut dengan data uji dari *MIT-BIH Arrhythmia Database*:")
    
    # Dataframe Report
    report_data = {
        "Class": ["Normal", "Arrhythmia", "Tachycardia", "Bradycardia"],
        "Precision": [0.80, 0.89, 0.99, 0.99],
        "Recall": [0.91, 0.81, 0.98, 0.99],
        "F1-Score": [0.85, 0.85, 0.98, 0.99],
        "Support": [8035, 11661, 3837, 1939]
    }
    df_report = pd.DataFrame(report_data)
    st.table(df_report.set_index("Class"))
    
    # Visualisasi Metrik Evaluasi
    fig_metrics = go.Figure()
    fig_metrics.add_trace(go.Bar(x=df_report["Class"], y=df_report["Precision"], name="Precision", marker_color="#1f77b4"))
    fig_metrics.add_trace(go.Bar(x=df_report["Class"], y=df_report["Recall"], name="Recall", marker_color="#aec7e8"))
    fig_metrics.add_trace(go.Bar(x=df_report["Class"], y=df_report["F1-Score"], name="F1-Score", marker_color="#ff7f0e"))
    
    fig_metrics.update_layout(
        title="Perbandingan Metrik Evaluasi per Kelas",
        barmode='group',
        template="plotly_dark",
        xaxis_title="Kelas Diagnosis",
        yaxis_title="Nilai Skor (0 - 1.0)",
        yaxis=dict(range=[0, 1.1])
    )
    st.plotly_chart(fig_metrics, use_container_width=True)

# --- LOOP UTAMA UPDATE DASHBOARD ---
try:
    while True:
        data = data_store.latest_data
        
        # --- Update Tab 1: Monitoring ---
        bpm_placeholder.metric(label="❤️ Avg BPM", value=f"{data['bpm']} bpm")
        ibi_placeholder.metric(label="⏱️ IBI (Interval)", value=f"{data['ibi']} ms")
        hrv_placeholder.metric(label="🌊 HRV (SDNN)", value=f"{data['hrv']:.1f} ms")
        
        status_color = "green" if "Good" in data['status'] else "red"
        sensor_status_placeholder.markdown(
            f"**🛡️ Sensor Status:** <span style='color:{status_color}; font-size:18px; font-weight:bold;'>{data['status']}</span>", 
            unsafe_allow_html=True
        )

        # Plot Sinyal PPG
        if len(data_store.ppg_data) > 0:
            df_ppg = pd.DataFrame({"Filtered Signal": list(data_store.ppg_data)})
            fig_ppg = px.line(df_ppg, y="Filtered Signal", template="plotly_dark", height=350)
            fig_ppg.update_layout(
                xaxis_title="Timestep Sample", yaxis_title="Pulse Amplitude (AC Component)",
                yaxis_range=[-1500, 1500], margin=dict(l=0, r=0, t=10, b=0),
                xaxis=dict(showgrid=False), yaxis=dict(showgrid=False)
            )
            fig_ppg.update_traces(line_color='#00FF7F', line_width=3)
            chart_placeholder.plotly_chart(fig_ppg, use_container_width=True, key=f"ppg_{time.time()}")
            
        # Plot Tren BPM
        if len(data_store.bpm_data) > 0:
            df_bpm = pd.DataFrame({"BPM": list(data_store.bpm_data)})
            fig_bpm = px.line(df_bpm, y="BPM", template="plotly_dark", height=220)
            fig_bpm.update_layout(
                xaxis_title="Waktu", yaxis_title="Beats Per Minute",
                margin=dict(l=0, r=0, t=10, b=0), xaxis=dict(showgrid=False), yaxis=dict(range=[40, 160])  
            )
            fig_bpm.update_traces(line_color='#FF69B4', line_width=2)
            bpm_chart_placeholder.plotly_chart(fig_bpm, use_container_width=True, key=f"bpm_{time.time()}")

        # Plot Tren IBI
        if len(data_store.ibi_data) > 0:
            df_ibi = pd.DataFrame({"IBI": list(data_store.ibi_data)})
            fig_ibi = px.line(df_ibi, y="IBI", template="plotly_dark", height=220)
            fig_ibi.update_layout(
                xaxis_title="Waktu", yaxis_title="Interval (ms)",
                margin=dict(l=0, r=0, t=10, b=0), xaxis=dict(showgrid=False), yaxis=dict(range=[300, 1500])  
            )
            fig_ibi.update_traces(line_color='#9370DB', line_width=2)
            ibi_chart_placeholder.plotly_chart(fig_ibi, use_container_width=True, key=f"ibi_{time.time()}")

        # --- Update Tab 2: AI Classification ---
        diag = data['ml_class']
        if diag == "Normal":
            bg_color, text_color = "#d4edda", "#155724"
        elif diag == "Arrhythmia":
            bg_color, text_color = "#fff3cd", "#856404"
        elif diag in ["Tachycardia", "Bradycardia"]:
            bg_color, text_color = "#f8d7da", "#721c24"
        else:
            bg_color, text_color = "#e2e3e5", "#383d41"

        ai_status_placeholder.markdown(
            f"""
            <div style="background-color:{bg_color}; padding:25px; border-radius:10px; border-left: 8px solid {text_color};">
                <h4 style="color:{text_color}; margin:0;">🚨 LIVE DIAGNOSIS RESULT:</h4>
                <p style="color:{text_color}; font-size:35px; font-weight:bold; margin:10px 0 0 0;">{diag}</p>
            </div>
            """, 
            unsafe_allow_html=True
        )

        # --- Update Tab 3: Telemetry ---
        cpu_placeholder.metric(label="🧠 Real ESP32 CPU Load", value=f"{data['cpu']:.1f} %")
        mem_placeholder.metric(label="💾 ESP32 Memory Used", value=f"{data['mem']:.1f} %")
        lat_placeholder.metric(label="📶 Transmission Latency", value=f"{data['latency']} ms")
            
        time.sleep(0.1) 
        
except Exception as e:
    st.error(f"Sistem dashboard terhenti: {e}")