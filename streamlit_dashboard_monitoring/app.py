import streamlit as st
import paho.mqtt.client as mqtt
import json
import time
from collections import deque
import pandas as pd
import plotly.express as px

# --- Konfigurasi Halaman ---
st.set_page_config(page_title="Real-Time PPG Dashboard", layout="wide")
st.title("🩸 Real-Time Photoplethysmography (PPG) Monitor")

# --- KELAS UNTUK SHARED MEMORY & FILTER DATA ---
class SensorData:
    def __init__(self):
        self.ppg_data = deque(maxlen=150)
        self.bpm_data = deque(maxlen=150) 
        self.ibi_data = deque(maxlen=150)
        self.latest_data = {
            "bpm": 0, "ibi": 0, "hrv": 0.0, "status": "Waiting...", 
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

# Fungsi Pemicu Ekspor ke Excel
def trigger_excel_export():
    if len(data_store.export_buffer) > 0:
        filename = f"ppg_sensor_{data_store.export_counter}.xlsx"
        df = pd.DataFrame(data_store.export_buffer)
        try:
            df.to_excel(filename, index=False)
            print(f"✅ EXCEL SUCCESS: {len(df)} baris data berhasil diekspor ke {filename}")
            data_store.export_counter += 1
        except Exception as e:
            print(f"❌ EXCEL ERROR: Gagal menyimpan data {e}")
        
        # Bersihkan buffer dan reset timer
        data_store.export_buffer.clear()
        data_store.last_export_time = time.time()

# --- Konfigurasi MQTT ---
MQTT_BROKER = "broker.hivemq.com"
MQTT_PORT = 1883
MQTT_TOPIC = "arsyad/brawijaya_med/ppg_sensor_01" 

def on_connect(client, userdata, flags, rc, *args):
    print(f"\n[STATUS MQTT] Terhubung ke Broker dengan kode: {rc}")
    client.subscribe(MQTT_TOPIC)
    print(f"[STATUS MQTT] Berhasil Subscribe ke topik: {MQTT_TOPIC}\n")

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

        # --- LOGIKA PENYIMPANAN DATA EXCEL (YANG DIPERBAIKI) ---
        finger_detected_now = (raw_ppg > 50000)

        # 1. Deteksi momen persis ketika jari BARU SAJA diletakkan
        if finger_detected_now and not data_store.is_finger_currently_detected:
            # Reset stopwatch ke detik ini juga!
            data_store.last_export_time = time.time()
            data_store.export_buffer.clear() # Pastikan keranjang kosong

        # 2. Kondisi saat jari sedang menempel
        if finger_detected_now:
            filtered_ppg = data_store.filter_dc_removal(raw_ppg)
            
            # Simpan data fitur jika valid
            if bpm_val > 0 and ibi_val > 0:
                data_store.export_buffer.append({
                    "Timestamp_PC": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "Timestamp_ESP32": esp_ts,
                    "PPG_Raw": raw_ppg,
                    "PPG_Filtered": round(filtered_ppg, 2),
                    "BPM": bpm_val,
                    "IBI_ms": ibi_val,
                    "HRV_SDNN_ms": round(hrv_val, 2),
                    "Sensor_Status": status_val
                })

            # Ekspor berkala HANYA JIKA benar-benar sudah lewat 30 detik sejak jari nempel
            # if (time.time() - data_store.last_export_time) >= 30.0:
            #     trigger_excel_export()

        # 3. Kondisi saat jari tidak ada (atau baru saja dilepas)
        else:
            filtered_ppg = 0
            data_store.w = 0.0 
            
            # Deteksi momen persis ketika jari BARU SAJA DILEPAS sebelum 30 detik
            # if data_store.is_finger_currently_detected:
            #     trigger_excel_export()

        # Update status jari saat ini untuk iterasi berikutnya (Sangat Penting!)
        data_store.is_finger_currently_detected = finger_detected_now

        # --- Update data grafik & memori UI ---
        data_store.ppg_data.append(filtered_ppg)
        data_store.bpm_data.append(bpm_val)
        data_store.ibi_data.append(ibi_val)

        data_store.latest_data.update({
            "bpm": bpm_val, "ibi": ibi_val, "hrv": hrv_val,
            "status": status_val, "cpu": payload.get("cpu", 0.0),
            "mem": payload.get("mem", 0.0), "latency": latency
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

# --- Layout UI ---
st.markdown("### 🩺 Vital Signs & Advanced Analytics")
col1, col2, col3 = st.columns(3)
bpm_placeholder = col1.empty()
ibi_placeholder = col2.empty()
hrv_placeholder = col3.empty()

st.markdown("<br>", unsafe_allow_html=True)
status_placeholder = st.empty()

st.markdown("---")
st.markdown("### ⚙️ IoT Device Telemetry (ESP32-S3)")
sys1, sys2, sys3 = st.columns(3)
cpu_placeholder = sys1.empty()
mem_placeholder = sys2.empty()
lat_placeholder = sys3.empty()

st.markdown("---")
st.markdown("### 📈 Sinyal Gelombang Detak Jantung (Filtered PPG)")
chart_placeholder = st.empty()

st.markdown("---")
st.markdown("### 📊 Tren Stabilitas Jantung (BPM & IBI)")
chart_col1, chart_col2 = st.columns(2)
bpm_chart_placeholder = chart_col1.empty()
ibi_chart_placeholder = chart_col2.empty()

try:
    while True:
        data = data_store.latest_data
        
        bpm_placeholder.metric(label="❤️ Avg BPM", value=f"{data['bpm']} bpm")
        ibi_placeholder.metric(label="⏱️ IBI (Interval)", value=f"{data['ibi']} ms")
        hrv_placeholder.metric(label="🌊 HRV (SDNN)", value=f"{data['hrv']:.1f} ms")
        
        status_color = "green" if "Good" in data['status'] else "red"
        status_placeholder.markdown(
            f"**🛡️ Sensor Status:** <span style='color:{status_color}; font-size:20px'>{data['status']}</span>", 
            unsafe_allow_html=True
        )

        cpu_placeholder.metric(label="🧠 Real ESP32 CPU Load", value=f"{data['cpu']:.1f} %")
        mem_placeholder.metric(label="💾 ESP32 Memory Used", value=f"{data['mem']:.1f} %")
        lat_placeholder.metric(label="📶 Transmission Latency", value=f"{data['latency']} ms")

        if len(data_store.ppg_data) > 0:
            df_ppg = pd.DataFrame({"Filtered Signal": list(data_store.ppg_data)})
            fig_ppg = px.line(df_ppg, y="Filtered Signal", template="plotly_dark", height=400)
            fig_ppg.update_layout(
                xaxis_title="Waktu", yaxis_title="Pulse Amplitude (AC Component)",
                yaxis_range=[-1500, 1500], margin=dict(l=0, r=0, t=30, b=0),
                xaxis=dict(showgrid=False), yaxis=dict(showgrid=False)
            )
            fig_ppg.update_traces(line_color='#00FF7F', line_width=3)
            chart_placeholder.plotly_chart(fig_ppg, use_container_width=True, key=f"ppg_{time.time()}")
            
        if len(data_store.bpm_data) > 0:
            df_bpm = pd.DataFrame({"BPM": list(data_store.bpm_data)})
            fig_bpm = px.line(df_bpm, y="BPM", template="plotly_dark", height=250)
            fig_bpm.update_layout(
                xaxis_title="Waktu", yaxis_title="Beats Per Minute",
                margin=dict(l=0, r=0, t=10, b=0), xaxis=dict(showgrid=False),
                yaxis=dict(range=[40, 160])  
            )
            fig_bpm.update_traces(line_color='#FF69B4', line_width=2)
            bpm_chart_placeholder.plotly_chart(fig_bpm, use_container_width=True, key=f"bpm_{time.time()}")

        if len(data_store.ibi_data) > 0:
            df_ibi = pd.DataFrame({"IBI": list(data_store.ibi_data)})
            fig_ibi = px.line(df_ibi, y="IBI", template="plotly_dark", height=250)
            fig_ibi.update_layout(
                xaxis_title="Waktu", yaxis_title="Interval (ms)",
                margin=dict(l=0, r=0, t=10, b=0), xaxis=dict(showgrid=False),
                yaxis=dict(range=[300, 1500])  
            )
            fig_ibi.update_traces(line_color='#9370DB', line_width=2)
            ibi_chart_placeholder.plotly_chart(fig_ibi, use_container_width=True, key=f"ibi_{time.time()}")
            
        time.sleep(0.1) 
        
except Exception as e:
    st.error(f"Sistem berhenti: {e}")