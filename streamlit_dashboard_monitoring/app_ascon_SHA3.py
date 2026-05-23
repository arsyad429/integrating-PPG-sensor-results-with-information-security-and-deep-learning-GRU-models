import streamlit as st
import paho.mqtt.client as mqtt
import json
import time
from collections import deque
import pandas as pd
import plotly.express as px
import ascon 
import hashlib

# --- Konfigurasi Halaman ---
st.set_page_config(page_title="Secure PPG ASCON & SHA3", layout="wide")
st.title("🔒 Secure Real-Time Photoplethysmography (PPG) Monitor (ASCON-128 + SHA3-256)")

# Kunci Rahasia harus SAMA dengan di Arduino
SECRET_KEY = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])

# --- KELAS UNTUK SHARED MEMORY & FILTER DATA ---
class SensorData:
    def __init__(self):
        self.ppg_data = deque(maxlen=150)
        self.bpm_data = deque(maxlen=150) 
        self.ibi_data = deque(maxlen=150)
        self.latest_data = {
            "bpm": 0, "ibi": 0, "status": "Waiting...", 
            "cpu": 0.0, "mem": 0.0, "latency": 0,
            "enc_t": 0, "enc_o": 0, "dec_t": 0.0,
            "sha3_status": "Waiting..."
        }
        self.w = 0.0  

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
MQTT_TOPIC = "arsyad/brawijaya_med/secure_ppg"

def on_connect(client, userdata, flags, rc, *args):
    print(f"\n[STATUS MQTT] Terhubung ke Broker dengan kode: {rc}")
    client.subscribe(MQTT_TOPIC)
    print(f"[STATUS MQTT] Berhasil Subscribe ke topik: {MQTT_TOPIC}\n")

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode("utf-8"))
        
        # 1. Hitung Latency Transmisi Jaringan
        current_time_ms = int(time.time() * 1000)
        esp_ts = payload.get("ts", current_time_ms)
        latency = abs(current_time_ms - esp_ts) 

        # 2. Ambil data kriptografi mentah
        nonce_bytes = bytes.fromhex(payload.get("nonce", "00"*16))
        ct_bytes = bytes.fromhex(payload.get("ct", ""))
        incoming_sha3 = payload.get("sha3", "")
        
        # 3. Proses Dekripsi ASCON
        start_dec = time.perf_counter()
        plaintext_bytes = ascon.decrypt(SECRET_KEY, nonce_bytes, b"", ct_bytes, variant="Ascon-128")
        dec_time_ms = (time.perf_counter() - start_dec) * 1000 
        
        # 4. VERIFIKASI INTEGRITAS DATA (SHA3-256)
        # Hitung ulang hash SHA3 dari hasil dekripsi plaintext
        calculated_sha3 = hashlib.sha3_256(plaintext_bytes).hexdigest()
        
        if calculated_sha3 == incoming_sha3:
            sha3_verified = "🟢 Valid (No Tampering)"
        else:
            sha3_verified = "🔴 CORRUPTED / ALTERED!"
            print("⚠️ Peringatan: Integritas SHA3 tidak cocok! Data mungkin telah diubah di jalan.")
        
        # 5. Urai Plaintext menjadi data medis
        medical_data = json.loads(plaintext_bytes.decode('utf-8'))
        
        bpm_val = medical_data.get("bpm", 0)
        ibi_val = medical_data.get("ibi", 0)
        raw_ppg = medical_data.get("ppg", 0)

        if raw_ppg > 50000:  
            filtered_ppg = data_store.filter_dc_removal(raw_ppg)
        else:
            filtered_ppg = 0
            data_store.w = 0.0  

        data_store.ppg_data.append(filtered_ppg)
        data_store.bpm_data.append(bpm_val)
        data_store.ibi_data.append(ibi_val)

        # Update nilai teks metrik terbaru ke Data Store
        data_store.latest_data["bpm"] = bpm_val
        data_store.latest_data["ibi"] = ibi_val
        data_store.latest_data["status"] = medical_data.get("status", "Unknown")
        data_store.latest_data["cpu"] = payload.get("cpu", 0.0)
        data_store.latest_data["mem"] = payload.get("mem", 0.0)
        data_store.latest_data["latency"] = latency
        data_store.latest_data["enc_t"] = payload.get("enc_t", 0)
        data_store.latest_data["enc_o"] = payload.get("enc_o", 0)
        data_store.latest_data["dec_t"] = dec_time_ms
        data_store.latest_data["sha3_status"] = sha3_verified

    except ValueError as ve:
        print(f"❌ INTEGRITAS GAGAL (Kunci salah / Data diubah di jalan): {ve}")
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

# --- Layout UI Medis ---
st.markdown("### 🩺 Vital Signs")
col1, col2, col3 = st.columns(3)
bpm_placeholder = col1.empty()
ibi_placeholder = col2.empty()
status_placeholder = col3.empty()

st.markdown("---")
st.markdown("### 🛡️ Evaluasi Keamanan Jaringan & Sistem (ASCON-128 + SHA3-256)")
sec1, sec2, sec3, sec4, sec5 = st.columns(5) # Kolom ditambah 1 untuk SHA3 Status
enc_t_placeholder = sec1.empty()
dec_t_placeholder = sec2.empty()
enc_o_placeholder = sec3.empty()
lat_placeholder = sec4.empty()
sha3_placeholder = sec5.empty()

st.markdown("<br>", unsafe_allow_html=True)
st.markdown("### ⚙️ IoT Device Telemetry (ESP32-S3)")
sys1, sys2 = st.columns(2)
cpu_placeholder = sys1.empty()
mem_placeholder = sys2.empty()

st.markdown("---")
st.markdown("### 📈 Sinyal Gelombang Detak Jantung (Filtered Secure PPG)")
chart_placeholder = st.empty()

st.markdown("---")
st.markdown("### 📊 Tren Stabilitas Jantung (BPM & IBI)")
chart_col1, chart_col2 = st.columns(2)
bpm_chart_placeholder = chart_col1.empty()
ibi_chart_placeholder = chart_col2.empty()

try:
    while True:
        data = data_store.latest_data
        
        # --- Update Teks Metrik ---
        bpm_placeholder.metric(label="❤️ Avg BPM", value=f"{data['bpm']} bpm")
        ibi_placeholder.metric(label="⏱️ IBI (Inter-Beat Interval)", value=f"{data['ibi']} ms")
        
        status_color = "green" if "Good" in data['status'] else "red"
        status_placeholder.markdown(
            f"**🫀 Sensor Status:** \n<span style='color:{status_color}; font-size:24px'>{data['status']}</span>", 
            unsafe_allow_html=True
        )

        # --- Update Teks Metrik Keamanan ---
        enc_t_placeholder.metric(label="🔐 Encryption Time (ESP32)", value=f"{data['enc_t']} µs")
        dec_t_placeholder.metric(label="🔓 Decryption Time (Python)", value=f"{data['dec_t']:.3f} ms")
        enc_o_placeholder.metric(label="📦 Encryption Overhead", value=f"{data['enc_o']} Bytes")
        lat_placeholder.metric(label="📶 Transmission Latency", value=f"{data['latency']} ms")
        
        # Tampilkan apakah data mengalami kebocoran/manipulasi atau aman via SHA3
        sha3_placeholder.metric(label="🛡️ SHA3-256 Integrity", value=data['sha3_status'])

        # --- Update Teks Metrik Telemetri ---
        cpu_placeholder.metric(label="🧠 ESP32 CPU Load", value=f"{data['cpu']:.1f} %")
        mem_placeholder.metric(label="💾 ESP32 Memory Used", value=f"{data['mem']:.1f} %")

        # --- 1. Update Grafik PPG ---
        if len(data_store.ppg_data) > 0:
            df_ppg = pd.DataFrame({"Filtered Signal": list(data_store.ppg_data)})
            fig_ppg = px.line(df_ppg, y="Filtered Signal", template="plotly_dark", height=400)
            fig_ppg.update_layout(
                xaxis_title="Waktu (Siklus Berjalan)", yaxis_title="Pulse Amplitude (AC Component)",
                yaxis_range=[-1500, 1500], margin=dict(l=0, r=0, t=30, b=0),
                xaxis=dict(showgrid=False), yaxis=dict(showgrid=False)
            )
            fig_ppg.update_traces(line_color='#00FF7F', line_width=3)
            chart_placeholder.plotly_chart(fig_ppg, use_container_width=True, key=f"ppg_{time.time()}")
            
        # --- 2. Update Grafik Tren BPM ---
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

        # --- 3. Update Grafik Tren IBI ---
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