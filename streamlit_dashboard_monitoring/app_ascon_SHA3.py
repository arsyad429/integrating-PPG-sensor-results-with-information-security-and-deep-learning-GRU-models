import streamlit as st
import paho.mqtt.client as mqtt
import json
import time
from collections import deque
import pandas as pd
import plotly.express as px
import ascon 
import hashlib
import os 

# --- Konfigurasi Halaman ---
st.set_page_config(page_title="Secure PPG ASCON & SHA3", layout="wide")
st.title("🔒 Secure Real-Time PPG Monitor (ASCON-128 + SHA3-256)")

# Kunci Rahasia harus SAMA dengan di Arduino
SECRET_KEY = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])

# --- KELAS UNTUK SHARED MEMORY & FILTER DATA ---
class SensorData:
    def __init__(self):
        self.ppg_data = deque(maxlen=150)
        self.bpm_data = deque(maxlen=150) 
        self.ibi_data = deque(maxlen=150)
        self.integrity_log = deque(maxlen=50) # Untuk Log Tabel
        self.latest_data = {
            "bpm": 0, "ibi": 0, "hrv": 0.0, "status": "Waiting...", 
            "cpu": 0.0, "mem": 0.0, "latency": 0,
            "enc_t": 0, "enc_o": 0, "dec_t": 0.0,
            "sha3_status": "Waiting...",
            "hash_preview": "-",
            "total_valid": 0,
            "total_invalid": 0
        }
        self.w = 0.0  

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

# --- Fungsi Export Excel ---
def trigger_excel_export():
    if len(data_store.export_buffer) > 0:
        folder_path = "captured_data/with_ASCON_SHA3"
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

        filename = f"{folder_path}/ppg_sensor_lvl9_{data_store.export_counter}.xlsx"
        df = pd.DataFrame(data_store.export_buffer)
        try:
            df.to_excel(filename, index=False)
            print(f"✅ EXCEL SUCCESS: {len(df)} baris data diekspor ke {filename}")
            data_store.export_counter += 1
        except Exception as e:
            print(f"❌ EXCEL ERROR: {e}")
        
        data_store.export_buffer.clear()
        data_store.last_export_time = time.time()

# --- Konfigurasi MQTT ---
MQTT_BROKER = "broker.hivemq.com"
MQTT_PORT = 1883
MQTT_TOPIC = "secure_ppg"

def on_connect(client, userdata, flags, rc, *args):
    print(f"\n[STATUS MQTT] Terhubung ke Broker dengan kode: {rc}")
    client.subscribe(MQTT_TOPIC)

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode("utf-8"))
        
        current_time_ms = int(time.time() * 1000)
        esp_ts = payload.get("ts", current_time_ms)
        latency = abs(current_time_ms - esp_ts) 

        # --- PERISAI REPLAY ATTACK (FRESHNESS CHECK) ---
        if latency > 5000:
            print(f"🛡️ BLOKIR: Replay Attack Dideteksi! (Latency: {latency} ms).")
            data_store.latest_data["sha3_status"] = "❌ REPLAY ATTACK"
            data_store.latest_data["total_invalid"] += 1
            # Catat serangan Replay ke tabel Log
            data_store.integrity_log.append({
                "Waktu": time.strftime("%H:%M:%S"),
                "Status": "❌ REPLAY ATTACK",
                "Hash Preview": "-",
                "Latency (ms)": latency
            })
            return 
        # ------------------------------------------------------------

        nonce_bytes = bytes.fromhex(payload.get("nonce", "00"*16))
        ct_bytes = bytes.fromhex(payload.get("ct", ""))
        incoming_sha3 = payload.get("sha3", "")
        
        # Proses Dekripsi ASCON
        start_dec = time.perf_counter()
        plaintext_bytes = ascon.decrypt(SECRET_KEY, nonce_bytes, b"", ct_bytes, variant="Ascon-128")
        dec_time_ms = (time.perf_counter() - start_dec) * 1000 
        
        # VERIFIKASI INTEGRITAS DATA (SHA3-256)
        calculated_sha3 = hashlib.sha3_256(plaintext_bytes).hexdigest()
        is_valid = (calculated_sha3 == incoming_sha3)
        hash_preview_str = incoming_sha3[:16] + "..." if incoming_sha3 else "-"

        if is_valid:
            sha3_verified = "🟢 Valid (No Tampering)"
            data_store.latest_data["total_valid"] += 1
        else:
            sha3_verified = "🔴 CORRUPTED / ALTERED!"
            data_store.latest_data["total_invalid"] += 1
            print("⚠️ Peringatan: Integritas SHA3 tidak cocok! Data diubah di jalan.")
            
        # Catat status ke Log Integritas
        data_store.integrity_log.append({
            "Waktu": time.strftime("%H:%M:%S"),
            "Status": "✅ VALID" if is_valid else "❌ MANIPULASI",
            "Hash Preview": hash_preview_str,
            "Latency (ms)": latency
        })
        
        medical_data = json.loads(plaintext_bytes.decode('utf-8'))
        
        bpm_val = medical_data.get("bpm", 0)
        ibi_val = medical_data.get("ibi", 0)
        hrv_val = medical_data.get("hrv", 0.0)
        raw_ppg = medical_data.get("ppg", 0)
        status_val = medical_data.get("status", "Unknown")

        cpu_val = payload.get("cpu", 0.0)
        mem_val = payload.get("mem", 0.0)

        # --- LOGIKA PENYIMPANAN EXCEL ---
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
                    "Integrity_Status": "VALID" if is_valid else "TAMPERED",
                    "CPU_Load_%": round(cpu_val, 2),
                    "Memory_Used_%": round(mem_val, 2),
                    "Latency_ms": latency
                })
            if (time.time() - data_store.last_export_time) >= 30.0:
                trigger_excel_export()
        else:
            filtered_ppg = 0
            data_store.w = 0.0  
            if data_store.is_finger_currently_detected:
                trigger_excel_export()

        data_store.is_finger_currently_detected = finger_detected_now
        # ---------------------------------------------

        data_store.ppg_data.append(filtered_ppg)
        data_store.bpm_data.append(bpm_val)
        data_store.ibi_data.append(ibi_val)

        # Update nilai teks metrik terbaru ke Data Store
        data_store.latest_data["bpm"] = bpm_val
        data_store.latest_data["ibi"] = ibi_val
        data_store.latest_data["hrv"] = hrv_val
        data_store.latest_data["status"] = status_val
        data_store.latest_data["cpu"] = cpu_val
        data_store.latest_data["mem"] = mem_val
        data_store.latest_data["latency"] = latency
        data_store.latest_data["enc_t"] = payload.get("enc_t", 0)
        data_store.latest_data["enc_o"] = payload.get("enc_o", 0)
        data_store.latest_data["dec_t"] = dec_time_ms
        data_store.latest_data["sha3_status"] = sha3_verified
        data_store.latest_data["hash_preview"] = hash_preview_str

    except ValueError as ve:
        # Menangani jika kunci ASCON salah
        data_store.latest_data["total_invalid"] += 1
        data_store.integrity_log.append({
            "Waktu": time.strftime("%H:%M:%S"),
            "Status": "❌ DECRYPT FAILED",
            "Hash Preview": "-",
            "Latency (ms)": "-"
        })
        print(f"❌ INTEGRITAS GAGAL (Kunci salah): {ve}")
    except Exception as e:
        pass

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

# ==========================================
# --- LAYOUT UI ---
# ==========================================
st.markdown("### 🩺 Vital Signs")
col1, col2, col3, col4 = st.columns(4) 
bpm_placeholder = col1.empty()
ibi_placeholder = col2.empty()
hrv_placeholder = col3.empty()
status_placeholder = col4.empty()

st.markdown("---")
st.markdown("### 🛡️ Evaluasi Keamanan Jaringan & Sistem (ASCON-128 + SHA3-256)")
sec1, sec2, sec3, sec4, sec5 = st.columns(5) 
enc_t_placeholder = sec1.empty()
dec_t_placeholder = sec2.empty()
enc_o_placeholder = sec3.empty()
lat_placeholder = sec4.empty()
sha3_placeholder = sec5.empty()

st.markdown("<br>", unsafe_allow_html=True)
st.markdown("### 🔏 Statistik & Hash Preview")
hash_col, valid_col, invalid_col = st.columns(3)
hash_preview_placeholder = hash_col.empty()
valid_count_placeholder = valid_col.empty()
invalid_count_placeholder = invalid_col.empty()

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

st.markdown("---")
st.markdown("### 🗒️ Log Verifikasi Integritas (ASCON + SHA3)")
log_placeholder = st.empty()

try:
    while True:
        data = data_store.latest_data
        
        # --- Update Teks Metrik ---
        bpm_placeholder.metric(label="❤️ Avg BPM", value=f"{data['bpm']} bpm")
        ibi_placeholder.metric(label="⏱️ IBI (Interval)", value=f"{data['ibi']} ms")
        hrv_placeholder.metric(label="🌊 HRV (SDNN)", value=f"{data['hrv']:.1f} ms") 
        
        status_color = "green" if "Good" in data['status'] else "red"
        status_placeholder.markdown(
            f"**🫀 Sensor Status:** <br><span style='color:{status_color}; font-size:24px'>{data['status']}</span>", 
            unsafe_allow_html=True
        )

        # --- Update Teks Metrik Keamanan ---
        enc_t_placeholder.metric(label="🔐 Encryption Time (ESP32)", value=f"{data['enc_t']} µs")
        dec_t_placeholder.metric(label="🔓 Decryption Time (Python)", value=f"{data['dec_t']:.3f} ms")
        enc_o_placeholder.metric(label="📦 Encryption Overhead", value=f"{data['enc_o']} Bytes")
        lat_placeholder.metric(label="📶 Transmission Latency", value=f"{data['latency']} ms")
        
        sha3_color = "red" if "❌" in data['sha3_status'] or "🔴" in data['sha3_status'] else "green"
        sha3_placeholder.markdown(
            f"**🛡️ SHA3-256 Integrity:** <br><span style='color:{sha3_color}; font-size:18px'>{data['sha3_status']}</span>", 
            unsafe_allow_html=True
        )

        # --- Update Teks Statistik & Hash ---
        hash_preview_placeholder.markdown(
            f"**#️⃣ Hash SHA3 Preview**\n\n`{data['hash_preview']}`",
            unsafe_allow_html=True
        )
        valid_count_placeholder.metric(label="✅ Paket Valid", value=data['total_valid'], delta="Integritas & Kerahasiaan Terjaga")
        invalid_count_placeholder.metric(label="❌ Paket Manipulasi / Replay", value=data['total_invalid'], delta="Serangan Diblokir" if data['total_invalid'] > 0 else None, delta_color="inverse")

        # --- Update Teks Metrik Telemetri ---
        cpu_placeholder.metric(label="🧠 ESP32 CPU Load", value=f"{data['cpu']:.1f} %")
        mem_placeholder.metric(label="💾 ESP32 Memory Used", value=f"{data['mem']:.1f} %")

        # --- Update Grafik ---
        if len(data_store.ppg_data) > 0:
            df_ppg = pd.DataFrame({"Filtered Signal": list(data_store.ppg_data)})
            fig_ppg = px.line(df_ppg, y="Filtered Signal", template="plotly_dark", height=400)
            fig_ppg.update_layout(
                xaxis_title="Waktu (Siklus Berjalan)", yaxis_title="Pulse Amplitude (AC)",
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
            
        # --- Update Log Table ---
        if len(data_store.integrity_log) > 0:
            df_log = pd.DataFrame(list(data_store.integrity_log))
            log_placeholder.dataframe(df_log, use_container_width=True)

        time.sleep(0.1) 
        
except Exception as e:
    st.error(f"Sistem berhenti: {e}")