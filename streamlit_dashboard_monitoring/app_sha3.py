import streamlit as st
import paho.mqtt.client as mqtt
import json
import time
import hashlib
from collections import deque
import pandas as pd
import plotly.express as px
import os

# --- Konfigurasi Halaman ---
st.set_page_config(page_title="Secure PPG SHA3", layout="wide")
st.title("🔏 Secure Real-Time PPG Monitor — SHA3-256 Integrity")

# ================================================================
#  KELAS SHARED MEMORY
# ================================================================
class SensorData:
    def __init__(self):
        self.ppg_data = deque(maxlen=150)
        self.bpm_data = deque(maxlen=150)
        self.ibi_data = deque(maxlen=150)
        self.integrity_log = deque(maxlen=50) 
        self.latest_data = {
            "bpm": 0, "ibi": 0, "hrv": 0.0, "status": "Waiting...",
            "cpu": 0.0, "mem": 0.0, "latency": 0,
            "hash_t": 0,            
            "integrity_valid": "-", 
            "hash_preview": "-",    
            "total_valid": 0,       
            "total_invalid": 0,     
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

def trigger_excel_export():
    if len(data_store.export_buffer) > 0:
        folder_path = "captured_data/with_SHA3"

        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

        filename = f"{folder_path}/ppg_sensor_sha3_{data_store.export_counter}.xlsx"
        df = pd.DataFrame(data_store.export_buffer)
        try:
            df.to_excel(filename, index=False)
            print(f"✅ EXCEL SUCCESS: {len(df)} baris data diekspor ke {filename}")
            data_store.export_counter += 1
        except Exception as e:
            print(f"❌ EXCEL ERROR: {e}")
        
        data_store.export_buffer.clear()
        data_store.last_export_time = time.time()

# ================================================================
#  FUNGSI VERIFIKASI SHA3
# ================================================================
def verifikasi_sha3(payload):
    hash_dari_esp32 = payload.get("hash", "")

    # Rekonstruksi data yang di-hash ESP32
    data_untuk_hash = {
        "ppg":    payload.get("ppg", 0),
        "bpm":    payload.get("bpm", 0),
        "ibi":    payload.get("ibi", 0),
        "hrv":    payload.get("hrv", 0.0),
        "status": payload.get("status", ""),
    }
    data_string = json.dumps(data_untuk_hash, separators=(',', ':'))

    # Hitung ulang hash di sisi Python
    hash_ulang = hashlib.sha3_256(data_string.encode()).hexdigest()

    # Bandingkan
    is_valid = (hash_ulang == hash_dari_esp32)

    return is_valid, data_untuk_hash, hash_dari_esp32[:16] 

# ================================================================
#  KONFIGURASI MQTT
# ================================================================
MQTT_BROKER = "broker.hivemq.com"
MQTT_PORT   = 1883
MQTT_TOPIC  = "sha3_ppg"  

def on_connect(client, userdata, flags, rc, *args):
    print(f"\n[STATUS MQTT] Terhubung ke Broker dengan kode: {rc}")
    client.subscribe(MQTT_TOPIC)
    print(f"[STATUS MQTT] Berhasil Subscribe ke topik: {MQTT_TOPIC}\n")

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode("utf-8"))

        current_time_ms = int(time.time() * 1000)
        esp_ts  = payload.get("ts", current_time_ms)
        latency = abs(current_time_ms - esp_ts)

        # --- PERISAI REPLAY ATTACK (FRESHNESS CHECK) ---
        if latency > 5000:
            print(f"🛡️ BLOKIR: Replay Attack Dideteksi! (Latency: {latency} ms). Paket basi dibuang.")
            data_store.latest_data["integrity_valid"] = "❌ REPLAY ATTACK"
            data_store.latest_data["total_invalid"] += 1
            
            # Catat serangan Replay ke tabel Log juga
            data_store.integrity_log.append({
                "waktu": time.strftime("%H:%M:%S"),
                "status": "❌ REPLAY ATTACK",
                "hash": "-",
                "latency": latency
            })
            return 
        # -----------------------------------------------

        is_valid, data_medis, hash_preview = verifikasi_sha3(payload)

        bpm_val = data_medis.get("bpm", 0)
        ibi_val = data_medis.get("ibi", 0)
        hrv_val = data_medis.get("hrv", 0.0)
        raw_ppg = data_medis.get("ppg", 0)
        status_val = data_medis.get("status", "Unknown")

        # --- TANGKAP DATA CPU, MEMORY & WAKTU HASH ---
        cpu_val = payload.get("cpu", 0.0)
        mem_val = payload.get("mem", 0.0)
        hash_t_val = payload.get("hash_t", 0)

        # --- LOGIKA PENYIMPANAN DATA EXCEL (Edge Detection) ---
        finger_detected_now = (raw_ppg > 50000)

        # 1. Jari baru ditempelkan
        if finger_detected_now and not data_store.is_finger_currently_detected:
            data_store.last_export_time = time.time()
            data_store.export_buffer.clear()

        # 2. Jari sedang menempel
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
                    "Integrity_Status": "VALID" if is_valid else "MANIPULATED",
                    "CPU_Load_%": round(cpu_val, 2),
                    "Memory_Used_%": round(mem_val, 2),
                    "Latency_ms": latency,
                    "Hash_Time_us": hash_t_val
                })

            if (time.time() - data_store.last_export_time) >= 30.0:
                trigger_excel_export()

        # 3. Jari dilepas
        else:
            filtered_ppg = 0
            data_store.w = 0.0 
            
            if data_store.is_finger_currently_detected:
                trigger_excel_export()

        data_store.is_finger_currently_detected = finger_detected_now

        # 4. Simpan data ke memori
        data_store.ppg_data.append(filtered_ppg)
        data_store.bpm_data.append(bpm_val)
        data_store.ibi_data.append(ibi_val)

        # 5. Update counter valid/invalid
        if is_valid:
            data_store.latest_data["total_valid"] += 1
        else:
            data_store.latest_data["total_invalid"] += 1

        # 6. Simpan log integritas
        data_store.integrity_log.append({
            "waktu": time.strftime("%H:%M:%S"),
            "status": "✅ VALID" if is_valid else "❌ MANIPULASI",
            "hash": hash_preview + "...",
            "latency": latency
        })

        # 7. Update latest_data
        data_store.latest_data.update({
            "bpm": bpm_val, "ibi": ibi_val, "hrv": hrv_val,
            "status": status_val, "cpu": cpu_val,
            "mem": mem_val, "latency": latency,
            "hash_t": hash_t_val,
            "integrity_valid": "✅ VALID" if is_valid else "❌ MANIPULASI TERDETEKSI",
            "hash_preview": hash_preview + "..."
        })

        if not is_valid:
            print(f"❌ PERINGATAN: Integritas data GAGAL! Data kemungkinan dimanipulasi.")

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

# ================================================================
#  LAYOUT UI
# ================================================================

# --- Vital Signs ---
st.markdown("### 🩺 Vital Signs")
col1, col2, col3, col4 = st.columns(4) # <-- Diubah jadi 4 kolom agar sejajar
bpm_placeholder    = col1.empty()
ibi_placeholder    = col2.empty()
hrv_placeholder    = col3.empty()
status_placeholder = col4.empty()

st.markdown("---")

# --- Evaluasi Integritas SHA3 ---
st.markdown("### 🔏 Evaluasi Integritas SHA3-256")
sec1, sec2, sec3, sec4 = st.columns(4)
integrity_placeholder  = sec1.empty()  
hash_t_placeholder     = sec2.empty()  
hash_preview_placeholder = sec3.empty()  
lat_placeholder        = sec4.empty()  

st.markdown("<br>", unsafe_allow_html=True)

# --- Counter valid/invalid ---
st.markdown("### 📊 Statistik Integritas")
cnt1, cnt2 = st.columns(2)
valid_count_placeholder   = cnt1.empty()
invalid_count_placeholder = cnt2.empty()

st.markdown("---")

# --- Telemetri ESP32 ---
st.markdown("### ⚙️ IoT Device Telemetry (ESP32-S3)")
sys1, sys2 = st.columns(2)
cpu_placeholder = sys1.empty()
mem_placeholder = sys2.empty()

st.markdown("---")

# --- Grafik PPG ---
st.markdown("### 📈 Sinyal Gelombang Detak Jantung (Filtered PPG)")
chart_placeholder = st.empty()

st.markdown("---")

# --- Grafik BPM & IBI ---
st.markdown("### 📊 Tren Stabilitas Jantung (BPM & IBI)")
chart_col1, chart_col2 = st.columns(2)
bpm_chart_placeholder = chart_col1.empty()
ibi_chart_placeholder = chart_col2.empty()

st.markdown("---")

# --- Log Integritas ---
st.markdown("### 🗒️ Log Verifikasi Integritas")
log_placeholder = st.empty()

# ================================================================
#  MAIN LOOP
# ================================================================
try:
    while True:
        data = data_store.latest_data

        # Vital Signs
        bpm_placeholder.metric(label="❤️ Avg BPM", value=f"{data['bpm']} bpm")
        ibi_placeholder.metric(label="⏱️ IBI (Interval)", value=f"{data['ibi']} ms")
        hrv_placeholder.metric(label="🌊 HRV (SDNN)", value=f"{data['hrv']:.1f} ms")

        status_color = "green" if "Good" in data['status'] else "red"
        status_placeholder.markdown(
            f"**🫀 Sensor Status:** <br><span style='color:{status_color}; font-size:24px'>{data['status']}</span>",
            unsafe_allow_html=True
        )

        # Evaluasi Integritas SHA3
        integrity_color = "green" if "VALID" in str(data['integrity_valid']) and "MANIPULASI" not in str(data['integrity_valid']) else "red"
        integrity_placeholder.markdown(
            f"**🔏 Integrity Status**\n\n<span style='color:{integrity_color}; font-size:20px'>{data['integrity_valid']}</span>",
            unsafe_allow_html=True
        )
        hash_t_placeholder.metric(label="⚡ Hashing Time (ESP32)", value=f"{data['hash_t']} µs")
        hash_preview_placeholder.markdown(
            f"**#️⃣ Hash SHA3 Preview**\n\n`{data['hash_preview']}`",
            unsafe_allow_html=True
        )
        lat_placeholder.metric(label="📶 Transmission Latency", value=f"{data['latency']} ms")

        # Counter
        valid_count_placeholder.metric(
            label="✅ Paket Valid", value=data['total_valid'],
            delta="integritas terjaga"
        )
        invalid_count_placeholder.metric(
            label="❌ Paket Manipulasi / Replay", value=data['total_invalid'],
            delta="serangan terdeteksi" if data['total_invalid'] > 0 else None,
            delta_color="inverse"
        )

        # Telemetri
        cpu_placeholder.metric(label="🧠 ESP32 CPU Load", value=f"{data['cpu']:.1f} %")
        mem_placeholder.metric(label="💾 ESP32 Memory Used", value=f"{data['mem']:.1f} %")

        # Grafik PPG
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

        # Grafik BPM
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

        # Grafik IBI
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

        # Log Integritas
        if len(data_store.integrity_log) > 0:
            df_log = pd.DataFrame(list(data_store.integrity_log))
            log_placeholder.dataframe(df_log, use_container_width=True)

        time.sleep(0.1)

except Exception as e:
    st.error(f"Sistem berhenti: {e}")