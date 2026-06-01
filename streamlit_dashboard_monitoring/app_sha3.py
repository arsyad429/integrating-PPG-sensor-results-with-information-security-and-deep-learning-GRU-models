import streamlit as st
import paho.mqtt.client as mqtt
import json
import time
import hashlib
from collections import deque
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os

# --- Konfigurasi Halaman ---
st.set_page_config(page_title="Secure PPG SHA3 AI", layout="wide")
st.title("🔏 Secure Real-Time PPG Monitor & AI Diagnosis (SHA3-256)")

# ================================================================
#  KELAS SHARED MEMORY
# ================================================================
class SensorData:
    def __init__(self):
        self.ppg_data = deque(maxlen=150)
        self.bpm_data = deque(maxlen=150)
        self.ibi_data = deque(maxlen=150)
        self.integrity_log = deque(maxlen=200) 
        self.latest_data = {
            "bpm": 0, "ibi": 0, "hrv": 0.0, "status": "Waiting...",
            "ml_class": "Waiting for data...",
            "cpu": 0.0, "mem": 0.0, "latency": 0,
            "hash_t": 0,            
            "integrity_valid": "-", 
            "hash_preview": "-",    
            "total_valid": 0,       
            "total_manipulated": 0, # Gagal uji kecocokan hash (tanda tangan waktu/desimal)
            "total_replay": 0,      # Gagal uji kesegaran waktu (latency > 5 detik)
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
#  FUNGSI VERIFIKASI SHA3 (Sinkronisasi String Float)
# ================================================================
def verifikasi_sha3(payload):
    hash_dari_esp32 = payload.get("hash", "")
    hrv_raw = payload.get("hrv", 0.0)
    
    # Paksa format float menjadi 2 desimal string murni agar cocok dengan serializeJson() Arduino
    hrv_formatted = float("{:.2f}".format(hrv_raw)) if hrv_raw != 0 else 0

    # Rekonstruksi pasangan Key-Value presisi sesuai plainDoc firmware ESP32
    data_untuk_hash = {
        "ppg":      payload.get("ppg", 0),
        "bpm":      payload.get("bpm", 0),
        "ibi":      payload.get("ibi", 0),
        "hrv":      hrv_formatted,
        "status":   payload.get("status", ""),
        "ml_class": payload.get("ml_class", "")
    }
    
    # Generate JSON minified tanpa spasi kosong pembatas
    data_string = json.dumps(data_untuk_hash, separators=(',', ':'))

    # Hitung ulang SHA3-256 hash
    hash_ulang = hashlib.sha3_256(data_string.encode()).hexdigest()
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

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode("utf-8"))

        current_time_ms = int(time.time() * 1000)
        esp_ts  = payload.get("ts", current_time_ms)
        latency = abs(current_time_ms - esp_ts)

        # --- PERISAI REPLAY ATTACK (FRESHNESS CHECK) ---
        if latency > 5000:
            data_store.latest_data["total_replay"] += 1
            data_store.latest_data["integrity_valid"] = "❌ REPLAY ATTACK DETECTED"
            
            # Catat ke log historis paling atas (.appendleft)
            data_store.integrity_log.appendleft({
                "waktu": time.strftime("%H:%M:%S"),
                "status": "❌ REPLAY ATTACK",
                "hash": payload.get("hash", "")[:16] + "...",
                "latency_ms": latency
            })
            return # Drop paket dan kunci jalur eksekusi di bawahnya
        # -----------------------------------------------

        # Jalankan Verifikasi Hash
        is_valid, data_medis, hash_preview = verifikasi_sha3(payload)

        bpm_val = data_medis.get("bpm", 0)
        ibi_val = data_medis.get("ibi", 0)
        hrv_val = data_medis.get("hrv", 0.0)
        raw_ppg = data_medis.get("ppg", 0)
        status_val = data_medis.get("status", "Unknown")
        ml_class_val = data_medis.get("ml_class", "Waiting for finger...")

        cpu_val = payload.get("cpu", 0.0)
        mem_val = payload.get("mem", 0.0)
        hash_t_val = payload.get("hash_t", 0)

        # Logika Pengondisian Jari Tempel (Edge Detection)
        finger_detected_now = (raw_ppg > 50000)

        if finger_detected_now and not data_store.is_finger_currently_detected:
            data_store.last_export_time = time.time()
            data_store.export_buffer.clear()

        if finger_detected_now:
            filtered_ppg = data_store.filter_dc_removal(raw_ppg)
            
            if bpm_val > 0 and ibi_val > 0 and is_valid:
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

            if (time.time() - data_store.last_export_time) >= 30.0:
                trigger_excel_export()
        else:
            filtered_ppg = 0
            data_store.w = 0.0 
            
            if data_store.is_finger_currently_detected:
                trigger_excel_export()

        data_store.is_finger_currently_detected = finger_detected_now

        # Isikan ke Antrean Grafik
        data_store.ppg_data.append(filtered_ppg)
        data_store.bpm_data.append(bpm_val)
        data_store.ibi_data.append(ibi_val)

        # Update Hitungan Counter Berdasarkan Hasil Validasi
        if is_valid:
            data_store.latest_data["total_valid"] += 1
            msg_status = "✅ VALID"
        else:
            data_store.latest_data["total_manipulated"] += 1
            msg_status = "❌ MANIPULASI TERDETEKSI"

        # Tambahkan ke Log Historis
        data_store.integrity_log.appendleft({
            "waktu": time.strftime("%H:%M:%S"),
            "status": msg_status,
            "hash": hash_preview + "...",
            "latency_ms": latency
        })

        # Update State Utama Dashboard
        data_store.latest_data.update({
            "bpm": bpm_val, "ibi": ibi_val, "hrv": hrv_val,
            "status": status_val, "ml_class": ml_class_val,
            "cpu": cpu_val, "mem": mem_val, "latency": latency,
            "hash_t": hash_t_val,
            "integrity_valid": msg_status,
            "hash_preview": hash_preview + "..."
        })

    except Exception as e:
        print(f"❌ Error saat memproses payload MQTT: {e}")

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
#  SISTEM NAVIGASI MULTI-TAB
# ================================================================
tab_monitor, tab_ai, tab_security, tab_report = st.tabs([
    "📊 Real-Time Monitoring", 
    "🤖 AI Classification", 
    "🔒 Security Integrity & Log",
    "📈 Model Performance Report"
])

# 1. TAB REAL-TIME MONITORING
with tab_monitor:
    st.markdown("### 🩺 Vital Signs Real-Time")
    col1, col2, col3, col4 = st.columns(4)
    bpm_placeholder    = col1.empty()
    ibi_placeholder    = col2.empty()
    hrv_placeholder    = col3.empty()
    status_placeholder = col4.empty()

    st.markdown("---")
    st.markdown("### 📈 Sinyal Gelombang Detak Jantung (Filtered PPG)")
    chart_placeholder = st.empty()

    st.markdown("---")
    st.markdown("### 📊 Tren Stabilitas Jantung (BPM & IBI)")
    chart_col1, chart_col2 = st.columns(2)
    bpm_chart_placeholder = chart_col1.empty()
    ibi_chart_placeholder = chart_col2.empty()

# 2. TAB AI CLASSIFICATION
with tab_ai:
    st.markdown("### 🧠 Edge AI Classification Result (On-Device GRU)")
    st.info("Prediksi di bawah ini dieksekusi secara lokal di dalam mikroprosesor ESP32-S3 menggunakan TensorFlow Lite, dan keaslian datanya diproteksi penuh oleh hashing SHA3-256.")
    
    ai_status_placeholder = st.empty()
    st.markdown("---")
    st.markdown("#### Panduan Klinis Hasil Diagnosis:")
    
    gcol1, gcol2, gcol3, gcol4 = st.columns(4)
    gcol1.success("**Normal**\n\nDetak jantung berada di rentang normal dan ritme teratur.")
    gcol2.warning("**Arrhythmia**\n\nTerdeteksi adanya ketidakteraturan pada ritme detak jantung.")
    gcol3.error("**Tachycardia**\n\nRata-rata detak jantung terlalu cepat (> 100 BPM).")
    gcol4.error("**Bradycardia**\n\nRata-rata detak jantung terlalu lambat (< 60 BPM).")

# 3. TAB SECURITY INTEGRITY & LOG (Modifikasi Konter Gabungan)
with tab_security:
    st.markdown("### 🔏 Evaluasi Integritas Data & Anti-Tampering")
    sec1, sec2, sec3, sec4 = st.columns(4)
    integrity_placeholder    = sec1.empty()  
    hash_t_placeholder       = sec2.empty()  
    hash_preview_placeholder = sec3.empty()  
    lat_placeholder          = sec4.empty()  

    st.markdown("---")
    st.markdown("#### 📊 Statistik Keamanan & Telemetri Perangkat")
    cnt1, cnt2, cnt3 = st.columns(3) # Disederhanakan menjadi 3 Kolom Utama
    valid_count_placeholder   = cnt1.empty()
    total_rejected_placeholder = cnt2.empty() # Satu Pintu untuk Seluruh Paket Rusak/Serangan
    hardware_placeholder      = cnt3.empty()

    st.markdown("---")
    st.markdown("### 🗒️ Log Historis Verifikasi Integritas (Urutan Terbaru di Atas)")
    log_placeholder = st.empty()

# 4. TAB PERFORMANCE REPORT
with tab_report:
    st.markdown("### 📑 Classification Report (Model Evaluation)")
    st.markdown("Metrik performa model GRU tingkat lanjut hasil pengujian menggunakan *MIT-BIH Arrhythmia Database*:")
    
    report_data = {
        "Class": ["Normal", "Arrhythmia", "Tachycardia", "Bradycardia"],
        "Precision": [0.80, 0.89, 0.99, 0.99],
        "Recall": [0.91, 0.81, 0.98, 0.99],
        "F1-Score": [0.85, 0.85, 0.98, 0.99],
        "Support": [8035, 11661, 3837, 1939]
    }
    df_report = pd.DataFrame(report_data)
    st.table(df_report.set_index("Class"))
    
    fig_metrics = go.Figure()
    fig_metrics.add_trace(go.Bar(x=df_report["Class"], y=df_report["Precision"], name="Precision", marker_color="#1f77b4"))
    fig_metrics.add_trace(go.Bar(x=df_report["Class"], y=df_report["Recall"], name="Recall", marker_color="#aec7e8"))
    fig_metrics.add_trace(go.Bar(x=df_report["Class"], y=df_report["F1-Score"], name="F1-Score", marker_color="#ff7f0e"))
    
    fig_metrics.update_layout(
        title="Perbandingan Metrik Evaluasi Per Kelas",
        barmode='group', template="plotly_dark",
        xaxis_title="Kelas Diagnosis", yaxis_title="Nilai Skor (0 - 1.0)",
        yaxis=dict(range=[0, 1.1])
    )
    st.plotly_chart(fig_metrics, use_container_width=True)

# ================================================================
#  LOOP AKTIF REFRESH DASHBOARD
# ================================================================
try:
    while True:
        data = data_store.latest_data

        # --- UPDATE TAB 1: Real-Time Monitoring ---
        bpm_placeholder.metric(label="❤️ Avg BPM", value=f"{data['bpm']} bpm")
        ibi_placeholder.metric(label="⏱️ IBI (Interval)", value=f"{data['ibi']} ms")
        hrv_placeholder.metric(label="🌊 HRV (SDNN)", value=f"{data['hrv']:.1f} ms")

        status_color = "green" if "Good" in data['status'] else "red"
        status_placeholder.markdown(
            f"**🫀 Sensor Status:** <br><span style='color:{status_color}; font-size:22px; font-weight:bold;'>{data['status']}</span>",
            unsafe_allow_html=True
        )

        # Plot PPG Wave
        if len(data_store.ppg_data) > 0:
            df_ppg = pd.DataFrame({"Filtered Signal": list(data_store.ppg_data)})
            fig_ppg = px.line(df_ppg, y="Filtered Signal", template="plotly_dark", height=350)
            fig_ppg.update_layout(
                xaxis_title="Timestep Sample", yaxis_title="Pulse Amplitude (AC Component)",
                yaxis_range=[-1500, 1500], margin=dict(l=0, r=0, t=10, b=0),
                xaxis=dict(showgrid=False), yaxis=dict(showgrid=False)
            )
            fig_ppg.update_traces(line_color='#00FF7F', line_width=3)
            chart_placeholder.plotly_chart(fig_ppg, use_container_width=True, key=f"ppg_sha3_{time.time()}")

        # Plot Tren BPM
        if len(data_store.bpm_data) > 0:
            df_bpm = pd.DataFrame({"BPM": list(data_store.bpm_data)})
            fig_bpm = px.line(df_bpm, y="BPM", template="plotly_dark", height=220)
            fig_bpm.update_layout(
                xaxis_title="Waktu", yaxis_title="Beats Per Minute",
                margin=dict(l=0, r=0, t=10, b=0), xaxis=dict(showgrid=False), yaxis=dict(range=[40, 160])
            )
            fig_bpm.update_traces(line_color='#FF69B4', line_width=2)
            bpm_chart_placeholder.plotly_chart(fig_bpm, use_container_width=True, key=f"bpm_sha3_{time.time()}")

        # Plot Tren IBI
        if len(data_store.ibi_data) > 0:
            df_ibi = pd.DataFrame({"IBI": list(data_store.ibi_data)})
            fig_ibi = px.line(df_ibi, y="IBI", template="plotly_dark", height=220)
            fig_ibi.update_layout(
                xaxis_title="Waktu", yaxis_title="Interval (ms)",
                margin=dict(l=0, r=0, t=10, b=0), xaxis=dict(showgrid=False), yaxis=dict(range=[300, 1500])
            )
            fig_ibi.update_traces(line_color='#9370DB', line_width=2)
            ibi_chart_placeholder.plotly_chart(fig_ibi, use_container_width=True, key=f"ibi_sha3_{time.time()}")

        # --- UPDATE TAB 2: AI Classification ---
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
                <h4 style="color:{text_color}; margin:0;">🚨 INTEGRITY VERIFIED LIVE DIAGNOSIS:</h4>
                <p style="color:{text_color}; font-size:35px; font-weight:bold; margin:10px 0 0 0;">{diag}</p>
            </div>
            """, 
            unsafe_allow_html=True
        )

        # --- UPDATE TAB 3: Security & Cryptography Log ---
        integrity_color = "green" if "✅ VALID" in str(data['integrity_valid']) else "red"
        integrity_placeholder.markdown(
            f"**🔏 Current State**\n\n<span style='color:{integrity_color}; font-size:18px; font-weight:bold;'>{data['integrity_valid']}</span>",
            unsafe_allow_html=True
        )
        hash_t_placeholder.metric(label="⚡ Hashing Time (ESP32)", value=f"{data['hash_t']} µs")
        hash_preview_placeholder.markdown(
            f"**#️⃣ Hash SHA3 Preview**\n\n`{data['hash_preview']}`",
            unsafe_allow_html=True
        )
        lat_placeholder.metric(label="📶 Transmission Latency", value=f"{data['latency']} ms")

        # LOGIKA GABUNGAN: Akumulasi penolakan
        gagal_hash = data['total_manipulated']
        gagal_replay = data['total_replay']
        total_ditolak = gagal_hash + gagal_replay

        # Tampilkan Konter Statistik Baru
        valid_count_placeholder.metric(label="✅ Paket Aman (Valid)", value=data['total_valid'])
        
        total_rejected_placeholder.metric(
            label="❌ Total Paket Ditolak", 
            value=total_ditolak,
            delta=f"{gagal_replay} Replay | {gagal_hash} Mismatch", # Breakdown forensik tetap terlihat di sub-label
            delta_color="inverse"
        )
        
        hardware_placeholder.markdown(
            f"**🧠 CPU Load:** {data['cpu']:.1f} %  \n"
            f"**💾 RAM Used:** {data['mem']:.1f} %"
        )

        # Cetak Tabel Log Integrasi Historis
        if len(data_store.integrity_log) > 0:
            df_log = pd.DataFrame(list(data_store.integrity_log))
            log_placeholder.dataframe(df_log, use_container_width=True)

        time.sleep(0.1)

except Exception as e:
    st.error(f"Sistem dashboard terhenti: {e}")