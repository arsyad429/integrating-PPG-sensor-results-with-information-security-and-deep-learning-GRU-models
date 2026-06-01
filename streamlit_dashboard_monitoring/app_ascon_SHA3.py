import streamlit as st
import paho.mqtt.client as mqtt
import json
import time
from collections import deque
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import ascon 
import hashlib
import os 

# --- Konfigurasi Halaman ---
st.set_page_config(page_title="Secure PPG ASCON & SHA3", layout="wide")
st.title("🔒 Ultimate Secure PPG Monitor (Hybrid Defense: ASCON-128 + SHA3-256 + AI)")

# Kunci Rahasia harus SAMA dengan di Arduino (PPG_ASCON_SHA3.ino)
SECRET_KEY = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])

# ================================================================
#  KELAS SHARED MEMORY
# ================================================================
class SensorData:
    def __init__(self):
        self.ppg_data = deque(maxlen=150)
        self.bpm_data = deque(maxlen=150) 
        self.ibi_data = deque(maxlen=150)
        self.integrity_log = deque(maxlen=200) # Diperbesar agar log tidak mudah tergilas data normal
        
        # MEMORI CACHE BARU: Untuk implementasi Lapis 2 (Mencegat Duplikasi Instan)
        self.hash_cache = [] # Struktur di dalamnya: {"timestamp": float, "hash": str}
        
        self.latest_data = {
            "bpm": 0, "ibi": 0, "hrv": 0.0, "status": "Waiting...", 
            "ml_class": "Waiting for data...",
            "cpu": 0.0, "mem": 0.0, "latency": 0,
            "enc_t": 0, "enc_o": 0, "dec_t": 0.0,
            "sha3_status": "Waiting...",
            "hash_preview": "-",
            "total_valid": 0,
            "total_manipulated": 0, # Gagal karena manipulasi isi data / salah kunci
            "total_replay": 0        # Gagal karena aturan Lapis 1 (Timestamp) atau Lapis 2 (Hash Duplikat)
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

# ================================================================
#  KONFIGURASI MQTT & PIPELINE KEAMANAN GANDA (HYBRID APPROACH)
# ================================================================
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
        incoming_sha3 = payload.get("sha3", "") # Ambil hash dari payload jaringan
        
        current_time_sec = time.time()

        # ------------------------------------------------------------
        # LAPIS 1: FRESHNESS CHECK (ATURAN TIMESTAMP 5 DETIK)
        # ------------------------------------------------------------
        if latency > 5000:
            data_store.latest_data["total_replay"] += 1
            data_store.latest_data["sha3_status"] = "❌ REPLAY ATTACK (EXP_TIMESTAMP)"
            
            data_store.integrity_log.appendleft({
                "Waktu": time.strftime("%H:%M:%S"),
                "Status": "❌ REPLAY ATTACK (Lapis 1: Usia > 5s)",
                "Hash Preview": incoming_sha3[:16] + "..." if incoming_sha3 else "-",
                "Latency (ms)": latency
            })
            return # Drop paket usang secepatnya!
        
        # ------------------------------------------------------------
        # LAPIS 2: REPLICATED CHECK (ATURAN SLIDING CACHE HASH 5 DETIK)
        # ------------------------------------------------------------
        # 2a. Bersihkan cache internal dari data yang umurnya sudah melebihi jendela waktu 5 detik (Garbage Collection RAM)
        data_store.hash_cache = [item for item in data_store.hash_cache if (current_time_sec - item["timestamp"]) <= 5.0]
        
        # 2b. Periksa apakah hash paket yang baru masuk ini sudah pernah diterima dalam 5 detik terakhir
        hash_sudah_ada = any(item["hash"] == incoming_sha3 for item in data_store.hash_cache)
        
        if hash_sudah_ada:
            data_store.latest_data["total_replay"] += 1
            data_store.latest_data["sha3_status"] = "❌ REPLAY ATTACK (DUPLICATE_HASH)"
            
            data_store.integrity_log.appendleft({
                "Waktu": time.strftime("%H:%M:%S"),
                "Status": "❌ REPLAY ATTACK (Lapis 2: Duplikasi Instan)",
                "Hash Preview": incoming_sha3[:16] + "..." if incoming_sha3 else "-",
                "Latency (ms)": latency
            })
            return # Drop paket tiruan instan hacker secepatnya!
            
        # 2c. Jika paket lolos Lapis 1 & Lapis 2, masukkan hash-nya ke cache agar tidak bisa diduplikasi oleh hacker nanti
        if incoming_sha3:
            data_store.hash_cache.append({"timestamp": current_time_sec, "hash": incoming_sha3})
        # ------------------------------------------------------------

        # Jalankan Proses Dekripsi ASCON-128 (Ciphertext + Tag digabung di parameter ct_bytes)
        nonce_bytes = bytes.fromhex(payload.get("nonce", "00"*16))
        ct_bytes = bytes.fromhex(payload.get("ct", ""))
        
        start_dec = time.perf_counter()
        plaintext_bytes = ascon.decrypt(SECRET_KEY, nonce_bytes, b"", ct_bytes, variant="Ascon-128")
        dec_time_ms = (time.perf_counter() - start_dec) * 1000 
        
        # VERIFIKASI MATEMATIS KECOCOKAN HASH (Mencegah Manipulasi Bit data)
        calculated_sha3 = hashlib.sha3_256(plaintext_bytes).hexdigest()
        is_valid = (calculated_sha3 == incoming_sha3)
        hash_preview_str = incoming_sha3[:16] + "..." if incoming_sha3 else "-"

        if is_valid:
            sha3_verified = "🟢 Valid (No Tampering)"
            data_store.latest_data["total_valid"] += 1
            msg_status = "✅ VALID"
        else:
            sha3_verified = "🔴 CORRUPTED / ALTERED!"
            data_store.latest_data["total_manipulated"] += 1
            msg_status = "❌ MANIPULASI TERDETEKSI"
            
        # Catat status ke Log Integritas urutan teratas
        data_store.integrity_log.appendleft({
            "Waktu": time.strftime("%H:%M:%S"),
            "Status": msg_status,
            "Hash Preview": hash_preview_str,
            "Latency (ms)": latency
        })
        
        # Parse data plaintext medis hasil dekripsi
        medical_data = json.loads(plaintext_bytes.decode('utf-8'))
        
        bpm_val = medical_data.get("bpm", 0)
        ibi_val = medical_data.get("ibi", 0)
        hrv_val = medical_data.get("hrv", 0.0)
        raw_ppg = medical_data.get("ppg", 0)
        status_val = medical_data.get("status", "Unknown")
        ml_class_val = medical_data.get("ml_class", "Waiting for finger...")

        cpu_val = payload.get("cpu", 0.0)
        mem_val = payload.get("mem", 0.0)

        # --- LOGIKA PENYIMPANAN EXCEL ---
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

        # Masukkan ke Antrean Grafik hanya jika paket aman dan valid
        if is_valid:
            data_store.ppg_data.append(filtered_ppg)
            data_store.bpm_data.append(bpm_val)
            data_store.ibi_data.append(ibi_val)

        # Update penampung memori utama
        data_store.latest_data.update({
            "bpm": bpm_val, "ibi": ibi_val, "hrv": hrv_val, "status": status_val,
            "ml_class": ml_class_val, "cpu": cpu_val, "mem": mem_val, "latency": latency,
            "enc_t": payload.get("enc_t", 0), "enc_o": payload.get("enc_o", 0),
            "dec_t": dec_time_ms, "sha3_status": sha3_verified, "hash_preview": hash_preview_str
        })

    except ValueError:
        data_store.latest_data["total_manipulated"] += 1
        data_store.integrity_log.appendleft({
            "Waktu": time.strftime("%H:%M:%S"),
            "Status": "❌ DECRYPT FAILED (BAD SECRET KEY)",
            "Hash Preview": "-",
            "Latency (ms)": "-"
        })
    except Exception as e:
        print(f"❌ Error memproses data: {e}")

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
    st.markdown("### 🩺 Vital Signs Real-Time (Decrypted & Integrity Verified)")
    col1, col2, col3, col4 = st.columns(4) 
    bpm_placeholder = col1.empty()
    ibi_placeholder = col2.empty()
    hrv_placeholder = col3.empty()
    status_placeholder = col4.empty()

    st.markdown("---")
    st.markdown("### 📈 Sinyal Gelombang Detak Jantung (Filtered Secure PPG)")
    chart_placeholder = st.empty()

    st.markdown("---")
    st.markdown("### 📊 Tren Stabilitas Jantung (BPM & IBI)")
    chart_col1, chart_col2 = st.columns(2)
    bpm_chart_placeholder = chart_col1.empty()
    ibi_chart_placeholder = chart_col2.empty()

# 2. TAB AI CLASSIFICATION
with tab_ai:
    st.markdown("### 🧠 Edge AI Classification Result (On-Device GRU)")
    st.info("Prediksi di bawah ini dieksekusi secara lokal di dalam mikroprosesor ESP32-S3 menggunakan TensorFlow Lite, lalu dibungkus protokol pertahanan siber ganda industri (ASCON + SHA3).")
    
    ai_status_placeholder = st.empty()
    st.markdown("---")
    st.markdown("#### Panduan Klinis Hasil Diagnosis:")
    
    gcol1, gcol2, gcol3, gcol4 = st.columns(4)
    gcol1.success("**Normal**\n\nDetak jantung berada di rentang normal dan ritme teratur.")
    gcol2.warning("**Arrhythmia**\n\nTerdeteksi adanya ketidakteraturan pada ritme detak jantung.")
    gcol3.error("**Tachycardia**\n\nRata-rata detak jantung terlalu cepat (> 100 BPM).")
    gcol4.error("**Bradycardia**\n\nRata-rata detak jantung terlalu lambat (< 60 BPM).")

# 3. TAB SECURITY INTEGRITY & LOG
with tab_security:
    st.markdown("### 🛡️ Evaluasi Keamanan Jaringan & Sistem (Hybrid Validation Engine)")
    sec1, sec2, sec3, sec4, sec5 = st.columns(5) 
    enc_t_placeholder = sec1.empty()
    dec_t_placeholder = sec2.empty()
    enc_o_placeholder = sec3.empty()
    lat_placeholder = sec4.empty()
    sha3_placeholder = sec5.empty()

    st.markdown("---")
    st.markdown("#### 📊 Statistik Keamanan & Telemetri Perangkat")
    cnt1, cnt2, cnt3, cnt4 = st.columns(4)
    valid_count_placeholder = cnt1.empty()
    total_rejected_placeholder = cnt2.empty() # Satu pintu konter gabungan seluruh metode penolakan
    hash_preview_placeholder = cnt3.empty()
    hardware_placeholder = cnt4.empty()

    st.markdown("---")
    st.markdown("### 🗒️ Log Verifikasi Integritas (Urutan Terbaru di Atas)")
    log_placeholder = st.empty()

# 4. TAB PERFORMANCE REPORT
with tab_report:
    st.markdown("### 📑 Classification Report (Model Evaluation)")
    st.markdown("Metrik performa model GRU tingkat lanjut hasil pengujian menggunakan data sekunder uji *MIT-BIH Arrhythmia Database*:")
    
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
#  LOOP AKTIF REFRESH DASHBOARD UI
# ================================================================
try:
    while True:
        data = data_store.latest_data
        
        # --- Update Tab 1 Metrik Medis ---
        bpm_placeholder.metric(label="❤️ Avg BPM", value=f"{data['bpm']} bpm")
        ibi_placeholder.metric(label="⏱️ IBI (Interval)", value=f"{data['ibi']} ms")
        hrv_placeholder.metric(label="🌊 HRV (SDNN)", value=f"{data['hrv']:.1f} ms") 
        
        status_color = "green" if "Good" in data['status'] else "red"
        status_placeholder.markdown(
            f"**🫀 Sensor Status:** <br><span style='color:{status_color}; font-size:22px; font-weight:bold;'>{data['status']}</span>", 
            unsafe_allow_html=True
        )

        # Plot PPG Secure Wave
        if len(data_store.ppg_data) > 0:
            df_ppg = pd.DataFrame({"Filtered Signal": list(data_store.ppg_data)})
            fig_ppg = px.line(df_ppg, y="Filtered Signal", template="plotly_dark", height=350)
            fig_ppg.update_layout(
                xaxis_title="Timestep Sample", yaxis_title="Pulse Amplitude (AC)",
                yaxis_range=[-1500, 1500], margin=dict(l=0, r=0, t=10, b=0),
                xaxis=dict(showgrid=False), yaxis=dict(showgrid=False)
            )
            fig_ppg.update_traces(line_color='#00FF7F', line_width=3)
            chart_placeholder.plotly_chart(fig_ppg, use_container_width=True, key=f"ppg_lvl9_{time.time()}")
            
        # Plot Tren BPM
        if len(data_store.bpm_data) > 0:
            df_bpm = pd.DataFrame({"BPM": list(data_store.bpm_data)})
            fig_bpm = px.line(df_bpm, y="BPM", template="plotly_dark", height=220)
            fig_bpm.update_layout(
                xaxis_title="Waktu", yaxis_title="Beats Per Minute",
                margin=dict(l=0, r=0, t=10, b=0), xaxis=dict(showgrid=False), yaxis=dict(range=[40, 160]) 
            )
            fig_bpm.update_traces(line_color='#FF69B4', line_width=2)
            bpm_chart_placeholder.plotly_chart(fig_bpm, use_container_width=True, key=f"bpm_lvl9_{time.time()}")

        # Plot Tren IBI
        if len(data_store.ibi_data) > 0:
            df_ibi = pd.DataFrame({"IBI": list(data_store.ibi_data)})
            fig_ibi = px.line(df_ibi, y="IBI", template="plotly_dark", height=220)
            fig_ibi.update_layout(
                xaxis_title="Waktu", yaxis_title="Interval (ms)",
                margin=dict(l=0, r=0, t=10, b=0), xaxis=dict(showgrid=False), yaxis=dict(range=[300, 1500]) 
            )
            fig_ibi.update_traces(line_color='#9370DB', line_width=2)
            ibi_chart_placeholder.plotly_chart(fig_ibi, use_container_width=True, key=f"ibi_lvl9_{time.time()}")

        # --- Update Tab 2 AI Classification Result ---
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
                <h4 style="color:{text_color}; margin:0;">🚨 CRYPTO-VERIFIED LIVE DIAGNOSIS:</h4>
                <p style="color:{text_color}; font-size:35px; font-weight:bold; margin:10px 0 0 0;">{diag}</p>
            </div>
            """, 
            unsafe_allow_html=True
        )

        # --- Update Tab 3 Kriptografi Keamanan ---
        enc_t_placeholder.metric(label="🔐 Encryption Time (ESP32)", value=f"{data['enc_t']} µs")
        dec_t_placeholder.metric(label="🔓 Decryption Time (Python)", value=f"{data['dec_t']:.3f} ms")
        enc_o_placeholder.metric(label="📦 Encryption Overhead", value=f"{data['enc_o']} Bytes")
        lat_placeholder.metric(label="📶 Transmission Latency", value=f"{data['latency']} ms")
        
        sha3_color = "red" if "❌" in data['sha3_status'] or "🔴" in data['sha3_status'] else "green"
        sha3_placeholder.markdown(
            f"**🛡️ SHA3-256 Integrity:** <br><span style='color:{sha3_color}; font-size:16px; font-weight:bold;'>{data['sha3_status']}</span>", 
            unsafe_allow_html=True
        )

        # Perhitungan Komponen Konter Gabungan
        gagal_manipulasi = data['total_manipulated']
        gagal_replay = data['total_replay']
        total_ditolak = gagal_manipulasi + gagal_replay

        # Tampilkan Statistik & Telemetri
        valid_count_placeholder.metric(label="✅ Paket Valid", value=data['total_valid'])
        
        total_rejected_placeholder.metric(
            label="❌ Total Paket Ditolak", 
            value=total_ditolak,
            delta=f"{gagal_replay} Replay | {gagal_manipulasi} Mismatch", # Tampilkan breakdown di sub-label delta
            delta_color="inverse"
        )
        
        hash_preview_placeholder.markdown(
            f"**#️⃣ Hash SHA3 Preview**\n\n`{data['hash_preview']}`",
            unsafe_allow_html=True
        )
        hardware_placeholder.markdown(
            f"**🧠 ESP32 CPU Load:** {data['cpu']:.1f} %  \n"
            f"**💾 ESP32 RAM Used:** {data['mem']:.1f} %"
        )

        # Cetak Tabel Log Jalur .appendleft() secara berkala
        if len(data_store.integrity_log) > 0:
            df_log = pd.DataFrame(list(data_store.integrity_log))
            log_placeholder.dataframe(df_log, use_container_width=True)

        time.sleep(0.1) 
        
except Exception as e:
    st.error(f"Sistem dashboard terhenti: {e}")