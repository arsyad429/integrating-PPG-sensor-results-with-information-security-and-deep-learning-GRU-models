import paho.mqtt.client as mqtt

# Hacker menargetkan topik tanpa enkripsi dan dengan enkripsi
TOPIC_NON_SECURE = "arsyad/brawijaya_med/ppg_sensor_01"
TOPIC_SECURE = "arsyad/brawijaya_med/secure_ppg"

def on_message(client, userdata, msg):
    print(f"\n[🚨 SNIFFER MENANGKAP PAKET DARI {msg.topic}]")
    print(f"Isi Payload: {msg.payload.decode('utf-8')}")

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_message = on_message
client.connect("broker.hivemq.com", 1883, 60)

client.subscribe(TOPIC_NON_SECURE)
client.subscribe(TOPIC_SECURE)

print("Hacker sedang menyadap jaringan... (Tekan Ctrl+C untuk berhenti)")
client.loop_forever()