#!/usr/bin/env python3
"""
MQTT Listener for Real-Time Network Monitoring
Receives CSVs from Raspberry Pi edge devices
"""
import paho.mqtt.client as mqtt
from pathlib import Path
import sys
from datetime import datetime
import json

# Add ML pipeline to path
sys.path.insert(0, '/home/shared/IoT_Project/AI_Anomaly_Detection')

# MQTT Configuration
BROKER = "100.90.12.111"  # Free public broker
PORT = 1883
TOPIC_FLOWS = "nids/+/flows"      # Subscribe to all devices
TOPIC_STATUS = "nids/+/status"    # Device health
DEVICE_ID = "dell-server"

# Paths
INCOMING_DIR = Path("/home/shared/IoT_Project/incoming_data")
RESULTS_DIR = Path("/home/shared/IoT_Project/analysis_results")
INCOMING_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

# Statistics
stats = {
    'messages_received': 0,
    'files_analyzed': 0,
    'attacks_detected': 0,
    'start_time': datetime.now()
}

def on_connect(client, userdata, flags, rc):
    """Called when connected to MQTT broker"""
    if rc == 0:
        print("=" * 60)
        print("🚀 MQTT REAL-TIME MONITORING SYSTEM")
        print("=" * 60)
        print(f"✅ Connected to broker: {BROKER}:{PORT}")
        print(f"📡 Device ID: {DEVICE_ID}")
        print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Subscribe to topics
        client.subscribe(TOPIC_FLOWS, qos=1)
        client.subscribe(TOPIC_STATUS, qos=1)
        
        print(f"📥 Subscribed to: {TOPIC_FLOWS}")
        print(f"📥 Subscribed to: {TOPIC_STATUS}")
        print("=" * 60)
        print("\n⏳ Waiting for messages from edge devices...\n")
    else:
        print(f"❌ Connection failed with code: {rc}")

def on_message(client, userdata, msg):
    """Called when message received"""
    global stats
    
    try:
        stats['messages_received'] += 1
        
        # Parse topic to get device ID and message type
        topic_parts = msg.topic.split('/')
        device_id = topic_parts[1]  # nids/rpi-01/flows -> rpi-01
        msg_type = topic_parts[2]   # flows or status
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if msg_type == "status":
            # Device status update
            status = msg.payload.decode('utf-8')
            print(f"[{timestamp}] 📊 Device {device_id}: {status}")
            return
        
        elif msg_type == "flows":
            # Network flow data received
            print("\n" + "=" * 60)
            print(f"[{timestamp}] 📥 DATA RECEIVED FROM {device_id.upper()}")
            print("=" * 60)
            print(f"📦 Payload size: {len(msg.payload):,} bytes")
            
            # Save CSV file
            timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"flows_{device_id}_{timestamp_file}.csv"
            filepath = INCOMING_DIR / filename
            
            with open(filepath, "wb") as f:
                f.write(msg.payload)
            
            print(f"✅ Saved: {filename}")
            print(f"📁 Location: {filepath}")
            
            # Quick analysis WITHOUT ML (faster for demo)
            try:
                import pandas as pd
                df = pd.read_csv(filepath)
                num_flows = len(df)
                print(f"\n📊 Quick Stats:")
                print(f"   • Total flows: {num_flows}")
                print(f"   • Columns: {len(df.columns)}")
                print(f"   • Size: {filepath.stat().st_size / 1024:.1f} KB")
                
                stats['files_analyzed'] += 1
                
            except Exception as e:
                print(f"⚠️  Quick analysis failed: {e}")
            
            # Optional: Run full ML analysis (comment out if too slow)
            # print("\n🤖 Running ML analysis...")
            # from layered_ensemble.file_analyzer import analyze_file
            # results = analyze_file(str(filepath), verbose=False)
            # ml_stats = results['stats']
            # print(f"   • Attacks detected: {ml_stats['attacks_detected']}")
            # print(f"   • Attack rate: {ml_stats['attack_rate']:.1f}%")
            
            print("=" * 60)
            print(f"📈 Session Stats:")
            print(f"   • Messages received: {stats['messages_received']}")
            print(f"   • Files analyzed: {stats['files_analyzed']}")
            print(f"   • Uptime: {(datetime.now() - stats['start_time']).total_seconds():.0f}s")
            print("=" * 60 + "\n")
            
    except Exception as e:
        print(f"❌ Error processing message: {e}")
        import traceback
        traceback.print_exc()

def on_disconnect(client, userdata, rc):
    """Called when disconnected"""
    if rc != 0:
        print(f"\n⚠️  Unexpected disconnect! Code: {rc}")
        print("🔄 Attempting to reconnect...")

# Setup MQTT client
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, DEVICE_ID)
client.on_connect = on_connect
client.on_message = on_message
client.on_disconnect = on_disconnect

# Main execution
if __name__ == "__main__":
    try:
        print("\n🔌 Connecting to MQTT broker...")
        client.connect(BROKER, PORT, keepalive=60)
        
        # Start the loop (blocks here)
        client.loop_forever()
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Stopping MQTT listener...")
        print(f"📊 Final Stats:")
        print(f"   • Total messages: {stats['messages_received']}")
        print(f"   • Files analyzed: {stats['files_analyzed']}")
        print(f"   • Runtime: {(datetime.now() - stats['start_time']).total_seconds():.0f}s")
        print("\n✅ Goodbye!\n")
        client.disconnect()
        
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
