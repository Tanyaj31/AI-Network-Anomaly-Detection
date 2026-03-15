#!/usr/bin/env python3
"""Send test flow to database"""
import sqlite3
from datetime import datetime
import json

db_path = "live_stats.db"

# Test flow
test_flow = {
    'timestamp': datetime.now().isoformat(),
    'device_id': 'rpi-01',
    'attack_type': 'Normal Traffic',
    'threat_level': 'INFO',
    'confidence': 95.5,
    'layer0_flagged': False,
    'layer1_flagged': False,
    'flow_details': json.dumps({
        'src_ip': '192.168.1.100',
        'src_port': 54321,
        'dst_ip': '8.8.8.8',
        'dst_port': 443,
        'protocol': 'TCP',
        'packet_count': 10,
        'byte_count': 5000
    })
}

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

cursor.execute("""
INSERT INTO threat_feed 
(timestamp, device_id, classification, threat_level, confidence, layer0_flagged, layer1_flagged, flow_details)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
""", (
    test_flow['timestamp'],
    test_flow['device_id'],
    test_flow['attack_type'],
    test_flow['threat_level'],
    test_flow['confidence'],
    test_flow['layer0_flagged'],
    test_flow['layer1_flagged'],
    test_flow['flow_details']
))

conn.commit()
conn.close()

print("✅ Test flow inserted!")
