#!/usr/bin/env python3
"""
Check analyzer status and show recent alerts
"""

from pathlib import Path
from datetime import datetime, timedelta
import json

BASE_PATH = Path('/home/shared/IoT_Project/AI_Anomaly_Detection/realtime_monitor')
LOGS_DIR = BASE_PATH / 'logs'
ALERTS_DIR = BASE_PATH / 'alerts'

print("=" * 70)
print("🔍 ANALYZER STATUS CHECK")
print("=" * 70)

# Check if analyzer is running
import subprocess
result = subprocess.run(['pgrep', '-f', 'mqtt_auto_analyzer'], capture_output=True)
if result.returncode == 0:
    print("✅ Analyzer is RUNNING")
    print(f"   PID: {result.stdout.decode().strip()}")
else:
    print("❌ Analyzer is NOT running")

# Check recent logs
today = datetime.now().strftime('%Y%m%d')
log_file = LOGS_DIR / f"analyzer_{today}.log"

if log_file.exists():
    print(f"\n📋 Recent Log Entries (last 10):")
    with open(log_file, 'r') as f:
        lines = f.readlines()
        for line in lines[-10:]:
            print(f"   {line.strip()}")
else:
    print("\n⚠️  No logs today yet")

# Check recent alerts
alert_files = sorted(ALERTS_DIR.glob('alert_*.json'), key=lambda x: x.stat().st_mtime, reverse=True)

if alert_files:
    print(f"\n🚨 Recent Alerts ({len(alert_files)} total):")
    for alert_file in alert_files[:5]:  # Show last 5
        with open(alert_file, 'r') as f:
            alert = json.load(f)
            print(f"\n   📁 {alert_file.name}")
            print(f"   ⏰ {alert['timestamp']}")
            print(f"   🔴 {alert['attack']['type']} ({alert['attack']['count']} flows)")
else:
    print("\n✅ No alerts yet")

print("=" * 70)
