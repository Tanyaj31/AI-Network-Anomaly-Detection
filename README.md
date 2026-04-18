# 🛡️ AI-Powered Network Anomaly Detection System 

> Production-ready IoT Network Security capstone project — Metropolia University of Applied Sciences  
> 6-month project | 4-member team | Parallel Learning Methodology

---

## 📸 Dashboard Overview

<!-- Screenshot: Full dashboard home page -->
![Dashboard Overview](https://github.com/Tanyaj31/AI-Network-Anomaly-Detection/blob/main/Screenshots/Screenshot%202026-03-25%20112454.png)

---

## 🎯 Project Summary

A real-world AI-powered Network Anomaly Detection System ( built for IoT environments. The system uses a **three-layer detection architecture** combining unsupervised anomaly detection and supervised ensemble classification to achieve **99.92% accuracy** on real cybersecurity datasets.

The project follows a **parallel learning** approach — all 4 team members gained hands-on experience across every component (ML training, backend, dashboard, edge devices) rather than siloing into specializations.

---

## ⚡ Key Results

| Metric | Value |
|--------|-------|
| 🎯 Detection Accuracy | **99.92%** (XGBoost on CICIDS2017) |
| ⚡ Throughput | **~7,000 flows/sec** |
| 🧠 Architecture | 3-Layer (Autoencoder + XGBoost Ensemble) |
| 📡 Edge Devices | Raspberry Pi distributed sensors |
| 🗃️ Datasets | CICIDS2017, CIC-IoT-2023, UNSW-NB15 |
| 🔍 Attack Types | 30+ categories detected |

---

## 🏗️ System Architecture

```
Raspberry Pi (rp-01)          Dell GB10 Server              Streamlit Dashboard
─────────────────────         ──────────────────            ─────────────────────
Network Interface              MQTT Analyzer                 Live Monitor Tab
      │                              │                       Threat Feed Tab
      ▼                              ▼                       Human Review Tab
Packet Capture             Layer 0: CICIDS Autoencoder       History Tab
      │                    (Zero-day / anomaly detection)
      ▼                              │
Feature Extraction         Layer 1: XGBoost Ensemble
(147 universal features)   ┌─────────────────────────┐
      │                    │ CICIDS XGBoost (52 feat) │
      ▼                    │ IoT XGBoost   (39 feat)  │
MQTT Broker ────────────►  │ UNSW XGBoost  (48 feat)  │
(port 1883)                └─────────────────────────┘
                                       │
                           Confidence-Weighted Voting
                                       │
                               Layer 2: Human Review
                               (low-confidence cases)
                                       │
                                  SQLite DB
```

<!-- Screenshot: Architecture diagram or live monitor showing detections -->
![Architecture](https://github.com/Tanyaj31/AI-Network-Anomaly-Detection/blob/main/Screenshots/Screenshot%202026-03-13%20100252.png)

---

## 🧠 Detection Layers

### Layer 0 — Anomaly Detection (Zero-Day)
- CICIDS2017-trained Autoencoder
- Flags traffic that deviates from learned "normal" patterns
- Catches unknown/novel attacks not seen during training

### Layer 1 — Ensemble Classification
- Three XGBoost models trained on different datasets
- **Confidence-weighted voting** across all three models
- Specialist label preference for IoT-specific attacks
- Detects 30+ named attack categories (DDoS, PortScan, Brute Force, etc.)

### Layer 2 — Human-in-the-Loop
- Low-confidence predictions queued for human review
- Reviewable directly from the dashboard
- Reviewed decisions feed back into system logging

---

## 📊 Model Performance

| Model | Dataset | Accuracy |
|-------|---------|----------|
| XGBoost | CICIDS2017 | **99.92%** |
| XGBoost | CIC-IoT-2023 | 96.80% |
| XGBoost | UNSW-NB15 | 97.20% |
| Autoencoder | CICIDS2017 | 97.73% |

<!-- Screenshot: Models page from dashboard showing confusion matrices or accuracy charts -->
![Model Performance]()

---

## 🖥️ Dashboard

Built with **Streamlit**, the dashboard provides:

- **Live Monitor** — Real-time threat feed as traffic flows in from the Pi
- **Threat Feed** — All detected attacks with IP, type, confidence, timestamp
- **Human Review Queue** — Flagged low-confidence detections for manual review
- **History** — Past attack trends and statistics
- **Models** — Per-model accuracy, confusion matrices, feature importance
- **Analyze** — Upload CSV/PCAP for offline batch analysis

<!-- Screenshot: Live monitor tab showing active threats -->
![Live Monitor](https://github.com/Tanyaj31/AI-Network-Anomaly-Detection/blob/main/Screenshots/Screenshot%202026-03-15%20115058.png)

<!-- Screenshot: Human review queue -->
![Review Queue](https://github.com/Tanyaj31/AI-Network-Anomaly-Detection/blob/main/Screenshots/Screenshot%202026-03-13%20100638.png)

---

## 📡 Infrastructure

| Component | Details |
|-----------|---------|
| **Edge Sensor** | Raspberry Pi 4 Model B |
| **Server** | Dell GB10 (128GB RAM, 20 cores, 4TB SSD) |
| **Broker** | Mosquitto MQTT (port 1883) |
| **VPN** | Tailscale (cross-network access) |
| **Database** | SQLite (`live_stats.db`) |
| **OS** | Ubuntu (Dell), Raspberry Pi OS (Pi) |

---

## 📁 Repository Structure

```
AI_Anomaly_Detection/
├── streamlit_app/              # Dashboard UI
│   ├── app.py                  # Main entry point
│   ├── pages/
│   │   ├── 2_Analyze.py        # Offline file analysis
│   │   ├── 3_Live_Monitor.py   # Real-time monitoring
│   │   ├── 4_Models.py         # Model info & stats
│   │   └── 5_About.py          # Project info
│   └── utils/
│       ├── visualizations.py
│       ├── analyzer.py
│       └── config.py
├── layered_ensemble/           # Core detection pipeline
│   └── production_pipeline_COMPLETE_FIXED.py
├── realtime_monitor/           # MQTT analyzer (runs on Dell)
│   ├── mqtt_auto_analyzer.py
│   └── shared_state.py
├── feature_extraction/         # Flow feature calculators
├── pi_edge/                    # Raspberry Pi edge code
│   ├── pi_edge_controlled2.py  # Main Pi monitor script
│   ├── pi_control_listener.py  # MQTT control handler
│   └── feature_extraction/
├── config/                     # System configuration
└── human_review/               # Review queue logic
```

> ⚠️ **Note:** Trained model files (`*.pkl`, `*.h5`) and datasets (`*.csv`) are not included due to size. See [`models/README.md`](models/README.md) for how to retrain or obtain them.

---

## 🚀 Running the System

### Prerequisites
```bash
pip install streamlit xgboost tensorflow scikit-learn paho-mqtt pandas numpy plotly
```

### Start the MQTT Analyzer (Dell)
```bash
sudo systemctl start mqtt-analyzer
sudo systemctl status mqtt-analyzer
```

### Start the Pi Edge Sensor (Raspberry Pi)
```bash
cd ~/network_monitor
python3 pi_edge_controlled2.py
```

Or trigger via MQTT:
```bash
mosquitto_pub -h localhost -t "nids/control/rpi-01/start" -m "start"
```

### Launch the Dashboard (Dell)
```bash
cd /home/shared/IoT_Project/AI_Anomaly_Detection
streamlit run streamlit_app/app.py
```

---

## 🎭 Attack Simulation (Demo)

```bash
# HTTP flood (requires nginx on Pi)
ab -n 50000 -c 200 http://192.168.0.140/

# SYN flood
sudo hping3 -S --flood -V -p 80 192.168.0.140

# Port scan
nmap -sS 192.168.0.140
```

---

## 👥 Team

**Institution:** Metropolia University of Applied Sciences, Finland  
**Program:** IoT Network Security  
**Duration:** September 2025 – March 2026  

| Member | Role |
|--------|------|
| Bibek | ML Pipeline, MQTT Analyzer, System Integration |
| Tanya | Dashboard UI, Dataset Training, Infrastructure |
| Sangam | Feature Extraction, Model Training |
| Chris | Edge Sensing, Testing, Documentation |

> All members contributed across all areas — **parallel learning** methodology.

---

## 🔮 Future Work

- REST API for external SIEM integration
- Continuous model retraining pipeline
- Email/SMS alerting
- Expanded Pi sensor nodes
- Login authentication for dashboard
- Scheduled PDF security reports
- Attack trend graphs and analytics

---

## 📄 License

This project was developed as an academic capstone. For inquiries about use in commercial or research settings, contact the team.
