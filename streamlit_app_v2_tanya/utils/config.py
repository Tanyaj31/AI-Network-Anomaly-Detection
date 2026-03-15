"""
Configuration for Streamlit Network IDS Application
"""
import os

# ============================================================================
# PATHS
# ============================================================================

BASE_PATH = '/home/shared/IoT_Project/AI_Anomaly_Detection'

PATHS = {
    'base': BASE_PATH,
    'layered_ensemble': os.path.join(BASE_PATH, 'layered_ensemble'),
    'feature_extraction': os.path.join(BASE_PATH, 'feature_extraction'),
    'demo_csv': os.path.join(BASE_PATH, 'layered_ensemble/test_results/extracted_features.csv'),
    'cicids_results': os.path.join(BASE_PATH, 'cicds/results'),
    'iot_results': os.path.join(BASE_PATH, 'cic_iot_2023/results'),
    'unsw_results': os.path.join(BASE_PATH, 'UNSW_NB15/results'),
}

# ============================================================================
# PROJECT INFO
# ============================================================================

PROJECT_INFO = {
    'title': 'AI Network Intrusion Detection System',
    'version': '1.0.0',
    'institution': 'Metropolia University of Applied Sciences',
    'team_size': 4,
    'duration': '6 months',
    'completion': 'March 2025'
}

# ============================================================================
# MODEL PERFORMANCE
# ============================================================================

MODEL_PERFORMANCE = {
    'CICIDS': {
        'XGBoost': {'accuracy': 99.92, 'features': 52},
        'Random Forest': {'accuracy': 99.88, 'features': 52},
        'LightGBM': {'accuracy': 98.96, 'features': 52},
        'Neural Network': {'accuracy': 98.49, 'features': 52},
        'Autoencoder': {'accuracy': 97.73, 'features': 52}
    },
    'IoT': {
        'XGBoost': {'accuracy': 96.80, 'features': 39},
        'Random Forest': {'accuracy': 95.20, 'features': 39},
        'Autoencoder': {'accuracy': 94.50, 'features': 39}
    },
    'UNSW': {
        'XGBoost': {'accuracy': 97.20, 'features': 48},
        'Isolation Forest': {'accuracy': 99.45, 'features': 48},
        'Autoencoder': {'accuracy': 96.80, 'features': 48}
    }
}

# ============================================================================
# ATTACK TYPES
# ============================================================================

ATTACK_TYPES = {
    'CICIDS': [
        'DoS', 'DDoS', 'Port Scanning', 'Brute Force', 
        'Web Attacks', 'Botnet', 'Normal Traffic'
    ],
    'IoT': [
        'DDoS-UDP', 'DDoS-TCP', 'DDoS-HTTP', 'Mirai', 
        'MITM', 'Scanning', 'Normal Traffic'
    ],
    'UNSW': [
        'Analysis', 'Backdoor', 'DoS', 'Exploits', 'Fuzzers',
        'Generic', 'Reconnaissance', 'Shellcode', 'Worms', 'Normal Traffic'
    ]
}

# ============================================================================
# UI SETTINGS
# ============================================================================

UI_SETTINGS = {
    'max_upload_size': 500,  # MB
    'supported_formats': ['csv', 'pcap', 'pcapng'],
    'demo_file_size': '215 MB',
    'demo_file_flows': 262152,
    'page_icon': '🛡️',
    'layout': 'wide'
}

# ============================================================================
# COLORS (for visualizations)
# ============================================================================

COLORS = {
    'attack': '#e74c3c',      # Red
    'normal': '#2ecc71',      # Green
    'warning': '#f39c12',     # Orange
    'info': '#3498db',        # Blue
    'primary': '#9b59b6'      # Purple
}