"""
Configuration for Boss's Production IDS System
==============================================

All paths configured for your exact folder structure at:
/home/shared/IoT_Project/AI_Anomaly_Detection/
"""

import os

# Base directory
BASE_DIR = "/home/shared/IoT_Project/AI_Anomaly_Detection"

# ============================================================================
# CICIDS PATHS
# ============================================================================

CICIDS_BASE = os.path.join(BASE_DIR, "cicds")

CICIDS_MODELS = {
    'supervised': {
        'xgboost': os.path.join(CICIDS_BASE, 'trained_models/xgboost_multiclass.pkl'),
        'random_forest': os.path.join(CICIDS_BASE, 'trained_models/random_forest_multiclass.pkl'),
        'lightgbm': os.path.join(CICIDS_BASE, 'trained_models/lightgbm_multiclass.pkl'),
        'neural_network': os.path.join(CICIDS_BASE, 'trained_models/neural_network_multiclass.h5'),
    },
    'unsupervised': {
        'autoencoder': os.path.join(CICIDS_BASE, 'trained_models/autoencoder_PURE.keras'),
        'autoencoder_threshold': os.path.join(CICIDS_BASE, 'trained_models/autoencoder_PURE_threshold.npy'),
        'isolation_forest': os.path.join(CICIDS_BASE, 'trained_models/isolation_forest_PURE.pkl'),
    },
    'ensemble': {
        'weighted': os.path.join(CICIDS_BASE, 'trained_models/ensemble_weighted_voting.pkl'),
        'majority': os.path.join(CICIDS_BASE, 'trained_models/ensemble_majority_voting.pkl'),
        'confidence': os.path.join(CICIDS_BASE, 'trained_models/ensemble_confidence_based.pkl'),
    }
}

CICIDS_DATA = {
    'scaler': os.path.join(CICIDS_BASE, 'prepared_data/scaler_multiclass.pkl'),
    'scaler_unsupervised': os.path.join(CICIDS_BASE, 'prepared_data/scaler_unsupervised_pure.pkl'),
    'label_encoder': os.path.join(CICIDS_BASE, 'prepared_data/label_encoder.pkl'),
    'feature_names': os.path.join(CICIDS_BASE, 'prepared_data/feature_names.pkl'),
}

# ============================================================================
# IoT PATHS
# ============================================================================

IOT_BASE = os.path.join(BASE_DIR, "cic_iot_2023")

IOT_MODELS = {
    'supervised': {
        'random_forest': os.path.join(IOT_BASE, 'trained_models/rf_merged_validated.pkl'),
        'xgboost': os.path.join(IOT_BASE, 'trained_models/xgboost_merged.pkl'),
        'lightgbm': os.path.join(IOT_BASE, 'trained_models/lightgbm_merged.pkl'),
        'neural_network': os.path.join(IOT_BASE, 'trained_models/neural_network_merged.h5'),
    },
    'unsupervised': {
        'autoencoder': os.path.join(IOT_BASE, 'trained_models/autoencoder.h5'),
        'autoencoder_threshold': os.path.join(IOT_BASE, 'trained_models/autoencoder_threshold.pkl'),
        'isolation_forest': os.path.join(IOT_BASE, 'trained_models/isolation_forest.pkl'),
    }
}

IOT_DATA = {
    'scaler': os.path.join(IOT_BASE, 'prepared_data/scaler.pkl'),
    'label_encoder': os.path.join(IOT_BASE, 'prepared_data/label_encoder_merged.pkl'),
    'feature_names': os.path.join(IOT_BASE, 'prepared_data/feature_names.pkl'),
}

# ============================================================================
# UNSW PATHS
# ============================================================================

UNSW_BASE = os.path.join(BASE_DIR, "UNSW_NB15")

UNSW_MODELS = {
    'supervised': {
        'xgboost': os.path.join(UNSW_BASE, 'trained_models/supervised_models/xgboost_model.pkl'),
        'random_forest': os.path.join(UNSW_BASE, 'trained_models/supervised_models/random_forest_model.pkl'),
        'lightgbm': os.path.join(UNSW_BASE, 'trained_models/supervised_models/lightgbm_model.pkl'),
    },
    'unsupervised': {
        'autoencoder': os.path.join(UNSW_BASE, 'trained_models/unsupervised_models_CLEAN/autoencoder_CLEAN.keras'),
        'autoencoder_threshold': os.path.join(UNSW_BASE, 'trained_models/unsupervised_models_CLEAN/autoencoder_threshold_CLEAN.npy'),
        'isolation_forest': os.path.join(UNSW_BASE, 'trained_models/unsupervised_models_CLEAN/isolation_forest_CLEAN.pkl'),
    }
}

UNSW_DATA = {
    'scaler': os.path.join(UNSW_BASE, 'prepared_data_multiclass/scaler.pkl'),
    'label_encoder': os.path.join(UNSW_BASE, 'prepared_data_multiclass/target_encoder.pkl'),  # ← ADD THIS
    'feature_names': os.path.join(UNSW_BASE, 'prepared_data_multiclass/feature_names.pkl'),
    'categorical_encoders': os.path.join(UNSW_BASE, 'prepared_data_multiclass/categorical_encoders.pkl'),
}

# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

FEATURE_EXTRACTION = {
    'base': os.path.join(BASE_DIR, 'feature_extraction'),
    'mappings': os.path.join(BASE_DIR, 'feature_extraction/feature_mappings.py'),
    'selector': os.path.join(BASE_DIR, 'feature_extraction/feature_selector.py'),
    'pcap_parser': os.path.join(BASE_DIR, 'feature_extraction/pcap_parser.py'),
}

# ============================================================================
# PRODUCTION SETTINGS
# ============================================================================

PRODUCTION = {
    'output_dir': os.path.join(BASE_DIR, 'production_results'),
    'review_dir': os.path.join(BASE_DIR, 'human_review'),
    'logs_dir': os.path.join(BASE_DIR, 'logs'),
    'confidence_threshold': 0.70,  # Below this → human review
    'batch_size': 1000,
}

# ============================================================================
# LAYER CONFIGURATION
# ============================================================================

LAYER_CONFIG = {
    'layer0': {
        'models': ['cicids_autoencoder', 'unsw_autoencoder'],
        'decision': 'OR',  # Flag if EITHER detects anomaly
        'note': 'Using 2 autoencoders for dataset diversity'
    },
    'layer1': {
        'models': [
            {'name': 'cicids_xgboost', 'dataset': 'CICIDS', 'accuracy': 0.9992},
            {'name': 'cic_2023_xgboost', 'dataset': 'IoT', 'accuracy': 0.9650},
            {'name': 'unsw_xgboost', 'dataset': 'UNSW', 'accuracy': 0.9720}
        ],
        'voting': 'weighted',
        'trust_scoring': 'domain_aware'
    },
    'layer2': {
        'confidence_threshold': 0.70,
        'triggers': ['low_confidence', 'model_disagreement', 'layer_contradiction']
    }
}

# ============================================================================
# DOMAIN-AWARE TRUST SCORING
# ============================================================================

TRUST_RULES = {
    'iot_ports': {
        'ports': [8883, 1883, 5683, 8080],  # MQTT, CoAP
        'trust': {'iot': 0.6, 'cicids': 0.2, 'unsw': 0.2}
    },
    'web_ports': {
        'ports': [80, 443, 8080, 8443],  # HTTP/HTTPS
        'trust': {'cicids': 0.6, 'iot': 0.2, 'unsw': 0.2}
    },
    'enterprise_ports': {
        'ports': [22, 3389, 445, 135, 1433, 3306],  # SSH, RDP, SMB, SQL
        'trust': {'unsw': 0.6, 'cicids': 0.2, 'iot': 0.2}
    },
    'default': {
        'trust': {'cicids': 0.4, 'iot': 0.3, 'unsw': 0.3}
    }
}

# ============================================================================
# CRITICAL ATTACKS (for alerting)
# ============================================================================

CRITICAL_ATTACKS = ['DoS', 'DDoS', 'Botnet', 'Exploits', 'Backdoor']
HIGH_PRIORITY_PORTS = [22, 3389, 445, 135, 1433, 3306]

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def verify_paths():
    """Verify all critical paths exist"""
    missing = []
    
    # Check model files
    for model_path in [
        CICIDS_MODELS['supervised']['xgboost'],
        IOT_MODELS['supervised']['xgboost'],
        UNSW_MODELS['supervised']['xgboost'],
        CICIDS_MODELS['unsupervised']['autoencoder'],
        UNSW_MODELS['unsupervised']['autoencoder'],
    ]:
        if not os.path.exists(model_path):
            missing.append(model_path)
    
    # Check data files
    for data_path in [
        CICIDS_DATA['scaler'],
        IOT_DATA['scaler'],
        UNSW_DATA['scaler'],
    ]:
        if not os.path.exists(data_path):
            missing.append(data_path)
    
    return missing

def create_output_dirs():
    """Create output directories if they don't exist"""
    for dir_path in [
        PRODUCTION['output_dir'],
        PRODUCTION['review_dir'],
        PRODUCTION['logs_dir'],
    ]:
        os.makedirs(dir_path, exist_ok=True)

if __name__ == "__main__":
    print("=" * 70)
    print("CONFIGURATION VERIFICATION")
    print("=" * 70)
    
    missing = verify_paths()
    
    if missing:
        print(f"\n❌ Missing {len(missing)} files:")
        for path in missing[:10]:  # Show first 10
            print(f"   {path}")
    else:
        print("\n✅ All critical paths verified!")
    
    print("\n📁 Creating output directories...")
    create_output_dirs()
    print("✅ Done!")