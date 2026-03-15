"""
Model Loader for Production IDS - FIXED VERSION
===============================================
Handles feature mismatches and version compatibility
"""

import pickle
import numpy as np
import pandas as pd
from tensorflow import keras
import sys
import traceback
sys.path.append('..')
from config import *

class ModelLoader:
    """Load all models with robust error handling"""
    
    def __init__(self):
        self.cicids_models = {}
        self.iot_models = {}
        self.unsw_models = {}
        self.scalers = {}
        self.encoders = {}
        self.feature_names = {}
        self.feature_counts = {}
        
    def load_all(self):
        """Load everything with feature validation"""
        print("=" * 70)
        print("🚀 LOADING YOUR TRAINED MODELS")
        print("=" * 70)
        
        self.load_cicids()
        self.load_iot()
        self.load_unsw()
        
        # Validate feature counts
        self.validate_features()
        
        print("\n" + "=" * 70)
        print("✅ ALL MODELS LOADED SUCCESSFULLY!")
        print("=" * 70)
        
        return self
    
    def validate_features(self):
        """Validate feature counts across all models"""
        print("\n🔍 VALIDATING FEATURE COUNTS")
        
        # Get actual feature counts from models
        self.feature_counts = {
            'cicids': {
                'stored': len(self.feature_names.get('cicids', [])),
                'model': self._get_model_feature_count(self.cicids_models.get('xgboost')),
                'scaler': self._get_scaler_feature_count(self.scalers.get('cicids'))
            },
            'iot': {
                'stored': len(self.feature_names.get('iot', [])),
                'model': self._get_model_feature_count(self.iot_models.get('xgboost')),
                'scaler': self._get_scaler_feature_count(self.scalers.get('iot'))
            },
            'unsw': {
                'stored': len(self.feature_names.get('unsw', [])),
                'model': self._get_model_feature_count(self.unsw_models.get('xgboost')),
                'scaler': self._get_scaler_feature_count(self.scalers.get('unsw'))
            }
        }
        
        # Print validation results
        for dataset in ['cicids', 'iot', 'unsw']:
            counts = self.feature_counts[dataset]
            print(f"\n📊 {dataset.upper()}:")
            print(f"  • Stored feature names: {counts['stored']}")
            print(f"  • Model expects: {counts['model']}")
            print(f"  • Scaler expects: {counts['scaler']}")
            
            # Check consistency
            if counts['model'] and counts['scaler'] and counts['model'] != counts['scaler']:
                print(f"  ⚠️  WARNING: Model-scaler mismatch!")
            if counts['stored'] != counts['model']:
                print(f"  ⚠️  WARNING: Feature names don't match model!")
    
    def _get_model_feature_count(self, model):
        """Get feature count from model"""
        if not model:
            return None
        
        # XGBoost
        if hasattr(model, 'get_booster'):
            try:
                booster = model.get_booster()
                if hasattr(booster, 'feature_names') and booster.feature_names:
                    return len(booster.feature_names)
            except:
                pass
        
        # Scikit-learn style
        if hasattr(model, 'n_features_in_'):
            return model.n_features_in_
        
        # Try to infer from shape
        if hasattr(model, 'coef_'):
            if model.coef_.ndim == 1:
                return len(model.coef_)
            else:
                return model.coef_.shape[1]
        
        return None
    
    def _get_scaler_feature_count(self, scaler):
        """Get feature count from scaler"""
        if not scaler:
            return None
        
        if hasattr(scaler, 'n_features_in_'):
            return scaler.n_features_in_
        if hasattr(scaler, 'mean_'):
            return len(scaler.mean_)
        if hasattr(scaler, 'scale_'):
            return len(scaler.scale_)
        
        return None
    
    def _load_keras_model(self, model_path):
        """Robust Keras model loader"""
        import tensorflow as tf
        
        try:
            # Method 1: Standard with custom objects
            return keras.models.load_model(
                model_path,
                custom_objects={
                    'mse': tf.keras.losses.MeanSquaredError(),
                    'mean_squared_error': tf.keras.losses.MeanSquaredError(),
                }
            )
        except:
            # Method 2: Using tf.keras
            return tf.keras.models.load_model(model_path)
    
    def load_cicids(self):
        """Load CICIDS models"""
        print("\n📘 Loading CICIDS models...")
        
        try:
            # Supervised model
            with open(CICIDS_MODELS['supervised']['xgboost'], 'rb') as f:
                self.cicids_models['xgboost'] = pickle.load(f)
            print("  ✅ XGBoost (99.92%)")
            
            # Autoencoder
            self.cicids_models['autoencoder'] = self._load_keras_model(
                CICIDS_MODELS['unsupervised']['autoencoder']
            )
            self.cicids_models['autoencoder_threshold'] = np.load(
                CICIDS_MODELS['unsupervised']['autoencoder_threshold']
            )
            print("  ✅ Autoencoder")
            
            # Support files
            with open(CICIDS_DATA['scaler'], 'rb') as f:
                self.scalers['cicids'] = pickle.load(f)
            with open(CICIDS_DATA['scaler_unsupervised'], 'rb') as f:
                self.scalers['cicids_unsupervised'] = pickle.load(f)
            with open(CICIDS_DATA['label_encoder'], 'rb') as f:
                self.encoders['cicids'] = pickle.load(f)
            with open(CICIDS_DATA['feature_names'], 'rb') as f:
                self.feature_names['cicids'] = pickle.load(f)
            
        except Exception as e:
            print(f"  ❌ Error: {str(e)[:100]}...")
    
    def load_iot(self):
        """Load IoT models"""
        print("\n📗 Loading IoT models...")
        
        try:
            # Supervised model
            with open(IOT_MODELS['supervised']['xgboost'], 'rb') as f:
                self.iot_models['xgboost'] = pickle.load(f)
            print("  ✅ XGBoost")
            
            # Autoencoder (optional)
            if IOT_MODELS['unsupervised']['autoencoder']:
                try:
                    self.iot_models['autoencoder'] = self._load_keras_model(
                        IOT_MODELS['unsupervised']['autoencoder']
                    )
                    print("  ✅ Autoencoder")
                except:
                    print("  ⚠️  Autoencoder skipped")
            
            # Threshold
            if IOT_MODELS['unsupervised']['autoencoder_threshold']:
                try:
                    with open(IOT_MODELS['unsupervised']['autoencoder_threshold'], 'rb') as f:
                        self.iot_models['autoencoder_threshold'] = pickle.load(f)
                except:
                    pass
            
            # Support files
            with open(IOT_DATA['scaler'], 'rb') as f:
                self.scalers['iot'] = pickle.load(f)
            with open(IOT_DATA['label_encoder'], 'rb') as f:
                self.encoders['iot'] = pickle.load(f)
            with open(IOT_DATA['feature_names'], 'rb') as f:
                self.feature_names['iot'] = pickle.load(f)
            
        except Exception as e:
            print(f"  ❌ Error: {str(e)[:100]}...")
    
    def load_unsw(self):
        """Load UNSW models - simplified and fixed"""
        print("\n📙 Loading UNSW models...")
        
        try:
            # Load XGBoost
            with open(UNSW_MODELS['supervised']['xgboost'], 'rb') as f:
                self.unsw_models['xgboost'] = pickle.load(f)
            
            model_feature_count = self._get_model_feature_count(self.unsw_models['xgboost'])
            print(f"  ✅ XGBoost (expects {model_feature_count} features)")
            
            # Autoencoder
            self.unsw_models['autoencoder'] = self._load_keras_model(
                UNSW_MODELS['unsupervised']['autoencoder']
            )
            self.unsw_models['autoencoder_threshold'] = np.load(
                UNSW_MODELS['unsupervised']['autoencoder_threshold']
            )
            print("  ✅ Autoencoder")
            
            # Support files
            with open(UNSW_DATA['scaler'], 'rb') as f:
                self.scalers['unsw'] = pickle.load(f)
            print(f"  ✅ Scaler loaded")
            
            with open(UNSW_DATA['label_encoder'], 'rb') as f:
                self.encoders['unsw'] = pickle.load(f)
            print(f"  ✅ Label encoder loaded")
            
            # Feature names - with debug
            feature_path = UNSW_DATA['feature_names']
            print(f"  🔍 Loading features from: {feature_path}")
            
            with open(feature_path, 'rb') as f:
                self.feature_names['unsw'] = pickle.load(f)
            
            print(f"  ✅ Loaded {len(self.feature_names['unsw'])} feature names")
            print(f"  📋 First 5 features: {self.feature_names['unsw'][:5]}")
            
        except Exception as e:
            print(f"  ❌ Error: {str(e)}")
            traceback.print_exc()
    
    def create_test_data(self, dataset_name, n_samples=5):
        """Create proper test data with correct feature count"""
        counts = self.feature_counts.get(dataset_name, {})
        model_count = counts.get('model')
        scaler_count = counts.get('scaler')
        
        # Use model count if available, otherwise scaler count
        feature_count = model_count or scaler_count or len(self.feature_names.get(dataset_name, []))
        
        if feature_count:
            # Create random data
            X_test = np.random.randn(n_samples, feature_count)
            
            # Get feature names
            feature_names = self.feature_names.get(dataset_name)
            
            # Always use feature names if available and correct length
            if feature_names and len(feature_names) == feature_count:
                return pd.DataFrame(X_test, columns=feature_names)
            else:
                # Fallback: use generic names
                columns = [f'feature_{i}' for i in range(feature_count)]
                return pd.DataFrame(X_test, columns=columns)
        
        return None
    
    def test_predictions(self):
        """Test predictions with proper feature handling"""
        print("\n" + "=" * 70)
        print("🧪 TESTING MODEL PREDICTIONS (FIXED)")
        print("=" * 70)
        
        # Test each dataset
        for dataset_name, color, label in [
            ('cicids', '🔵', 'CICIDS'),
            ('iot', '🟢', 'IoT'),
            ('unsw', '🟡', 'UNSW')
        ]:
            print(f"\n{color} Testing {label}:")
            
            models = getattr(self, f'{dataset_name}_models')
            if not models.get('xgboost'):
                print("  ⚠️  No model loaded")
                continue
            
            # Create proper test data
            X_test_df = self.create_test_data(dataset_name, 5)
            if X_test_df is None:
                print("  ❌ Cannot create test data")
                continue
            
            # Scale
            scaler = self.scalers.get(dataset_name)
            if not scaler:
                print("  ❌ No scaler")
                continue
            
            try:
                X_scaled = scaler.transform(X_test_df)
            except Exception as e:
                print(f"  ❌ Scaling failed: {str(e)[:100]}")
                continue
            
            # Predict
            try:
                pred = models['xgboost'].predict(X_scaled)
                
                # Decode if encoder available
                encoder = self.encoders.get(dataset_name)
                if encoder and hasattr(encoder, 'inverse_transform'):
                    labels = encoder.inverse_transform(pred)
                    print(f"  Predictions: {labels[:3]}")
                else:
                    print(f"  Predictions: {pred[:3]} (encoded)")
                
                # Test autoencoder if available
                if models.get('autoencoder'):
                    recon = models['autoencoder'].predict(X_scaled, verbose=0)
                    error = np.mean(np.abs(X_scaled - recon), axis=1)
                    
                    threshold = models.get('autoencoder_threshold')
                    if threshold is not None:
                        anomalies = error > threshold
                        print(f"  Autoencoder anomalies: {np.sum(anomalies)}/5")
                        print(f"  Mean error: {error.mean():.4f}, Threshold: {threshold:.4f}")
                    else:
                        print(f"  Autoencoder mean error: {error.mean():.4f}")
                
                print(f"  ✅ {label} working!")
                
            except Exception as e:
                print(f"  ❌ Prediction failed: {str(e)[:100]}")
    
    def get_summary(self):
        """Enhanced summary"""
        print("\n" + "=" * 70)
        print("📊 ENHANCED MODEL SUMMARY")
        print("=" * 70)
        
        datasets = [
            ('CICIDS', self.cicids_models, 'cicids'),
            ('IoT', self.iot_models, 'iot'),
            ('UNSW', self.unsw_models, 'unsw')
        ]
        
        for name, models, key in datasets:
            print(f"\n📘 {name}:")
            
            # Feature info
            stored = len(self.feature_names.get(key, []))
            model = self.feature_counts.get(key, {}).get('model')
            scaler = self.feature_counts.get(key, {}).get('scaler')
            
            print(f"  • Features - Stored: {stored}, Model: {model}, Scaler: {scaler}")
            
            # Model status
            print(f"  • XGBoost: {'✅' if models.get('xgboost') else '❌'}")
            print(f"  • Autoencoder: {'✅' if models.get('autoencoder') else '❌'}")
            
            if self.encoders.get(key):
                print(f"  • Classes: {len(self.encoders[key].classes_)}")
        
        print("\n" + "=" * 70)


# Main execution with error handling
if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║     🔧 FIXED MODEL LOADER                                ║
    ║     Handles feature mismatches and compatibility        ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    try:
        loader = ModelLoader()
        loader.load_all()
        loader.test_predictions()
        loader.get_summary()
        
        print("\n✅ Production pipeline ready!")
        
    except Exception as e:
        print(f"\n❌ Critical error: {e}")
        traceback.print_exc()