"""
Feature name mappings for all 3 datasets
"""
import pickle
import os

class FeatureMappings:
    """Load and store feature names for CICIDS, IoT, and UNSW"""
    
    def __init__(self, base_path='/home/shared/IoT_Project/AI_Anomaly_Detection'):
        self.base_path = base_path
        
        print("📥 Loading feature mappings...")
        
        # Load from each dataset
        self.cicids_features = self._load_cicids()
        self.iot_features = self._load_iot()
        self.unsw_features = self._load_unsw()
        
        print(f"✅ Loaded!")
        print(f"   CICIDS: {len(self.cicids_features)} features")
        print(f"   IoT:    {len(self.iot_features)} features")  
        print(f"   UNSW:   {len(self.unsw_features)} features")
    
    def _load_cicids(self):
        """Load CICIDS features from trained model"""
        path = os.path.join(self.base_path, 'cicds/prepared_data/feature_names.pkl')
        
        if not os.path.exists(path):
            print(f"   ⚠️  CICIDS features not found at: {path}")
            return []
            
        with open(path, 'rb') as f:
            features = pickle.load(f)
        return features
    
    def _load_iot(self):
        """Load IoT feature names"""
        path = os.path.join(self.base_path, 'cic_iot_2023/prepared_data/feature_names.pkl')
        
        if not os.path.exists(path):
            print(f"   ⚠️  IoT features not found at: {path}")
            return []
            
        with open(path, 'rb') as f:
            features = pickle.load(f)
        return features
    
    def _load_unsw(self):
        """Load UNSW feature names"""
        path = os.path.join(self.base_path, 'UNSW_NB15/prepared_data_multiclass/feature_names.pkl')
        
        if not os.path.exists(path):
            print(f"   ⚠️  UNSW features not found at: {path}")
            return []
            
        with open(path, 'rb') as f:
            features = pickle.load(f)
        return features
    
    def get_features(self, dataset):
        """Get features for a specific dataset"""
        if dataset.lower() == 'cicids':
            return self.cicids_features
        elif dataset.lower() == 'iot':
            return self.iot_features
        elif dataset.lower() == 'unsw':
            return self.unsw_features
        else:
            raise ValueError(f"Unknown dataset: {dataset}")
