"""
Feature Selector - Extracts dataset-specific features with IP conversion
"""
import numpy as np
import pandas as pd
import socket
import struct

# ============================================================================
# REMAP: CSV column name  →  model expected name  (only where they differ)
# ============================================================================
CICIDS_REMAP = {
    'dsport':        'Destination Port',
    'flow_duration': 'Flow Duration',
}

UNSW_REMAP = {
    'sload':             'Sload',
    'dload':             'Dload',
    'spkts':             'Spkts',
    'dpkts':             'Dpkts',
    'smean':             'smeansz',
    'dmean':             'dmeansz',
    'sjit':              'Sjit',
    'djit':              'Djit',
    'sinpkt':            'Sintpkt',
    'dinpkt':            'Dintpkt',
    'response_body_len': 'res_bdy_len',
    'ct_src_ltm':        'ct_src_ ltm',   # space typo in the pkl — must match exactly
}

# ============================================================================
# UNSW STRING ENCODING — integer = alphabetical index, exactly as in the pkl
# state and service are object dtype in CSV, must become int before model.
# proto is already int64 (6/17/1) — leave it alone.
# srcip/dstip are IP strings — convert with ip_to_int, not LabelEncoder.
# ct_ftp_cmd is already int64 (0) — leave it alone.
# ============================================================================
_STATE_CLASSES   = ['ACC','CON','ECO','ECR','FIN','INT','MAS','PAR','REQ','RST','TST','TXD','URN','no']
STATE_MAP        = {s: i for i, s in enumerate(_STATE_CLASSES)}

_SERVICE_CLASSES = ['-','dhcp','dns','ftp','ftp-data','http','irc','pop3','radius','smtp','snmp','ssh','ssl']
SERVICE_MAP      = {s: i for i, s in enumerate(_SERVICE_CLASSES)}


class FeatureSelector:
    """
    Selects appropriate features for each dataset's models

    Takes a dictionary/DataFrame with all available features
    Returns arrays with only the features each model needs

    Automatically converts IP addresses from strings to integers
    """

    def __init__(self, feature_mappings):
        """
        Args:
            feature_mappings: FeatureMappings instance with all feature names
        """
        self.mappings = feature_mappings

        print("✅ FeatureSelector initialized")
        print(f"   Ready to extract features for 3 datasets")
        print(f"   🔄 IP conversion enabled")

    @staticmethod
    def ip_to_int(ip_value):
        """
        Convert IP address to integer

        Args:
            ip_value: IP address (string, int, or None)

        Returns:
            int: Numeric IP value
        """
        try:
            if isinstance(ip_value, (int, float)):
                return int(ip_value)
            if pd.isna(ip_value) or ip_value == '' or str(ip_value) == 'nan':
                return 0
            ip_str = str(ip_value).strip()
            return struct.unpack("!I", socket.inet_aton(ip_str))[0]
        except:
            return 0

    def _convert_value(self, feature_name, value):
        """
        Convert feature value to numeric, handling IPs specially

        Args:
            feature_name: Name of the feature
            value: Feature value (any type)

        Returns:
            float: Numeric value ready for model
        """
        if 'ip' in feature_name.lower() and 'tip' not in feature_name.lower():
            return float(self.ip_to_int(value))
        try:
            if pd.isna(value):
                return 0.0
            return float(value)
        except:
            return 0.0

    # ========================================================================
    # SINGLE-ROW methods — these already worked (use .get() with default 0)
    # Kept exactly as they were.
    # ========================================================================

    def extract_for_cicids(self, features_dict):
        """
        Extract 52 CICIDS features from feature dictionary

        Args:
            features_dict: dict with feature_name: value

        Returns:
            numpy array (1, 52) with CICIDS features in correct order
        """
        cicids_array = []
        for feature_name in self.mappings.cicids_features:
            value = features_dict.get(feature_name, 0)
            numeric_value = self._convert_value(feature_name, value)
            cicids_array.append(numeric_value)
        return np.array(cicids_array, dtype=np.float32).reshape(1, -1)

    def extract_for_iot(self, features_dict):
        """
        Extract 39 IoT features from feature dictionary

        Args:
            features_dict: dict with feature_name: value

        Returns:
            numpy array (1, 39) with IoT features in correct order
        """
        iot_array = []
        for feature_name in self.mappings.iot_features:
            value = features_dict.get(feature_name, 0)
            numeric_value = self._convert_value(feature_name, value)
            iot_array.append(numeric_value)
        return np.array(iot_array, dtype=np.float32).reshape(1, -1)

    def extract_for_unsw(self, features_dict):
        """
        Extract 48 UNSW features from feature dictionary

        Args:
            features_dict: dict with feature_name: value

        Returns:
            numpy array (1, 48) with UNSW features in correct order
        """
        unsw_array = []
        for feature_name in self.mappings.unsw_features:
            value = features_dict.get(feature_name, 0)
            numeric_value = self._convert_value(feature_name, value)
            unsw_array.append(numeric_value)
        return np.array(unsw_array, dtype=np.float32).reshape(1, -1)

    def extract_all(self, features_dict):
        """
        Extract features for all 3 datasets at once

        Args:
            features_dict: dict with all available features

        Returns:
            dict with keys 'cicids', 'iot', 'unsw' containing arrays
        """
        return {
            'cicids': self.extract_for_cicids(features_dict),
            'iot':    self.extract_for_iot(features_dict),
            'unsw':   self.extract_for_unsw(features_dict)
        }

    # ========================================================================
    # BATCH methods — these are the ones that were broken.
    # Old code:  features_df[self.mappings.X_features]  → KeyError
    # New code:  rename mismatches → pick columns → fill missing with 0 → encode
    # ========================================================================

    def extract_batch_for_cicids(self, features_df):
        """
        Extract CICIDS features from entire DataFrame (batch mode)

        Args:
            features_df: pandas DataFrame with all features

        Returns:
            numpy array (N, 52) with CICIDS features
        """
        df = features_df.rename(columns=CICIDS_REMAP)

        # Build output with exactly the 52 columns the model wants, in order.
        # If a column doesn't exist after remapping, it becomes 0.
        out = pd.DataFrame(index=df.index)
        for col in self.mappings.cicids_features:
            out[col] = df[col] if col in df.columns else 0

        out = out.apply(pd.to_numeric, errors='coerce').fillna(0)

        print(f"   CICIDS batch ready: {out.shape}")
        return out.values.astype(np.float32)

    def extract_batch_for_iot(self, features_df):
        """
        Extract IoT features from entire DataFrame (batch mode)

        Args:
            features_df: pandas DataFrame with all features

        Returns:
            numpy array (N, 39) with IoT features
        """
        df = features_df.copy()

        # Time_To_Live is missing from CSV — approximate it from sttl + dttl average
        if 'Time_To_Live' not in df.columns:
            if 'sttl' in df.columns and 'dttl' in df.columns:
                df['Time_To_Live'] = ((df['sttl'].apply(pd.to_numeric, errors='coerce').fillna(0) +
                                       df['dttl'].apply(pd.to_numeric, errors='coerce').fillna(0)) / 2)
            else:
                df['Time_To_Live'] = 0

        # Build output with exactly the 39 columns the model wants, in order.
        out = pd.DataFrame(index=df.index)
        for col in self.mappings.iot_features:
            out[col] = df[col] if col in df.columns else 0

        out = out.apply(pd.to_numeric, errors='coerce').fillna(0)

        print(f"   IoT batch ready: {out.shape}")
        return out.values.astype(np.float32)

    def extract_batch_for_unsw(self, features_df):
        """
        Extract UNSW features from entire DataFrame (batch mode)

        Args:
            features_df: pandas DataFrame with all features

        Returns:
            numpy array (N, 48) with UNSW features
        """
        df = features_df.rename(columns=UNSW_REMAP)

        # --- Encode string columns BEFORE selecting, so they're numeric ---

        # state: object → int using training-time class order
        if 'state' in df.columns and df['state'].dtype == object:
            df['state'] = df['state'].map(STATE_MAP).fillna(0).astype(int)

        # service: object → int using training-time class order
        if 'service' in df.columns and df['service'].dtype == object:
            df['service'] = df['service'].map(SERVICE_MAP).fillna(0).astype(int)

        # srcip / dstip: IP strings → integers
        _SRCIP_CLASSES = ['10.40.170.2','10.40.182.1','10.40.182.3','10.40.182.6',
                          '10.40.85.1','10.40.85.10','10.40.85.30',
                          '149.171.126.0','149.171.126.1','149.171.126.10',
                          '149.171.126.11','149.171.126.12','149.171.126.13',
                          '149.171.126.14','149.171.126.15','149.171.126.16',
                          '149.171.126.17','149.171.126.18','149.171.126.19',
                          '149.171.126.2','149.171.126.3','149.171.126.4',
                          '149.171.126.5','149.171.126.6','149.171.126.7',
                          '149.171.126.8','149.171.126.9',
                          '175.45.176.0','175.45.176.1','175.45.176.2','175.45.176.3',
                          '59.166.0.0','59.166.0.1','59.166.0.2','59.166.0.3',
                          '59.166.0.4','59.166.0.5','59.166.0.6','59.166.0.7',
                          '59.166.0.8','59.166.0.9']
        _DSTIP_CLASSES = ['10.40.170.2','10.40.182.255','10.40.182.3','10.40.182.6',
                          '10.40.198.10','10.40.85.1','10.40.85.30',
                          '149.171.126.0','149.171.126.1','149.171.126.10',
                          '149.171.126.11','149.171.126.12','149.171.126.13',
                          '149.171.126.14','149.171.126.15','149.171.126.16',
                          '149.171.126.17','149.171.126.18','149.171.126.19',
                          '149.171.126.2','149.171.126.3','149.171.126.4',
                          '149.171.126.5','149.171.126.6','149.171.126.7',
                          '149.171.126.8','149.171.126.9',
                          '175.45.176.0','175.45.176.1','175.45.176.2','175.45.176.3',
                          '192.168.241.50','224.0.0.1','224.0.0.5','32.50.32.66',
                          '59.166.0.0','59.166.0.1','59.166.0.2','59.166.0.3',
                          '59.166.0.4','59.166.0.5','59.166.0.6','59.166.0.7',
                          '59.166.0.8','59.166.0.9']
        SRCIP_MAP = {ip: i for i, ip in enumerate(_SRCIP_CLASSES)}
        DSTIP_MAP = {ip: i for i, ip in enumerate(_DSTIP_CLASSES)}

        if 'srcip' in df.columns and df['srcip'].dtype == object:
            df['srcip'] = df['srcip'].map(SRCIP_MAP).fillna(0).astype(int)
        if 'dstip' in df.columns and df['dstip'].dtype == object:
            df['dstip'] = df['dstip'].map(DSTIP_MAP).fillna(0).astype(int)

        # proto is already int64 (6/17/1) — nothing to do.
        # ct_ftp_cmd is already int64 (0) — nothing to do.

        # Build output with exactly the 48 columns the model wants, in order.
        out = pd.DataFrame(index=df.index)
        for col in self.mappings.unsw_features:
            if col in ['Stime', 'Ltime']:
                out[col] = 0  # Zero out absolute timestamps
            else:
                out[col] = df[col] if col in df.columns else 0

        out = out.apply(pd.to_numeric, errors='coerce').fillna(0)

        print(f"   UNSW batch ready: {out.shape}")
        return out.values.astype(np.float32)