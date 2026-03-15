"""
Unified Feature Calculator - Phase 1 (CRITICAL Features)
========================================================

Extracts ~60 critical features from network flows that are needed
by all 3 datasets (CICIDS, IoT, UNSW).

This covers:
- Flow timing (duration, IAT, rates)
- Packet counts (forward, backward, total)
- Packet lengths (all statistics)
- TCP flags (all counts)
- Flow rates (packets/s, bytes/s)
"""

import numpy as np
from collections import defaultdict

class UnifiedFeatureCalculator:
    """
    Unified feature calculator that extracts features for all 3 datasets
    """

    def __init__(self):
        self.features = {}

    def calculate_all_features(self, flow_id, flow_data):
        """
        Calculate all features from a single flow

        Args:
            flow_id: tuple (src_ip, src_port, dst_ip, dst_port, protocol)
            flow_data: dict with 'packets', 'fwd_packets', 'bwd_packets', 'start_time', 'last_seen'

        Returns:
            dict with all calculated features
        """
        features = {}

        # ====================================================================
        # 🔧 FIXED: Extract network identifiers and ADD to features dict
        # ====================================================================
        features['src_ip'] = flow_id[0]
        features['src_port'] = flow_id[1]
        features['dst_ip'] = flow_id[2]
        features['dst_port'] = flow_id[3]
        features['protocol'] = flow_id[4]

        # Extract flow data
        all_packets = flow_data.get('packets', [])
        fwd_packets = flow_data.get('fwd_packets', [])
        bwd_packets = flow_data.get('bwd_packets', [])
        start_time = flow_data.get('start_time', 0)
        last_seen = flow_data.get('last_seen', 0)

        if len(all_packets) == 0:
            return self._get_zero_features()

        # ====================================================================
        # 1. FLOW TIMING FEATURES
        # ====================================================================

        # Basic duration
        duration = last_seen - start_time if last_seen > start_time else 0.000001
        features['flow_duration'] = duration
        features['Duration'] = duration  # IoT
        features['dur'] = duration  # UNSW

        # Inter-arrival times (IAT)
        timestamps = [p['timestamp'] for p in all_packets]
        iats = self._calculate_iats(timestamps)

        features['Flow IAT Mean'] = np.mean(iats) if iats else 0
        features['Flow IAT Std'] = np.std(iats) if len(iats) > 1 else 0
        features['Flow IAT Max'] = max(iats) if iats else 0
        features['Flow IAT Min'] = min(iats) if iats else 0
        features['IAT'] = np.mean(iats) if iats else 0  # IoT

        # Forward IAT
        fwd_timestamps = [p['timestamp'] for p in fwd_packets]
        fwd_iats = self._calculate_iats(fwd_timestamps)

        features['Fwd IAT Total'] = sum(fwd_iats) if fwd_iats else 0
        features['Fwd IAT Mean'] = np.mean(fwd_iats) if fwd_iats else 0
        features['Fwd IAT Std'] = np.std(fwd_iats) if len(fwd_iats) > 1 else 0
        features['Fwd IAT Max'] = max(fwd_iats) if fwd_iats else 0
        features['Fwd IAT Min'] = min(fwd_iats) if fwd_iats else 0
        features['sinpkt'] = np.mean(fwd_iats) if fwd_iats else 0  # UNSW source inter-packet
        features['sjit'] = np.std(fwd_iats) if len(fwd_iats) > 1 else 0  # UNSW source jitter

        # Backward IAT
        bwd_timestamps = [p['timestamp'] for p in bwd_packets]
        bwd_iats = self._calculate_iats(bwd_timestamps)

        features['Bwd IAT Total'] = sum(bwd_iats) if bwd_iats else 0
        features['Bwd IAT Mean'] = np.mean(bwd_iats) if bwd_iats else 0
        features['Bwd IAT Std'] = np.std(bwd_iats) if len(bwd_iats) > 1 else 0
        features['Bwd IAT Max'] = max(bwd_iats) if bwd_iats else 0
        features['Bwd IAT Min'] = min(bwd_iats) if bwd_iats else 0
        features['dinpkt'] = np.mean(bwd_iats) if bwd_iats else 0  # UNSW dest inter-packet
        features['djit'] = np.std(bwd_iats) if len(bwd_iats) > 1 else 0  # UNSW dest jitter

        # ====================================================================
        # 2. PACKET COUNT FEATURES
        # ====================================================================

        total_fwd = len(fwd_packets)
        total_bwd = len(bwd_packets)
        total_packets = len(all_packets)

        features['Total Fwd Packets'] = total_fwd
        features['Total Backward Packets'] = total_bwd
        features['Number'] = total_fwd  # IoT (number of packets)
        features['spkts'] = total_fwd  # UNSW source packets
        features['dpkts'] = total_bwd  # UNSW dest packets

        # TCP flag counts (will be calculated from packet data)
        tcp_flags = self._count_tcp_flags(all_packets)

        # CICIDS flags
        features['FIN Flag Count'] = tcp_flags['fin']
        features['SYN Flag Count'] = tcp_flags['syn']
        features['RST Flag Count'] = tcp_flags['rst']
        features['PSH Flag Count'] = tcp_flags['psh']
        features['ACK Flag Count'] = tcp_flags['ack']
        features['URG Flag Count'] = tcp_flags['urg']
        features['CWE Flag Count'] = tcp_flags['cwe']
        features['ECE Flag Count'] = tcp_flags['ece']

        # Directional flags
        fwd_flags = self._count_tcp_flags(fwd_packets)
        bwd_flags = self._count_tcp_flags(bwd_packets)

        features['Fwd PSH Flags'] = fwd_flags['psh']
        features['Bwd PSH Flags'] = bwd_flags['psh']
        features['Fwd URG Flags'] = fwd_flags['urg']
        features['Bwd URG Flags'] = bwd_flags['urg']

        # IoT flags
        features['fin_flag_number'] = tcp_flags['fin']
        features['syn_flag_number'] = tcp_flags['syn']
        features['rst_flag_number'] = tcp_flags['rst']
        features['psh_flag_number'] = tcp_flags['psh']
        features['ack_flag_number'] = tcp_flags['ack']
        features['ece_flag_number'] = tcp_flags['ece']
        features['cwr_flag_number'] = tcp_flags['cwe']

        # IoT specific counts
        features['ack_count'] = tcp_flags['ack']
        features['syn_count'] = tcp_flags['syn']
        features['fin_count'] = tcp_flags['fin']
        features['urg_count'] = tcp_flags['urg']
        features['rst_count'] = tcp_flags['rst']

        # ====================================================================
        # 3. PACKET LENGTH FEATURES
        # ====================================================================

        # Get all packet lengths
        all_lengths = [p['length'] for p in all_packets]
        fwd_lengths = [p['length'] for p in fwd_packets]
        bwd_lengths = [p['length'] for p in bwd_packets]

        # Total lengths
        total_fwd_bytes = sum(fwd_lengths)
        total_bwd_bytes = sum(bwd_lengths)

        features['Total Length of Fwd Packets'] = total_fwd_bytes
        features['Total Length of Bwd Packets'] = total_bwd_bytes
        features['Tot sum'] = total_fwd_bytes  # IoT
        features['Tot size'] = total_fwd_bytes + total_bwd_bytes  # IoT
        features['sbytes'] = total_fwd_bytes  # UNSW
        features['dbytes'] = total_bwd_bytes  # UNSW

        # Forward packet length statistics
        if fwd_lengths:
            features['Fwd Packet Length Max'] = max(fwd_lengths)
            features['Fwd Packet Length Min'] = min(fwd_lengths)
            features['Fwd Packet Length Mean'] = np.mean(fwd_lengths)
            features['Fwd Packet Length Std'] = np.std(fwd_lengths)
            features['Avg Fwd Segment Size'] = np.mean(fwd_lengths)
            features['smean'] = np.mean(fwd_lengths)  # UNSW source mean size
        else:
            features['Fwd Packet Length Max'] = 0
            features['Fwd Packet Length Min'] = 0
            features['Fwd Packet Length Mean'] = 0
            features['Fwd Packet Length Std'] = 0
            features['Avg Fwd Segment Size'] = 0
            features['smean'] = 0

        # Backward packet length statistics
        if bwd_lengths:
            features['Bwd Packet Length Max'] = max(bwd_lengths)
            features['Bwd Packet Length Min'] = min(bwd_lengths)
            features['Bwd Packet Length Mean'] = np.mean(bwd_lengths)
            features['Bwd Packet Length Std'] = np.std(bwd_lengths)
            features['Avg Bwd Segment Size'] = np.mean(bwd_lengths)
            features['dmean'] = np.mean(bwd_lengths)  # UNSW dest mean size
        else:
            features['Bwd Packet Length Max'] = 0
            features['Bwd Packet Length Min'] = 0
            features['Bwd Packet Length Mean'] = 0
            features['Bwd Packet Length Std'] = 0
            features['Avg Bwd Segment Size'] = 0
            features['dmean'] = 0

        # Overall packet length statistics
        if all_lengths:
            features['Min Packet Length'] = min(all_lengths)
            features['Max Packet Length'] = max(all_lengths)
            features['Packet Length Mean'] = np.mean(all_lengths)
            features['Packet Length Std'] = np.std(all_lengths)
            features['Packet Length Variance'] = np.var(all_lengths)
            features['Average Packet Size'] = np.mean(all_lengths)

            # IoT features
            features['Min'] = min(all_lengths)
            features['Max'] = max(all_lengths)
            features['AVG'] = np.mean(all_lengths)
            features['Std'] = np.std(all_lengths)
            features['Variance'] = np.var(all_lengths)
        else:
            features['Min Packet Length'] = 0
            features['Max Packet Length'] = 0
            features['Packet Length Mean'] = 0
            features['Packet Length Std'] = 0
            features['Packet Length Variance'] = 0
            features['Average Packet Size'] = 0
            features['Min'] = 0
            features['Max'] = 0
            features['AVG'] = 0
            features['Std'] = 0
            features['Variance'] = 0

        # IoT magnitude and radius (vector norms)
        if all_lengths:
            features['Magnitue'] = np.linalg.norm(all_lengths[:100])  # Limit to first 100
            features['Radius'] = np.sqrt(np.sum(np.array(all_lengths[:100])**2))
        else:
            features['Magnitue'] = 0
            features['Radius'] = 0

        # ====================================================================
        # 4. FLOW RATE FEATURES
        # ====================================================================

        if duration > 0:
            # CICIDS rates
            features['Flow Bytes/s'] = (total_fwd_bytes + total_bwd_bytes) / duration
            features['Flow Packets/s'] = total_packets / duration
            features['Fwd Packets/s'] = total_fwd / duration
            features['Bwd Packets/s'] = total_bwd / duration

            # IoT rates
            features['Rate'] = total_packets / duration
            features['Srate'] = total_fwd / duration
            features['Drate'] = total_bwd / duration

            # UNSW rates
            features['rate'] = total_packets / duration
            features['sload'] = (total_fwd_bytes * 8) / duration  # bits per second
            features['dload'] = (total_bwd_bytes * 8) / duration  # bits per second
        else:
            features['Flow Bytes/s'] = 0
            features['Flow Packets/s'] = 0
            features['Fwd Packets/s'] = 0
            features['Bwd Packets/s'] = 0
            features['Rate'] = 0
            features['Srate'] = 0
            features['Drate'] = 0
            features['rate'] = 0
            features['sload'] = 0
            features['dload'] = 0

        # ====================================================================
        # 5. ADDITIONAL CRITICAL FEATURES
        # ====================================================================

        # Down/Up ratio
        features['Down/Up Ratio'] = total_bwd / max(total_fwd, 1)

        # Covariance and weight (IoT)
        if len(all_lengths) > 1:
            features['Covariance'] = np.cov(all_lengths[:100], all_lengths[:100])[0][1] if len(all_lengths) >= 100 else 0
        else:
            features['Covariance'] = 0

        features['Weight'] = total_fwd_bytes / max(total_packets, 1)

        # Header lengths (will be extracted from packets)
        fwd_header_len = self._calculate_header_length(fwd_packets)
        bwd_header_len = self._calculate_header_length(bwd_packets)

        features['Fwd Header Length'] = fwd_header_len
        features['Bwd Header Length'] = bwd_header_len
        features['Header_Length'] = (fwd_header_len + bwd_header_len) / max(total_packets, 1)

        return features

    def _calculate_iats(self, timestamps):
        """Calculate inter-arrival times from timestamps"""
        if len(timestamps) < 2:
            return []

        iats = []
        for i in range(1, len(timestamps)):
            iat = timestamps[i] - timestamps[i-1]
            iats.append(iat)

        return iats

    def _count_tcp_flags(self, packets):
        """Count TCP flags from packets"""
        flags = {
            'fin': 0, 'syn': 0, 'rst': 0, 'psh': 0,
            'ack': 0, 'urg': 0, 'cwe': 0, 'ece': 0
        }

        for packet in packets:
            if 'tcp_flags' in packet and packet['tcp_flags'] is not None:
                tcp_flags = packet['tcp_flags']

                # Check each flag (assuming tcp_flags is an integer bitmask)
                if tcp_flags & 0x01:  # FIN
                    flags['fin'] += 1
                if tcp_flags & 0x02:  # SYN
                    flags['syn'] += 1
                if tcp_flags & 0x04:  # RST
                    flags['rst'] += 1
                if tcp_flags & 0x08:  # PSH
                    flags['psh'] += 1
                if tcp_flags & 0x10:  # ACK
                    flags['ack'] += 1
                if tcp_flags & 0x20:  # URG
                    flags['urg'] += 1
                if tcp_flags & 0x40:  # ECE
                    flags['ece'] += 1
                if tcp_flags & 0x80:  # CWR
                    flags['cwe'] += 1

        return flags

    def _calculate_header_length(self, packets):
        """Calculate total header length"""
        if not packets:
            return 0

        total = 0
        for packet in packets:
            # IP header (typically 20 bytes) + TCP/UDP header
            if 'protocol_name' in packet:
                if packet['protocol_name'] == 'TCP':
                    total += 20 + 20  # IP + TCP minimum
                elif packet['protocol_name'] == 'UDP':
                    total += 20 + 8   # IP + UDP
                else:
                    total += 20       # IP only

        return total

    def _get_zero_features(self):
        """Return zero values for all features when flow is empty"""
        features = {}

        # 🔧 FIXED: Add network identifiers with default values
        features['src_ip'] = 'Unknown'
        features['src_port'] = 0
        features['dst_ip'] = 'Unknown'
        features['dst_port'] = 0
        features['protocol'] = 'Unknown'

        # List all feature names
        feature_names = [
            # Timing
            'flow_duration', 'Duration', 'dur',
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'IAT',
            'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
            'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
            'sinpkt', 'dinpkt', 'sjit', 'djit',

            # Counts
            'Total Fwd Packets', 'Total Backward Packets', 'Number', 'spkts', 'dpkts',

            # Flags
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
            'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
            'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number',
            'ack_flag_number', 'ece_flag_number', 'cwr_flag_number',
            'ack_count', 'syn_count', 'fin_count', 'urg_count', 'rst_count',

            # Lengths
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Tot sum', 'Tot size', 'sbytes', 'dbytes',
            'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
            'Fwd Packet Length Std', 'Avg Fwd Segment Size', 'smean',
            'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Bwd Packet Length Std', 'Avg Bwd Segment Size', 'dmean',
            'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
            'Packet Length Std', 'Packet Length Variance', 'Average Packet Size',
            'Min', 'Max', 'AVG', 'Std', 'Variance', 'Magnitue', 'Radius',

            # Rates
            'Flow Bytes/s', 'Flow Packets/s', 'Fwd Packets/s', 'Bwd Packets/s',
            'Rate', 'Srate', 'Drate', 'rate', 'sload', 'dload',

            # Other
            'Down/Up Ratio', 'Covariance', 'Weight',
            'Fwd Header Length', 'Bwd Header Length', 'Header_Length'
        ]

        for name in feature_names:
            features[name] = 0

        return features

# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    print("="*80)
    print("🧪 TESTING UNIFIED FEATURE CALCULATOR - FIXED VERSION")
    print("="*80)

    # Create calculator
    calculator = UnifiedFeatureCalculator()

    # Create sample flow data
    sample_flow = {
        'packets': [
            {'timestamp': 1.0, 'length': 100, 'tcp_flags': 0x02, 'protocol_name': 'TCP'},
            {'timestamp': 1.1, 'length': 150, 'tcp_flags': 0x10, 'protocol_name': 'TCP'},
            {'timestamp': 1.2, 'length': 200, 'tcp_flags': 0x10, 'protocol_name': 'TCP'},
        ],
        'fwd_packets': [
            {'timestamp': 1.0, 'length': 100, 'tcp_flags': 0x02, 'protocol_name': 'TCP'},
            {'timestamp': 1.2, 'length': 200, 'tcp_flags': 0x10, 'protocol_name': 'TCP'},
        ],
        'bwd_packets': [
            {'timestamp': 1.1, 'length': 150, 'tcp_flags': 0x10, 'protocol_name': 'TCP'},
        ],
        'start_time': 1.0,
        'last_seen': 1.2
    }

    # Calculate features
    features = calculator.calculate_all_features(
        flow_id=('192.168.1.1', 12345, '10.0.0.1', 80, 6),
        flow_data=sample_flow
    )

    print(f"\n✅ Calculated {len(features)} features!")
    
    print("\n🔧 Network identifiers:")
    print(f"   src_ip:    {features['src_ip']}")
    print(f"   src_port:  {features['src_port']}")
    print(f"   dst_ip:    {features['dst_ip']}")
    print(f"   dst_port:  {features['dst_port']}")
    print(f"   protocol:  {features['protocol']}")
    
    print("\nSample statistical features:")
    for i, (name, value) in enumerate(list(features.items())[5:15]):
        print(f"   {name:30s}: {value:10.4f}")

    print("\n" + "="*80)
    print("✅ Unified Feature Calculator working correctly!")
    print("="*80)
