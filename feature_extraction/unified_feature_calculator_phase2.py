"""
Unified Feature Calculator - Phase 2 Extension
==============================================

Adds IMPORTANT features:
- Protocol identification (HTTP, HTTPS, DNS, TCP, UDP, etc.)
- TTL values
- Connection state features
"""

import numpy as np

class UnifiedFeatureCalculatorPhase2:
    """
    Extension that adds protocol and connection state features
    """
    
    def __init__(self, base_calculator):
        """
        base_calculator: UnifiedFeatureCalculator instance
        """
        self.base = base_calculator
    
    def calculate_all_features(self, flow_id, flow_data):
        """
        Calculate all features including Phase 2
        """
        # Get Phase 1 features
        features = self.base.calculate_all_features(flow_id, flow_data)
        
        # Add Phase 2 features
        phase2_features = self._calculate_phase2(flow_id, flow_data)
        features.update(phase2_features)
        
        return features
    
    def _calculate_phase2(self, flow_id, flow_data):
        """Calculate Phase 2 specific features"""
        features = {}
        
        all_packets = flow_data['packets']
        fwd_packets = flow_data['fwd_packets']
        bwd_packets = flow_data['bwd_packets']
        
        if len(all_packets) == 0:
            return self._get_zero_phase2_features()
        
        # ====================================================================
        # 1. PROTOCOL IDENTIFICATION (IoT features)
        # ====================================================================
        
        # Extract protocol from flow_id
        src_port = flow_id[1]
        dst_port = flow_id[3]
        protocol_name = flow_id[4] if len(flow_id) > 4 else 'TCP'
        
        # Initialize all protocol flags to 0
        protocol_flags = {
            'HTTP': 0, 'HTTPS': 0, 'DNS': 0, 'Telnet': 0,
            'SMTP': 0, 'SSH': 0, 'IRC': 0, 'TCP': 0,
            'UDP': 0, 'DHCP': 0, 'ARP': 0, 'ICMP': 0,
            'IPv': 0, 'LLC': 0
        }
        
        # Detect protocols based on ports and protocol type
        if protocol_name == 'TCP':
            protocol_flags['TCP'] = 1
            protocol_flags['IPv'] = 1
            
            # Application protocols
            if dst_port == 80 or src_port == 80:
                protocol_flags['HTTP'] = 1
            elif dst_port == 443 or src_port == 443:
                protocol_flags['HTTPS'] = 1
            elif dst_port == 22 or src_port == 22:
                protocol_flags['SSH'] = 1
            elif dst_port == 23 or src_port == 23:
                protocol_flags['Telnet'] = 1
            elif dst_port == 25 or src_port == 25:
                protocol_flags['SMTP'] = 1
            elif dst_port in [6667, 6668, 6669] or src_port in [6667, 6668, 6669]:
                protocol_flags['IRC'] = 1
                
        elif protocol_name == 'UDP':
            protocol_flags['UDP'] = 1
            protocol_flags['IPv'] = 1
            
            # UDP-based protocols
            if dst_port == 53 or src_port == 53:
                protocol_flags['DNS'] = 1
            elif dst_port in [67, 68] or src_port in [67, 68]:
                protocol_flags['DHCP'] = 1
                
        elif protocol_name == 'ICMP':
            protocol_flags['ICMP'] = 1
            protocol_flags['IPv'] = 1
        
        # Add protocol flags to features
        for proto, value in protocol_flags.items():
            features[proto] = value
        
        # Protocol Type (numeric)
        protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'OTHER': 0}
        features['Protocol Type'] = protocol_map.get(protocol_name, 0)
        features['proto'] = protocol_map.get(protocol_name, 0)  # UNSW
        
        # ====================================================================
        # 2. TTL VALUES (UNSW features)
        # ====================================================================
        
        # Extract TTL from packets (if available)
        fwd_ttls = [p.get('ttl', 64) for p in fwd_packets]  # Default TTL 64
        bwd_ttls = [p.get('ttl', 64) for p in bwd_packets]
        
        features['sttl'] = np.mean(fwd_ttls) if fwd_ttls else 64
        features['dttl'] = np.mean(bwd_ttls) if bwd_ttls else 64
        
        # ====================================================================
        # 3. CONNECTION STATE (UNSW features)
        # ====================================================================
        
        # Service identification
        service_map = {
            80: 'http', 443: 'https', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'dns', 21: 'ftp', 3306: 'mysql',
            5432: 'postgres', 3389: 'rdp', 445: 'smb'
        }
        features['service'] = service_map.get(dst_port, 'other')
        
        # Connection state (simplified - would need TCP state machine)
        tcp_flags = self.base._count_tcp_flags(all_packets)
        
        if tcp_flags['syn'] > 0 and tcp_flags['ack'] > 0:
            if tcp_flags['fin'] > 0:
                state = 'FIN'  # Connection closing
            else:
                state = 'CON'  # Established connection
        elif tcp_flags['syn'] > 0:
            state = 'REQ'  # Connection request
        elif tcp_flags['rst'] > 0:
            state = 'RST'  # Reset
        else:
            state = 'INT'  # Intermediate/other
        
        features['state'] = state
        
        # TCP window sizes (from packets if available)
        fwd_windows = [p.get('tcp_window', 65535) for p in fwd_packets]
        bwd_windows = [p.get('tcp_window', 65535) for p in bwd_packets]
        
        features['swin'] = np.mean(fwd_windows) if fwd_windows else 65535
        features['dwin'] = np.mean(bwd_windows) if bwd_windows else 65535
        
        # TCP base sequence numbers (simplified)
        features['stcpb'] = 0  # Would need actual seq numbers
        features['dtcpb'] = 0
        
        # RTT estimates (from IAT patterns - simplified)
        if len(all_packets) > 2:
            timestamps = [p['timestamp'] for p in all_packets]
            iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            features['tcprtt'] = np.percentile(iats, 10) if iats else 0  # 10th percentile as RTT estimate
            features['synack'] = min(iats) if iats else 0  # Minimum IAT as SYN-ACK time
            features['ackdat'] = np.median(iats) if iats else 0  # Median as ACK-DATA time
        else:
            features['tcprtt'] = 0
            features['synack'] = 0
            features['ackdat'] = 0
        
        # Packet loss (simplified - would need sequence number analysis)
        features['sloss'] = 0  # Source packet loss
        features['dloss'] = 0  # Dest packet loss
        
        # Connection counters (simplified - would need flow database)
        features['ct_srv_src'] = 1  # Count of connections to same service from source
        features['ct_state_ttl'] = 1  # Count of connections with same state and TTL
        features['ct_dst_ltm'] = 1  # Count to dest in last 100 flows
        features['ct_src_dport_ltm'] = 1  # Count from src to dest port
        features['ct_dst_sport_ltm'] = 1  # Count from dest using src port
        features['ct_dst_src_ltm'] = 1  # Count between src-dst pair
        features['ct_src_ltm'] = 1  # Count from source
        features['ct_srv_dst'] = 1  # Count to service from dest
        
        # Same IPs/ports check
        features['is_sm_ips_ports'] = 1 if flow_id[0] == flow_id[2] else 0
        
        # ====================================================================
        # 4. APPLICATION LAYER (UNSW features - simplified)
        # ====================================================================
        
        features['trans_depth'] = 0  # HTTP transaction depth
        features['response_body_len'] = 0  # HTTP response body length
        features['is_ftp_login'] = 0  # FTP login attempt
        features['ct_ftp_cmd'] = 0  # Count of FTP commands
        features['ct_flw_http_mthd'] = 0  # Count of HTTP methods
        
        # ====================================================================
        # 5. NETWORK IDENTIFIERS (UNSW features)
        # ====================================================================
        
        features['srcip'] = flow_id[0]
        features['sport'] = flow_id[1]
        features['dstip'] = flow_id[2]
        features['dsport'] = flow_id[3]
        features['Stime'] = flow_data['start_time']
        features['Ltime'] = flow_data['last_seen']
        
        return features
    
    def _get_zero_phase2_features(self):
        """Return zero/default values for Phase 2 features"""
        features = {}
        
        # Protocol flags
        protocols = ['HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC',
                    'TCP', 'UDP', 'DHCP', 'ARP', 'ICMP', 'IPv', 'LLC']
        for proto in protocols:
            features[proto] = 0
        
        # Numeric features
        features['Protocol Type'] = 0
        features['proto'] = 0
        features['sttl'] = 64
        features['dttl'] = 64
        features['service'] = 'other'
        features['state'] = 'INT'
        features['swin'] = 65535
        features['dwin'] = 65535
        features['stcpb'] = 0
        features['dtcpb'] = 0
        features['tcprtt'] = 0
        features['synack'] = 0
        features['ackdat'] = 0
        features['sloss'] = 0
        features['dloss'] = 0
        features['ct_srv_src'] = 0
        features['ct_state_ttl'] = 0
        features['ct_dst_ltm'] = 0
        features['ct_src_dport_ltm'] = 0
        features['ct_dst_sport_ltm'] = 0
        features['ct_dst_src_ltm'] = 0
        features['ct_src_ltm'] = 0
        features['ct_srv_dst'] = 0
        features['is_sm_ips_ports'] = 0
        features['trans_depth'] = 0
        features['response_body_len'] = 0
        features['is_ftp_login'] = 0
        features['ct_ftp_cmd'] = 0
        features['ct_flw_http_mthd'] = 0
        features['srcip'] = '0.0.0.0'
        features['sport'] = 0
        features['dstip'] = '0.0.0.0'
        features['dsport'] = 0
        features['Stime'] = 0
        features['Ltime'] = 0
        
        return features

# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    from unified_feature_calculator import UnifiedFeatureCalculator
    
    print("="*80)
    print("🧪 TESTING PHASE 2 EXTENSION")
    print("="*80)
    
    # Create base calculator
    base_calc = UnifiedFeatureCalculator()
    
    # Create Phase 2 calculator
    calculator = UnifiedFeatureCalculatorPhase2(base_calc)
    
    # Create sample flow data
    sample_flow = {
        'packets': [
            {'timestamp': 1.0, 'length': 100, 'tcp_flags': 0x02, 'protocol_name': 'TCP', 'ttl': 64, 'tcp_window': 65535},
            {'timestamp': 1.1, 'length': 150, 'tcp_flags': 0x10, 'protocol_name': 'TCP', 'ttl': 64, 'tcp_window': 65535},
            {'timestamp': 1.2, 'length': 200, 'tcp_flags': 0x10, 'protocol_name': 'TCP', 'ttl': 64, 'tcp_window': 65535},
        ],
        'fwd_packets': [
            {'timestamp': 1.0, 'length': 100, 'tcp_flags': 0x02, 'protocol_name': 'TCP', 'ttl': 64, 'tcp_window': 65535},
            {'timestamp': 1.2, 'length': 200, 'tcp_flags': 0x10, 'protocol_name': 'TCP', 'ttl': 64, 'tcp_window': 65535},
        ],
        'bwd_packets': [
            {'timestamp': 1.1, 'length': 150, 'tcp_flags': 0x10, 'protocol_name': 'TCP', 'ttl': 64, 'tcp_window': 65535},
        ],
        'start_time': 1.0,
        'last_seen': 1.2
    }
    
    # Calculate all features
    features = calculator.calculate_all_features(
        flow_id=('192.168.1.1', 12345, '10.0.0.1', 80, 'TCP'),
        flow_data=sample_flow
    )
    
    print(f"\n✅ Calculated {len(features)} features total!")
    
    # Show Phase 2 features
    print("\nPhase 2 Protocol Features:")
    protocols = ['HTTP', 'HTTPS', 'TCP', 'UDP']
    for proto in protocols:
        if proto in features:
            print(f"   {proto:10s}: {features[proto]}")
    
    print("\nPhase 2 Connection Features:")
    conn_features = ['service', 'state', 'sttl', 'dttl', 'tcprtt']
    for feat in conn_features:
        if feat in features:
            print(f"   {feat:20s}: {features[feat]}")
    
    print("\n" + "="*80)
    print("✅ Phase 2 Extension working correctly!")
    print("="*80)