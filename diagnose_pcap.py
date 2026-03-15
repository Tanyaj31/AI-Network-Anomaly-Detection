#!/usr/bin/env python3
"""
Diagnostic: Check what's happening with PCAP processing
Run this to see where features are getting lost
"""

import sys
sys.path.insert(0, '/home/shared/IoT_Project/AI_Anomaly_Detection')

from feature_extraction.optimized_pcap_parser import OptimizedPcapParser
from feature_extraction.vectorized_flow_tracker import VectorizedFlowTracker
from feature_extraction.unified_feature_calculator import UnifiedFeatureCalculator

# Use a small PCAP for testing
pcap_file = "/home/shared/IoT_Project/AI_Anomaly_Detection/layered_ensemble/IoT_Dataset_TCP_DDoS__00072_20180604174023.pcap"

print("=" * 70)
print("PCAP PROCESSING DIAGNOSTIC")
print("=" * 70)

# Step 1: Parse packets
print("\n1️⃣ Parsing PCAP...")
parser = OptimizedPcapParser(pcap_file, chunk_size=5000)
packets_df = parser.parse_all()

print(f"   Packets extracted: {len(packets_df)}")
if len(packets_df) > 0:
    print(f"   Columns: {list(packets_df.columns)}")
    print(f"   Sample packet:")
    print(packets_df.head(1).T)
else:
    print("   ❌ No packets extracted!")
    sys.exit(1)

# Step 2: Create flows
print("\n2️⃣ Creating flows...")
tracker = VectorizedFlowTracker()
flows = tracker.create_flows(packets_df, verbose=True)

print(f"   Flows created: {len(flows)}")
if len(flows) > 0:
    # Check first flow structure
    first_flow_id = list(flows.keys())[0]
    first_flow = flows[first_flow_id]
    print(f"   First flow ID: {first_flow_id}")
    print(f"   Flow structure keys: {list(first_flow.keys())}")
    print(f"   Packets in flow: {len(first_flow['packets'])}")
    print(f"   Forward packets: {len(first_flow['fwd_packets'])}")
    print(f"   Backward packets: {len(first_flow['bwd_packets'])}")
else:
    print("   ❌ No flows created!")
    sys.exit(1)

# Step 3: Calculate features
print("\n3️⃣ Calculating features...")
calculator = UnifiedFeatureCalculator()

features_list = []
errors = 0

for i, (flow_id, flow_data) in enumerate(flows.items()):
    if i >= 5:  # Test first 5 flows
        break
    
    try:
        print(f"\n   Flow {i+1}:")
        print(f"      ID: {flow_id}")
        print(f"      Packets: {len(flow_data['packets'])}")
        
        features = calculator.calculate_all_features(flow_id, flow_data)
        
        print(f"      Features extracted: {len(features)} features")
        if len(features) > 0:
            print(f"      Sample features: {list(features.keys())[:5]}")
            features_list.append(features)
        else:
            print(f"      ⚠️ Empty features dict!")
            errors += 1
            
    except Exception as e:
        print(f"      ❌ Error: {e}")
        errors += 1

print(f"\n   Successfully extracted features from {len(features_list)} flows")
print(f"   Errors: {errors}")

if len(features_list) == 0:
    print("\n❌ PROBLEM: No features extracted!")
    print("   Check UnifiedFeatureCalculator.calculate_all_features()")
else:
    print("\n✅ Feature extraction working!")
    
    # Check feature DataFrame
    import pandas as pd
    features_df = pd.DataFrame(features_list)
    print(f"\n   DataFrame shape: {features_df.shape}")
    print(f"   Columns: {len(features_df.columns)}")
    print(f"   Sample columns: {list(features_df.columns)[:10]}")

print("\n" + "=" * 70)
