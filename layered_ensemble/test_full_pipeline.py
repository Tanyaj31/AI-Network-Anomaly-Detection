#!/usr/bin/env python3
"""
Full pipeline test on all 262K flows
"""
import sys
sys.path.insert(0, '/home/shared/IoT_Project/AI_Anomaly_Detection')
import pandas as pd
import time
from layered_ensemble.production_pipeline import ProductionPipeline
from feature_extraction.feature_mappings import FeatureMappings
from feature_extraction.feature_selector import FeatureSelector

print("\n" + "="*70)
print("🚀 FULL PIPELINE TEST - 262,152 FLOWS")
print("="*70)

# Load pipeline
pipeline = ProductionPipeline()
pipeline.load_models()

# Load features
print("\n📥 Loading extracted features...")
df = pd.read_csv('/home/shared/IoT_Project/AI_Anomaly_Detection/layered_ensemble/test_results/extracted_features.csv')
print(f"✅ Loaded {len(df):,} flows")

# Prepare batches
mappings = FeatureMappings()
selector = FeatureSelector(mappings)

print("\n⚙️  Preparing feature batches...")
cicids_batch = selector.extract_batch_for_cicids(df)
iot_batch = selector.extract_batch_for_iot(df)
unsw_batch = selector.extract_batch_for_unsw(df)
print(f"✅ CICIDS: {cicids_batch.shape}")
print(f"✅ IoT: {iot_batch.shape}")
print(f"✅ UNSW: {unsw_batch.shape}")

# Run pipeline
print("\n🔥 RUNNING PIPELINE...")
start = time.time()
results = pipeline.analyze_batch(cicids_batch, iot_batch, unsw_batch)
elapsed = time.time() - start

# Get statistics
stats = pipeline.get_statistics()

# Detailed analysis
from collections import Counter
attack_types = Counter()
threat_levels = Counter()

for r in results:
    attack_types[r['analysis']['classification']] += 1
    threat_levels[r['analysis']['threat_level']] += 1

# Print results
print("\n" + "="*70)
print("📊 ANALYSIS RESULTS")
print("="*70)

print(f"\n🔍 Layer 0 (Zero-Day Detection):")
print(f"   Total flows: {stats['total_flows']:,}")
print(f"   Flagged: {stats['layer0_flagged']:,} ({stats['layer0_flag_rate']:.2f}%)")

print(f"\n🎯 Layer 1 (Attack Classification):")
print(f"   Attacks detected: {stats['attacks_detected']:,} ({stats['attack_rate']:.2f}%)")
print(f"   Normal traffic: {stats['normal_traffic']:,} ({stats['normal_rate']:.2f}%)")

print(f"\n⚠️  Threat Levels:")
for level, count in sorted(threat_levels.items(), key=lambda x: x[1], reverse=True):
    print(f"   {level}: {count:,} ({count/len(results)*100:.2f}%)")

print(f"\n🔎 Top Attack Types:")
for attack, count in attack_types.most_common(10):
    print(f"   {attack}: {count:,} ({count/len(results)*100:.2f}%)")

print(f"\n⚡ Performance:")
print(f"   Total time: {elapsed:.2f} seconds")
print(f"   Throughput: {len(results)/elapsed:,.0f} flows/sec")

print("\n" + "="*70)
print("✅ PIPELINE TEST COMPLETE!")
print("="*70)
