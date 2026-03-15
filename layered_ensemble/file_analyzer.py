"""
Universal File Analyzer - Handles both PCAP and CSV files
==========================================================

This wrapper provides a single interface for analyzing network traffic
regardless of input format (PCAP or CSV).

Usage:
    from layered_ensemble.file_analyzer import analyze_file
    
    # Works with PCAP
    results = analyze_file('traffic.pcap')
    
    # Works with CSV  
    results = analyze_file('features.csv')
"""

import sys
import os
import pandas as pd
import time
from pathlib import Path

# Add project to path
sys.path.insert(0, '/home/shared/IoT_Project/AI_Anomaly_Detection')

# Import required modules
from layered_ensemble.production_pipeline import ProductionPipeline
from feature_extraction.feature_mappings import FeatureMappings
from feature_extraction.feature_selector import FeatureSelector


def analyze_file(filepath: str, verbose: bool = True) -> dict:
    """
    Universal file analyzer - handles PCAP or CSV automatically
    
    Args:
        filepath: Path to PCAP or CSV file
        verbose: Print progress messages (default: True)
        
    Returns:
        dict with:
            - results: List of per-flow analysis results
            - stats: Overall statistics
            - performance: Timing information
            - metadata: File information
    """
    
    if verbose:
        print("\n" + "="*70)
        print("🔍 UNIVERSAL FILE ANALYZER")
        print("="*70)
        print(f"📁 File: {filepath}")
    
    start_total = time.time()
    
    # ========================================================================
    # STEP 1: DETECT FILE TYPE & LOAD FEATURES
    # ========================================================================
    
    file_ext = Path(filepath).suffix.lower()
    
    if file_ext in ['.pcap', '.pcapng']:
        # ────────────────────────────────────────────────────────────────────
        # PCAP WORKFLOW: Parse → Extract Features → Analyze
        # ────────────────────────────────────────────────────────────────────
        
        if verbose:
            print("📦 PCAP file detected - extracting features...")
        
        try:
            # Import optimized pipeline
            sys.path.insert(0, '/home/shared/IoT_Project/AI_Anomaly_Detection/feature_extraction')
            from optimized_pipeline import OptimizedPipeline
            
            # Extract features from PCAP
            extractor = OptimizedPipeline()
            features_df = extractor.process_pcap(filepath)
            
            if verbose:
                print(f"✅ Extracted {len(features_df):,} flows with 147 features")
                
        except ImportError:
            # Fallback: Manual PCAP processing if optimized_pipeline not available
            if verbose:
                print("⚠️  Optimized pipeline not found, using manual extraction...")
            
            from optimized_pcap_parser import OptimizedPcapParser
            from unified_feature_calculator import UnifiedFeatureCalculator
            from vectorized_flow_tracker import VectorizedFlowTracker
            
            # Parse PCAP
            parser = OptimizedPcapParser(filepath)
            packets_df = parser.parse_all()
            
            # Create flows
            flow_tracker = VectorizedFlowTracker()
            flows = flow_tracker.create_flows(packets_df)
            
            # Calculate features
            calculator = UnifiedFeatureCalculator()
            features_list = []
            
            for flow_id, flow_data in flows.items():
                features = calculator.calculate_all_features(flow_id, flow_data)
                features_list.append(features)
            
            features_df = pd.DataFrame(features_list)
            
            if verbose:
                print(f"✅ Extracted {len(features_df):,} flows")
        
    elif file_ext == '.csv':
        # ────────────────────────────────────────────────────────────────────
        # CSV WORKFLOW: Load directly (features already extracted)
        # ────────────────────────────────────────────────────────────────────
        
        if verbose:
            print("📊 CSV file detected - loading pre-extracted features...")
        
        features_df = pd.read_csv(filepath)
        
        if verbose:
            print(f"✅ Loaded {len(features_df):,} flows with {len(features_df.columns)} features")
    
    else:
        raise ValueError(f"Unsupported file type: {file_ext}. Must be .pcap, .pcapng, or .csv")
    
    extraction_time = time.time() - start_total
    
    # ========================================================================
    # STEP 2: PREPARE DATASET-SPECIFIC FEATURES
    # ========================================================================
    
    if verbose:
        print("\n⚙️  Preparing dataset-specific features...")
    
    start_prep = time.time()
    
    # Initialize feature mappings and selector
    mappings = FeatureMappings()
    selector = FeatureSelector(mappings)
    
    # Extract features for each dataset
    cicids_batch = selector.extract_batch_for_cicids(features_df)
    iot_batch = selector.extract_batch_for_iot(features_df)
    unsw_batch = selector.extract_batch_for_unsw(features_df)
    
    prep_time = time.time() - start_prep
    
    if verbose:
        print(f"✅ Feature preparation complete: {prep_time:.2f}s")
        print(f"   CICIDS: {cicids_batch.shape}")
        print(f"   IoT: {iot_batch.shape}")
        print(f"   UNSW: {unsw_batch.shape}")
    
    # ========================================================================
    # STEP 3: RUN 3-LAYER ANALYSIS PIPELINE
    # ========================================================================
    
    if verbose:
        print("\n🔥 Running 3-layer security analysis...")
    
    start_analysis = time.time()
    
    # Load and run pipeline
    pipeline = ProductionPipeline()
    pipeline.load_models()
    
    results = pipeline.analyze_batch(cicids_batch, iot_batch, unsw_batch)
    
    analysis_time = time.time() - start_analysis
    
    # Get statistics
    stats = pipeline.get_statistics()
    
    total_time = time.time() - start_total
    
    # ========================================================================
    # STEP 4: COMPILE RESULTS
    # ========================================================================
    
    if verbose:
        print(f"✅ Analysis complete: {analysis_time:.2f}s")
        print(f"\n📊 RESULTS SUMMARY:")
        print(f"   Total flows: {stats['total_flows']:,}")
        print(f"   Layer 0 flagged: {stats['layer0_flagged']:,} ({stats['layer0_flag_rate']:.2f}%)")
        print(f"   Attacks detected: {stats['attacks_detected']:,} ({stats['attack_rate']:.2f}%)")
        print(f"   Normal traffic: {stats['normal_traffic']:,} ({stats['normal_rate']:.2f}%)")
        print(f"\n⚡ PERFORMANCE:")
        print(f"   Total time: {total_time:.2f}s")
        print(f"   Throughput: {len(results)/total_time:,.0f} flows/sec")
        print("="*70 + "\n")
    
    # Return comprehensive results
    return {
        'results': results,
        'stats': stats,
        'features_df': features_df,
        'performance': {
            'extraction_time': extraction_time,
            'preparation_time': prep_time,
            'analysis_time': analysis_time,
            'total_time': total_time,
            'throughput': len(results) / total_time
        },
        'metadata': {
            'file': filepath,
            'file_type': file_ext,
            'total_flows': len(results),
            'features_extracted': len(features_df.columns) if file_ext != '.csv' else 'pre-extracted'
        }
    }


# ============================================================================
# SIMPLIFIED INTERFACE FOR UI
# ============================================================================

def analyze_file_simple(filepath: str) -> tuple:
    """
    Simplified interface for UI - returns just results and stats
    
    Args:
        filepath: Path to PCAP or CSV file
        
    Returns:
        (results, stats) tuple
    """
    output = analyze_file(filepath, verbose=False)
    return output['results'], output['stats']


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python file_analyzer.py <pcap_or_csv_file>")
        print("\nExample:")
        print("  python file_analyzer.py traffic.pcap")
        print("  python file_analyzer.py features.csv")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    if not os.path.exists(filepath):
        print(f"❌ Error: File not found: {filepath}")
        sys.exit(1)
    
    # Analyze file
    output = analyze_file(filepath, verbose=True)
    
    # Show top attack types
    from collections import Counter
    attack_types = Counter()
    
    for result in output['results']:
        attack_types[result['analysis']['classification']] += 1
    
    print("\n🔎 TOP ATTACK TYPES:")
    for attack, count in attack_types.most_common(10):
        pct = (count / len(output['results'])) * 100
        print(f"   {attack:30s}: {count:6,} ({pct:5.2f}%)")
    
    print("\n✅ Analysis complete!")