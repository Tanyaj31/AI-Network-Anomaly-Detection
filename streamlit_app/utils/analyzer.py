"""
Analyzer Utility - Wrapper around file_analyzer for Streamlit
"""
import sys
import os

# Add project to path
sys.path.insert(0, '/home/shared/IoT_Project/AI_Anomaly_Detection')

from layered_ensemble.file_analyzer import analyze_file, analyze_file_simple
import streamlit as st


def analyze_with_progress(filepath: str, file_type: str):
    """
    Analyze file with Streamlit progress bar
    
    Args:
        filepath: Path to file
        file_type: 'csv' or 'pcap'
        
    Returns:
        dict with results, stats, performance, metadata
    """
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        # Stage 1: File detection
        status_text.text("🔍 Detecting file type...")
        progress_bar.progress(10)
        
        if file_type in ['pcap', 'pcapng']:
            # PCAP workflow
            status_text.text("📦 Parsing PCAP file...")
            progress_bar.progress(20)
            
            status_text.text("🔄 Extracting network flows...")
            progress_bar.progress(40)
            
            status_text.text("⚙️ Calculating 147 features...")
            progress_bar.progress(60)
            
        else:
            # CSV workflow
            status_text.text("📊 Loading CSV file...")
            progress_bar.progress(30)
        
        # Stage 2: Feature preparation
        status_text.text("🔧 Preparing dataset-specific features...")
        progress_bar.progress(70)
        
        # Stage 3: ML analysis
        status_text.text("🤖 Running 3-layer security analysis...")
        progress_bar.progress(80)
        
        status_text.text("🔥 Layer 0: Zero-day detection...")
        progress_bar.progress(85)
        
        status_text.text("🎯 Layer 1: Attack classification...")
        progress_bar.progress(90)
        
        status_text.text("📊 Generating results...")
        progress_bar.progress(95)
        
        # Actually run analysis
        output = analyze_file(filepath, verbose=False)
        
        progress_bar.progress(100)
        status_text.text("✅ Analysis complete!")
        
        return output
        
    except Exception as e:
        progress_bar.empty()
        status_text.empty()
        raise e


def get_demo_file_path():
    """Get path to demo CSV file"""
    return '/home/shared/IoT_Project/AI_Anomaly_Detection/layered_ensemble/test_results/extracted_features.csv'


def validate_file(uploaded_file):
    """
    Validate uploaded file
    
    Returns:
        (is_valid, error_message)
    """
    
    # Check file extension
    filename = uploaded_file.name.lower()
    
    if not any(filename.endswith(ext) for ext in ['.csv', '.pcap', '.pcapng']):
        return False, "❌ Unsupported file type. Please upload CSV, PCAP, or PCAPNG files."
    
    # Check file size (limit 500MB)
    size_mb = uploaded_file.size / (1024 * 1024)
    if size_mb > 500:
        return False, f"❌ File too large ({size_mb:.1f}MB). Maximum size is 500MB."
    
    return True, None


def format_results_summary(stats: dict) -> dict:
    """
    Format statistics for display
    
    Returns:
        dict with formatted metrics
    """
    
    return {
        'total_flows': f"{stats['total_flows']:,}",
        'layer0_flagged': f"{stats['layer0_flagged']:,} ({stats['layer0_flag_rate']:.2f}%)",
        'attacks_detected': f"{stats['attacks_detected']:,} ({stats['attack_rate']:.2f}%)",
        'normal_traffic': f"{stats['normal_traffic']:,} ({stats['normal_rate']:.2f}%)",
    }