"""
Analyze Traffic Page - Main analysis interface
"""
import streamlit as st
import sys
import os
import tempfile
from pathlib import Path
from utils.navigation import render_sidebar_nav

# Add project to path
sys.path.insert(0, '/home/shared/IoT_Project/AI_Anomaly_Detection')
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from utils.analyzer import analyze_with_progress, get_demo_file_path, validate_file, format_results_summary
from utils.visualizations import (
    create_attack_distribution_pie,
    create_threat_level_bar,
    create_attack_types_bar,
    create_layer_agreement_chart,
    create_performance_metrics
)
from collections import Counter
import json
import pandas as pd

# Page config
st.set_page_config(page_title="Analyze Traffic", page_icon="📊", layout="wide")

render_sidebar_nav("2_analyze")

st.markdown("""
<style>
    section[data-testid="stSidebar"] [data-testid="stSidebarNav"] > ul > li:first-child {
        display: none;
    }
</style>
""", unsafe_allow_html=True)

st.title("📊 Network Traffic Analysis")
st.markdown("Upload your network traffic files for comprehensive security analysis")

st.markdown("---")

# Initialize session state
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'analysis_metadata' not in st.session_state:
    st.session_state.analysis_metadata = None
if 'demo_selected' not in st.session_state:
    st.session_state.demo_selected = False

# Info box
st.info("""
**📁 Supported File Types:**
- **CSV** - Pre-extracted network flow features (99 features)
- **PCAP/PCAPNG** - Raw packet captures (features extracted automatically)

**⚡ What You'll Get:**
- Attack type classification
- Threat level assessment  
- Layer-by-layer analysis breakdown
- Interactive visualizations
- Downloadable results (JSON/CSV)
""")

# File upload section
st.markdown("### 📤 Upload Network Traffic")

col1, col2 = st.columns([2, 1])

with col1:
    uploaded_file = st.file_uploader(
        "Choose a file",
        type=['csv', 'pcap', 'pcapng'],
        help="Upload CSV with extracted features or raw PCAP file"
    )
    if uploaded_file is not None:
        st.session_state.demo_selected = False

with col2:
    st.markdown("**Or try our demo:**")
    if st.button("🎯 Analyze Demo File (262K flows)", type="primary", use_container_width=True):
        st.session_state.demo_selected = True
        st.rerun()

if st.session_state.demo_selected:
    uploaded_file = "DEMO"

if 'features_df' not in st.session_state:
    st.session_state.features_df = None

st.markdown("---")

# Analysis logic
if uploaded_file:
    
    # Determine if demo or uploaded
    if uploaded_file == "DEMO":
        st.success("✅ Using demo file: 262,152 flows from IoT DDoS dataset")
        filepath = get_demo_file_path()
        filename = "IoT_Dataset_TCP_DDoS__00072_20180604174023.csv"
        file_type = 'csv'
        
    else:
        # Validate uploaded file
        is_valid, error_msg = validate_file(uploaded_file)
        
        if not is_valid:
            st.error(error_msg)
            st.markdown("""
            **💡 Suggestions:**
            - Ensure file is CSV, PCAP, or PCAPNG format
            - Check file size is under 500MB
            - For large files, consider using the demo first
            """)
            st.stop()
        
        # Save uploaded file temporarily
        filename = uploaded_file.name
        file_type = Path(filename).suffix[1:].lower()  # Remove dot
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{file_type}") as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            filepath = tmp_file.name
        
        st.success(f"✅ File uploaded: {filename} ({uploaded_file.size / 1024 / 1024:.1f} MB)")
    
    # ── File info + Data Preview ──────────────────────────────────────────
    with st.expander("ℹ️ File Information", expanded=True):

        # Basic metadata row
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f"**Filename:** {filename}")
        with col2:
            st.markdown(f"**Type:** {file_type.upper()}")
        with col3:
            if uploaded_file != "DEMO":
                st.markdown(f"**Size:** {uploaded_file.size / 1024 / 1024:.1f} MB")
            else:
                st.markdown(f"**Size:** 215 MB")

        st.markdown("---")
        st.markdown("**📋 Data Preview**")
        
        if st.session_state.features_df is not None:
            df = st.session_state.features_df
            st.caption(f"{len(df.columns)} columns · {len(df):,} total rows · showing first 5")
            st.dataframe(df.head(5), use_container_width=True)
        else:
            if file_type == 'csv' or uploaded_file == "DEMO":
                st.info("⏳ Run analysis to see the extracted features preview")
            else:
                size_bytes = uploaded_file.size if uploaded_file != "DEMO" else 225 * 1024 * 1024
                est_packets = size_bytes // 450
                est_flows   = est_packets // 5
                st.info(
                    f"📦 PCAP file · Estimated **~{est_packets:,} packets** "
                    f"→ **~{est_flows:,} flows** · Run analysis to see extracted features"
                )
    # Analyze button
    st.markdown("---")
    
    if st.button("🔍 START ANALYSIS", type="primary", use_container_width=True):
        
        try:
            # Run analysis with progress
            st.markdown("### ⚙️ Analysis in Progress...")
            
            output = analyze_with_progress(filepath, file_type)
            
            # Store in session state
            st.session_state.analysis_results = output['results']
            st.session_state.features_df = output.get('features_df', None)
            st.session_state.analysis_metadata = {
                'stats': output['stats'],
                'performance': output['performance'],
                'metadata': output['metadata']
            }
            
            # Clean up temp file
            if uploaded_file != "DEMO" and os.path.exists(filepath):
                os.unlink(filepath)
            
            st.success("✅ Analysis complete!")
            st.rerun()
            
        except Exception as e:
            st.error(f"❌ Analysis failed: {str(e)}")
            
            st.markdown("""
            **💡 Troubleshooting Suggestions:**
            - **CSV files:** Ensure file contains network flow features (not raw logs)
            - **PCAP files:** Verify file is not corrupted
            - **Large files:** Try the demo file first to verify system is working
            - **Feature mismatch:** CSV should have 147 universal features or match expected dataset format
            """)
            
            with st.expander("🔧 Technical Details"):
                st.code(str(e))

# Display results if available
if st.session_state.analysis_results:
    
    st.markdown("---")
    st.markdown("## 📊 Analysis Results")
    
    results = st.session_state.analysis_results
    metadata = st.session_state.analysis_metadata
    stats = metadata['stats']
    performance = metadata['performance']
    
    # Summary metrics
    st.markdown("### 📈 Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Total Flows",
            f"{stats['total_flows']:,}",
            help="Total number of network flows analyzed"
        )
    
    with col2:
        st.metric(
            "Layer 0 Flagged",
            f"{stats['layer0_flagged']:,}",
            delta=f"{stats['layer0_flag_rate']:.2f}%",
            help="Flows flagged by zero-day detection (Layer 0)"
        )
    
    with col3:
        st.metric(
            "Attacks Detected",
            f"{stats['attacks_detected']:,}",
            delta=f"{stats['attack_rate']:.2f}%",
            delta_color="inverse",
            help="Flows classified as attacks by Layer 1"
        )
    
    with col4:
        st.metric(
            "Normal Traffic",
            f"{stats['normal_traffic']:,}",
            delta=f"{stats['normal_rate']:.2f}%",
            help="Flows classified as legitimate traffic"
        )
    
    # Threat assessment
    st.markdown("---")
    st.markdown("### ⚠️ Threat Assessment")
    
    threat_level_pct = stats['attack_rate']
    
    if threat_level_pct > 50:
        st.error(f"""
        🔴 **HIGH THREAT LEVEL** ({threat_level_pct:.1f}% attacks)
        
        **Immediate actions recommended:**
        - Review Layer 1 classifications below
        - Investigate high-confidence attack flows
        - Consider blocking suspicious IPs
        - Escalate to security team
        """)
    elif threat_level_pct > 20:
        st.warning(f"""
        🟡 **ELEVATED THREAT LEVEL** ({threat_level_pct:.1f}% attacks)
        
        **Recommended actions:**
        - Monitor attack patterns
        - Review uncertain cases
        - Investigate top attack types
        """)
    else:
        st.success(f"""
        🟢 **NORMAL OPERATIONS** ({threat_level_pct:.1f}% attacks)
        
        **Status:** Traffic appears mostly legitimate. Continue monitoring.
        """)
    
    # Visualizations
    st.markdown("---")
    st.markdown("### 📊 Visual Analysis")
    
    tab1, tab2, tab3 = st.tabs(["Attack Distribution", "Threat Levels", "Layer Analysis"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            fig_pie = create_attack_distribution_pie(results)
            st.plotly_chart(fig_pie, use_container_width=True)
        
        with col2:
            fig_attacks = create_attack_types_bar(results, top_n=10)
            if fig_attacks:
                st.plotly_chart(fig_attacks, use_container_width=True)
            else:
                st.info("No attacks detected in this traffic")
    
    with tab2:
        fig_threat = create_threat_level_bar(results)
        st.plotly_chart(fig_threat, use_container_width=True)
    
    with tab3:
        fig_agreement = create_layer_agreement_chart(results)
        st.plotly_chart(fig_agreement, use_container_width=True)
        
        st.markdown("""
        **Understanding Layer Agreement:**
        - **Both Flagged**: Layer 0 and Layer 1 both detected threat (high confidence)
        - **Layer 0 Only**: Zero-day detection flagged, but no known attack pattern (investigate!)
        - **Layer 1 Only**: Known attack detected, but passed zero-day filter (expected)
        - **Both Normal**: Both layers agree traffic is legitimate
        """)
    
    # Detailed breakdown
    st.markdown("---")
    st.markdown("### 🔎 Detailed Attack Breakdown")
    
    attack_counter = Counter()
    for r in results:
        if r['analysis']['classification'] != 'Normal Traffic':
            attack_counter[r['analysis']['classification']] += 1
    
    if attack_counter:
        attack_df = []
        for attack_type, count in attack_counter.most_common():
            pct = (count / stats['total_flows']) * 100
            attack_df.append({
                'Attack Type': attack_type,
                'Count': f"{count:,}",
                'Percentage': f"{pct:.2f}%",
                'Severity': '🔴 High' if pct > 5 else '🟡 Medium' if pct > 1 else '🟢 Low'
            })
        
        st.dataframe(attack_df, use_container_width=True, hide_index=True)
    else:
        st.success("✅ No attacks detected in this traffic sample")
    
    # Performance metrics
    st.markdown("---")
    st.markdown("### ⚡ Performance Metrics")
    
    metrics = create_performance_metrics(performance)
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    cols = [col1, col2, col3, col4, col5]
    for col, (label, value) in zip(cols, metrics.items()):
        with col:
            st.metric(label, value)
    
    # Download results
    st.markdown("---")
    st.markdown("### 💾 Export Results")
    
    col1, col2 = st.columns(2)
    
    with col1:
        json_data = json.dumps({
            'metadata': metadata['metadata'],
            'stats': stats,
            'performance': performance,
            'results': results
        }, indent=2)
        
        st.download_button(
            label="📥 Download Full Results (JSON)",
            data=json_data,
            file_name="analysis_results.json",
            mime="application/json",
            use_container_width=True
        )
    
    with col2:
        summary_csv = f"""Metric,Value
Total Flows,{stats['total_flows']}
Layer 0 Flagged,{stats['layer0_flagged']}
Layer 0 Flag Rate,{stats['layer0_flag_rate']:.2f}%
Attacks Detected,{stats['attacks_detected']}
Attack Rate,{stats['attack_rate']:.2f}%
Normal Traffic,{stats['normal_traffic']}
Normal Rate,{stats['normal_rate']:.2f}%
Total Time,{performance['total_time']:.2f}s
Throughput,{performance['throughput']:.0f} flows/sec
"""
        
        st.download_button(
            label="📥 Download Summary (CSV)",
            data=summary_csv,
            file_name="analysis_summary.csv",
            mime="text/csv",
            use_container_width=True
        )
    
    # Clear results button
    if st.button("🔄 Analyze Another File", use_container_width=True):
        st.session_state.analysis_results = None
        st.session_state.analysis_metadata = None
        st.session_state.demo_selected = False
        st.rerun()

else:
    # No results yet - show instructions
    st.markdown("---")
    st.markdown("### 📖 How to Use")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        #### For CSV Files:
        1. Prepare CSV with network flow features
        2. Ensure 147 universal features or dataset-specific format
        3. Upload file above
        4. Click "Start Analysis"
        5. Review results and visualizations
        
        **CSV Format:** Each row = one network flow  
        **Required:** Flow duration, packet stats, flag counts, etc.
        """)
    
    with col2:
        st.markdown("""
        #### For PCAP Files:
        1. Capture network traffic with Wireshark/tcpdump
        2. Save as .pcap or .pcapng
        3. Upload file above
        4. System automatically extracts features
        5. Review analysis results
        
        **PCAP Processing:** Automatic feature extraction  
        **Time:** ~10-20 seconds per 100K packets
        """)