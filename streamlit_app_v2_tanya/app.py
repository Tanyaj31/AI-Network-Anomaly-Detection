"""
AI Network Intrusion Detection System - Streamlit UI
=====================================================

Main entry point for the Streamlit application.

Team: 4 members (Parallel Learning Approach)
Institution: Metropolia University of Applied Sciences
Duration: 6 months
Completion: March 2025
"""

import streamlit as st
import sys

# Add project to path
sys.path.insert(0, '/home/shared/IoT_Project/AI_Anomaly_Detection')

# Page configuration
st.set_page_config(
    page_title="AI Network IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem 0;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #666;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .success-box {
        background-color: #d4edda;
        border-left: 4px solid #28a745;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 0.3rem;
    }
    .info-box {
        background-color: #d1ecf1;
        border-left: 4px solid #17a2b8;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 0.3rem;
    }
    .warning-box {
        background-color: #fff3cd;
        border-left: 4px solid #ffc107;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 0.3rem;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image("https://via.placeholder.com/150x50/1f77b4/ffffff?text=IDS", use_container_width=True)
    
    st.markdown("---")
    
    st.markdown("### 📊 Project Info")
    st.markdown("""
    **Institution:** Metropolia UAS  
    **Team:** 4 members  
    **Duration:** 6 months  
    **Status:** Production Ready
    """)
    
    st.markdown("---")
    
    st.markdown("### 🎯 Key Achievements")
    st.markdown("""
    ✅ **99.92%** Accuracy (XGBoost)  
    ✅ **7K** flows/sec throughput  
    ✅ **3-Layer** Architecture  
    ✅ **Zero-Day** Detection
    """)
    
    st.markdown("---")
    
    st.markdown("### 📚 Quick Links")
    st.markdown("""
    - [🏠 Home](#home)
    - [📊 Analyze Traffic](#analyze)
    - [📡 Live Monitor](#monitor)
    - [🤖 Models Info](#models)
    - [ℹ️ About](#about)
    """)

# Main content
st.markdown('<div class="main-header">🛡️ AI Network Intrusion Detection System</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Production-Ready ML Security with 99.92% Accuracy</div>', unsafe_allow_html=True)

st.markdown("---")

# Welcome section
col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("### 🎯 Multi-Strategy Detection")
    st.markdown("""
    Our system uses **three complementary approaches**:
    - **Supervised Learning** - Identifies specific attack types
    - **Unsupervised Learning** - Detects unknown/zero-day attacks
    - **Ensemble Methods** - Combines models for maximum reliability
    """)

with col2:
    st.markdown("### 🏗️ 3-Layer Architecture")
    st.markdown("""
    **Layer 0:** Zero-day detection using autoencoders  
    **Layer 1:** Attack classification with 3 XGBoost models  
    **Layer 2:** Human-in-the-loop review system
    
    ⚡ Processes **7,000 flows/sec** in production
    """)

with col3:
    st.markdown("### 📈 Proven Performance")
    st.markdown("""
    **99.92%** - Best accuracy (XGBoost on CICIDS)  
    **97.08%** - Attack detection rate  
    **9.97%** - Zero-day flagging rate  
    **262K** - Flows analyzed in testing
    """)

st.markdown("---")

# Getting started
st.markdown("## 🚀 Getting Started")

col1, col2 = st.columns(2)

with col1:
    st.markdown("""
    ### 📊 Analyze Network Traffic
    
    Upload your network traffic files for analysis:
    
    1. Click **📊 Analyze** in the sidebar
    2. Upload CSV or PCAP file
    3. Get instant results with:
       - Attack type classification
       - Threat level assessment
       - Visual analytics
       - Downloadable reports
    
    **Supported formats:** CSV, PCAP, PCAPNG
    """)
    
    if st.button("🎯 Start Analysis", type="primary", use_container_width=True):
        st.switch_page("pages/2_📊_Analyze.py")

with col2:
    st.markdown("""
    ### 🤖 Explore Model Performance
    
    Review our trained models and their performance:
    
    1. Click **🤖 Models** in the sidebar
    2. Explore performance metrics
    3. View confusion matrices
    4. Understand ROC curves
    5. See feature importance
    
    **Datasets:** CICIDS2017, CIC IoT 2023, UNSW-NB15
    """)
    
    if st.button("📈 View Models", use_container_width=True):
        st.switch_page("pages/4_🤖_Models.py")

st.markdown("---")

# Key features
st.markdown("## ✨ Key Features")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown("### 🔍 Real-Time Detection")
    st.markdown("Analyze network traffic in real-time with sub-second latency per flow")

with col2:
    st.markdown("### 🎯 Multi-Dataset Training")
    st.markdown("Trained on 3 major datasets covering enterprise, IoT, and research traffic")

with col3:
    st.markdown("### 🌐 Universal Features")
    st.markdown("147 universal features work across any network environment")

with col4:
    st.markdown("### 📡 Edge Deployment")
    st.markdown("Deploy on Raspberry Pi for distributed threat detection")

st.markdown("---")

# Recent activity (placeholder)
st.markdown("## 📊 System Status")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        label="Models Loaded",
        value="9",
        delta="All operational",
        delta_color="normal"
    )

with col2:
    st.metric(
        label="Accuracy",
        value="99.92%",
        delta="XGBoost CICIDS",
        delta_color="normal"
    )

with col3:
    st.metric(
        label="Throughput",
        value="7K flows/sec",
        delta="Production tested",
        delta_color="normal"
    )

with col4:
    st.metric(
        label="System Status",
        value="✅ Ready",
        delta="All systems operational",
        delta_color="normal"
    )

st.markdown("---")

# Footer
st.markdown("""
<div style='text-align: center; color: #666; padding: 2rem 0;'>
    <p><strong>AI Network Intrusion Detection System</strong></p>
    <p>Metropolia University of Applied Sciences | IoT Network Security Project</p>
    <p>Team: 4 members | Duration: 6 months | Completion: March 2025</p>
    <p>Built with ❤️ using Python, TensorFlow, XGBoost, and Streamlit</p>
</div>
""", unsafe_allow_html=True)