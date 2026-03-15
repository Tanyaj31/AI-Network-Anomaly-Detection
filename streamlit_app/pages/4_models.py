"""
Models Info Page - Detailed model performance and metrics
"""
import streamlit as st
import os
import pandas as pd
from PIL import Image
from utils.navigation import render_sidebar_nav

st.set_page_config(page_title="Models Info", page_icon="🤖", layout="wide")

render_sidebar_nav("4_models")

st.markdown("""
<style>
    section[data-testid="stSidebar"] [data-testid="stSidebarNav"] > ul > li:first-child {
        display: none;
    }
</style>
""", unsafe_allow_html=True)

st.title("🤖 Model Performance & Metrics")
st.markdown("Detailed information about our trained models")

st.markdown("---")

# Model performance table
st.markdown("### 📊 Model Accuracy Comparison")

model_data = {
    'Dataset': ['CICIDS', 'CICIDS', 'CICIDS', 'CICIDS', 'CICIDS', 
                'IoT', 'IoT', 'IoT', 
                'UNSW', 'UNSW', 'UNSW'],
    'Model': ['XGBoost', 'Random Forest', 'LightGBM', 'Neural Network', 'Autoencoder', 
              'XGBoost', 'Random Forest', 'Autoencoder',
              'XGBoost', 'Isolation Forest', 'Autoencoder'],
    'Accuracy': ['99.92%', '99.88%', '98.96%', '98.49%', '97.73%',
                 '96.80%', '95.20%', '94.50%',
                 '97.20%', '99.45%', '96.80%'],
    'Features': [52, 52, 52, 52, 52, 39, 39, 39, 48, 48, 48],
    'Type': ['Supervised', 'Supervised', 'Supervised', 'Supervised', 'Unsupervised',
             'Supervised', 'Supervised', 'Unsupervised',
             'Supervised', 'Unsupervised', 'Unsupervised']
}

df = pd.DataFrame(model_data)
st.dataframe(df, use_container_width=True, hide_index=True)

st.markdown("---")

# Key achievements
st.markdown("### 🏆 Key Achievements")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Best Accuracy", "99.92%", "XGBoost CICIDS")
with col2:
    st.metric("Total Models", "11", "3 datasets")
with col3:
    st.metric("Training Time", "~5 min", "All models")
with col4:
    st.metric("Throughput", "7K flows/sec", "Production")

st.markdown("---")

# 3-Layer Architecture
st.markdown("### 🏗️ Production Architecture")

col1, col2 = st.columns([1, 1])

with col1:
    st.markdown("""
    #### Layer 0: Zero-Day Detection
    **Purpose:** Flag unknown/novel attacks
    
    **Models Used:**
    - CICIDS Autoencoder (97.73% accuracy)
    - Trained ONLY on normal traffic
    - Flags 10-15% of traffic as suspicious
    
    **How it works:**
    - Learns what "normal" looks like
    - High reconstruction error = anomaly
    - No prior knowledge of attacks needed
    
    **Performance:**
    - 9.97% flagging rate (optimal range)
    - Catches zero-day threats
    - Low false positive rate
    """)

with col2:
    st.markdown("""
    #### Layer 1: Attack Classification
    **Purpose:** Identify specific attack types
    
    **Models Used (Parallel):**
    - CICIDS XGBoost (99.92%) - 52 features
    - IoT XGBoost (96.80%) - 39 features  
    - UNSW XGBoost (97.20%) - 48 features
    
    **How it works:**
    - ALL 3 models analyze ALL traffic
    - Weighted ensemble voting
    - Domain-aware trust scoring
    
    **Performance:**
    - 97.08% attack detection rate
    - <2% false positive rate
    - Real-time classification
    """)

st.markdown("""
#### Layer 2: Human Review Queue
**Purpose:** Handle uncertain cases + continuous learning

**Triggers:**
- Confidence < 70%
- Layer 0 and Layer 1 disagree
- Novel attack patterns

**Features:**
- Analyst labeling interface
- Model retraining pipeline
- Feedback loop for improvement
""")

st.markdown("---")

# Dataset information
st.markdown("### 📚 Training Datasets")

tab1, tab2, tab3 = st.tabs(["CICIDS2017", "CIC IoT 2023", "UNSW-NB15"])

with tab1:
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        **CICIDS2017**
        - **Source:** Canadian Institute for Cybersecurity
        - **Total Samples:** 2,520,751
        - **Features:** 52 network flow features
        - **Classes:** 7 (6 attack types + normal)
        - **Training Split:** 80/20 train/test
        
        **Attack Types:**
        - DoS (Denial of Service)
        - DDoS (Distributed DoS)
        - Port Scanning
        - Brute Force
        - Web Attacks
        - Botnet
        """)
    with col2:
        st.markdown("""
        **Performance:**
        - XGBoost: 99.92% ⭐ **BEST**
        - Random Forest: 99.88%
        - LightGBM: 98.96%
        - Neural Net: 98.49%
        - Autoencoder: 97.73%
        
        **Novel Discovery:**
        DoS attacks exhibit unique **210x amplification signature**:
        - Tiny forward packets
        - Massive backward responses
        - Enables >99% DoS detection
        """)

with tab2:
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        **CIC IoT 2023**
        - **Source:** Canadian Institute for Cybersecurity
        - **Total Samples:** 21,000,000+
        - **Features:** 39 IoT-specific features
        - **Focus:** IoT device security
        - **Devices:** 100+ IoT devices tested
        
        **Attack Types:**
        - DDoS (UDP/TCP/HTTP)
        - Mirai botnet
        - MITM attacks
        - IoT-specific scanning
        """)
    with col2:
        st.markdown("""
        **Performance:**
        - XGBoost: 96.80% ⭐ **BEST**
        - Random Forest: 95.20%
        - Autoencoder: 94.50%
        
        **Key Insight:**
        IoT attacks show distinct patterns from traditional network attacks:
        - Different protocol usage
        - Unique timing patterns
        - Device-specific vulnerabilities
        """)

with tab3:
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        **UNSW-NB15**
        - **Source:** University of New South Wales
        - **Total Samples:** 821,000+
        - **Features:** 48 network features
        - **Classes:** 10 (9 attack types + normal)
        - **Year:** 2015 (modern attacks)
        
        **Attack Types:**
        - Analysis, Backdoor
        - DoS, Exploits
        - Fuzzers, Generic
        - Reconnaissance
        - Shellcode, Worms
        """)
    with col2:
        st.markdown("""
        **Performance:**
        - Isolation Forest: 99.45% ⭐ **BEST (Unsupervised)**
        - XGBoost: 97.20%
        - Autoencoder: 96.80%
        
        **Key Insight:**
        Unsupervised methods (Isolation Forest) excel at detecting novel attack patterns without labeled training data
        """)

st.markdown("---")

# Visualizations
st.markdown("### 📈 Model Visualizations")

viz_tab1, viz_tab2, viz_tab3 = st.tabs(["Confusion Matrices", "ROC Curves", "Other Metrics"])

base_path = '/home/shared/IoT_Project/AI_Anomaly_Detection'

with viz_tab1:
    st.markdown("#### Confusion Matrices")
    
    # Check for available confusion matrices
    cm_files = []
    
    cicids_cm = os.path.join(base_path, 'cicds/results/autoencoder_confusion_matrix.png')
    if os.path.exists(cicids_cm):
        cm_files.append(('CICIDS Autoencoder', cicids_cm))
    
    if cm_files:
        cols = st.columns(min(2, len(cm_files)))
        for idx, (title, filepath) in enumerate(cm_files):
            with cols[idx % 2]:
                try:
                    img = Image.open(filepath)
                    st.image(img, caption=title, use_container_width=True)
                except Exception as e:
                    st.error(f"Error loading {title}: {e}")
    else:
        st.info("📊 Confusion matrices available in trained model results folders")
    
    st.markdown("""
    **Understanding Confusion Matrices:**
    - **True Positives:** Correctly identified attacks
    - **True Negatives:** Correctly identified normal traffic
    - **False Positives:** Normal traffic flagged as attack (minimize this!)
    - **False Negatives:** Missed attacks (critical to minimize)
    """)

with viz_tab2:
    st.markdown("#### ROC Curves (Receiver Operating Characteristic)")
    
    roc_files = []
    
    cicids_roc = os.path.join(base_path, 'cicds/results/autoencoder_roc_curve.png')
    if os.path.exists(cicids_roc):
        roc_files.append(('CICIDS Autoencoder', cicids_roc))
    
    cicids_roc_comp = os.path.join(base_path, 'cicds/results/anomaly_detection_roc_comparison.png')
    if os.path.exists(cicids_roc_comp):
        roc_files.append(('CICIDS ROC Comparison', cicids_roc_comp))
    
    if roc_files:
        for title, filepath in roc_files:
            try:
                img = Image.open(filepath)
                st.image(img, caption=title, use_container_width=True)
            except Exception as e:
                st.error(f"Error loading {title}: {e}")
    else:
        st.info("📈 ROC curves available in trained model results folders")
    
    st.markdown("""
    **Understanding ROC Curves:**
    - **AUC (Area Under Curve):** Higher is better (1.0 = perfect)
    - **Trade-off:** True Positive Rate vs False Positive Rate
    - **Optimal Point:** Top-left corner (high TPR, low FPR)
    - **Our Models:** AUC > 0.98 for most models
    """)

with viz_tab3:
    st.markdown("#### Additional Metrics & Comparisons")
    
    # Error distribution
    error_dist = os.path.join(base_path, 'cicds/results/autoencoder_error_distribution.png')
    if os.path.exists(error_dist):
        try:
            img = Image.open(error_dist)
            st.image(img, caption="CICIDS Autoencoder - Reconstruction Error Distribution", use_container_width=True)
            st.markdown("""
            **Reconstruction Error:**
            - Normal traffic: Low error (model reconstructs well)
            - Attack traffic: High error (unusual patterns)
            - Threshold: Automatically determined during training
            """)
        except Exception as e:
            st.error(f"Error loading visualization: {e}")
    
    # Training history
    iot_history = os.path.join(base_path, 'cic_iot_2023/results/autoencoder_training_history.png')
    if os.path.exists(iot_history):
        try:
            img = Image.open(iot_history)
            st.image(img, caption="IoT Autoencoder - Training History", use_container_width=True)
            st.markdown("""
            **Training Convergence:**
            - Early stopping used to prevent overfitting
            - Validation loss monitored
            - Typically converges in 30-50 epochs
            """)
        except Exception as e:
            st.error(f"Error loading visualization: {e}")
    
    # Model comparison
    comparison = os.path.join(base_path, 'cicds/results/anomaly_detection_comparison.png')
    if os.path.exists(comparison):
        try:
            img = Image.open(comparison)
            st.image(img, caption="Anomaly Detection Methods Comparison", use_container_width=True)
        except Exception as e:
            st.error(f"Error loading visualization: {e}")

st.markdown("---")

# Feature importance
st.markdown("### 🔍 Key Detection Features")

col1, col2 = st.columns(2)

with col1:
    st.markdown("""
    #### Most Important Features (CICIDS)
    
    **Top 5 for Attack Detection:**
    1. **Backward Packet Length Std** - DoS 210x signature
    2. **Packet Length Variance** - Attack pattern indicator
    3. **Flow Duration** - Abnormal connection times
    4. **Flow IAT Mean** - Inter-arrival time patterns
    5. **Packet Length Mean** - Average packet size anomalies
    
    **Why These Matter:**
    - DoS attacks: Massive variance in backward packets
    - DDoS: Short flow durations, high packet rates
    - Port Scanning: Predictable timing patterns
    """)

with col2:
    st.markdown("""
    #### Feature Categories
    
    **Flow-based (Timing):**
    - Duration, IAT (Inter-Arrival Time)
    - Flow rate metrics
    
    **Packet-based (Size):**
    - Length statistics (mean, std, max, min)
    - Header lengths
    
    **Protocol-based:**
    - TCP flags (SYN, FIN, RST, ACK)
    - Protocol counts
    
    **Directional:**
    - Forward vs Backward packets
    - Bidirectional flow analysis
    """)

st.markdown("---")

# Technical implementation
st.markdown("### 🔧 Technical Implementation")

col1, col2 = st.columns(2)

with col1:
    st.markdown("""
    **Hardware:**
    - **Server:** Dell GB10 Blackwell
    - **RAM:** 128GB LPDDR5X
    - **CPU:** 20 cores
    - **Storage:** 4TB SSD
    - **GPU:** NVIDIA Blackwell (for deep learning)
    
    **Software Stack:**
    - **Python:** 3.12
    - **ML Libraries:** scikit-learn, XGBoost, LightGBM
    - **Deep Learning:** TensorFlow 2.x / Keras
    - **Data Processing:** Pandas, NumPy
    - **Visualization:** Matplotlib, Seaborn, Plotly
    """)

with col2:
    st.markdown("""
    **Training Performance:**
    - **Total Time:** ~5 minutes (all 11 models)
    - **CICIDS:** ~2 minutes
    - **IoT:** ~2 minutes  
    - **UNSW:** ~1 minute
    
    **Optimization Techniques:**
    - Batch processing (10K samples/batch)
    - GPU acceleration (deep learning models)
    - Vectorized operations (NumPy/Pandas)
    - Early stopping (prevent overfitting)
    - Parallel training (multiple models simultaneously)
    """)

st.markdown("---")

# Production deployment
st.markdown("### 🚀 Production Deployment")

st.markdown("""
**Current Production Pipeline:**

```
Input: Network Traffic (PCAP or CSV)
    ↓
Feature Extraction: 147 universal features
    ↓
Feature Selection: Split to 52/39/48 per dataset
    ↓
Layer 0: CICIDS Autoencoder (zero-day detection)
    ↓ (10-15% flagged)
Layer 1: Ensemble Classification (3 XGBoost models in parallel)
    ↓ (weighted voting)
Layer 2: Human Review (uncertain cases)
    ↓
Output: Attack type, Threat level, Confidence score
```

**Performance Metrics:**
- **Throughput:** 7,000 flows/second
- **Latency:** <1ms per flow
- **Accuracy:** 97-99% depending on attack type
- **False Positive Rate:** <2%
""")

st.markdown("---")

# Model versioning
st.markdown("### 📦 Model Information")

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("""
    **Version:** 1.0.0  
    **Training Date:** January 2025  
    **Status:** ✅ Production  
    **Last Updated:** February 2025
    """)

with col2:
    st.markdown("""
    **Total Parameters:**
    - XGBoost models: ~10K trees each
    - Neural Network: ~50K parameters
    - Autoencoders: ~100K parameters
    """)

with col3:
    st.markdown("""
    **Model Sizes:**
    - XGBoost: ~50MB each
    - Neural Networks: ~5MB each
    - Autoencoders: ~20MB each
    - Total: ~300MB all models
    """)

st.markdown("---")

# Footer
st.markdown("""
<div style='text-align: center; color: #666; padding: 2rem 0;'>
    <p><strong>Model Performance Summary</strong></p>
    <p>11 trained models | 99.92% best accuracy | 7K flows/sec throughput</p>
    <p>Production-ready for enterprise deployment</p>
</div>
""", unsafe_allow_html=True)
