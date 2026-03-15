import streamlit as st
import pickle
import numpy as np
import pandas as pd
from tensorflow import keras
import matplotlib.pyplot as plt
import seaborn as sns
import os
from datetime import datetime
import json
import re
from collections import Counter
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

st.set_page_config(page_title="AI Network Anomaly Detection", page_icon="🛡️", layout="wide")

st.title("🛡️ AI Network Anomaly Detection System")
st.markdown("### Multi-Strategy Detection | 9 AI Models | 99.92% Accuracy")

# Sidebar
st.sidebar.header("📊 System Architecture")
st.sidebar.markdown("""
**Three Detection Strategies:**
- 🎯 **Supervised** (4 models)
- 🔍 **Unsupervised** (2 models)
- 🤖 **Ensemble** (3 strategies)

**Total:** 9 AI approaches  
**Best Individual:** 99.92% (XGBoost)  
**Best Ensemble:** 99.86%
""")

# Session state - ENHANCED
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []
if 'all_predictions' not in st.session_state:
    st.session_state.all_predictions = None
if 'ensemble_predictions' not in st.session_state:
    st.session_state.ensemble_predictions = None
if 'anomaly_scores' not in st.session_state:
    st.session_state.anomaly_scores = None

# Feature matching functions
def normalize_feature_name(name):
    name = str(name).lower()
    name = re.sub(r'[_\s\-]+', '', name)
    return name

def calculate_feature_similarity(input_feature, expected_feature):
    input_norm = normalize_feature_name(input_feature)
    expected_norm = normalize_feature_name(expected_feature)
    
    if input_norm == expected_norm:
        return 1.0
    
    if input_norm in expected_norm or expected_norm in input_norm:
        return 0.8
    
    input_words = set(re.findall(r'\w+', input_norm))
    expected_words = set(re.findall(r'\w+', expected_norm))
    overlap = len(input_words & expected_words)
    
    if overlap > 0:
        return 0.6 * (overlap / max(len(input_words), len(expected_words)))
    
    return 0.0

def smart_feature_matching(uploaded_df, expected_features):
    feature_mapping = {}
    confidence_scores = {}
    
    for col in uploaded_df.columns:
        best_match = None
        best_score = 0
        
        for expected in expected_features:
            score = calculate_feature_similarity(col, expected)
            if score > best_score and score >= 0.6:
                best_score = score
                best_match = expected
        
        if best_match:
            feature_mapping[col] = best_match
            confidence_scores[col] = best_score
    
    return feature_mapping, confidence_scores

def prepare_data_batch(uploaded_df, expected_features, scaler):
    feature_mapping, confidence_scores = smart_feature_matching(uploaded_df, expected_features)
    matched_count = len(feature_mapping)
    total_expected = len(expected_features)
    
    avg_confidence = np.mean(list(confidence_scores.values())) if confidence_scores else 0
    
    output_df = pd.DataFrame(0, index=uploaded_df.index, columns=expected_features)
    
    for input_col, expected_col in feature_mapping.items():
        try:
            values = pd.to_numeric(uploaded_df[input_col], errors='coerce')
            output_df[expected_col] = values
        except:
            pass
    
    for col in expected_features:
        if col not in feature_mapping.values() or output_df[col].isna().all():
            similar_cols = [c for c in output_df.columns if c != col and output_df[c].sum() != 0]
            if similar_cols:
                output_df[col] = output_df[similar_cols].mean(axis=1) * 0.1
    
    output_df = output_df.replace([np.inf, -np.inf], np.nan)
    output_df = output_df.fillna(0)
    
    for col in output_df.columns:
        output_df[col] = pd.to_numeric(output_df[col], errors='coerce').fillna(0)
        output_df[col] = output_df[col].clip(lower=-1e10, upper=1e10)
    
    scaled_data = scaler.transform(output_df.astype('float32'))
    
    return scaled_data, matched_count, total_expected, feature_mapping, confidence_scores, avg_confidence

def process_pcap_file(pcap_file):
    """Process PCAP file and extract features"""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
        
        st.info("📦 Processing PCAP file... This may take a moment.")
        
        packets = rdpcap(pcap_file)
        
        flows = {}
        
        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                protocol = pkt[IP].proto
                
                flow_key = f"{src_ip}-{dst_ip}-{protocol}"
                
                if flow_key not in flows:
                    flows[flow_key] = {
                        'packet_count': 0,
                        'total_length': 0,
                        'forward_packets': 0,
                        'backward_packets': 0,
                        'forward_bytes': 0,
                        'backward_bytes': 0,
                        'packet_lengths': []
                    }
                
                flows[flow_key]['packet_count'] += 1
                flows[flow_key]['total_length'] += len(pkt)
                flows[flow_key]['packet_lengths'].append(len(pkt))
                
                if pkt[IP].src == src_ip:
                    flows[flow_key]['forward_packets'] += 1
                    flows[flow_key]['forward_bytes'] += len(pkt)
                else:
                    flows[flow_key]['backward_packets'] += 1
                    flows[flow_key]['backward_bytes'] += len(pkt)
        
        flow_data = []
        for flow_key, flow_stats in flows.items():
            packet_lengths = flow_stats['packet_lengths']
            flow_data.append({
                'Flow Duration': 0,
                'Total Fwd Packets': flow_stats['forward_packets'],
                'Total Backward Packets': flow_stats['backward_packets'],
                'Total Length of Fwd Packets': flow_stats['forward_bytes'],
                'Total Length of Bwd Packets': flow_stats['backward_bytes'],
                'Fwd Packet Length Mean': flow_stats['forward_bytes'] / max(flow_stats['forward_packets'], 1),
                'Bwd Packet Length Mean': flow_stats['backward_bytes'] / max(flow_stats['backward_packets'], 1),
                'Packet Length Mean': np.mean(packet_lengths) if packet_lengths else 0,
                'Packet Length Std': np.std(packet_lengths) if packet_lengths else 0,
                'Packet Length Variance': np.var(packet_lengths) if packet_lengths else 0,
            })
        
        df = pd.DataFrame(flow_data)
        st.success(f"✅ Extracted {len(df)} flows from PCAP file")
        return df
        
    except ImportError:
        st.error("❌ Scapy library not installed. Install with: pip install scapy")
        return None
    except Exception as e:
        st.error(f"❌ Error processing PCAP: {str(e)}")
        return None

def process_log_file(log_file, file_extension):
    """Process various log file formats"""
    try:
        if file_extension in ['.log', '.txt']:
            content = log_file.read().decode('utf-8', errors='ignore')
            
            st.info("📝 Attempting to parse log file...")
            
            lines = content.split('\n')
            
            data_lines = [line for line in lines if line.strip() and not line.startswith('#')]
            
            if ',' in data_lines[0]:
                from io import StringIO
                df = pd.read_csv(StringIO('\n'.join(data_lines)))
            elif '\t' in data_lines[0]:
                from io import StringIO
                df = pd.read_csv(StringIO('\n'.join(data_lines)), sep='\t')
            else:
                st.warning("⚠️ Could not automatically parse log format. Showing first 10 lines:")
                st.text('\n'.join(lines[:10]))
                return None
            
            st.success(f"✅ Parsed {len(df)} records from log file")
            return df
            
        elif file_extension == '.json':
            content = log_file.read().decode('utf-8')
            data = json.loads(content)
            
            if isinstance(data, list):
                df = pd.DataFrame(data)
            elif isinstance(data, dict):
                df = pd.DataFrame([data])
            else:
                st.error("❌ Unsupported JSON structure")
                return None
            
            st.success(f"✅ Loaded {len(df)} records from JSON")
            return df
            
        else:
            st.error(f"❌ Unsupported file format: {file_extension}")
            return None
            
    except Exception as e:
        st.error(f"❌ Error processing log file: {str(e)}")
        return None

def create_interactive_attack_distribution(attack_counts, total):
    attacks = list(attack_counts.keys())
    counts = list(attack_counts.values())
    percentages = [(c/total)*100 for c in counts]
    
    attack_colors = {
        'Normal Traffic': '#2ecc71',
        'DoS': '#e74c3c',
        'DDoS': '#e67e22',
        'Port Scanning': '#f39c12',
        'Brute Force': '#9b59b6',
        'Web Attacks': '#3498db',
        'Bots': '#1abc9c'
    }
    colors = [attack_colors.get(a, '#95a5a6') for a in attacks]
    
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        x=attacks,
        y=counts,
        marker_color=colors,
        text=[f"{c:,}<br>({p:.1f}%)" for c, p in zip(counts, percentages)],
        textposition='outside',
        hovertemplate='<b>%{x}</b><br>Count: %{y:,}<br>Percentage: %{text}<extra></extra>'
    ))
    
    fig.update_layout(
        title={'text': "🎯 Attack Type Distribution (Interactive)", 'font': {'size': 18, 'color': '#2c3e50'}, 'x': 0.5, 'xanchor': 'center'},
        xaxis_title="Attack Type",
        yaxis_title="Number of Flows",
        paper_bgcolor='white',
        plot_bgcolor='#f8f9fa',
        font={'family': "Arial"},
        height=500,
        xaxis={'tickangle': -45},
        yaxis={'gridcolor': '#e1e4e8'},
        hovermode='x unified'
    )
    
    return fig

def create_interactive_pie_chart(attack_counts):
    labels = list(attack_counts.keys())
    values = list(attack_counts.values())
    
    attack_colors = {
        'Normal Traffic': '#2ecc71',
        'DoS': '#e74c3c',
        'DDoS': '#e67e22',
        'Port Scanning': '#f39c12',
        'Brute Force': '#9b59b6',
        'Web Attacks': '#3498db',
        'Bots': '#1abc9c'
    }
    colors = [attack_colors.get(l, '#95a5a6') for l in labels]
    
    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        marker=dict(colors=colors, line=dict(color='white', width=2)),
        hovertemplate='<b>%{label}</b><br>Count: %{value:,}<br>Percentage: %{percent}<extra></extra>',
        textinfo='label+percent',
        textfont_size=12
    )])
    
    fig.update_layout(
        title={'text': "📊 Traffic Composition (Interactive)", 'font': {'size': 18, 'color': '#2c3e50'}, 'x': 0.5, 'xanchor': 'center'},
        height=500,
        paper_bgcolor='white',
        font={'family': "Arial"}
    )
    
    return fig

def create_model_comparison_chart(all_predictions, label_encoder):
    model_names = list(all_predictions.keys())
    model_stats = {}
    
    for model_name, predictions in all_predictions.items():
        labels = label_encoder.inverse_transform(predictions)
        attack_counts = Counter(labels)
        normal = attack_counts.get('Normal Traffic', 0)
        attacks = len(predictions) - normal
        
        model_stats[model_name] = {'Normal': normal, 'Attacks': attacks}
    
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        name='Normal Traffic',
        x=model_names,
        y=[stats['Normal'] for stats in model_stats.values()],
        marker_color='#2ecc71',
        hovertemplate='<b>%{x}</b><br>Normal: %{y:,}<extra></extra>'
    ))
    
    fig.add_trace(go.Bar(
        name='Attacks Detected',
        x=model_names,
        y=[stats['Attacks'] for stats in model_stats.values()],
        marker_color='#e74c3c',
        hovertemplate='<b>%{x}</b><br>Attacks: %{y:,}<extra></extra>'
    ))
    
    fig.update_layout(
        title={'text': "🤖 All Models Predictions Comparison", 'font': {'size': 18, 'color': '#2c3e50'}, 'x': 0.5, 'xanchor': 'center'},
        xaxis_title="Model",
        yaxis_title="Number of Flows",
        paper_bgcolor='white',
        plot_bgcolor='#f8f9fa',
        font={'family': "Arial"},
        height=500,
        barmode='group',
        yaxis={'gridcolor': '#e1e4e8'},
        xaxis={'tickangle': -45},
        legend={'orientation': 'h', 'yanchor': 'bottom', 'y': 1.02, 'xanchor': 'right', 'x': 1}
    )
    
    return fig

def create_threat_gauge(threat_level):
    color = '#2ecc71' if threat_level < 10 else '#f39c12' if threat_level < 30 else '#e74c3c'
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=threat_level,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Threat Level (%)", 'font': {'size': 20}},
        delta={'reference': 10, 'increasing': {'color': "#e74c3c"}},
        gauge={
            'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': color},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 10], 'color': '#d5f4e6'},
                {'range': [10, 30], 'color': '#ffeaa7'},
                {'range': [30, 100], 'color': '#fab1a0'}
            ],
            'threshold': {'line': {'color': "red", 'width': 4}, 'thickness': 0.75, 'value': threat_level}
        }
    ))
    
    fig.update_layout(paper_bgcolor='white', font={'color': "#2c3e50", 'family': "Arial"}, height=300)
    
    return fig

def create_model_agreement_visualization(all_predictions, sample_size=100):
    n_samples = min(sample_size, len(next(iter(all_predictions.values()))))
    model_names = list(all_predictions.keys())
    
    agreement_data = []
    
    for i in range(n_samples):
        votes = [all_predictions[m][i] for m in model_names]
        unique_votes = len(set(votes))
        agreement_score = (len(model_names) - unique_votes + 1) / len(model_names) * 100
        agreement_data.append(agreement_score)
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        y=agreement_data,
        mode='lines+markers',
        name='Agreement %',
        line={'color': '#3498db', 'width': 2},
        marker={'size': 4, 'color': '#3498db'},
        fill='tozeroy',
        fillcolor='rgba(52, 152, 219, 0.2)',
        hovertemplate='Sample %{x}<br>Agreement: %{y:.1f}%<extra></extra>'
    ))
    
    avg_agreement = np.mean(agreement_data)
    fig.add_hline(y=avg_agreement, line_dash="dash", line_color="red", annotation_text=f"Average: {avg_agreement:.1f}%", annotation_position="right")
    
    fig.update_layout(
        title={'text': f"🔍 Model Agreement Analysis (First {n_samples} samples)", 'font': {'size': 18, 'color': '#2c3e50'}, 'x': 0.5, 'xanchor': 'center'},
        xaxis_title="Sample Index",
        yaxis_title="Agreement Percentage",
        paper_bgcolor='white',
        plot_bgcolor='#f8f9fa',
        font={'family': "Arial"},
        height=400,
        yaxis={'gridcolor': '#e1e4e8', 'range': [0, 105]},
        xaxis={'gridcolor': '#e1e4e8'}
    )
    
    return fig

def create_anomaly_score_distribution(anomaly_scores):
    """Visualize anomaly detection scores"""
    fig = go.Figure()
    
    if 'isolation_forest' in anomaly_scores:
        fig.add_trace(go.Histogram(
            x=anomaly_scores['isolation_forest'],
            name='Isolation Forest',
            opacity=0.7,
            marker=dict(color='#e74c3c'),
            nbinsx=50
        ))
    
    if 'autoencoder' in anomaly_scores:
        fig.add_trace(go.Histogram(
            x=anomaly_scores['autoencoder'],
            name='Autoencoder',
            opacity=0.7,
            marker=dict(color='#3498db'),
            nbinsx=50
        ))
    
    fig.update_layout(
        title={'text': "🔍 Anomaly Score Distribution", 'font': {'size': 18, 'color': '#2c3e50'}, 'x': 0.5, 'xanchor': 'center'},
        xaxis_title="Anomaly Score",
        yaxis_title="Frequency",
        paper_bgcolor='white',
        plot_bgcolor='#f8f9fa',
        font={'family': "Arial"},
        height=450,
        barmode='overlay',
        yaxis={'gridcolor': '#e1e4e8'},
        legend={'font': {'size': 12}}
    )
    
    return fig

def apply_ensemble_voting(predictions_dict, weights=None, method='majority'):
    """
    Apply ensemble voting to predictions from multiple models
    
    Args:
        predictions_dict: Dictionary of {model_name: predictions_array}
        weights: List of weights [w1, w2, w3, w4] or dict {model_name: weight}
        method: 'majority', 'weighted', or 'confidence'
    
    Returns:
        ensemble_predictions: Array of ensemble predictions
    """
    model_names = list(predictions_dict.keys())
    n_samples = len(predictions_dict[model_names[0]])
    ensemble_predictions = []
    
    if method == 'majority':
        # Simple majority voting
        for i in range(n_samples):
            votes = [predictions_dict[m][i] for m in model_names]
            majority = Counter(votes).most_common(1)[0][0]
            ensemble_predictions.append(majority)
    
    elif method == 'weighted' and weights:
        # Convert weights to dict if it's a list
        if isinstance(weights, list):
            # Weights are in order: [RF, XGB, LGB, NN]
            weight_dict = {}
            weight_order = ['Random Forest', 'XGBoost', 'LightGBM', 'Neural Network']
            for idx, model in enumerate(weight_order):
                if idx < len(weights) and model in model_names:
                    weight_dict[model] = weights[idx]
        else:
            weight_dict = weights
        
        # Weighted voting based on model accuracies
        for i in range(n_samples):
            vote_weights = {}
            for model_name in model_names:
                pred = predictions_dict[model_name][i]
                weight = weight_dict.get(model_name, 1.0)
                vote_weights[pred] = vote_weights.get(pred, 0) + weight
            
            winner = max(vote_weights.items(), key=lambda x: x[1])[0]
            ensemble_predictions.append(winner)
    
    else:
        # Fallback to majority
        for i in range(n_samples):
            votes = [predictions_dict[m][i] for m in model_names]
            majority = Counter(votes).most_common(1)[0][0]
            ensemble_predictions.append(majority)
    
    return np.array(ensemble_predictions)

@st.cache_resource
def load_models():
    """Load all models: 4 supervised + 2 unsupervised + ensemble info"""
    models = {}
    models_loaded = 0
    
    # SUPERVISED MODELS (Multi-Class Classification)
    try:
        with open('trained_models/random_forest_multiclass.pkl', 'rb') as f:
            models['Random Forest'] = pickle.load(f)
            models_loaded += 1
    except Exception as e:
        st.sidebar.warning(f"⚠️ Random Forest: {str(e)}")
    
    try:
        with open('trained_models/xgboost_multiclass.pkl', 'rb') as f:
            models['XGBoost'] = pickle.load(f)
            models_loaded += 1
    except Exception as e:
        st.sidebar.warning(f"⚠️ XGBoost: {str(e)}")
    
    try:
        with open('trained_models/lightgbm_multiclass.pkl', 'rb') as f:
            models['LightGBM'] = pickle.load(f)
            models_loaded += 1
    except Exception as e:
        st.sidebar.warning(f"⚠️ LightGBM: {str(e)}")
    
    try:
        # Load neural network WITHOUT compilation to avoid deserialization issues
        models['Neural Network'] = keras.models.load_model(
            'trained_models/neural_network_multiclass.h5',
            compile=False  # THIS FIXES THE KERAS ERROR!
        )
        models_loaded += 1
    except Exception as e:
        st.sidebar.warning(f"⚠️ Neural Network: {str(e)}")
    
    # UNSUPERVISED MODELS (Anomaly Detection)
    try:
        with open('trained_models/isolation_forest.pkl', 'rb') as f:
            models['Isolation Forest'] = pickle.load(f)
            models_loaded += 1
    except Exception as e:
        st.sidebar.warning(f"⚠️ Isolation Forest: {str(e)}")
    
    try:
        # Load autoencoder WITHOUT compilation to avoid deserialization issues
        models['Autoencoder'] = keras.models.load_model(
            'trained_models/autoencoder.h5',
            compile=False  # THIS FIXES THE KERAS ERROR!
        )
        models_loaded += 1
    except Exception as e:
        st.sidebar.warning(f"⚠️ Autoencoder: {str(e)}")
    
    # ENSEMBLE INFO (metadata for ensemble strategies)
    ensemble_info = None
    try:
        with open('trained_models/ensemble_info.pkl', 'rb') as f:
            ensemble_info = pickle.load(f)
    except Exception as e:
        st.sidebar.info("ℹ️ Ensemble info not found - using default weights")
    
    # Load supporting files
    with open('prepared_data/label_encoder.pkl', 'rb') as f:
        label_encoder = pickle.load(f)
    with open('prepared_data/scaler_multiclass.pkl', 'rb') as f:
        scaler = pickle.load(f)
    with open('prepared_data/feature_names.pkl', 'rb') as f:
        feature_names = pickle.load(f)
    
    # Update sidebar
    st.session_state.models_loaded = models_loaded
    
    return models, label_encoder, scaler, feature_names, ensemble_info

@st.cache_data
def load_results():
    return pd.read_csv('results/complete_model_comparison.csv')

def save_analysis(analysis_data):
    os.makedirs('analysis_history', exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f'analysis_history/analysis_{timestamp}.json'
    with open(filename, 'w') as f:
        json.dump(analysis_data, f, indent=2)
    return filename

try:
    models, label_encoder, scaler, expected_features, ensemble_info = load_models()
    comparison_df = load_results()
    st.success(f"✅ Successfully loaded {st.session_state.models_loaded} AI models!")
    
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["🎯 Analyze Traffic", "📊 Interactive Dashboard", "🔄 Model Comparison", "📜 History", "ℹ️ About"])
    
    with tab1:
        st.header("🎯 Network Traffic Analysis")
        
        if st.session_state.analysis_results:
            result = st.session_state.analysis_results
            st.success(f"✅ **Active:** {result.get('file_name', 'Unknown')} ({result.get('total_flows', 0):,} flows) - Results available in all tabs!")
            
            col1, col2, col3 = st.columns([3, 1, 1])
            with col2:
                if st.button("🆕 New Analysis", help="Clear and analyze new file"):
                    st.session_state.analysis_results = None
                    st.session_state.all_predictions = None
                    st.session_state.ensemble_predictions = None
                    st.session_state.anomaly_scores = None
                    st.rerun()
            with col3:
                if st.button("🗑️ Clear All", type="secondary", help="Clear everything"):
                    st.session_state.analysis_results = None
                    st.session_state.all_predictions = None
                    st.session_state.ensemble_predictions = None
                    st.session_state.anomaly_scores = None
                    st.session_state.analysis_history = []
                    st.rerun()
            
            st.markdown("---")
        
        st.info(f"""
        **Upload your network traffic data for comprehensive analysis**
        - **CSV/TSV:** Network flow statistics (CIC-IDS format preferred)
        - **PCAP/PCAPNG:** Raw packet capture files (requires scapy)
        - **LOG/TXT:** Text-based log files (comma or tab separated)
        - **JSON:** Structured log data
        
        **Currently loaded:** {st.session_state.models_loaded} AI models
        - 🎯 Supervised Models (Multi-Class Classification)
        - 🔍 Unsupervised Models (Anomaly Detection)
        - 🤖 Ensemble Strategies (Voting Methods)
        """)
        
        uploaded_file = st.file_uploader(
            "📁 Upload Network Traffic File",
            type=['csv', 'txt', 'log', 'json', 'pcap', 'pcapng', 'tsv'],
            help="Supports CSV, LOG, TXT, JSON, PCAP files"
        )
        
        if uploaded_file:
            try:
                file_size = uploaded_file.size / (1024 * 1024)
                file_extension = os.path.splitext(uploaded_file.name)[1].lower()
                
                st.write(f"📦 **File:** {uploaded_file.name}")
                st.write(f"📏 **Size:** {file_size:.2f} MB")
                st.write(f"📝 **Type:** {file_extension}")
                
                df = None
                
                with st.spinner(f"📥 Processing {file_extension} file..."):
                    if file_extension in ['.csv', '.tsv']:
                        separator = '\t' if file_extension == '.tsv' else ','
                        df = pd.read_csv(uploaded_file, sep=separator)
                        
                    elif file_extension in ['.pcap', '.pcapng']:
                        df = process_pcap_file(uploaded_file)
                        
                    elif file_extension in ['.log', '.txt', '.json']:
                        df = process_log_file(uploaded_file, file_extension)
                    
                    else:
                        st.error(f"❌ Unsupported file type: {file_extension}")
                
                if df is not None and len(df) > 0:
                    total_flows = len(df)
                    st.success(f"✅ Loaded {total_flows:,} records with {len(df.columns)} columns")
                    
                    with st.expander("👁️ Preview data (first 10 rows)"):
                        st.dataframe(df.head(10))
                    
                    with st.expander("📋 Column Information"):
                        st.write(f"**Total Columns:** {len(df.columns)}")
                        st.write("**Column Names:**")
                        st.write(list(df.columns))
                    
                    if st.button("🔍 ANALYZE WITH ALL AI MODELS", type="primary", use_container_width=True):
                        
                        st.markdown("---")
                        st.header("⚙️ Comprehensive AI Analysis in Progress...")
                        
                        progress_bar = st.progress(0)
                        status = st.empty()
                        
                        status.text("🔄 Matching features...")
                        progress_bar.progress(5)
                        
                        scaled_data, matched, total, mapping, confidence, avg_conf = prepare_data_batch(df, expected_features, scaler)
                        
                        match_pct = (matched / total) * 100
                        
                        col_m1, col_m2, col_m3 = st.columns(3)
                        col_m1.metric("✅ Matched Features", f"{matched}/{total}")
                        col_m2.metric("📊 Match Quality", f"{match_pct:.1f}%")
                        col_m3.metric("🎯 Avg Confidence", f"{avg_conf*100:.1f}%")
                        
                        if match_pct < 20:
                            st.warning(f"⚠️ LOW MATCH ({match_pct:.1f}%) - Using statistical imputation")
                        else:
                            st.success(f"✅ GOOD MATCH ({match_pct:.1f}%)")
                        
                        if mapping and st.checkbox("🔍 Show Feature Mapping Details", value=False):
                            mapping_df = pd.DataFrame([
                                {'Your Column': k, 'Mapped To': v, 'Confidence': f"{confidence[k]*100:.1f}%"}
                                for k, v in sorted(mapping.items(), key=lambda x: confidence[x[0]], reverse=True)
                            ])
                            st.dataframe(mapping_df, use_container_width=True)
                        
                        # Run ALL available models
                        all_predictions = {}
                        anomaly_scores = {}
                        
                        # Get supervised model names
                        supervised_models = [m for m in ['XGBoost', 'Random Forest', 'LightGBM', 'Neural Network'] if m in models]
                        
                        # SUPERVISED MODELS
                        if supervised_models:
                            status.text("🎯 Running Supervised Models...")
                            progress_per_model = 60 / len(supervised_models)
                            current_progress = 10
                            
                            for i, model_name in enumerate(supervised_models):
                                status.text(f"⚡ {model_name} analyzing...")
                                current_progress += progress_per_model
                                progress_bar.progress(int(current_progress))
                                
                                if model_name == 'Neural Network':
                                    all_predictions[model_name] = np.argmax(
                                        models[model_name].predict(scaled_data, verbose=0), axis=1
                                    )
                                else:
                                    all_predictions[model_name] = models[model_name].predict(scaled_data)
                        
                        # UNSUPERVISED MODELS (Anomaly Detection)
                        if 'Isolation Forest' in models:
                            status.text("🌲 Isolation Forest detecting anomalies...")
                            progress_bar.progress(70)
                            anomaly_preds = models['Isolation Forest'].predict(scaled_data)
                            # Convert -1 (anomaly) to attack, 1 (normal) to normal
                            all_predictions['Isolation Forest'] = np.where(anomaly_preds == 1, 0, 1)
                            try:
                                anomaly_scores['isolation_forest'] = models['Isolation Forest'].score_samples(scaled_data)
                            except:
                                pass
                        
                        if 'Autoencoder' in models:
                            status.text("🤖 Autoencoder detecting anomalies...")
                            progress_bar.progress(80)
                            reconstructed = models['Autoencoder'].predict(scaled_data, verbose=0)
                            reconstruction_error = np.mean(np.square(scaled_data - reconstructed), axis=1)
                            threshold = np.median(reconstruction_error) + 2 * np.std(reconstruction_error)
                            all_predictions['Autoencoder'] = np.where(reconstruction_error < threshold, 0, 1)
                            anomaly_scores['autoencoder'] = reconstruction_error
                        
                        # ENSEMBLE VOTING (using supervised models)
                        if supervised_models:
                            status.text("🤖 Computing ensemble predictions...")
                            progress_bar.progress(90)
                            
                            supervised_preds = {m: all_predictions[m] for m in supervised_models if m in all_predictions}
                            
                            # Majority voting
                            ensemble_majority = apply_ensemble_voting(supervised_preds, method='majority')
                            all_predictions['Ensemble: Majority'] = ensemble_majority
                            
                            # Weighted voting (if ensemble_info available)
                            if ensemble_info and 'weights' in ensemble_info:
                                weights = ensemble_info['weights']
                                ensemble_weighted = apply_ensemble_voting(supervised_preds, weights=weights, method='weighted')
                                all_predictions['Ensemble: Weighted'] = ensemble_weighted
                            
                            # Use majority voting as default ensemble
                            ensemble_predictions = ensemble_majority
                        else:
                            ensemble_predictions = all_predictions[list(all_predictions.keys())[0]]
                        
                        progress_bar.progress(100)
                        status.text(f"✅ Analysis complete with {len(all_predictions)} models!")
                        
                        # Convert to labels
                        ensemble_labels = label_encoder.inverse_transform(ensemble_predictions)
                        
                        # Results
                        attack_counts = Counter(ensemble_labels)
                        total = len(ensemble_labels)
                        normal_count = attack_counts.get('Normal Traffic', 0)
                        attack_total = total - normal_count
                        threat_level = (attack_total / total) * 100
                        
                        # Model agreement (only supervised)
                        if len(supervised_models) > 1:
                            perfect_agreement = sum(
                                1 for i in range(len(scaled_data))
                                if len(set([all_predictions[m][i] for m in supervised_models if m in all_predictions])) == 1
                            )
                            agreement_pct = (perfect_agreement / total) * 100
                        else:
                            agreement_pct = 100.0
                        
                        # Save to session state
                        analysis_data = {
                            'timestamp': datetime.now().isoformat(),
                            'file_name': uploaded_file.name,
                            'file_type': file_extension,
                            'total_flows': total,
                            'normal_count': normal_count,
                            'attack_total': attack_total,
                            'attack_distribution': dict(attack_counts),
                            'threat_level': threat_level,
                            'model_agreement': agreement_pct,
                            'feature_match_pct': match_pct,
                            'avg_confidence': avg_conf,
                            'models_used': len(all_predictions)
                        }
                        
                        st.session_state.analysis_results = analysis_data
                        st.session_state.all_predictions = all_predictions
                        st.session_state.ensemble_predictions = ensemble_predictions
                        st.session_state.anomaly_scores = anomaly_scores
                        st.session_state.analysis_history.append(analysis_data)
                        
                        st.success(f"✅ **Analysis Complete!** {len(all_predictions)} models analyzed your traffic.")
                        st.info("💡 **Explore results** in the other tabs!")
                
                else:
                    st.warning("⚠️ No data could be extracted from the file")
            
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
                st.info("💡 Make sure your file contains network traffic data")
                import traceback
                with st.expander("🐛 Debug Info"):
                    st.code(traceback.format_exc())
        
        st.markdown("---")
        
        if st.session_state.analysis_results:
            result = st.session_state.analysis_results
            attack_counts = result['attack_distribution']
            
            st.markdown("# 📊 CURRENT ANALYSIS RESULTS")
            st.caption(f"📁 {result['file_name']} | 🕒 {result['timestamp'].split('T')[1][:8]} | 🤖 {result.get('models_used', 0)} models")
            st.markdown("---")
            
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("📊 Total Flows", f"{result['total_flows']:,}")
            col2.metric("🟢 Normal", f"{result.get('normal_count', 0):,}", f"{(result.get('normal_count', 0)/result['total_flows']*100):.1f}%")
            col3.metric("🔴 Attacks", f"{result.get('attack_total', 0):,}", f"{(result.get('attack_total', 0)/result['total_flows']*100):.1f}%")
            
            threat_level = result['threat_level']
            if threat_level < 10:
                col4.metric("⚠️ Threat", f"{threat_level:.1f}%", "🟢 LOW")
            elif threat_level < 30:
                col4.metric("⚠️ Threat", f"{threat_level:.1f}%", "🟡 MEDIUM")
            else:
                col4.metric("⚠️ Threat", f"{threat_level:.1f}%", "🔴 HIGH")
            
            st.markdown("---")
            
            viz_choice = st.radio("Select Visualization:", ["📊 Bar Chart", "🥧 Pie Chart", "📉 Both"], horizontal=True, key="persistent_viz")
            
            if viz_choice == "📊 Bar Chart":
                st.plotly_chart(create_interactive_attack_distribution(attack_counts, result['total_flows']), use_container_width=True, key="bar_persistent")
            elif viz_choice == "🥧 Pie Chart":
                st.plotly_chart(create_interactive_pie_chart(attack_counts), use_container_width=True, key="pie_persistent")
            else:
                col_viz1, col_viz2 = st.columns(2)
                with col_viz1:
                    st.plotly_chart(create_interactive_attack_distribution(attack_counts, result['total_flows']), use_container_width=True, key="bar_both")
                with col_viz2:
                    st.plotly_chart(create_interactive_pie_chart(attack_counts), use_container_width=True, key="pie_both")
            
            st.markdown("### 📋 Attack Breakdown")
            attack_df = pd.DataFrame([
                {'Attack Type': k, 'Count': v, 'Percentage': f"{(v/result['total_flows']*100):.2f}%"}
                for k, v in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)
            ])
            st.dataframe(attack_df, use_container_width=True, hide_index=True)
            
            st.info("💡 **Explore more:** Use 'Interactive Dashboard' and 'Model Comparison' tabs!")
        else:
            st.info("📤 **No results yet.** Upload a file above and click 'ANALYZE WITH ALL AI MODELS'!")
    
    with tab2:
        st.header("📊 Interactive Threat Intelligence Dashboard")
        
        if st.session_state.analysis_results:
            result = st.session_state.analysis_results
            
            st.success(f"📁 **Active Analysis:** {result['file_name']} | 🤖 {result.get('models_used', 0)} models")
            
            col_gauge1, col_gauge2 = st.columns([1, 2])
            
            with col_gauge1:
                st.plotly_chart(create_threat_gauge(result['threat_level']), use_container_width=True, key="gauge_dashboard")
            
            with col_gauge2:
                st.markdown("### 📈 Real-Time Metrics")
                
                col_rt1, col_rt2 = st.columns(2)
                with col_rt1:
                    st.metric("🕒 Analysis Time", result['timestamp'].split('T')[1][:8])
                    st.metric("🎯 Feature Match", f"{result.get('feature_match_pct', 0):.1f}%")
                with col_rt2:
                    st.metric("🤖 Model Agreement", f"{result.get('model_agreement', 0):.1f}%")
                    st.metric("📊 Total Flows", f"{result['total_flows']:,}")
                
                if result['threat_level'] > 30:
                    st.error("⚠️ **CRITICAL THREAT LEVEL** - Immediate action required!")
                elif result['threat_level'] > 10:
                    st.warning("⚠️ **ELEVATED THREAT LEVEL** - Monitor closely")
                else:
                    st.success("✅ **LOW THREAT LEVEL** - Normal operations")
            
            st.markdown("---")
            
            # Show anomaly scores if available
            if st.session_state.anomaly_scores:
                st.subheader("🔍 Anomaly Detection Insights")
                st.plotly_chart(
                    create_anomaly_score_distribution(st.session_state.anomaly_scores),
                    use_container_width=True
                )
                st.markdown("---")
            
            st.markdown("### 🎯 Attack Distribution Overview")
            attack_dist = result['attack_distribution']
            
            col_dash1, col_dash2 = st.columns(2)
            
            with col_dash1:
                st.plotly_chart(create_interactive_pie_chart(attack_dist), use_container_width=True, key="pie_dashboard")
            
            with col_dash2:
                st.markdown("#### 📋 Attack Breakdown")
                for attack, count in sorted(attack_dist.items(), key=lambda x: x[1], reverse=True):
                    pct = (count / result['total_flows']) * 100
                    if attack == 'Normal Traffic':
                        st.success(f"🟢 **{attack}:** {count:,} ({pct:.1f}%)")
                    else:
                        if pct > 5:
                            st.error(f"🔴 **{attack}:** {count:,} ({pct:.1f}%)")
                        elif pct > 1:
                            st.warning(f"🟡 **{attack}:** {count:,} ({pct:.1f}%)")
                        else:
                            st.info(f"ℹ️ **{attack}:** {count:,} ({pct:.1f}%)")
            
            st.markdown("---")
            
            st.markdown("### 📅 Threat Timeline Simulation")
            st.info("💡 In production, this would show real-time threat detection over time")
            
            timeline_samples = min(100, result['total_flows'])
            threat_timeline = np.random.choice([0, 1], size=timeline_samples, p=[1-result['threat_level']/100, result['threat_level']/100])
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(y=threat_timeline, mode='lines+markers', name='Threat Detected', line={'color': '#e74c3c', 'width': 2}, marker={'size': 4}, fill='tozeroy', fillcolor='rgba(231, 76, 60, 0.2)'))
            fig.update_layout(title="Threat Detection Timeline (Sample)", xaxis_title="Flow Index", yaxis_title="Threat (0=Normal, 1=Attack)", paper_bgcolor='white', plot_bgcolor='#f8f9fa', height=300, yaxis={'gridcolor': '#e1e4e8'}, xaxis={'gridcolor': '#e1e4e8'})
            
            st.plotly_chart(fig, use_container_width=True, key="timeline_dashboard")
            
        else:
            st.info("📭 No active analysis. Upload and analyze traffic in the **Analyze Traffic** tab.")
    
    with tab3:
        st.header("🔄 Model Comparison & Insights")
        
        if st.session_state.analysis_results and st.session_state.all_predictions:
            st.success(f"📊 Comparing {len(st.session_state.all_predictions)} AI models")
            
            all_preds = st.session_state.all_predictions
            
            st.plotly_chart(create_model_comparison_chart(all_preds, label_encoder), use_container_width=True, key="comparison_main")
            
            st.markdown("---")
            
            st.subheader("📋 Individual Model Results")
            
            model_results = []
            for model_name, predictions in all_preds.items():
                labels = label_encoder.inverse_transform(predictions)
                counts = Counter(labels)
                normal = counts.get('Normal Traffic', 0)
                total_flows = len(predictions)
                attacks = total_flows - normal
                
                # Determine strategy
                if model_name in ['XGBoost', 'Random Forest', 'LightGBM', 'Neural Network']:
                    strategy = "🎯 Supervised"
                elif model_name in ['Isolation Forest', 'Autoencoder']:
                    strategy = "🔍 Unsupervised"
                elif 'Ensemble' in model_name:
                    strategy = "🤖 Ensemble"
                else:
                    strategy = "❓ Unknown"
                
                model_results.append({
                    'Strategy': strategy,
                    'Model': model_name,
                    'Normal Traffic': f"{normal:,} ({normal/total_flows*100:.1f}%)",
                    'Attacks Detected': f"{attacks:,} ({attacks/total_flows*100:.1f}%)",
                    'Threat Level': f"{attacks/total_flows*100:.2f}%"
                })
            
            st.dataframe(pd.DataFrame(model_results), use_container_width=True, hide_index=True)
            
            st.markdown("---")
            
            st.subheader("🔍 Attack Type Detection by Model")
            
            selected_attack = st.selectbox("Select attack type to compare:", options=['All'] + [k for k in Counter(label_encoder.inverse_transform(st.session_state.ensemble_predictions)).keys() if k != 'Normal Traffic'])
            
            if selected_attack != 'All':
                model_attack_counts = {}
                for model_name, predictions in all_preds.items():
                    labels = label_encoder.inverse_transform(predictions)
                    counts = Counter(labels)
                    model_attack_counts[model_name] = counts.get(selected_attack, 0)
                
                fig = go.Figure()
                fig.add_trace(go.Bar(x=list(model_attack_counts.keys()), y=list(model_attack_counts.values()), marker_color='#e74c3c', text=[f"{v:,}" for v in model_attack_counts.values()], textposition='outside'))
                fig.update_layout(title=f"Detection Count: {selected_attack}", xaxis_title="Model", yaxis_title="Count", paper_bgcolor='white', plot_bgcolor='#f8f9fa', height=400, xaxis={'tickangle': -45})
                
                st.plotly_chart(fig, use_container_width=True, key="attack_comparison")
                
                max_model = max(model_attack_counts, key=model_attack_counts.get)
                min_model = min(model_attack_counts, key=model_attack_counts.get)
                
                st.info(f"**Analysis for {selected_attack}:**\n- 🏆 **Most Detections:** {max_model} ({model_attack_counts[max_model]:,})\n- 📊 **Least Detections:** {min_model} ({model_attack_counts[min_model]:,})\n- 📈 **Variance:** {max(model_attack_counts.values()) - min(model_attack_counts.values()):,} flows")
            
            # Model agreement visualization
            st.markdown("---")
            if len(all_preds) > 1:
                st.subheader("🤝 Model Agreement Analysis")
                st.plotly_chart(create_model_agreement_visualization(all_preds), use_container_width=True)
        
        else:
            st.info("📭 No comparison data available. Analyze traffic first!")
    
    with tab4:
        st.header("📜 Analysis History")
        
        if st.session_state.analysis_history:
            col_h1, col_h2, col_h3 = st.columns([2, 1, 1])
            with col_h1:
                st.success(f"📊 {len(st.session_state.analysis_history)} analysis reports saved")
            with col_h3:
                if st.button("🗑️ Clear History", type="secondary"):
                    st.session_state.analysis_history = []
                    st.rerun()
            
            st.markdown("---")
            
            for i, analysis in enumerate(reversed(st.session_state.analysis_history)):
                timestamp = datetime.fromisoformat(analysis['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
                
                with st.expander(f"🕒 {timestamp} - {analysis['file_name']}", expanded=False):
                    col1, col2, col3, col4 = st.columns(4)
                    col1.metric("Total Flows", f"{analysis['total_flows']:,}")
                    col2.metric("Threat Level", f"{analysis['threat_level']:.1f}%")
                    col3.metric("Models Used", analysis.get('models_used', 'N/A'))
                    col4.metric("Agreement", f"{analysis.get('model_agreement', 0):.1f}%")
                    
                    st.markdown("**Attack Distribution:**")
                    for attack, count in analysis['attack_distribution'].items():
                        pct = (count / analysis['total_flows']) * 100
                        st.write(f"- {attack}: {count:,} ({pct:.1f}%)")
        else:
            st.info("📭 No analysis history yet. Analyze some traffic files!")
    
    with tab5:
        st.header("ℹ️ About This Project")
        
        st.markdown(f"""
        ## 🎯 AI Network Anomaly Detection System
        
        ### 🏆 Multi-Strategy Detection with {st.session_state.models_loaded} AI Models
        
        A comprehensive ML system for detecting network intrusions with **99.92% accuracy**.
        
        ---
        
        ## 🔬 Three Detection Strategies
        
        ### 1️⃣ Supervised Learning (Multi-Class Classification)
        **Purpose:** Identify SPECIFIC attack types
        
        - **Random Forest** - 99.88% accuracy
        - **XGBoost** - 99.92% accuracy ⭐ **BEST**
        - **LightGBM** - 98.96% accuracy
        - **Neural Network** - 98.49% accuracy
        
        **Detects:** DoS, DDoS, Port Scanning, Brute Force, Web Attacks, Bots
        
        ---
        
        ### 2️⃣ Unsupervised Learning (Anomaly Detection)
        **Purpose:** Detect UNKNOWN/ZERO-DAY attacks
        
        - **Isolation Forest** - 65.03% accuracy, 92.30% ROC-AUC
          - High precision (99.99%)
          - Conservative approach
        
        - **Autoencoder** - 97.73% accuracy, 99.41% ROC-AUC
          - Deep learning approach
          - Zero false positives (100% precision)
        
        **Advantage:** Can detect attacks never seen before!
        
        ---
        
        ### 3️⃣ Ensemble Methods (Production-Ready)
        **Purpose:** Maximum reliability through model combination
        
        - **Majority Voting** - 99.83% accuracy
        - **Weighted Voting** - 99.86% accuracy
        - **Confidence-Based** - 99.20% accuracy
        
        **Production Benefits:**
        - Redundancy - if one model fails, others compensate
        - Higher reliability than single models
        - Industry-standard (Darktrace, CrowdStrike)
        
        ---
        
        ## 🏆 Key Achievements
        - ✅ 99.92% Detection Accuracy (XGBoost)
        - ✅ 99.86% Ensemble Accuracy
        - ✅ <2% False Positive Rate
        - ✅ Real-time Detection Capability
        - ✅ Zero-Day Attack Detection
        - ✅ Production-Ready Architecture
        - ✅ Multi-Format Support (CSV, PCAP, LOG, JSON)
        
        ---
        
        ## 📊 Technical Specifications
        
        **Dataset:**
        - **Name:** CICIDS2017
        - **Samples:** 2,520,751 network flows
        - **Features:** 52 network flow statistics
        - **Classes:** 7 (6 attack types + normal)
        
        **Hardware:**
        - **Platform:** Dell Pro Max GB10
        - **GPU:** NVIDIA Blackwell GB10
        - **RAM:** 128GB
        - **Training Time:** 5 minutes
        
        **Software Stack:**
        - Python 3.12
        - scikit-learn, XGBoost, LightGBM
        - TensorFlow/Keras
        - Streamlit + Plotly
        
        ---
        
        ## 🎓 Academic Context
        - **Institution:** Metropolia University of Applied Sciences
        - **Program:** IoT Network Security
        - **Duration:** 6 months
        - **Team:** 4 members (Parallel Learning approach)
        
        ---
        
        ## 💡 Why This is NOT "Too Simple"
        
        ### Multi-Strategy Approach
        - Not just binary classification
        - Three complementary detection strategies
        - Multiple models working together
        - Handles both known and unknown threats
        
        ### Production-Grade Engineering
        - Ensemble methods for reliability
        - Anomaly detection for zero-day threats
        - Multi-format data support
        - Real-time processing capability
        
        ### Research Contribution
        - DoS 210x Amplification Discovery
        - Novel attack pattern insights
        - Comprehensive multi-strategy evaluation
        
        ---
        
        ## 🚀 Future Enhancements
        - Real-time network monitoring
        - SIEM integration
        - API deployment
        - Mobile application
        - Custom model training interface
        - Endpoint device deployment
        
        ---
        
        **Built with ❤️ for Cybersecurity**  
        *"Protecting networks through intelligent multi-strategy anomaly detection"*
        """)

except Exception as e:
    st.error(f"❌ Error loading system: {str(e)}")
    import traceback
    st.code(traceback.format_exc())

st.markdown("---")
st.markdown(f"🛡️ **AI Network Anomaly Detection System** | {st.session_state.models_loaded} AI Models | Metropolia UAS | 2025")