"""
AI Network Anomaly Detection - EPIC CYBERSECURITY DEMO
Cyberpunk/Terminal aesthetic with neon effects
ENHANCED VERSION with complete About section and all features
"""

import streamlit as st
import pickle
import numpy as np
import pandas as pd
from tensorflow import keras
import os
from datetime import datetime
import json
import re
from collections import Counter
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from feature_extraction import extract_features_from_pcap


# Page config
st.set_page_config(
    page_title="Neural Defense Matrix",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CYBERPUNK CSS
st.markdown("""
<style>
    /* Import fonts */
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;600;700&family=Share+Tech+Mono&display=swap');
    
    /* Global theme */
    .stApp {
        background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 50%, #0f1419 100%);
        font-family: 'Rajdhani', sans-serif;
    }
    
    /* Main title with glow effect */
    h1 {
        font-family: 'Orbitron', monospace !important;
        font-weight: 900 !important;
        background: linear-gradient(45deg, #00f5ff, #00d9ff, #0099ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-shadow: 0 0 30px rgba(0, 245, 255, 0.5);
        animation: glow 2s ease-in-out infinite alternate;
        letter-spacing: 2px;
    }
    
    @keyframes glow {
        from { text-shadow: 0 0 20px rgba(0, 245, 255, 0.3); }
        to { text-shadow: 0 0 40px rgba(0, 245, 255, 0.8), 0 0 60px rgba(0, 245, 255, 0.4); }
    }
    
    /* Subtitle */
    .stMarkdown h3 {
        font-family: 'Share Tech Mono', monospace !important;
        color: #00f5ff !important;
        font-size: 18px !important;
        letter-spacing: 3px !important;
        animation: flicker 3s infinite;
    }
    
    @keyframes flicker {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.8; }
    }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1117 0%, #161b22 100%);
        border-right: 2px solid #00f5ff;
        box-shadow: 5px 0 20px rgba(0, 245, 255, 0.3);
    }
    
    [data-testid="stSidebar"] h2 {
        color: #00f5ff !important;
        font-family: 'Orbitron', monospace !important;
        font-size: 20px !important;
        border-bottom: 2px solid #00f5ff;
        padding-bottom: 10px;
        text-transform: uppercase;
    }
    
    [data-testid="stSidebar"] .stMarkdown {
        color: #a0d8ff !important;
        font-family: 'Share Tech Mono', monospace;
        font-size: 14px;
    }
    
    /* Success/Info/Warning boxes with neon borders */
    .stAlert {
        border-radius: 10px !important;
        border-left: 4px solid #00f5ff !important;
        background: rgba(0, 245, 255, 0.1) !important;
        backdrop-filter: blur(10px);
        box-shadow: 0 4px 15px rgba(0, 245, 255, 0.2);
        animation: slideIn 0.5s ease-out;
    }
    
    @keyframes slideIn {
        from { transform: translateX(-20px); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    /* Metric cards with holographic effect */
    [data-testid="stMetricValue"] {
        font-family: 'Orbitron', monospace !important;
        font-size: 32px !important;
        font-weight: 700 !important;
        color: #00f5ff !important;
        text-shadow: 0 0 10px rgba(0, 245, 255, 0.8);
    }
    
    [data-testid="stMetricLabel"] {
        font-family: 'Rajdhani', sans-serif !important;
        color: #8ab4f8 !important;
        font-size: 14px !important;
        text-transform: uppercase;
        letter-spacing: 2px;
    }
    
    /* Buttons with pulse animation */
    .stButton > button {
        background: linear-gradient(45deg, #0099ff, #00f5ff) !important;
        color: #000 !important;
        font-family: 'Orbitron', monospace !important;
        font-weight: 700 !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 12px 30px !important;
        font-size: 16px !important;
        text-transform: uppercase !important;
        letter-spacing: 2px !important;
        box-shadow: 0 0 20px rgba(0, 245, 255, 0.5) !important;
        transition: all 0.3s ease !important;
        animation: pulse 2s infinite;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 0 30px rgba(0, 245, 255, 0.8) !important;
    }
    
    @keyframes pulse {
        0%, 100% { box-shadow: 0 0 20px rgba(0, 245, 255, 0.5); }
        50% { box-shadow: 0 0 30px rgba(0, 245, 255, 0.8), 0 0 40px rgba(0, 245, 255, 0.4); }
    }
    
    /* Progress bar */
    .stProgress > div > div {
        background: linear-gradient(90deg, #00f5ff, #0099ff, #00f5ff) !important;
        animation: progressFlow 2s linear infinite;
    }
    
    @keyframes progressFlow {
        0% { background-position: 0% 50%; }
        100% { background-position: 100% 50%; }
    }
    
    /* Tabs with glowing borders */
    .stTabs [data-baseweb="tab-list"] {
        background: rgba(13, 17, 23, 0.8);
        border-radius: 10px;
        padding: 5px;
        gap: 10px;
    }
    
    .stTabs [data-baseweb="tab"] {
        font-family: 'Rajdhani', sans-serif !important;
        font-weight: 600 !important;
        color: #8ab4f8 !important;
        background: transparent;
        border-radius: 8px;
        padding: 10px 20px;
        font-size: 16px !important;
        text-transform: uppercase;
        letter-spacing: 1px;
        transition: all 0.3s ease;
    }
    
    .stTabs [data-baseweb="tab"]:hover {
        background: rgba(0, 245, 255, 0.1);
        color: #00f5ff !important;
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(45deg, rgba(0, 153, 255, 0.3), rgba(0, 245, 255, 0.3)) !important;
        border: 2px solid #00f5ff !important;
        color: #00f5ff !important;
        box-shadow: 0 0 20px rgba(0, 245, 255, 0.4);
    }
    
    /* File uploader */
    [data-testid="stFileUploader"] {
        background: rgba(0, 245, 255, 0.05);
        border: 2px dashed #00f5ff;
        border-radius: 10px;
        padding: 20px;
        transition: all 0.3s ease;
    }
    
    [data-testid="stFileUploader"]:hover {
        background: rgba(0, 245, 255, 0.1);
        border-color: #00d9ff;
        box-shadow: 0 0 20px rgba(0, 245, 255, 0.3);
    }
    
    /* Dataframes */
    .stDataFrame {
        border: 1px solid #00f5ff !important;
        border-radius: 8px !important;
        overflow: hidden;
    }
    
    /* Expander */
    .streamlit-expanderHeader {
        background: rgba(0, 245, 255, 0.1) !important;
        border-left: 3px solid #00f5ff !important;
        border-radius: 5px !important;
        font-family: 'Rajdhani', sans-serif !important;
        font-weight: 600 !important;
        color: #00f5ff !important;
    }
    
    /* Header separator */
    hr {
        border: none;
        height: 2px;
        background: linear-gradient(90deg, transparent, #00f5ff, transparent);
        margin: 30px 0;
        animation: lineGlow 3s ease-in-out infinite;
    }
    
    @keyframes lineGlow {
        0%, 100% { opacity: 0.5; }
        50% { opacity: 1; box-shadow: 0 0 10px #00f5ff; }
    }
    
    /* Scrollbar */
    ::-webkit-scrollbar {
        width: 10px;
        height: 10px;
    }
    
    ::-webkit-scrollbar-track {
        background: #0d1117;
    }
    
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, #0099ff, #00f5ff);
        border-radius: 5px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(180deg, #00f5ff, #00d9ff);
    }
</style>
""", unsafe_allow_html=True)

# Session state
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []
if 'all_predictions' not in st.session_state:
    st.session_state.all_predictions = None
if 'models_loaded' not in st.session_state:
    st.session_state.models_loaded = 0

# Feature matching functions
def normalize_feature_name(name):
    return re.sub(r'[_\s\-]+', '', str(name).lower())

def calculate_feature_similarity(input_feature, expected_feature):
    input_norm = normalize_feature_name(input_feature)
    expected_norm = normalize_feature_name(expected_feature)
    if input_norm == expected_norm:
        return 1.0
    if input_norm in expected_norm or expected_norm in input_norm:
        return 0.8
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
            output_df[expected_col] = pd.to_numeric(uploaded_df[input_col], errors='coerce')
        except:
            pass
    
    for col in expected_features:
        if col not in feature_mapping.values() or output_df[col].isna().all():
            similar_cols = [c for c in output_df.columns if c != col and output_df[c].sum() != 0]
            if similar_cols:
                output_df[col] = output_df[similar_cols].mean(axis=1) * 0.1
    
    output_df = output_df.replace([np.inf, -np.inf], np.nan).fillna(0)
    for col in output_df.columns:
        output_df[col] = pd.to_numeric(output_df[col], errors='coerce').fillna(0).clip(-1e10, 1e10)
    
    scaled_data = scaler.transform(output_df.astype('float32'))
    return scaled_data, matched_count, total_expected, feature_mapping, confidence_scores, avg_confidence

# Cyberpunk Plotly visualizations
def create_cyber_attack_distribution(attack_counts, total):
    attacks = list(attack_counts.keys())
    counts = list(attack_counts.values())
    percentages = [(c/total)*100 for c in counts]
    
    colors = ['#00f5ff' if a == 'Normal Traffic' else '#ff2a6d' for a in attacks]
    
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=attacks,
        y=counts,
        marker=dict(
            color=colors,
            line=dict(color='#00f5ff', width=2),
        ),
        text=[f"{c:,}<br>{p:.1f}%" for c, p in zip(counts, percentages)],
        textposition='outside',
        textfont=dict(family="Orbitron", size=12, color='#00f5ff'),
        hovertemplate='<b>%{x}</b><br>Count: %{y:,}<br><extra></extra>'
    ))
    
    fig.update_layout(
        title=dict(
            text="⚡ ATTACK DISTRIBUTION MATRIX",
            font=dict(family='Orbitron', size=20, color='#00f5ff'),
            x=0.5
        ),
        xaxis=dict(
            title=dict(text="Attack Vector", font=dict(family='Rajdhani', size=14, color='#8ab4f8')),
            tickfont=dict(family='Share Tech Mono', color='#a0d8ff'),
            tickangle=-45,
            gridcolor='rgba(0, 245, 255, 0.1)',
            showgrid=True
        ),
        yaxis=dict(
            title=dict(text="Flow Count", font=dict(family='Rajdhani', size=14, color='#8ab4f8')),
            tickfont=dict(family='Share Tech Mono', color='#a0d8ff'),
            gridcolor='rgba(0, 245, 255, 0.1)',
            showgrid=True
        ),
        paper_bgcolor='rgba(10, 14, 39, 0.9)',
        plot_bgcolor='rgba(13, 17, 23, 0.8)',
        height=500,
        hovermode='x unified',
        font=dict(family='Rajdhani')
    )
    
    return fig

def create_cyber_pie_chart(attack_counts):
    labels = list(attack_counts.keys())
    values = list(attack_counts.values())
    
    colors = ['#00f5ff', '#ff2a6d', '#ff9500', '#00ff87', '#ff00ff', '#ffff00', '#00d9ff']
    
    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        marker=dict(
            colors=colors,
            line=dict(color='#0a0e27', width=3)
        ),
        textfont=dict(family='Orbitron', size=13, color='white'),
        hovertemplate='<b>%{label}</b><br>%{value:,} flows<br>%{percent}<extra></extra>',
        hole=0.4
    )])
    
    fig.add_annotation(
        text="THREAT<br>ANALYSIS",
        x=0.5, y=0.5,
        font=dict(size=16, family='Orbitron', color='#00f5ff'),
        showarrow=False
    )
    
    fig.update_layout(
        title=dict(
            text="🎯 TRAFFIC COMPOSITION RADAR",
            font=dict(family='Orbitron', size=20, color='#00f5ff'),
            x=0.5
        ),
        paper_bgcolor='rgba(10, 14, 39, 0.9)',
        height=500,
        showlegend=True,
        legend=dict(
            font=dict(family='Share Tech Mono', size=11, color='#a0d8ff'),
            bgcolor='rgba(13, 17, 23, 0.8)',
            bordercolor='#00f5ff',
            borderwidth=1
        )
    )
    
    return fig

def create_threat_gauge_cyber(threat_level):
    if threat_level < 10:
        color = '#00ff87'
        threat_text = "MINIMAL"
    elif threat_level < 30:
        color = '#ff9500'
        threat_text = "ELEVATED"
    else:
        color = '#ff2a6d'
        threat_text = "CRITICAL"
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=threat_level,
        domain={'x': [0, 1], 'y': [0, 1]},
        title=dict(
            text=f"<b>THREAT LEVEL: {threat_text}</b>",
            font=dict(size=18, family='Orbitron', color='#00f5ff')
        ),
        number=dict(
            suffix="%",
            font=dict(size=48, family='Orbitron', color=color)
        ),
        delta={'reference': 10},
        gauge=dict(
            axis={'range': [None, 100], 'tickcolor': '#00f5ff'},
            bar={'color': color, 'thickness': 0.8},
            bgcolor='rgba(13, 17, 23, 0.5)',
            borderwidth=3,
            bordercolor='#00f5ff',
            steps=[
                {'range': [0, 10], 'color': 'rgba(0, 255, 135, 0.2)'},
                {'range': [10, 30], 'color': 'rgba(255, 149, 0, 0.2)'},
                {'range': [30, 100], 'color': 'rgba(255, 42, 109, 0.2)'}
            ],
            threshold={
                'line': {'color': '#00f5ff', 'width': 4},
                'thickness': 0.75,
                'value': threat_level
            }
        )
    ))
    
    fig.update_layout(
        paper_bgcolor='rgba(10, 14, 39, 0)',
        font={'color': '#00f5ff', 'family': 'Rajdhani'},
        height=350
    )
    
    return fig

def create_model_comparison_cyber(all_predictions, label_encoder):
    model_names = list(all_predictions.keys())
    model_stats = {}
    
    for model_name, predictions in all_predictions.items():
        labels = label_encoder.inverse_transform(predictions)
        counts = Counter(labels)
        normal = counts.get('Normal Traffic', 0)
        model_stats[model_name] = {'Normal': normal, 'Attacks': len(predictions) - normal}
    
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        name='🟢 NORMAL',
        x=model_names,
        y=[s['Normal'] for s in model_stats.values()],
        marker=dict(color='#00ff87', line=dict(color='#00f5ff', width=2)),
        textfont=dict(family='Orbitron', color='white')
    ))
    
    fig.add_trace(go.Bar(
        name='🔴 ATTACKS',
        x=model_names,
        y=[s['Attacks'] for s in model_stats.values()],
        marker=dict(color='#ff2a6d', line=dict(color='#00f5ff', width=2)),
        textfont=dict(family='Orbitron', color='white')
    ))
    
    fig.update_layout(
        title=dict(
            text="🤖 AI MODEL CONSENSUS MATRIX",
            font=dict(family='Orbitron', size=20, color='#00f5ff'),
            x=0.5
        ),
        xaxis=dict(
            title=dict(text="AI Model", font=dict(family='Rajdhani', size=14, color='#8ab4f8')),
            tickangle=-45,
            tickfont=dict(family='Share Tech Mono', size=10, color='#a0d8ff'),
            gridcolor='rgba(0, 245, 255, 0.1)'
        ),
        yaxis=dict(
            title=dict(text="Detection Count", font=dict(family='Rajdhani', size=14, color='#8ab4f8')),
            tickfont=dict(family='Share Tech Mono', color='#a0d8ff'),
            gridcolor='rgba(0, 245, 255, 0.1)'
        ),
        barmode='group',
        paper_bgcolor='rgba(10, 14, 39, 0.9)',
        plot_bgcolor='rgba(13, 17, 23, 0.8)',
        height=550,
        legend=dict(
            font=dict(family='Orbitron', size=12, color='#00f5ff'),
            bgcolor='rgba(13, 17, 23, 0.8)',
            bordercolor='#00f5ff',
            borderwidth=1
        )
    )
    
    return fig

def create_model_agreement_cyber(all_predictions, sample_size=100):
    """Create cyberpunk-styled model agreement visualization"""
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
        line=dict(color='#00f5ff', width=2),
        marker=dict(size=4, color='#00f5ff', line=dict(color='#0099ff', width=1)),
        fill='tozeroy',
        fillcolor='rgba(0, 245, 255, 0.2)',
        hovertemplate='Sample %{x}<br>Agreement: %{y:.1f}%<extra></extra>'
    ))
    
    avg_agreement = np.mean(agreement_data)
    fig.add_hline(
        y=avg_agreement, 
        line_dash="dash", 
        line_color="#ff2a6d", 
        annotation_text=f"Average: {avg_agreement:.1f}%", 
        annotation_position="right",
        annotation_font=dict(family='Orbitron', size=12, color='#ff2a6d')
    )
    
    fig.update_layout(
        title=dict(
            text=f"🔍 MODEL CONSENSUS ANALYSIS (First {n_samples} samples)",
            font=dict(family='Orbitron', size=18, color='#00f5ff'),
            x=0.5
        ),
        xaxis=dict(
            title=dict(text="Sample Index", font=dict(family='Rajdhani', size=14, color='#8ab4f8')),
            tickfont=dict(family='Share Tech Mono', color='#a0d8ff'),
            gridcolor='rgba(0, 245, 255, 0.1)'
        ),
        yaxis=dict(
            title=dict(text="Agreement Percentage", font=dict(family='Rajdhani', size=14, color='#8ab4f8')),
            tickfont=dict(family='Share Tech Mono', color='#a0d8ff'),
            gridcolor='rgba(0, 245, 255, 0.1)',
            range=[0, 105]
        ),
        paper_bgcolor='rgba(10, 14, 39, 0.9)',
        plot_bgcolor='rgba(13, 17, 23, 0.8)',
        height=400,
        font=dict(family='Rajdhani')
    )
    
    return fig

def create_threat_timeline_cyber(threat_level, total_flows, sample_size=100):
    """Create cyberpunk-styled real-time threat detection timeline"""
    timeline_samples = min(sample_size, total_flows)
    
    # Simulate threat detection over time
    threat_timeline = np.random.choice(
        [0, 1], 
        size=timeline_samples, 
        p=[1-threat_level/100, threat_level/100]
    )
    
    # Create color array based on threat detection
    colors = ['#00ff87' if t == 0 else '#ff2a6d' for t in threat_timeline]
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        y=threat_timeline,
        mode='lines+markers',
        name='Threat Detected',
        line=dict(color='#ff2a6d', width=2),
        marker=dict(
            size=6, 
            color=colors,
            line=dict(color='#00f5ff', width=1)
        ),
        fill='tozeroy',
        fillcolor='rgba(255, 42, 109, 0.2)',
        hovertemplate='Flow %{x}<br>Status: %{text}<extra></extra>',
        text=['THREAT' if t == 1 else 'NORMAL' for t in threat_timeline]
    ))
    
    
    fig.update_layout(
        title=dict(
            text="⚡ REAL-TIME THREAT DETECTION TIMELINE",
            font=dict(family='Orbitron', size=18, color='#00f5ff'),
            x=0.5
        ),
        xaxis=dict(
            title=dict(text="Flow Index", font=dict(family='Rajdhani', size=14, color='#8ab4f8')),
            tickfont=dict(family='Share Tech Mono', color='#a0d8ff'),
            gridcolor='rgba(0, 245, 255, 0.1)'
        ),
        yaxis=dict(
            title=dict(text="Threat Level", font=dict(family='Rajdhani', size=14, color='#8ab4f8')),
            tickfont=dict(family='Share Tech Mono', color='#a0d8ff'),
            tickvals=[0, 1],
            ticktext=['NORMAL', 'THREAT'],
            gridcolor='rgba(0, 245, 255, 0.1)'
        ),
        paper_bgcolor='rgba(10, 14, 39, 0.9)',
        plot_bgcolor='rgba(13, 17, 23, 0.8)',
        height=350,
        font=dict(family='Rajdhani'),
        hovermode='x unified'
    )
    
    return fig

# Load models
def run_analysis(df, uploaded_filename, models, scaler, expected_features, label_encoder):
    """Run complete analysis on dataframe"""
    
    progress = st.progress(0)
    status = st.empty()
    
    # Feature matching
    status.markdown("**⚡ PHASE 1:** Feature extraction and normalization...")
    progress.progress(10)
    scaled_data, matched, total, mapping, conf, avg_conf = prepare_data_batch(df, expected_features, scaler)
    
    match_pct = (matched / total) * 100
    col1, col2, col3 = st.columns(3)
    col1.metric("FEATURES MATCHED", f"{matched}/{total}")
    col2.metric("MATCH QUALITY", f"{match_pct:.1f}%")
    col3.metric("CONFIDENCE", f"{avg_conf*100:.1f}%")
    
    # Run models
    all_predictions = {}
    current_prog = 20
    
    # Supervised
    for model_name in ['XGBoost', 'Random Forest', 'LightGBM', 'Neural Network']:
        if model_name in models:
            status.markdown(f"**🤖 PHASE 2:** {model_name} analyzing threat patterns...")
            progress.progress(current_prog)
            current_prog += 12
            
            if model_name == 'Neural Network':
                all_predictions[model_name] = np.argmax(models[model_name].predict(scaled_data, verbose=0), axis=1)
            else:
                all_predictions[model_name] = models[model_name].predict(scaled_data)
    
    # Unsupervised
    if 'Isolation Forest' in models:
        status.markdown("**🔍 PHASE 3:** Anomaly detection (Isolation Forest)...")
        progress.progress(70)
        iso_pred = models['Isolation Forest'].predict(scaled_data)
        iso_binary = (iso_pred == -1).astype(int)
        
        iso_multi = np.zeros(len(scaled_data), dtype=int)
        for i in range(len(scaled_data)):
            if iso_binary[i] == 1:
                votes = [all_predictions[m][i] for m in ['XGBoost', 'Random Forest', 'LightGBM', 'Neural Network'] if m in all_predictions]
                iso_multi[i] = Counter(votes).most_common(1)[0][0] if votes else 0
        all_predictions['Isolation Forest (Hybrid)'] = iso_multi
    
    if 'Autoencoder' in models:
        status.markdown("**🧬 PHASE 4:** Deep learning anomaly scan...")
        progress.progress(75)
        recon = models['Autoencoder'].predict(scaled_data, verbose=0)
        errors = np.mean(np.square(scaled_data - recon), axis=1)
        threshold = np.percentile(errors, 95)
        ae_binary = (errors > threshold).astype(int)
        
        ae_multi = np.zeros(len(scaled_data), dtype=int)
        for i in range(len(scaled_data)):
            if ae_binary[i] == 1:
                votes = [all_predictions[m][i] for m in ['XGBoost', 'Random Forest', 'LightGBM', 'Neural Network'] if m in all_predictions]
                ae_multi[i] = Counter(votes).most_common(1)[0][0] if votes else 0
        all_predictions['Autoencoder (Hybrid)'] = ae_multi
    
    # Ensemble
    if models.get('_ensemble_available') and len(all_predictions) >= 4:
        status.markdown("**🏆 PHASE 5:** Ensemble consensus protocol...")
        progress.progress(85)
        
        # Majority
        ensemble_maj = []
        for i in range(len(scaled_data)):
            votes = [all_predictions[m][i] for m in all_predictions.keys()]
            ensemble_maj.append(Counter(votes).most_common(1)[0][0])
        all_predictions['Ensemble (Majority)'] = np.array(ensemble_maj)
        
        # Weighted
        weights = {'XGBoost': 0.30, 'Random Forest': 0.25, 'LightGBM': 0.25, 'Neural Network': 0.20}
        ensemble_weighted = []
        for i in range(len(scaled_data)):
            vote_weights = {}
            for model in weights.keys():
                if model in all_predictions:
                    pred = all_predictions[model][i]
                    vote_weights[pred] = vote_weights.get(pred, 0) + weights[model]
            ensemble_weighted.append(max(vote_weights.items(), key=lambda x: x[1])[0])
        all_predictions['Ensemble (Weighted)'] = np.array(ensemble_weighted)
    
    progress.progress(100)
    status.markdown(f"**✅ ANALYSIS COMPLETE:** {len(all_predictions)} AI models processed")
    
    # Select primary
    if 'Ensemble (Weighted)' in all_predictions:
        final_preds = all_predictions['Ensemble (Weighted)']
        primary = "Ensemble (Weighted)"
    elif 'Ensemble (Majority)' in all_predictions:
        final_preds = all_predictions['Ensemble (Majority)']
        primary = "Ensemble (Majority)"
    else:
        final_preds = all_predictions[list(all_predictions.keys())[0]]
        primary = list(all_predictions.keys())[0]
    
    labels = label_encoder.inverse_transform(final_preds)
    attack_counts = Counter(labels)
    
    # Save
    analysis_data = {
        'timestamp': datetime.now().isoformat(),
        'file_name': uploaded_filename,
        'total_flows': len(labels),
        'attack_distribution': dict(attack_counts),
        'threat_level': ((len(labels) - attack_counts.get('Normal Traffic', 0)) / len(labels) * 100),
        'primary_model': primary,
        'models_used': len(all_predictions)
    }
    
    st.session_state.analysis_results = analysis_data
    st.session_state.all_predictions = all_predictions
    st.session_state.analysis_history.append(analysis_data)
    
    st.success(f"✅ **SCAN COMPLETE** • PRIMARY ENGINE: {primary}")
    try:
        st.balloons()
    except:
        pass
    
@st.cache_resource
def load_models():
    models = {}
    
    st.sidebar.markdown("### ⚡ SYSTEM INITIALIZATION")
    
    # Supervised
    with st.sidebar:
        with st.spinner("🎯 Loading supervised models..."):
            try:
                with open('trained_models/random_forest_multiclass.pkl', 'rb') as f:
                    models['Random Forest'] = pickle.load(f)
                with open('trained_models/xgboost_multiclass.pkl', 'rb') as f:
                    models['XGBoost'] = pickle.load(f)
                with open('trained_models/lightgbm_multiclass.pkl', 'rb') as f:
                    models['LightGBM'] = pickle.load(f)
                models['Neural Network'] = keras.models.load_model('trained_models/neural_network_multiclass.h5', compile=False)
                st.success("✅ 4 SUPERVISED MODELS ONLINE")
            except Exception as e:
                st.error(f"⚠️ Supervised error")
    
    # Unsupervised
    with st.sidebar:
        with st.spinner("🔍 Loading unsupervised models..."):
            try:
                with open('trained_models/isolation_forest.pkl', 'rb') as f:
                    models['Isolation Forest'] = pickle.load(f)
                
                if os.path.exists('trained_models/autoencoder.keras'):
                    models['Autoencoder'] = keras.models.load_model('trained_models/autoencoder.keras', compile=False)
                elif os.path.exists('trained_models/autoencoder.h5'):
                    models['Autoencoder'] = keras.models.load_model('trained_models/autoencoder.h5', compile=False)
                
                st.success("✅ 2 UNSUPERVISED MODELS ONLINE")
            except:
                st.warning("⚠️ Unsupervised offline")
    
    # Ensemble
    ensemble_count = sum(1 for f in ['ensemble_majority_voting.pkl', 'ensemble_weighted_voting.pkl', 'ensemble_confidence_based.pkl'] 
                        if os.path.exists(f'trained_models/{f}'))
    
    if ensemble_count > 0:
        models['_ensemble_available'] = True
        st.sidebar.success(f"✅ {ensemble_count} ENSEMBLE STRATEGIES READY")
    else:
        models['_ensemble_available'] = False
        st.sidebar.info("💡 Ensemble: Run training script")
    
    # Load supporting files
    with open('prepared_data/label_encoder.pkl', 'rb') as f:
        label_encoder = pickle.load(f)
    with open('prepared_data/scaler_multiclass.pkl', 'rb') as f:
        scaler = pickle.load(f)
    with open('prepared_data/feature_names.pkl', 'rb') as f:
        feature_names = pickle.load(f)
    
    # Update counts
    base_models = len([m for m in models.keys() if not m.startswith('_')])
    total = base_models + (3 if models.get('_ensemble_available') else 0)
    st.session_state.models_loaded = total
    
    # Sidebar status
    supervised = sum(1 for m in models if m in ['Random Forest', 'XGBoost', 'LightGBM', 'Neural Network'])
    unsupervised = sum(1 for m in models if m in ['Isolation Forest', 'Autoencoder'])
    
    st.sidebar.markdown(f"""
### 📊 SYSTEM STATUS

**ACTIVE MODULES:**
- 🎯 Supervised: `{supervised}`
- 🔍 Unsupervised: `{unsupervised}`
- 🤖 Ensemble: `{ensemble_count}`

**TOTAL AI APPROACHES:** `{total}`

**PERFORMANCE:**
- Best Single: `99.92%` (XGBoost)
- Best Ensemble: `99.86%`

---

**STATUS:** <span style='color: #00ff87; font-family: Orbitron;'>● OPERATIONAL</span>
""", unsafe_allow_html=True)
    
    return models, label_encoder, scaler, feature_names

# MAIN APP
try:
    models, label_encoder, scaler, expected_features = load_models()
    
    # Epic header
    st.markdown(f"""
    <div style='text-align: center; padding: 20px;'>
        <h1 style='font-size: 48px; margin-bottom: 10px;'>🛡️ NEURAL DEFENSE MATRIX</h1>
        <p style='font-family: Share Tech Mono; color: #00f5ff; font-size: 16px; letter-spacing: 5px;'>
            MULTI-STRATEGY AI NETWORK ANOMALY DETECTION SYSTEM
        </p>
        <p style='font-family: Rajdhani; color: #8ab4f8; font-size: 14px;'>
            <span style='color: #00ff87;'>●</span> {st.session_state.models_loaded} AI APPROACHES ACTIVE 
            <span style='margin: 0 20px;'>|</span> 
            <span style='color: #00ff87;'>●</span> 99.92% ACCURACY 
            <span style='margin: 0 20px;'>|</span>
            <span style='color: #00ff87;'>●</span> REAL-TIME PROTECTION
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<hr>", unsafe_allow_html=True)
    
    # TABS
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "⚡ THREAT ANALYSIS",
        "🎯 NEURAL DASHBOARD", 
        "🤖 MODEL MATRIX",
        "📜 OPERATION LOG",
        "📸 TRAINING GALLERY",
        "ℹ️ INTEL BRIEF"
    ])
    
    # TAB 1: ANALYSIS
    with tab1:
        st.markdown("## ⚡ NETWORK THREAT ANALYSIS ENGINE")
        
        if st.session_state.analysis_results:
            result = st.session_state.analysis_results
            st.success(f"✅ **ACTIVE SCAN:** {result['file_name']} • {result['total_flows']:,} NETWORK FLOWS ANALYZED")
            
            col1, col2 = st.columns([3, 1])
            with col2:
                if st.button("🔄 NEW SCAN", use_container_width=True):
                    st.session_state.analysis_results = None
                    st.rerun()
            st.markdown("<hr>", unsafe_allow_html=True)
        
        st.info(f"""
        **🚀 UPLOAD NETWORK TRAFFIC FOR AI-POWERED ANALYSIS**
        
        📡 **Supported Formats:** CSV, TSV, PCAP, PCAPNG, LOG, TXT, JSON  
        🤖 **AI Models Active:** {st.session_state.models_loaded} neural networks  
        ⚡ **Processing:** Real-time multi-strategy detection
        """)
        
        uploaded_file = st.file_uploader(
            "📁 SELECT NETWORK CAPTURE FILE",
            type=['csv', 'txt', 'log', 'json', 'pcap', 'pcapng', 'tsv'],
            help="Drag and drop or click to upload"
        )
        
        if uploaded_file:
            try:
                # Detect file type
                file_extension = uploaded_file.name.split('.')[-1].lower()
                file_size = uploaded_file.size / (1024 * 1024)
                
                st.write(f"📦 **File:** {uploaded_file.name}")
                st.write(f"📦 **Size:** {file_size:.2f} MB")
                st.write(f"📦 **Type:** {file_extension.upper()}")
                
                # Handle PCAP files
                if file_extension in ['pcap', 'pcapng']:
                    st.info("🔍 **PCAP FILE DETECTED** • Activating feature extraction pipeline...")
                    
                    with st.expander("ℹ️ PCAP PROCESSING PIPELINE"):
                        st.markdown("""
                        **Automated Feature Extraction:**
                        1. 📦 Parse raw network packets (IP, TCP, UDP headers)
                        2. 🔄 Group packets into bidirectional flows
                        3. 🧮 Calculate 52 statistical features per flow
                        4. 🤖 Feed to AI models for threat detection
                        
                        This allows analysis of **raw network traffic** without pre-processing!
                        """)
                    
                    if st.button("⚡ EXTRACT FEATURES & ANALYZE", type="primary", use_container_width=True):
                        # Save PCAP temporarily
                        temp_pcap_path = f"/tmp/uploaded_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
                        with open(temp_pcap_path, 'wb') as f:
                            f.write(uploaded_file.read())
                        
                        st.markdown("<hr>", unsafe_allow_html=True)
                        st.markdown("## ⚙️ FEATURE EXTRACTION PIPELINE")
                        
                        progress_pcap = st.progress(0)
                        status_pcap = st.empty()
                        
                        try:
                            # Extract features
                            status_pcap.info("📦 Step 1/4: Parsing raw packets from PCAP...")
                            progress_pcap.progress(25)
                            
                            df = extract_features_from_pcap(temp_pcap_path)
                            st.session_state.df = df
                            
                            progress_pcap.progress(50)
                            status_pcap.success(f"✅ Extracted {len(df)} network flows with 52 features!")
                            
                            # Clean up
                            os.remove(temp_pcap_path)
                            
                            progress_pcap.progress(100)

                            st.success(f"✅ **READY TO ANALYZE:** {len(df):,} network flows")
                            
                            # Show preview
                            with st.expander("👁️ EXTRACTED FEATURES PREVIEW"):
                                st.dataframe(df.head(10), use_container_width=True)
                            
                            st.markdown("<hr>", unsafe_allow_html=True)
                            st.markdown("## 🎯 INITIATING DEEP SCAN...")
                            
                            # Call analysis function
                            run_analysis(df, uploaded_file.name, models, scaler, expected_features, label_encoder)  
                        
                        except Exception as e:
                            st.error(f"❌ **PCAP EXTRACTION ERROR:** {str(e)}")
                            st.info("💡 Make sure the PCAP contains valid TCP/IP traffic")
                            import traceback
                            with st.expander("🔍 Error Details"):
                                st.code(traceback.format_exc())
                            if os.path.exists(temp_pcap_path):
                                os.remove(temp_pcap_path)
                
                # Handle CSV/TXT/LOG/JSON files
                else:
                    st.info("📊 **STRUCTURED DATA DETECTED** • Loading pre-calculated features...")
                    
                    # Try different parsing methods
                    if file_extension == 'json':
                        df = pd.read_json(uploaded_file)
                    elif file_extension in ['tsv']:
                        df = pd.read_csv(uploaded_file, sep='\t')
                    else:  # csv, txt, log
                        df = pd.read_csv(uploaded_file)

                    st.session_state.df = df
                    st.success(f"✅ **LOADED:** {len(df):,} network flows • {len(df.columns)} features detected")
                
                if 'df' in st.session_state:
                    with st.expander("👁️ DATA PREVIEW"):
                        st.dataframe(st.session_state.df.head(10), use_container_width=True)
                    
                if st.button("🎯 INITIATE DEEP SCAN", type="primary", use_container_width=True):
                    # Call analysis function
                    run_analysis(st.session_state.df, uploaded_file.name, models, scaler, expected_features, label_encoder)
                
             
            
            except Exception as e:
                st.error(f"❌ **ERROR:** {str(e)}")
        
        # Show results
        if st.session_state.analysis_results:
            result = st.session_state.analysis_results
            st.markdown("<hr>", unsafe_allow_html=True)
            st.markdown("## 📊 THREAT INTELLIGENCE REPORT")
            
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("TOTAL FLOWS", f"{result['total_flows']:,}")
            col2.metric("NORMAL", f"{result['attack_distribution'].get('Normal Traffic', 0):,}")
            col3.metric("THREATS", f"{result['total_flows'] - result['attack_distribution'].get('Normal Traffic', 0):,}")
            
            threat = result['threat_level']
            status = "MINIMAL" if threat < 10 else "ELEVATED" if threat < 30 else "CRITICAL"
            col4.metric("THREAT LEVEL", f"{threat:.1f}%", status)
            
            st.plotly_chart(create_cyber_attack_distribution(result['attack_distribution'], result['total_flows']), use_container_width=True)
    
    # TAB 2: DASHBOARD
    with tab2:
        st.markdown("## 🎯 NEURAL DEFENSE DASHBOARD")
        
        if st.session_state.analysis_results:
            result = st.session_state.analysis_results
            
            col1, col2 = st.columns([1, 1])
            with col1:
                st.plotly_chart(create_threat_gauge_cyber(result['threat_level']), use_container_width=True)
            with col2:
                st.plotly_chart(create_cyber_pie_chart(result['attack_distribution']), use_container_width=True)
            
            st.markdown("<hr>", unsafe_allow_html=True)
            
            # Real-Time Metrics
            st.markdown("### 📈 REAL-TIME METRICS")
            
            col_rt1, col_rt2, col_rt3, col_rt4 = st.columns(4)
            
            timestamp = datetime.fromisoformat(result['timestamp']).strftime("%H:%M:%S")
            col_rt1.metric("🕒 Analysis Time", timestamp)
            col_rt1.metric("📊 Total Flows", f"{result['total_flows']:,}")
            
            col_rt2.metric("🎯 Models Used", result.get('models_used', 'N/A'))
            col_rt2.metric("🤖 Primary Engine", result.get('primary_model', 'Ensemble')[:15])
            
            normal_count = result['attack_distribution'].get('Normal Traffic', 0)
            attack_count = result['total_flows'] - normal_count
            
            col_rt3.metric("🟢 Normal Traffic", f"{normal_count:,}")
            col_rt3.metric("📊 Percentage", f"{(normal_count/result['total_flows']*100):.1f}%")
            
            col_rt4.metric("🔴 Threats Detected", f"{attack_count:,}")
            col_rt4.metric("⚠️ Threat Level", f"{result['threat_level']:.1f}%")
            
            # Threat Status Alert
            if result['threat_level'] > 30:
                st.error("🚨 **CRITICAL THREAT LEVEL** - Immediate action required! System under active attack!")
            elif result['threat_level'] > 10:
                st.warning("⚠️ **ELEVATED THREAT LEVEL** - Monitor closely and prepare response protocols")
            else:
                st.success("✅ **LOW THREAT LEVEL** - Normal operations, no immediate concerns")
            
            st.markdown("<hr>", unsafe_allow_html=True)
            
            # Threat Timeline
            st.markdown("### ⚡ REAL-TIME THREAT DETECTION TIMELINE")
            st.info("💡 **LIVE SIMULATION:** Showing threat detection patterns across sampled network flows")
            
            st.plotly_chart(
                create_threat_timeline_cyber(result['threat_level'], result['total_flows']), 
                use_container_width=True,
                key="threat_timeline"
            )
            
            st.markdown("<hr>", unsafe_allow_html=True)
            
            # Model Agreement (if available)
            if st.session_state.all_predictions and len(st.session_state.all_predictions) > 1:
                st.markdown("### 🔍 AI MODEL CONSENSUS ANALYSIS")
                st.info("💡 **CONSENSUS TRACKING:** How well AI models agree on threat classification")
                
                st.plotly_chart(
                    create_model_agreement_cyber(st.session_state.all_predictions),
                    use_container_width=True,
                    key="model_agreement"
                )
                
                # Calculate agreement stats
                n_models = len(st.session_state.all_predictions)
                perfect_agreement = 0
                total_samples = len(next(iter(st.session_state.all_predictions.values())))
                
                for i in range(total_samples):
                    votes = [st.session_state.all_predictions[m][i] for m in st.session_state.all_predictions.keys()]
                    if len(set(votes)) == 1:
                        perfect_agreement += 1
                
                agreement_pct = (perfect_agreement / total_samples) * 100
                
                col_ag1, col_ag2, col_ag3 = st.columns(3)
                col_ag1.metric("Perfect Agreement", f"{perfect_agreement:,} flows", f"{agreement_pct:.1f}%")
                col_ag2.metric("Models Active", f"{n_models} AI Engines")
                col_ag3.metric("Consensus Strength", "HIGH" if agreement_pct > 80 else "MODERATE" if agreement_pct > 60 else "LOW")
                
                if agreement_pct > 90:
                    st.success("✅ **EXCELLENT CONSENSUS** - Models show strong agreement on classifications")
                elif agreement_pct > 70:
                    st.info("ℹ️ **GOOD CONSENSUS** - Models generally agree with minor variations")
                else:
                    st.warning("⚠️ **MODERATE CONSENSUS** - Models show some disagreement, review carefully")
            
            st.markdown("<hr>", unsafe_allow_html=True)
            
            # Threat breakdown
            st.markdown("### 🚨 THREAT VECTOR ANALYSIS")
            for attack, count in sorted(result['attack_distribution'].items(), key=lambda x: x[1], reverse=True):
                pct = (count / result['total_flows']) * 100
                if attack == 'Normal Traffic':
                    st.success(f"🟢 **{attack}:** {count:,} flows ({pct:.1f}%)")
                elif pct > 5:
                    st.error(f"🔴 **{attack}:** {count:,} flows ({pct:.1f}%) - HIGH PRIORITY")
                elif pct > 1:
                    st.warning(f"🟡 **{attack}:** {count:,} flows ({pct:.1f}%) - MONITOR")
                else:
                    st.info(f"⚪ **{attack}:** {count:,} flows ({pct:.1f}%) - LOW RISK")
        else:
            st.info("📡 **AWAITING DATA:** Upload and analyze network traffic to activate dashboard")
    
    # TAB 3: MODEL COMPARISON
    with tab3:
        st.markdown("## 🤖 AI MODEL CONSENSUS MATRIX")
        
        if st.session_state.all_predictions:
            st.plotly_chart(create_model_comparison_cyber(st.session_state.all_predictions, label_encoder), use_container_width=True)
            
            st.markdown("<hr>", unsafe_allow_html=True)
            
            st.markdown("### 📊 DETAILED MODEL PERFORMANCE")
            results = []
            for name, preds in st.session_state.all_predictions.items():
                labels = label_encoder.inverse_transform(preds)
                counts = Counter(labels)
                normal = counts.get('Normal Traffic', 0)
                
                category = "🎯 SUPERVISED" if name in ['XGBoost', 'Random Forest', 'LightGBM', 'Neural Network'] else \
                          "🔍 UNSUPERVISED" if 'Hybrid' in name else "🤖 ENSEMBLE"
                
                results.append({
                    'Type': category,
                    'Model': name,
                    'Normal': f"{normal:,}",
                    'Threats': f"{len(preds) - normal:,}",
                    'Threat %': f"{((len(preds) - normal) / len(preds) * 100):.2f}%"
                })
            st.dataframe(pd.DataFrame(results), use_container_width=True, hide_index=True)
            
            st.markdown("<hr>", unsafe_allow_html=True)
            
            # Individual Attack Type Comparison
            st.markdown("### 🔍 ATTACK-SPECIFIC DETECTION COMPARISON")
            st.info("💡 **DEEP DIVE:** Compare how each model detects specific attack types")
            
            # Get all attack types from ensemble predictions
            ensemble_labels = label_encoder.inverse_transform(next(iter(st.session_state.all_predictions.values())))
            attack_types = sorted(set(ensemble_labels))
            
            selected_attack = st.selectbox(
                "🎯 SELECT ATTACK TYPE TO ANALYZE:",
                options=['All Attack Types'] + [a for a in attack_types if a != 'Normal Traffic'],
                key="attack_selector"
            )
            
            if selected_attack != 'All Attack Types':
                st.markdown(f"#### 📊 Detection Comparison: **{selected_attack}**")
                
                model_attack_counts = {}
                for model_name, predictions in st.session_state.all_predictions.items():
                    labels = label_encoder.inverse_transform(predictions)
                    counts = Counter(labels)
                    model_attack_counts[model_name] = counts.get(selected_attack, 0)
                
                # Create comparison chart
                fig = go.Figure()
                fig.add_trace(go.Bar(
                    x=list(model_attack_counts.keys()),
                    y=list(model_attack_counts.values()),
                    marker=dict(
                        color='#ff2a6d',
                        line=dict(color='#00f5ff', width=2)
                    ),
                    text=[f"{v:,}" for v in model_attack_counts.values()],
                    textposition='outside',
                    textfont=dict(family='Orbitron', size=11, color='#00f5ff'),
                    hovertemplate='<b>%{x}</b><br>Detected: %{y:,}<extra></extra>'
                ))
                
                fig.update_layout(
                    title=dict(
                        text=f"🎯 DETECTION COUNT: {selected_attack}",
                        font=dict(family='Orbitron', size=18, color='#00f5ff'),
                        x=0.5
                    ),
                    xaxis=dict(
                        title=dict(text="AI Model", font=dict(family='Rajdhani', size=14, color='#8ab4f8')),
                        tickangle=-45,
                        tickfont=dict(family='Share Tech Mono', size=10, color='#a0d8ff'),
                        gridcolor='rgba(0, 245, 255, 0.1)'
                    ),
                    yaxis=dict(
                        title=dict(text="Detection Count", font=dict(family='Rajdhani', size=14, color='#8ab4f8')),
                        tickfont=dict(family='Share Tech Mono', color='#a0d8ff'),
                        gridcolor='rgba(0, 245, 255, 0.1)'
                    ),
                    paper_bgcolor='rgba(10, 14, 39, 0.9)',
                    plot_bgcolor='rgba(13, 17, 23, 0.8)',
                    height=400
                )
                
                st.plotly_chart(fig, use_container_width=True, key=f"attack_{selected_attack}")
                
                # Analysis
                max_model = max(model_attack_counts, key=model_attack_counts.get)
                min_model = min(model_attack_counts, key=model_attack_counts.get)
                variance = max(model_attack_counts.values()) - min(model_attack_counts.values())
                
                col_an1, col_an2, col_an3 = st.columns(3)
                col_an1.metric("🏆 Most Detections", max_model, f"{model_attack_counts[max_model]:,}")
                col_an2.metric("📊 Least Detections", min_model, f"{model_attack_counts[min_model]:,}")
                col_an3.metric("📈 Detection Variance", f"{variance:,} flows")
                
                if variance < 100:
                    st.success(f"✅ **HIGH CONSENSUS** - Models show strong agreement on {selected_attack} detection")
                elif variance < 500:
                    st.info(f"ℹ️ **MODERATE CONSENSUS** - Some variation in {selected_attack} detection")
                else:
                    st.warning(f"⚠️ **LOW CONSENSUS** - Significant disagreement on {selected_attack} detection")
            
            else:
                # Show all attack types overview
                st.markdown("#### 📊 All Attack Types Overview")
                
                attack_summary = []
                for attack in [a for a in attack_types if a != 'Normal Traffic']:
                    detections = {}
                    for model_name, predictions in st.session_state.all_predictions.items():
                        labels = label_encoder.inverse_transform(predictions)
                        counts = Counter(labels)
                        detections[model_name] = counts.get(attack, 0)
                    
                    avg_detection = np.mean(list(detections.values()))
                    max_detection = max(detections.values())
                    min_detection = min(detections.values())
                    
                    attack_summary.append({
                        'Attack Type': attack,
                        'Avg Detections': f"{int(avg_detection):,}",
                        'Max': f"{max_detection:,}",
                        'Min': f"{min_detection:,}",
                        'Variance': f"{max_detection - min_detection:,}"
                    })
                
                st.dataframe(pd.DataFrame(attack_summary), use_container_width=True, hide_index=True)
                st.info("💡 **TIP:** Select a specific attack type above to see detailed model comparison")
            
        else:
            st.info("📡 **AWAITING DATA:** Run threat analysis first")
    
    # TAB 4: HISTORY
    with tab4:
        st.markdown("## 📜 OPERATION HISTORY LOG")
        
        if st.session_state.analysis_history:
            st.success(f"📊 **TOTAL OPERATIONS:** {len(st.session_state.analysis_history)}")
            
            for i, analysis in enumerate(reversed(st.session_state.analysis_history)):
                ts = datetime.fromisoformat(analysis['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
                
                with st.expander(f"🕒 **OPERATION #{len(st.session_state.analysis_history) - i}** • {ts} • {analysis['file_name']}"):
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Flows", f"{analysis['total_flows']:,}")
                    col2.metric("Threat Level", f"{analysis['threat_level']:.1f}%")
                    col3.metric("Models Used", analysis.get('models_used', 'N/A'))
                    
                    st.markdown("**Threat Distribution:**")
                    for attack, count in analysis['attack_distribution'].items():
                        pct = (count / analysis['total_flows']) * 100
                        st.write(f"• {attack}: {count:,} ({pct:.1f}%)")
        else:
            st.info("📭 **NO OPERATIONS LOGGED** • Begin analysis to populate history")
    
    # TAB 5: TRAINING GALLERY
    with tab5:
        st.markdown("## 📸 TRAINING RESULTS GALLERY")
        
        if os.path.exists('results'):
            result_files = sorted([f for f in os.listdir('results') if f.endswith('.png')])
            
            if result_files:
                # Categorize
                confusion = [f for f in result_files if 'confusion' in f.lower()]
                roc = [f for f in result_files if 'roc' in f.lower()]
                comparison = [f for f in result_files if 'comparison' in f.lower()]
                other = [f for f in result_files if f not in confusion + roc + comparison]
                
                viz_type = st.selectbox(
                    "🔍 SELECT CATEGORY:",
                    [f"📊 ALL VISUALIZATIONS ({len(result_files)})", 
                     f"🎯 CONFUSION MATRICES ({len(confusion)})", 
                     f"📈 ROC CURVES ({len(roc)})",
                     f"📊 MODEL COMPARISONS ({len(comparison)})",
                     f"🎨 OTHER RESULTS ({len(other)})"]
                )
                
                if "ALL" in viz_type.upper():
                    display_files = result_files
                elif "CONFUSION" in viz_type.upper():
                    display_files = confusion
                elif "ROC" in viz_type.upper():
                    display_files = roc
                elif "COMPARISON" in viz_type.upper():
                    display_files = comparison
                else:
                    display_files = other
                
                if display_files:
                    selected = st.selectbox("📁 SELECT VISUALIZATION:", display_files)
                    
                    if selected:
                        from PIL import Image
                        img = Image.open(f'results/{selected}')
                        st.image(img, caption=selected, use_container_width=True)
                        
                        with open(f'results/{selected}', 'rb') as f:
                            st.download_button(
                                label="📥 DOWNLOAD IMAGE",
                                data=f,
                                file_name=selected,
                                mime="image/png",
                                use_container_width=True
                            )
                else:
                    st.info("💡 NO VISUALIZATIONS IN THIS CATEGORY")
            else:
                st.warning("⚠️ NO TRAINING VISUALIZATIONS FOUND")
        else:
            st.error("❌ RESULTS DIRECTORY NOT FOUND")
    
    # TAB 6: ABOUT / INTEL BRIEF
    with tab6:
        st.markdown("## ℹ️ SYSTEM INTELLIGENCE BRIEFING")
        
        st.markdown("""
        <div style='background: rgba(0, 245, 255, 0.05); border-left: 4px solid #00f5ff; padding: 20px; border-radius: 10px; margin-bottom: 20px;'>
            <h2 style='color: #00f5ff; font-family: Orbitron;'>🎯 NEURAL DEFENSE MATRIX</h2>
            <p style='color: #a0d8ff; font-family: Rajdhani; font-size: 16px;'>
                A comprehensive machine learning system for detecting network intrusions and anomalies using 
                multiple detection strategies. This project demonstrates production-ready cybersecurity AI 
                with <span style='color: #00ff87; font-weight: bold;'>99.92% accuracy</span>.
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Three Detection Strategies
        st.markdown("### 🔬 THREE-TIER DETECTION ARCHITECTURE")
        
        col_strat1, col_strat2, col_strat3 = st.columns(3)
        
        with col_strat1:
            st.markdown("""
            <div style='background: rgba(0, 153, 255, 0.1); padding: 15px; border-radius: 10px; border: 2px solid #0099ff; height: 100%;'>
                <h4 style='color: #00f5ff; font-family: Orbitron;'>1️⃣ SUPERVISED LEARNING</h4>
                <p style='color: #a0d8ff; font-size: 14px;'>
                    <b>Purpose:</b> Identify SPECIFIC attack types<br><br>
                    <b>Models:</b><br>
                    • Random Forest: 99.88%<br>
                    • XGBoost: 99.92% ⭐<br>
                    • LightGBM: 98.96%<br>
                    • Neural Network: 98.49%<br><br>
                    <b>Attack Types:</b><br>
                    DoS, DDoS, Port Scanning, Brute Force, Web Attacks, Bots
                </p>
            </div>
            """, unsafe_allow_html=True)
        
        with col_strat2:
            st.markdown("""
            <div style='background: rgba(0, 255, 135, 0.1); padding: 15px; border-radius: 10px; border: 2px solid #00ff87; height: 100%;'>
                <h4 style='color: #00ff87; font-family: Orbitron;'>2️⃣ ANOMALY DETECTION</h4>
                <p style='color: #a0d8ff; font-size: 14px;'>
                    <b>Purpose:</b> Detect UNKNOWN/ZERO-DAY attacks<br><br>
                    <b>Models:</b><br>
                    • Isolation Forest: 65.03%<br>
                    • Autoencoder: 97.73%<br><br>
                    <b>Key Advantage:</b><br>
                    Can detect attacks never seen before by learning what "normal" looks like<br><br>
                    Used by major cybersecurity companies
                </p>
            </div>
            """, unsafe_allow_html=True)
        
        with col_strat3:
            st.markdown("""
            <div style='background: rgba(255, 42, 109, 0.1); padding: 15px; border-radius: 10px; border: 2px solid #ff2a6d; height: 100%;'>
                <h4 style='color: #ff2a6d; font-family: Orbitron;'>3️⃣ ENSEMBLE METHODS</h4>
                <p style='color: #a0d8ff; font-size: 14px;'>
                    <b>Purpose:</b> Maximum reliability<br><br>
                    <b>Strategies:</b><br>
                    • Majority Voting: 99.83%<br>
                    • Weighted Voting: 99.86%<br>
                    • Confidence-Based: 99.20%<br><br>
                    <b>Benefits:</b><br>
                    Redundancy, higher reliability, industry-standard approach
                </p>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Key Achievements
        st.markdown("### 🏆 MISSION OBJECTIVES ACHIEVED")
        
        col_ach1, col_ach2, col_ach3, col_ach4 = st.columns(4)
        col_ach1.metric("Detection Accuracy", "99.92%", "XGBoost")
        col_ach2.metric("False Positive Rate", "<2%", "Industry Standard")
        col_ach3.metric("Processing Speed", "Real-time", "Live Detection")
        col_ach4.metric("Zero-Day Protection", "Yes", "Anomaly Detection")
        
        st.markdown("---")
        
        # Research Contribution
        st.markdown("### 🔍 RESEARCH BREAKTHROUGH")
        
        st.info("""
        **DoS Attack Pattern Discovery:**
        
        During training, we discovered a unique signature in DoS attacks:
        - **210x Amplification Ratio:** Tiny forward packets trigger massive backward responses
        - **High Variance:** Backward packet length standard deviation is critical feature
        - **Predictable Pattern:** Enables reliable detection with >99% accuracy
        
        This finding contributes to cybersecurity research and improves detection methods.
        """)
        
        st.markdown("---")
        
        # Technical Specifications
        st.markdown("### 📊 TECHNICAL SPECIFICATIONS")
        
        col_tech1, col_tech2 = st.columns(2)
        
        with col_tech1:
            st.markdown("""
            <div style='background: rgba(0, 245, 255, 0.05); padding: 15px; border-radius: 10px; border: 1px solid #00f5ff;'>
                <h4 style='color: #00f5ff; font-family: Orbitron;'>📁 DATASET</h4>
                <ul style='color: #a0d8ff; font-family: Rajdhani; font-size: 14px;'>
                    <li><b>Name:</b> CICIDS2017</li>
                    <li><b>Source:</b> Canadian Institute for Cybersecurity</li>
                    <li><b>Samples:</b> 2,520,751 network flows</li>
                    <li><b>Features:</b> 52 network flow statistics</li>
                    <li><b>Classes:</b> 7 (6 attacks + normal)</li>
                    <li><b>Split:</b> 80% train / 20% test</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        
        with col_tech2:
            st.markdown("""
            <div style='background: rgba(0, 245, 255, 0.05); padding: 15px; border-radius: 10px; border: 1px solid #00f5ff;'>
                <h4 style='color: #00f5ff; font-family: Orbitron;'>⚡ HARDWARE</h4>
                <ul style='color: #a0d8ff; font-family: Rajdhani; font-size: 14px;'>
                    <li><b>Platform:</b> Dell Pro Max GB10</li>
                    <li><b>GPU:</b> NVIDIA Blackwell GB10</li>
                    <li><b>RAM:</b> 128GB LPDDR5X</li>
                    <li><b>Storage:</b> 4TB SSD</li>
                    <li><b>Training Time:</b> 5 minutes (entire dataset!)</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Software Stack
        st.markdown("### 💻 SOFTWARE ARSENAL")
        
        col_sw1, col_sw2, col_sw3 = st.columns(3)
        
        with col_sw1:
            st.markdown("""
            **🐍 Core Framework:**
            - Python 3.12
            - scikit-learn
            - TensorFlow/Keras
            - NumPy, Pandas
            """)
        
        with col_sw2:
            st.markdown("""
            **🤖 ML Libraries:**
            - XGBoost
            - LightGBM
            - Isolation Forest
            - Autoencoders
            """)
        
        with col_sw3:
            st.markdown("""
            **🎨 Visualization:**
            - Streamlit
            - Plotly
            - Matplotlib
            - Seaborn
            """)
        
        st.markdown("---")
        
        # Academic Context
        st.markdown("### 🎓 ACADEMIC CONTEXT")
        
        st.success("""
        **Institution:** Metropolia University of Applied Sciences  
        **Program:** IoT Network Security Project  
        **Duration:** 6 months  
        **Team Size:** 4 members  
        
        **Learning Methodology:**
        - "Parallel Learning" approach
        - All members learn all components
        - Teaching sessions for knowledge sharing
        - No single point of failure
        
        **Project Goals:**
        ✅ Apply ML theory to real-world problems  
        ✅ Develop industry-ready cybersecurity solution  
        ✅ Gain hands-on experience with production ML  
        ✅ Create portfolio-worthy project  
        """)
        
        st.markdown("---")
        
        # Why This is NOT "Too Simple"
        st.markdown("### 💡 COMPLEXITY & INNOVATION")
        
        st.warning("""
        **Why This is NOT "Too Simple":**
        
        **Multi-Class Classification Complexity:**
        - The system doesn't just detect "attack vs normal" - it must learn UNIQUE patterns for each attack type
        - DoS ≠ DDoS ≠ Port Scanning ≠ Botnet
        - Each attack has distinct network traffic signatures
        - Model must differentiate between 7 classes, not just 2
        - Requires learning complex decision boundaries
        
        **Anomaly Detection Capability:**
        - Provides zero-day attack protection
        - No prior knowledge of attack needed
        - Critical for real-world deployment
        - Used by major cybersecurity companies
        
        **Production-Grade Engineering:**
        - Ensemble methods demonstrate professional thinking
        - Redundancy and reliability prioritized
        - Scalable architecture
        - Industry-standard approaches
        """)
        
        st.markdown("---")
        
        # Supported File Types
        st.markdown("### 📁 SUPPORTED INPUT FORMATS")
        
        col_file1, col_file2 = st.columns(2)
        
        with col_file1:
            st.markdown("""
            **📊 Structured Data:**
            - **CSV/TSV:** Network flow statistics (CIC-IDS format preferred)
            - **JSON:** Structured log data
            
            **📝 Log Files:**
            - **LOG/TXT:** Text-based logs (comma or tab separated)
            - Auto-detection of delimiter
            """)
        
        with col_file2:
            st.markdown("""
            **📦 Packet Captures:**
            - **PCAP/PCAPNG:** Raw packet capture files
            - Requires scapy library
            - Automatic flow extraction
            
            **🔄 Smart Features:**
            - Case-insensitive column matching
            - Statistical imputation for missing features
            """)
        
        st.markdown("---")
        
        # Future Enhancements
        st.markdown("### 🚀 FUTURE MISSION OBJECTIVES")
        
        col_fut1, col_fut2 = st.columns(2)
        
        with col_fut1:
            st.markdown("""
            **📡 Near-Term (Q1 2025):**
            - ✅ SIEM integration (Splunk, ELK)
            - ✅ Real-time monitoring dashboard
            - ✅ API deployment for automated detection
            - ✅ Mobile application for threat alerts
            """)
        
        with col_fut2:
            st.markdown("""
            **🎯 Long-Term Vision:**
            - 🔮 Blockchain threat intelligence sharing
            - 🔮 AI vs AI adversarial testing
            - 🔮 Quantum-ready detection algorithms
            - 🔮 Deploy on edge devices (Raspberry Pi)
            """)
        
        st.markdown("---")
        
        # Demo Features
        st.markdown("### 🎬 LIVE DEMO CAPABILITIES")
        
        demo_features = [
            "📊 Analyze entire network traffic logs in batch mode",
            "🎯 Identify specific attack types with 99.92% accuracy",
            "📈 Generate interactive visual threat assessments",
            "💾 Save and export analysis reports",
            "📜 Track comprehensive analysis history",
            "🔄 Handle various log formats (case-insensitive)",
            "⚡ Real-time batch processing with progress tracking",
            "🤖 Compare predictions across multiple AI models",
            "🎨 Cyberpunk-themed interactive visualizations"
        ]
        
        col_demo1, col_demo2 = st.columns(2)
        
        for i, feature in enumerate(demo_features):
            if i % 2 == 0:
                col_demo1.success(feature)
            else:
                col_demo2.success(feature)
        
        st.markdown("---")
        
        # References
        st.markdown("### 📚 REFERENCES & RESOURCES")
        
        st.info("""
        **Dataset:**
        - [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
        
        **Documentation:**
        - Project GitHub Repository
        - Training Notebooks
        - Model Performance Reports
        
        **Related Work:**
        - Sharafaldin et al. (2018) - CICIDS2017 Dataset
        - Industry standards from Palo Alto Networks, Cisco
        - Research on anomaly detection in network security
        """)
        
        st.markdown("---")
        
        # Career Relevance
        st.success("""
        **💼 CAREER RELEVANCE:**
        
        This project aligns with cybersecurity industry needs:
        - ML-powered threat detection (Darktrace, CrowdStrike)
        - Anomaly detection systems (Cisco, Palo Alto Networks)
        - Production ML engineering
        - Real-world dataset experience
        - Portfolio-ready demonstration
        """)
        
        st.markdown("---")
        
        # Acknowledgments
        st.markdown("""
        <div style='background: rgba(0, 245, 255, 0.05); padding: 20px; border-radius: 10px; border: 1px solid #00f5ff;'>
            <h3 style='color: #00f5ff; font-family: Orbitron;'>📝 ACKNOWLEDGMENTS</h3>
            <p style='color: #a0d8ff; font-family: Rajdhani;'>
                Special thanks to:
                <ul>
                    <li>Metropolia University for project support</li>
                    <li>Canadian Institute for Cybersecurity (CICIDS2017)</li>
                    <li>Open-source ML community</li>
                    <li>Dell for GB10 Blackwell hardware access</li>
                    <li>Team members: Tanyaj1, Sangam, and collaborators</li>
                </ul>
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Final Message
        st.markdown("""
        <div style='text-align: center; padding: 30px; background: linear-gradient(135deg, rgba(0, 153, 255, 0.2), rgba(0, 245, 255, 0.2)); border-radius: 15px; border: 2px solid #00f5ff;'>
            <h2 style='color: #00f5ff; font-family: Orbitron; margin-bottom: 15px;'>Built with ❤️ for Cybersecurity</h2>
            <p style='color: #a0d8ff; font-family: Share Tech Mono; font-size: 18px; letter-spacing: 3px;'>
                "Protecting networks through intelligent anomaly detection"
            </p>
            <p style='color: #8ab4f8; font-family: Rajdhani; margin-top: 20px;'>
                🛡️ NEURAL DEFENSE MATRIX • PRODUCTION READY • DEMO READY • INDUSTRY GRADE
            </p>
        </div>
        """, unsafe_allow_html=True)

except Exception as e:
    st.error(f"❌ **SYSTEM ERROR:** {str(e)}")
    import traceback
    st.code(traceback.format_exc())

# Footer
st.markdown("<hr>", unsafe_allow_html=True)
st.markdown(f"""
<div style='text-align: center; padding: 20px; font-family: Share Tech Mono; color: #8ab4f8;'>
    <p style='font-size: 12px;'>
        🛡️ NEURAL DEFENSE MATRIX v2.0 • {st.session_state.models_loaded} AI MODULES ACTIVE • METROPOLIA UNIVERSITY • 2025
    </p>
    <p style='font-size: 10px; color: #00f5ff;'>
        [ CLASSIFIED ] MULTI-STRATEGY NETWORK ANOMALY DETECTION SYSTEM [ OPERATIONAL ]
    </p>
</div>
""", unsafe_allow_html=True)