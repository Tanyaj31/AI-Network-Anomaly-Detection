"""
Home Page - Production-level landing for AI Network IDS
"""
import streamlit as st
import sys

from utils.navigation import render_sidebar_nav

sys.path.insert(0, '/home/shared/IoT_Project/AI_Anomaly_Detection')

st.set_page_config(page_title="Home | AI Network IDS", page_icon="🛡️", layout="wide")

render_sidebar_nav("1_home")

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;600;700;800&display=swap');

    /* ── Reset & base ── */
    html, body, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
        background: #080d14 !important;
    }
    [data-testid="stAppViewContainer"] { background: #080d14 !important; }
    [data-testid="block-container"] { padding-top: 1.5rem !important; }

    /* ── Sidebar clean-up ── */
    section[data-testid="stSidebar"] {
        background: #0c1520 !important;
        border-right: 1px solid rgba(0,255,170,0.08) !important;
    }
    section[data-testid="stSidebar"] [data-testid="stSidebarNav"] > ul > li:first-child { display: none; }

    /* ── Token grid scanlines overlay ── */
    [data-testid="stMain"]::before {
        content: "";
        position: fixed;
        inset: 0;
        background-image:
            repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(0,255,170,0.025) 40px),
            repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(0,255,170,0.015) 40px);
        pointer-events: none;
        z-index: 0;
    }

    * { font-family: 'Syne', sans-serif; box-sizing: border-box; }

    /* ── Hero ── */
    .ids-hero {
        position: relative;
        background: linear-gradient(135deg, #0e1e30 0%, #091624 60%, #06111c 100%);
        border: 1px solid rgba(0,255,170,0.15);
        border-radius: 20px;
        padding: 3rem 3.5rem 2.5rem;
        overflow: hidden;
        margin-bottom: 1.5rem;
    }
    .ids-hero::before {
        content: "";
        position: absolute;
        top: -80px; right: -80px;
        width: 380px; height: 380px;
        border-radius: 50%;
        background: radial-gradient(circle, rgba(0,255,170,0.07) 0%, transparent 70%);
        pointer-events: none;
    }
    .ids-hero::after {
        content: "";
        position: absolute;
        bottom: -60px; left: 20%;
        width: 260px; height: 260px;
        border-radius: 50%;
        background: radial-gradient(circle, rgba(30,144,255,0.06) 0%, transparent 70%);
        pointer-events: none;
    }
    .hero-eyebrow {
        font-family: 'Space Mono', monospace;
        font-size: 0.68rem;
        letter-spacing: 0.22em;
        text-transform: uppercase;
        color: #00ffaa;
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    .hero-eyebrow::before {
        content: "";
        display: inline-block;
        width: 28px; height: 1px;
        background: #00ffaa;
    }
    .hero-title {
        font-size: clamp(1.9rem, 3.5vw, 2.9rem);
        font-weight: 800;
        line-height: 1.1;
        color: #e8f4ff;
        margin: 0 0 0.85rem 0;
        max-width: 720px;
        letter-spacing: -0.02em;
    }
    .hero-title span { color: #00ffaa; }
    .hero-sub {
        color: #6b8ca8;
        font-size: 1rem;
        max-width: 620px;
        line-height: 1.65;
        margin-bottom: 1.8rem;
    }
    .status-row {
        display: flex;
        align-items: center;
        gap: 1rem;
        flex-wrap: wrap;
    }
    .badge {
        font-family: 'Space Mono', monospace;
        font-size: 0.73rem;
        padding: 0.3rem 0.8rem;
        border-radius: 6px;
        font-weight: 700;
        letter-spacing: 0.05em;
    }
    .badge-green {
        background: rgba(0,255,170,0.1);
        color: #00ffaa;
        border: 1px solid rgba(0,255,170,0.25);
    }
    .badge-blue {
        background: rgba(30,144,255,0.1);
        color: #4da6ff;
        border: 1px solid rgba(30,144,255,0.2);
    }
    .badge-amber {
        background: rgba(255,185,50,0.1);
        color: #ffb932;
        border: 1px solid rgba(255,185,50,0.2);
    }

    /* ── Stat strip ── */
    .stat-strip {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 1px;
        background: rgba(0,255,170,0.08);
        border: 1px solid rgba(0,255,170,0.1);
        border-radius: 14px;
        overflow: hidden;
        margin-bottom: 1.5rem;
    }
    .stat-cell {
        background: #0b1825;
        padding: 1.1rem 1.4rem;
        text-align: center;
        transition: background 0.2s;
    }
    .stat-cell:hover { background: #0f2030; }
    .stat-num {
        font-family: 'Space Mono', monospace;
        font-size: 1.65rem;
        font-weight: 700;
        color: #e8f4ff;
        line-height: 1;
        margin-bottom: 0.3rem;
    }
    .stat-num .accent { color: #00ffaa; }
    .stat-label {
        font-size: 0.75rem;
        color: #4a6a82;
        text-transform: uppercase;
        letter-spacing: 0.1em;
    }

    /* ── Section header ── */
    .sec-head {
        font-size: 0.68rem;
        font-family: 'Space Mono', monospace;
        letter-spacing: 0.2em;
        text-transform: uppercase;
        color: #4a6a82;
        margin: 2rem 0 1rem 0;
        display: flex;
        align-items: center;
        gap: 0.7rem;
    }
    .sec-head::after {
        content: "";
        flex: 1;
        height: 1px;
        background: rgba(0,255,170,0.07);
    }

    /* ── Feature cards ── */
    .feat-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 1px;
        background: rgba(0,255,170,0.06);
        border: 1px solid rgba(0,255,170,0.08);
        border-radius: 16px;
        overflow: hidden;
        margin-bottom: 1.5rem;
    }
    .feat-card {
        background: #0b1825;
        padding: 1.4rem 1.5rem;
        transition: background 0.2s;
    }
    .feat-card:hover { background: #0f2030; }
    .feat-icon {
        font-size: 1.4rem;
        margin-bottom: 0.7rem;
        display: block;
    }
    .feat-title {
        font-size: 0.92rem;
        font-weight: 700;
        color: #c8dff0;
        margin-bottom: 0.4rem;
    }
    .feat-desc {
        font-size: 0.8rem;
        color: #4a6a82;
        line-height: 1.55;
    }

    /* ── Architecture layers ── */
    .arch-wrap {
        border: 1px solid rgba(0,255,170,0.1);
        border-radius: 16px;
        overflow: hidden;
        margin-bottom: 1.5rem;
    }
    .arch-row {
        display: flex;
        align-items: stretch;
        border-bottom: 1px solid rgba(0,255,170,0.06);
    }
    .arch-row:last-child { border-bottom: none; }
    .arch-layer-badge {
        min-width: 88px;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 1rem;
        font-family: 'Space Mono', monospace;
        font-size: 0.7rem;
        font-weight: 700;
        letter-spacing: 0.08em;
    }
    .l0 { background: rgba(255,100,100,0.08); color: #ff6464; border-right: 1px solid rgba(255,100,100,0.15); }
    .l1 { background: rgba(0,255,170,0.06); color: #00ffaa; border-right: 1px solid rgba(0,255,170,0.12); }
    .l2 { background: rgba(30,144,255,0.06); color: #4da6ff; border-right: 1px solid rgba(30,144,255,0.12); }
    .arch-content {
        background: #0b1825;
        padding: 0.9rem 1.3rem;
        flex: 1;
    }
    .arch-content:hover { background: #0f2030; }
    .arch-name {
        font-size: 0.88rem;
        font-weight: 700;
        color: #c8dff0;
        margin-bottom: 0.25rem;
    }
    .arch-detail {
        font-size: 0.78rem;
        color: #4a6a82;
        line-height: 1.5;
    }
    .arch-tag {
        display: inline-block;
        font-family: 'Space Mono', monospace;
        font-size: 0.65rem;
        padding: 0.15rem 0.5rem;
        border-radius: 4px;
        background: rgba(0,255,170,0.08);
        color: #00ffaa;
        border: 1px solid rgba(0,255,170,0.15);
        margin-top: 0.4rem;
    }

    /* ── CTA cards ── */
    .cta-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 1rem;
        margin-bottom: 1.5rem;
    }
    .cta-card {
        background: #0b1825;
        border: 1px solid rgba(0,255,170,0.1);
        border-radius: 14px;
        padding: 1.3rem 1.4rem;
        transition: border-color 0.2s, background 0.2s;
        cursor: pointer;
    }
    .cta-card:hover {
        border-color: rgba(0,255,170,0.3);
        background: #0f2030;
    }
    .cta-card-num {
        font-family: 'Space Mono', monospace;
        font-size: 0.65rem;
        color: #2a4a5e;
        letter-spacing: 0.12em;
        margin-bottom: 0.6rem;
    }
    .cta-card-title {
        font-size: 1rem;
        font-weight: 700;
        color: #c8dff0;
        margin-bottom: 0.4rem;
    }
    .cta-card-sub {
        font-size: 0.78rem;
        color: #4a6a82;
        line-height: 1.5;
    }

    /* ── Dataset row ── */
    .ds-row {
        display: flex;
        gap: 1rem;
        flex-wrap: wrap;
        margin-bottom: 1.5rem;
    }
    .ds-chip {
        background: #0b1825;
        border: 1px solid rgba(0,255,170,0.1);
        border-radius: 10px;
        padding: 0.7rem 1.1rem;
        flex: 1;
        min-width: 160px;
    }
    .ds-chip-name {
        font-family: 'Space Mono', monospace;
        font-size: 0.75rem;
        color: #00ffaa;
        font-weight: 700;
        margin-bottom: 0.2rem;
    }
    .ds-chip-desc {
        font-size: 0.75rem;
        color: #4a6a82;
    }

    /* ── Footer ── */
    .ids-footer {
        border-top: 1px solid rgba(0,255,170,0.07);
        margin-top: 2rem;
        padding-top: 1.2rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 0.5rem;
    }
    .footer-left {
        font-family: 'Space Mono', monospace;
        font-size: 0.68rem;
        color: #2a4a5e;
        letter-spacing: 0.08em;
    }
    .footer-right {
        font-size: 0.72rem;
        color: #2a4a5e;
    }

    /* ── Streamlit button overrides ── */
    .stButton > button {
        background: rgba(0,255,170,0.08) !important;
        color: #00ffaa !important;
        border: 1px solid rgba(0,255,170,0.3) !important;
        border-radius: 8px !important;
        font-family: 'Space Mono', monospace !important;
        font-size: 0.75rem !important;
        letter-spacing: 0.08em !important;
        font-weight: 700 !important;
        transition: all 0.2s !important;
    }
    .stButton > button:hover {
        background: rgba(0,255,170,0.16) !important;
        border-color: rgba(0,255,170,0.55) !important;
        color: #00ffaa !important;
    }
    [data-testid="stBaseButton-primary"] > button,
    .stButton > button[kind="primary"] {
        background: #00ffaa !important;
        color: #080d14 !important;
        border-color: #00ffaa !important;
    }
    [data-testid="stBaseButton-primary"] > button:hover,
    .stButton > button[kind="primary"]:hover {
        background: #00e699 !important;
        border-color: #00e699 !important;
    }
</style>
""", unsafe_allow_html=True)

# ── Hero ─────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="ids-hero">
    <div class="hero-eyebrow">Production Security Console · Metropolia UAS</div>
    <h1 class="hero-title">AI-Powered <span>Network Intrusion</span><br>Detection System</h1>
    <p class="hero-sub">
        Three-layer hybrid intelligence for SOC teams. Detect zero-day threats with unsupervised
        autoencoders, classify known attacks with ensemble XGBoost, and streamline analyst review —
        all in a single production pipeline.
    </p>
    <div class="status-row">
        <span class="badge badge-green">● LIVE PIPELINE READY</span>
        <span class="badge badge-blue">7 K FLOWS / SEC</span>
        <span class="badge badge-amber">147 UNIVERSAL FEATURES</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Stat strip ───────────────────────────────────────────────────────────────
st.markdown("""
<div class="stat-strip">
    <div class="stat-cell">
        <div class="stat-num">99<span class="accent">.92</span>%</div>
        <div class="stat-label">Best Accuracy</div>
    </div>
    <div class="stat-cell">
        <div class="stat-num">97<span class="accent">.08</span>%</div>
        <div class="stat-label">Attack Detection Rate</div>
    </div>
    <div class="stat-cell">
        <div class="stat-num"><span class="accent">9.97</span>%</div>
        <div class="stat-label">Zero-Day Flag Rate</div>
    </div>
    <div class="stat-cell">
        <div class="stat-num">262<span class="accent">K</span></div>
        <div class="stat-label">Flows Analyzed</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Architecture ─────────────────────────────────────────────────────────────
st.markdown('<div class="sec-head">Detection Architecture</div>', unsafe_allow_html=True)

st.markdown("""
<div class="arch-wrap">
    <div class="arch-row">
        <div class="arch-layer-badge l0">LAYER 0</div>
        <div class="arch-content">
            <div class="arch-name">Zero-Day Anomaly Detection</div>
            <div class="arch-detail">
                Autoencoder-based unsupervised detection catches novel threats invisible to signature-based systems.
                Reconstruction error scoring with dynamic thresholding.
            </div>
            <span class="arch-tag">UNSUPERVISED</span>
        </div>
    </div>
    <div class="arch-row">
        <div class="arch-layer-badge l1">LAYER 1</div>
        <div class="arch-content">
            <div class="arch-name">Ensemble Attack Classification</div>
            <div class="arch-detail">
                Three XGBoost models trained on CICIDS2017, CIC IoT 2023, and UNSW-NB15.
                Confidence-weighted voting with 15+ attack categories.
            </div>
            <span class="arch-tag">SUPERVISED · ENSEMBLE</span>
        </div>
    </div>
    <div class="arch-row">
        <div class="arch-layer-badge l2">LAYER 2</div>
        <div class="arch-content">
            <div class="arch-name">Human-in-the-Loop Review</div>
            <div class="arch-detail">
                Analyst triage queue with active learning. Approved patterns are whitelisted to reduce
                recurring false positives. Gemini AI provides explainable threat context.
            </div>
            <span class="arch-tag">ACTIVE LEARNING</span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Feature highlights ────────────────────────────────────────────────────────
st.markdown('<div class="sec-head">Capabilities</div>', unsafe_allow_html=True)

st.markdown("""
<div class="feat-grid">
    <div class="feat-card">
        <span class="feat-icon">⚡</span>
        <div class="feat-title">Sub-Second Latency</div>
        <div class="feat-desc">7,000 flows per second through the full 3-layer pipeline on production hardware.</div>
    </div>
    <div class="feat-card">
        <span class="feat-icon">🌐</span>
        <div class="feat-title">Edge + Cloud Hybrid</div>
        <div class="feat-desc">Raspberry Pi captures & extracts features at the edge; Dell Blackwell server runs ML inference centrally via MQTT.</div>
    </div>
    <div class="feat-card">
        <span class="feat-icon">🔍</span>
        <div class="feat-title">Explainable AI</div>
        <div class="feat-desc">Layer agreement charts, SHAP-style feature importance, and natural-language Gemini summaries for every alert.</div>
    </div>
    <div class="feat-card">
        <span class="feat-icon">📡</span>
        <div class="feat-title">Remote Pi Control</div>
        <div class="feat-desc">Start / stop packet capture, adjust sampling, and view edge device health — directly from this dashboard over MQTT.</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Datasets ──────────────────────────────────────────────────────────────────
st.markdown('<div class="sec-head">Training Datasets</div>', unsafe_allow_html=True)

st.markdown("""
<div class="ds-row">
    <div class="ds-chip">
        <div class="ds-chip-name">CICIDS 2017</div>
        <div class="ds-chip-desc">Enterprise traffic · DoS, DDoS, Brute Force, Infiltration</div>
    </div>
    <div class="ds-chip">
        <div class="ds-chip-name">CIC IoT 2023</div>
        <div class="ds-chip-desc">IoT-specific attacks · 210× DoS amplification signatures</div>
    </div>
    <div class="ds-chip">
        <div class="ds-chip-name">UNSW-NB15</div>
        <div class="ds-chip-desc">Research traffic · Backdoors, Shellcode, Reconnaissance</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Navigation CTAs ───────────────────────────────────────────────────────────
st.markdown('<div class="sec-head">Workflow</div>', unsafe_allow_html=True)

st.markdown("""
<div class="cta-grid">
    <div class="cta-card">
        <div class="cta-card-num">01 — ANALYZE</div>
        <div class="cta-card-title">Traffic Analysis</div>
        <div class="cta-card-sub">Upload PCAP or CSV, run multi-layer detection, export annotated results.</div>
    </div>
    <div class="cta-card">
        <div class="cta-card-num">02 — MONITOR</div>
        <div class="cta-card-title">Live SOC Monitor</div>
        <div class="cta-card-sub">Watch live flows from edge devices, triage threats, drill into AI explanations.</div>
    </div>
    <div class="cta-card">
        <div class="cta-card-num">03 — INSPECT</div>
        <div class="cta-card-title">Models & Performance</div>
        <div class="cta-card-sub">Accuracy curves, confusion matrices, ROC, and feature importance across all datasets.</div>
    </div>
</div>
""", unsafe_allow_html=True)

col1, col2, col3 = st.columns(3)
with col1:
    if st.button("→ Open Analyze", type="primary", use_container_width=True):
        st.switch_page("pages/2_analyze.py")
with col2:
    if st.button("→ Open Live Monitor", use_container_width=True):
        st.switch_page("pages/3_live_monitor.py")
with col3:
    if st.button("→ Open Models", use_container_width=True):
        st.switch_page("pages/4_models.py")

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="ids-footer">
    <div class="footer-left">AI NETWORK IDS · METROPOLIA UAS · IOT NETWORK SECURITY · MARCH 2026</div>
    <div class="footer-right">Python · XGBoost · TensorFlow · Streamlit · MQTT · Tailscale</div>
</div>
""", unsafe_allow_html=True)
