"""🛡️ NETWORK SECURITY OPERATIONS CENTER
Complete 3-Layer System: Detection + Human Review
Tabs: Live | Threats | History | Review
Auto-refresh: 5 seconds
"""
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import os
from datetime import datetime, timedelta
import json
import sys
import paho.mqtt.publish as publish
import time
from collections import Counter
import google.generativeai as genai
from dotenv import load_dotenv
import re
from utils.navigation import render_sidebar_nav

load_dotenv()

project_root = "/home/shared/IoT_Project/AI_Anomaly_Detection"
sys.path.append(project_root)
sys.path.append(os.path.join(project_root, 'streamlit_app', 'utils'))
sys.path.insert(0, os.path.join(project_root, 'realtime_monitor'))
from shared_state import SharedState as LiveDataReader

MQTT_BROKER = "localhost"
MQTT_PORT   = 1883
AUTO_REFRESH_SECONDS = 5
HISTORY_DAYS = 30
LIVE_FEED_LIMIT = 1000
REVIEW_CONF_THRESHOLD = 0.70
REVIEW_PAGE_SIZE = 10

try:
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

load_dotenv()
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-1.5-flash')
gemini_available = False
available_models = []
GEMINI_MIN_SECONDS_BETWEEN_CALLS = 10
GEMINI_RATE_LIMIT_COOLDOWN_SECONDS = 60

st.set_page_config(page_title="Network Security Monitor", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")
render_sidebar_nav("3_live_monitor")

st.markdown("""<style>
    section[data-testid="stSidebar"] [data-testid="stSidebarNav"] > ul > li:first-child { display: none; }
    button[data-testid="collapsedControl"] { display: flex !important; visibility: visible !important; opacity: 1 !important; pointer-events: all !important; z-index: 999999 !important; }
    .ai-analysis-content { background: linear-gradient(135deg, rgba(102,126,234,0.1) 0%, rgba(118,75,162,0.1) 100%); border-left: 3px solid #667eea; border-radius: 8px; padding: 1rem; margin-top: 0.8rem; font-size: 0.9rem; color: #e2e8f0; }
</style>""", unsafe_allow_html=True)

defaults = {
    'last_refresh': datetime.now(), 'auto_refresh': True, 'reader': LiveDataReader(),
    'active_tab': 'live', 'ai_analyses': {}, 'ai_loading': {}, 'ai_visible': {},
    'ai_request_times': {}, 'stay_on_review_tab': False, 'session_start_flows': 0,
    'show_more_live': False, 'pi_last_state': None, 'pi_monitor_enabled': False,
    'review_skipped': [], 'gemini_checked': False, 'gemini_available': False,
    'gemini_models': [], 'gemini_error': None, 'ai_last_request_at': 0.0,
    'ai_cooldown_until': 0.0,
    'review_shown_count': REVIEW_PAGE_SIZE,
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

def init_gemini():
    global gemini_available, GEMINI_MODEL, available_models
    if st.session_state.gemini_checked:
        gemini_available = st.session_state.gemini_available
        available_models = st.session_state.gemini_models
        if gemini_available and available_models and GEMINI_MODEL not in available_models:
            alt = [m for m in available_models if 'flash' in m.lower() or 'pro' in m.lower()]
            GEMINI_MODEL = alt[0] if alt else available_models[0]
        return
    gemini_available = False; available_models = []; st.session_state.gemini_error = None
    if not GENAI_AVAILABLE:
        st.session_state.gemini_checked = True; st.session_state.gemini_available = False; return
    if not GEMINI_API_KEY or GEMINI_API_KEY == 'your_actual_gemini_api_key_here' or len(GEMINI_API_KEY) <= 20:
        st.session_state.gemini_checked = True; st.session_state.gemini_available = False; return
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        models = genai.list_models()
        for model in models:
            if 'generateContent' in model.supported_generation_methods:
                available_models.append(model.name)
        if available_models:
            gemini_available = True
            if GEMINI_MODEL not in available_models:
                alt = [m for m in available_models if 'flash' in m.lower() or 'pro' in m.lower()]
                GEMINI_MODEL = alt[0] if alt else available_models[0]
        else:
            gemini_available = False
    except Exception as e:
        st.session_state.gemini_error = str(e); gemini_available = False
    st.session_state.gemini_checked = True
    st.session_state.gemini_available = gemini_available
    st.session_state.gemini_models = available_models

def _is_rate_limit_error(msg):
    if not msg: return False
    m = str(msg).lower()
    return "rate limit" in m or "429" in m or "resource_exhausted" in m or "quota" in m or "too many requests" in m

init_gemini()

def strip_html_tags(text):
    if not text: return text
    import html
    text = html.unescape(text)
    clean = re.sub(r'<[^>]+>', '', text)
    clean = re.sub(r'\s+', ' ', clean)
    for pat, rep in [(r'\*\*([^*]+)\*\*', r'\1'), (r'__([^_]+)__', r'\1'),
                     (r'\*([^*]+)\*', r'\1'), (r'_([^_]+)_', r'\1')]:
        clean = re.sub(pat, rep, clean)
    return clean.strip()

def render_ai_analysis_box(analysis_text, is_threat, confidence):
    st.write(strip_html_tags(analysis_text))

def render_review_ai_analysis_box(analysis_text, assessment, timestamp):
    st.write(strip_html_tags(analysis_text))

def analyze_with_gemini(event_data):
    if not gemini_available:
        return {'success': False, 'error': 'Gemini AI not configured', 'analysis': 'AI analysis unavailable.'}
    try:
        flow = event_data.get('flow_details', {})
        classification = event_data.get('attack_type', event_data.get('classification', 'Unknown'))
        threat_level = event_data.get('threat_level', 'INFO')
        confidence = event_data.get('confidence', 0) * 100
        l0_flagged = event_data.get('layer0_flagged', False)
        l1_flagged = event_data.get('layer1_flagged', False)
        src_ip = flow.get('src_ip', 'N/A'); src_port = flow.get('src_port', 'N/A')
        dst_ip = flow.get('dst_ip', 'N/A'); dst_port = flow.get('dst_port', 'N/A')
        protocol = flow.get('protocol', 'N/A')
        try: bytes_transferred = int(flow.get('bytes', 0) or 0)
        except: bytes_transferred = 0
        try: packets = int(flow.get('packets', 0) or 0)
        except: packets = 0
        packet_reason = ""
        if packets > 0 and bytes_transferred > 0:
            avg = bytes_transferred / packets
            if avg > 1400 and packets > 10: packet_reason = f"large packets ({avg:.0f}B avg) typical for exfiltration"
            elif avg < 100 and packets > 20: packet_reason = f"many small packets ({packets} of {avg:.0f}B) indicating scanning/C2"
            elif packets > 1000: packet_reason = f"high packet volume ({packets}) suggesting automation"
        common_ports = {'80':{'name':'HTTP','desc':'web traffic','risk':'low','typical':'web browsing'},
            '443':{'name':'HTTPS','desc':'secure web','risk':'low','typical':'secure websites'},
            '22':{'name':'SSH','desc':'remote access','risk':'high','typical':'server admin'},
            '53':{'name':'DNS','desc':'domain lookups','risk':'low','typical':'browsing'},
            '3389':{'name':'RDP','desc':'remote desktop','risk':'critical','typical':'Windows remote'},
            '1883':{'name':'MQTT','desc':'IoT messaging','risk':'medium','typical':'IoT comms'},
            '3306':{'name':'MySQL','desc':'database','risk':'critical','typical':'DB queries'},
            '25':{'name':'SMTP','desc':'email','risk':'medium','typical':'email sending'},
            '445':{'name':'SMB','desc':'file sharing','risk':'high','typical':'Windows shares'},
            '8080':{'name':'HTTP-Alt','desc':'web alt','risk':'medium','typical':'proxies/dev'}}
        port_info = common_ports.get(str(dst_port), {'name':f'port {dst_port}','desc':'non-standard','risk':'unknown','typical':'custom app'})
        is_threat = 'Normal' not in str(classification)
        factors = []
        if str(dst_port) in common_ports:
            factors.append(f"port {dst_port} ({port_info['name']}) for {port_info['typical']}")
            if port_info['risk'] in ['high','critical']: factors.append(f"this port is {port_info['risk']} risk")
        else: factors.append(f"unusual port {dst_port}")
        if packet_reason: factors.append(packet_reason)
        if l0_flagged and l1_flagged: factors.append("both detection layers flagged independently")
        elif l0_flagged: factors.append("anomaly detector found unusual patterns")
        elif l1_flagged: factors.append("matches a known attack signature")
        if confidence > 90: factors.append(f"very high confidence ({confidence:.0f}%)")
        elif confidence < 70: factors.append(f"low confidence ({confidence:.0f}%)")
        why = ("This was flagged because " + ", ".join(factors) + ".") if factors else "Flagged by detection system."
        data_display = f"{bytes_transferred/1000000:.1f} MB" if bytes_transferred > 1000000 else f"{bytes_transferred/1000:.1f} KB" if bytes_transferred > 1000 else f"{bytes_transferred} bytes"
        if not is_threat:
            prompt = f"""Explain in 2-3 sentences why this is NORMAL traffic:\n{src_ip}:{src_port} → {dst_ip}:{dst_port} via {protocol}\n{data_display} in {packets} packets · Confidence: {confidence:.0f}%\nStart with "This is normal traffic because..." End with "No action needed." """
        else:
            is_uncertain = confidence < 70 or l0_flagged != l1_flagged
            if is_uncertain:
                prompt = f"""Explain this UNCERTAIN detection in 3 sentences:\n{classification} - {threat_level} ({confidence:.0f}%)\n{src_ip}:{src_port} → {dst_ip}:{dst_port} via {protocol} · {data_display}\nWhy: {why}\nStart "The system is unsure because..." End "Monitor this connection" or "Investigate further"."""
            else:
                prompt = f"""Explain this DETECTED ATTACK in 3 sentences:\n{classification} - {threat_level} ({confidence:.0f}%)\n{src_ip}:{src_port} → {dst_ip}:{dst_port} via {protocol} · {data_display}\nWhy: {why}\nStart "This is a {classification} attack because..." End with ONE action."""
        model_name = GEMINI_MODEL
        if available_models and model_name not in available_models: model_name = available_models[0]
        response = genai.GenerativeModel(model_name).generate_content(prompt)
        if response and response.text:
            return {'success': True, 'analysis': strip_html_tags(response.text.strip()),
                    'is_threat': is_threat, 'timestamp': datetime.now().isoformat(), 'model': GEMINI_MODEL}
        return {'success': False, 'error': 'Empty response', 'analysis': 'Failed.'}
    except Exception as e:
        return {'success': False, 'error': str(e), 'analysis': f'Error: {e}', 'rate_limited': _is_rate_limit_error(str(e))}

def analyze_with_gemini_review(event_data, custom_prompt=None):
    if not gemini_available:
        return {'success': False, 'error': 'Gemini AI not configured', 'analysis': 'AI unavailable.'}
    try:
        if custom_prompt:
            prompt = custom_prompt
        else:
            flow = event_data.get('flow_details', {})
            l0 = event_data.get('layer0_flagged', False); l1 = event_data.get('layer1_flagged', False)
            confidence = event_data.get('confidence', 0) * 100
            prompt = f"""Explain why this traffic needs HUMAN REVIEW.\nReason: {"layer disagreement" if l0 != l1 else "low confidence"}\nConfidence: {confidence:.1f}% · L0: {'⚠️ Anomaly' if l0 else '✅ Normal'} · L1: {'🔴 Attack' if l1 else '✅ Normal'}\n{flow.get('src_ip','N/A')}:{flow.get('src_port','N/A')} → {flow.get('dst_ip','N/A')}:{flow.get('dst_port','N/A')} via {flow.get('protocol','N/A')}\nWrite one paragraph."""
        model_name = GEMINI_MODEL
        if available_models and model_name not in available_models: model_name = available_models[0]
        response = genai.GenerativeModel(model_name).generate_content(prompt)
        if response and response.text:
            return {'success': True, 'analysis': strip_html_tags(response.text.strip()),
                    'timestamp': datetime.now().isoformat(), 'model': GEMINI_MODEL}
        return {'success': False, 'error': 'Empty response', 'analysis': 'Failed.'}
    except Exception as e:
        return {'success': False, 'error': str(e), 'analysis': f'Error: {e}', 'rate_limited': _is_rate_limit_error(str(e))}

def get_classification(event):
    return event.get('attack_type') or event.get('classification') or 'Unknown'

def is_normal_classification(classification):
    s = str(classification).lower()
    return s.startswith('normal') or s == 'benign' or 'normal traffic' in s or 'benign' in s

def threat_meta(threat_level, classification):
    if is_normal_classification(classification): return 'normal', 'b-normal', '🟢'
    lvl = str(threat_level).upper()
    if lvl in ('CRITICAL', 'HIGH'): return 'high', 'b-high', '🔴'
    if lvl == 'MEDIUM': return 'medium', 'b-medium', '🟡'
    return 'low', 'b-low', '🔵'

def fmt_flow(event):
    fd = event.get('flow_details', {})
    return f"{fd.get('src_ip','N/A')}:{fd.get('src_port','?')}  →  {fd.get('dst_ip','N/A')}:{fd.get('dst_port','?')}"

def fmt_time(ts_str):
    try: return datetime.fromisoformat(ts_str).strftime('%H:%M:%S')
    except: return '—'

def port_name(port):
    PORT_NAMES = {80:'HTTP',443:'HTTPS',22:'SSH',53:'DNS',3389:'RDP',1883:'MQTT',8883:'MQTT/TLS',3306:'MySQL',21:'FTP',23:'Telnet',25:'SMTP'}
    try: return PORT_NAMES.get(int(port), f':{port}')
    except: return str(port)

def render_event_card(event, compact=True, show_ai=True):
    classification = get_classification(event)
    threat_level   = event.get('threat_level', 'INFO')
    confidence     = event.get('confidence', 0) * 100
    css, badge, icon = threat_meta(threat_level, classification)
    flow_str = fmt_flow(event); fd = event.get('flow_details', {})
    protocol = fd.get('protocol', '?'); svc = port_name(fd.get('dst_port', ''))
    ts = fmt_time(event.get('timestamp', '')); is_threat = not is_normal_classification(classification)
    event_id = event.get('id', '')
    if not event_id:
        import hashlib
        event_id = hashlib.md5(f"{event.get('timestamp','')}_{flow_str}_{classification}_{confidence}".encode()).hexdigest()[:8]
    for d in ['ai_analyses', 'ai_loading', 'ai_visible']:
        if d not in st.session_state: st.session_state[d] = {}
    sk = f"event_{event_id}"
    if sk not in st.session_state.ai_analyses: st.session_state.ai_analyses[sk] = None
    if sk not in st.session_state.ai_loading:  st.session_state.ai_loading[sk] = False
    if sk not in st.session_state.ai_visible:  st.session_state.ai_visible[sk] = True
    l0 = bool(event.get('layer0_flagged')); l1 = bool(event.get('layer1_flagged'))
    st.markdown(f"""<div class="ev-card {css}">
  <div class="ev-row"><span class="ev-title">{icon} {classification}</span><span class="ev-time">{ts}</span></div>
  <div class="ev-flow">{flow_str}</div>
  <div class="ev-tags"><span class="tag">📡 {protocol}</span><span class="tag">🔌 {svc}</span><span class="tag">🎯 {confidence:.0f}% conf</span><span class="tag">L0: {'⚠️ Anomalous' if l0 else '✅ Normal'}</span><span class="tag">L1: {'🔴 Attack' if l1 else '✅ Normal'}</span><span class="badge {badge}">{threat_level}</span></div>
""", unsafe_allow_html=True)
    if show_ai:
        col1, col2 = st.columns([4, 1])
        with col2:
            if not st.session_state.ai_analyses[sk] and not st.session_state.ai_loading[sk]:
                btn_txt = "🔍 Explain Attack" if is_threat else "❓ Why Normal?"
                if st.button(btn_txt, key=f"ai_btn_{event_id}", width='stretch', type="primary" if is_threat else "secondary"):
                    now_ts = time.time()
                    cooldown = max(st.session_state.ai_cooldown_until - now_ts,
                                   GEMINI_MIN_SECONDS_BETWEEN_CALLS - (now_ts - st.session_state.ai_last_request_at))
                    if not gemini_available:
                        st.session_state.ai_analyses[sk] = {'success': False, 'error': 'Gemini not configured', 'analysis': 'AI unavailable.'}
                    elif cooldown > 0:
                        st.session_state.ai_analyses[sk] = {'success': False, 'error': f'Wait {int(cooldown)}s', 'analysis': 'Rate limit.'}
                    else:
                        st.session_state.ai_loading[sk] = True; st.session_state.ai_visible[sk] = True
                    st.rerun()
            elif st.session_state.ai_analyses[sk]:
                if st.button("👁️ Hide" if st.session_state.ai_visible[sk] else "👁️ Show",
                             key=f"hide_btn_{event_id}", width='stretch', type="secondary"):
                    st.session_state.ai_visible[sk] = not st.session_state.ai_visible[sk]; st.rerun()
        with col1:
            if st.session_state.ai_loading[sk]: st.info("⏳ Getting explanation...", icon="🤔")
            elif st.session_state.ai_analyses[sk] and st.session_state.ai_visible[sk]:
                a = st.session_state.ai_analyses[sk]
                if a.get('success'): render_ai_analysis_box(a['analysis'], is_threat, confidence)
                else: st.error(f"❌ {a.get('error','Analysis failed')}")
    st.markdown("</div>", unsafe_allow_html=True)
    if st.session_state.ai_loading[sk] and not st.session_state.ai_analyses[sk]:
        with st.spinner("🤔 Analyzing..."):
            st.session_state.ai_last_request_at = time.time()
            result = analyze_with_gemini(event)
            st.session_state.ai_analyses[sk] = result; st.session_state.ai_loading[sk] = False
            if result.get('rate_limited'): st.session_state.ai_cooldown_until = time.time() + GEMINI_RATE_LIMIT_COOLDOWN_SECONDS
            st.rerun()


@st.fragment(run_every=AUTO_REFRESH_SECONDS)
def render_live_page():
    if gemini_available:
        st.markdown("""<div style="display:flex;justify-content:flex-end;margin-bottom:0.5rem;"><span style="background:#4285F4;color:white;padding:0.3rem 1rem;border-radius:20px;font-family:'Share Tech Mono',monospace;font-size:0.8rem;">🤖 Gemini AI Ready • Click "Analyze with AI" on any event</span></div>""", unsafe_allow_html=True)

    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
        #MainMenu, footer, .stDeployButton { visibility: hidden; }
        .main .block-container { padding-top: 1.2rem; max-width: 100%; }
        .hero { background: linear-gradient(135deg,#0f2027 0%,#203a43 50%,#2c5364 100%); padding:1.8rem 2.5rem; border-radius:16px; margin-bottom:1.5rem; border:1px solid rgba(66,220,255,0.2); box-shadow:0 0 40px rgba(66,220,255,0.08); }
        .hero h1 { color:#42dcff; font-family:'Rajdhani',sans-serif; font-size:2.4rem; font-weight:700; margin:0; letter-spacing:2px; }
        .hero p  { color:rgba(255,255,255,0.7); font-family:'Share Tech Mono',monospace; font-size:0.95rem; margin:0.5rem 0 0 0; }
        .stat-card { background:#0d1117; border:1px solid rgba(66,220,255,0.15); border-radius:12px; padding:1.2rem 1rem; text-align:center; transition:border-color 0.3s; }
        .stat-card:hover { border-color:rgba(66,220,255,0.4); }
        .stat-label { font-family:'Share Tech Mono',monospace; font-size:0.75rem; color:#4a5568; text-transform:uppercase; letter-spacing:2px; }
        .stat-value { font-family:'Rajdhani',sans-serif; font-size:2.2rem; font-weight:700; margin:0.3rem 0; }
        .stat-sub   { font-size:0.8rem; color:#4a5568; }
        .ev-card { background:#0d1117; border-left:4px solid #4a5568; border-radius:10px; padding:1rem 1.2rem; margin-bottom:0.8rem; transition:transform 0.2s,box-shadow 0.2s; }
        .ev-card:hover { transform:translateX(4px); box-shadow:0 4px 20px rgba(0,0,0,0.4); }
        .ev-card.high   { border-left-color:#f56565; background:linear-gradient(90deg,rgba(245,101,101,0.08) 0%,#0d1117 25%); }
        .ev-card.medium { border-left-color:#ecc94b; background:linear-gradient(90deg,rgba(236,201,75,0.08) 0%,#0d1117 25%); }
        .ev-card.low    { border-left-color:#4299e1; background:linear-gradient(90deg,rgba(66,153,225,0.08) 0%,#0d1117 25%); }
        .ev-card.normal { border-left-color:#48bb78; background:linear-gradient(90deg,rgba(72,187,120,0.08) 0%,#0d1117 25%); }
        .ev-row   { display:flex; justify-content:space-between; align-items:center; }
        .ev-title { font-family:'Rajdhani',sans-serif; font-size:1.15rem; font-weight:700; color:white; }
        .ev-time  { font-family:'Share Tech Mono',monospace; font-size:0.85rem; color:#4a5568; background:rgba(0,0,0,0.3); padding:0.2rem 0.6rem; border-radius:6px; }
        .ev-flow  { font-family:'Share Tech Mono',monospace; font-size:0.9rem; color:#a0aec0; background:rgba(0,0,0,0.2); padding:0.5rem 0.8rem; border-radius:6px; margin:0.6rem 0; border-left:2px solid #42dcff; }
        .ev-tags  { display:flex; gap:0.6rem; flex-wrap:wrap; margin-top:0.5rem; }
        .tag      { font-family:'Share Tech Mono',monospace; font-size:0.75rem; padding:0.2rem 0.6rem; border-radius:20px; background:rgba(255,255,255,0.07); color:#a0aec0; }
        .sec-hdr  { font-family:'Rajdhani',sans-serif; font-size:1.3rem; font-weight:700; color:#42dcff; text-transform:uppercase; letter-spacing:3px; padding:0.6rem 0; margin:1.5rem 0 1rem 0; border-bottom:1px solid rgba(66,220,255,0.2); }
        .rev-card { background:rgba(237,137,54,0.07); border:1px solid rgba(237,137,54,0.35); border-radius:12px; padding:1.2rem; margin-bottom:1rem; transition:box-shadow 0.2s; }
        .rev-card:hover { box-shadow:0 6px 24px rgba(237,137,54,0.25); }
        .badge    { display:inline-block; padding:0.25rem 0.8rem; border-radius:20px; font-size:0.78rem; font-weight:700; text-transform:uppercase; letter-spacing:1px; }
        .b-high   { background:#742a2a; color:#fc8181; }
        .b-medium { background:#744210; color:#f6e05e; }
        .b-low    { background:#1a365d; color:#63b3ed; }
        .b-normal { background:#1c4532; color:#68d391; }
        .b-review { background:#7b341e; color:#fbd38d; }
        .pi-panel { background:#0d1117; border:1px solid rgba(66,220,255,0.15); border-radius:12px; padding:1.2rem; }
        .warn-box { background:rgba(237,137,54,0.12); border:1px solid rgba(237,137,54,0.4); border-radius:8px; padding:0.8rem 1rem; margin-top:0.8rem; color:#fbd38d; font-size:0.9rem; }
        .empty      { text-align:center; padding:3rem; background:rgba(72,187,120,0.05); border:2px dashed rgba(72,187,120,0.3); border-radius:16px; margin:1rem 0; }
        .empty-icon  { font-size:3rem; }
        .empty-title { font-family:'Rajdhani',sans-serif; font-size:1.6rem; color:#48bb78; font-weight:700; }
        .empty-text  { color:#4a5568; margin-top:0.3rem; }
        .refresh-bar { display:flex; align-items:center; justify-content:space-between; background:#0d1117; border:1px solid rgba(66,220,255,0.1); border-radius:10px; padding:0.6rem 1.2rem; margin-bottom:1rem; font-family:'Share Tech Mono',monospace; font-size:0.85rem; color:#4a5568; }
        .refresh-dot { width:8px; height:8px; border-radius:50%; background:#48bb78; display:inline-block; margin-right:0.5rem; animation:pulse 2s infinite; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
    </style>""", unsafe_allow_html=True)

    def send_mqtt(topic, payload):
        try: publish.single(topic=topic, payload=payload, hostname=MQTT_BROKER, port=MQTT_PORT); return True
        except Exception as e: st.error(f"❌ MQTT error: {e}"); return False

    def threat_meta_local(threat_level, classification):
        if is_normal_classification(classification): return 'normal','b-normal','🟢'
        lvl = str(threat_level).upper()
        if lvl in ('CRITICAL','HIGH'): return 'high','b-high','🔴'
        if lvl == 'MEDIUM': return 'medium','b-medium','🟡'
        return 'low','b-low','🔵'

    def fmt_flow_local(t):
        fd = t.get('flow_details',{})
        return f"{fd.get('src_ip','N/A')}:{fd.get('src_port','?')}  →  {fd.get('dst_ip','N/A')}:{fd.get('dst_port','?')}"

    def fmt_time_local(ts):
        try: return datetime.fromisoformat(ts).strftime('%H:%M:%S')
        except: return '—'

    def fmt_ts_full(ts):
        try: return datetime.fromisoformat(ts).strftime('%Y-%m-%d %H:%M:%S')
        except: return '—'

    def is_untrained_classification(c):
        s = str(c).lower()
        return 'unknown' in s or 'zero-day' in s or 'zero day' in s or 'uncertain' in s or 'needs review' in s

    def normalized_confidence(e):
        conf = e.get('confidence', 0) or 0
        try: conf = float(conf)
        except: return 0.0
        if conf > 1.0: conf /= 100.0
        return max(0.0, min(conf, 1.0))

    def needs_human_review(e):
        return normalized_confidence(e) < REVIEW_CONF_THRESHOLD or is_untrained_classification(get_classification(e))

    def is_threat_event(e):
        return not is_normal_classification(get_classification(e))

    PORT_NAMES = {80:'HTTP',443:'HTTPS',22:'SSH',53:'DNS',3389:'RDP',1883:'MQTT',8883:'MQTT/TLS',3306:'MySQL',21:'FTP',23:'Telnet',25:'SMTP'}
    def port_name_local(p):
        try: return PORT_NAMES.get(int(p), f':{p}')
        except: return str(p)

    def purge_old_history(reader):
        try:
            import sqlite3
            cutoff = (datetime.now() - timedelta(days=HISTORY_DAYS)).isoformat()
            conn = sqlite3.connect(reader.db_path)
            conn.execute("DELETE FROM threat_feed WHERE timestamp < ?", (cutoff,)); conn.commit(); conn.close()
        except Exception as e: print(f"[purge] {e}")

    def clear_threats(reader, threat_ids):
        if not threat_ids: return 0
        try:
            import sqlite3
            conn = sqlite3.connect(reader.db_path); cursor = conn.cursor()
            now = datetime.now().isoformat()
            placeholders = ",".join(["?"] * len(threat_ids))
            cursor.execute(f"UPDATE threat_feed SET reviewed=1,review_decision=?,review_timestamp=? WHERE id IN ({placeholders})", ("cleared", now, *threat_ids))
            conn.commit(); conn.close(); return cursor.rowcount or 0
        except Exception as e: print(f"[clear_threats] {e}"); return 0

    def get_history(reader, days=HISTORY_DAYS):
        try:
            import sqlite3
            cutoff = (datetime.now() - timedelta(days=days)).isoformat()
            conn = sqlite3.connect(reader.db_path); conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM threat_feed WHERE timestamp > ? ORDER BY timestamp DESC", (cutoff,)).fetchall()
            conn.close()
            result = []
            for r in rows:
                d = dict(r)
                if isinstance(d.get('flow_details'), str):
                    try: d['flow_details'] = json.loads(d['flow_details'])
                    except: d['flow_details'] = {}
                result.append(d)
            return result
        except Exception as e: print(f"[history] {e}"); return []

    # ── FIX: Dedicated DB queries for threats and review queue ─────────────────
    # These bypass the 1000-row live feed cap so items NEVER get washed out
    # by incoming normal traffic. Items only disappear when reviewed=1 is set.

    def get_all_threats_unreviewed(reader):
        """Fetch ALL unreviewed confirmed threats directly — no row cap."""
        try:
            import sqlite3
            conn = sqlite3.connect(reader.db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM threat_feed
                WHERE reviewed = 0
                  AND (
                    attack_type NOT IN ('Normal Traffic', 'Benign', 'BENIGN')
                    AND LOWER(attack_type) NOT LIKE '%normal%'
                    AND LOWER(attack_type) NOT LIKE '%benign%'
                  )
                  AND confidence >= ?
                ORDER BY id DESC
            """, (REVIEW_CONF_THRESHOLD,)).fetchall()
            conn.close()
            result = []
            for r in rows:
                d = dict(r)
                if isinstance(d.get('flow_details'), str):
                    try: d['flow_details'] = json.loads(d['flow_details'])
                    except: d['flow_details'] = {}
                result.append(d)
            return result
        except Exception as e:
            print(f"[get_all_threats_unreviewed] {e}")
            return []

    def get_all_pending_review(reader):
        """Fetch ALL items pending human review — no row cap.
        Items persist until the analyst explicitly acts on them."""
        try:
            import sqlite3
            conn = sqlite3.connect(reader.db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM threat_feed
                WHERE reviewed = 0
                  AND (
                    confidence < ?
                    OR LOWER(attack_type) LIKE '%unknown%'
                    OR LOWER(attack_type) LIKE '%zero-day%'
                    OR LOWER(attack_type) LIKE '%zero day%'
                    OR LOWER(attack_type) LIKE '%uncertain%'
                    OR LOWER(attack_type) LIKE '%needs review%'
                  )
                ORDER BY id DESC
            """, (REVIEW_CONF_THRESHOLD,)).fetchall()
            conn.close()
            result = []
            for r in rows:
                d = dict(r)
                if isinstance(d.get('flow_details'), str):
                    try: d['flow_details'] = json.loads(d['flow_details'])
                    except: d['flow_details'] = {}
                result.append(d)
            return result
        except Exception as e:
            print(f"[get_all_pending_review] {e}")
            return []

    def compute_review_stats(review_q, history_rows):
        today = datetime.now().date(); reviewed_today = low_confidence = 0
        for e in history_rows:
            if normalized_confidence(e) < REVIEW_CONF_THRESHOLD: low_confidence += 1
            if e.get('reviewed'):
                try:
                    ts = datetime.fromisoformat(e.get('review_timestamp') or e.get('timestamp'))
                    if ts.date() == today: reviewed_today += 1
                except: pass
        return {
            'pending': len(review_q),
            'reviewed_today': reviewed_today,
            'low_confidence': low_confidence,
        }

    reader = st.session_state.reader
    purge_old_history(reader)

    try:
        live_stats   = reader.get_system_stats()
        devices      = reader.get_all_devices()
        all_events   = reader.get_threat_feed(limit=LIVE_FEED_LIMIT)  # live feed only (charts + recent events)
        history_data = get_history(reader)                             # full history (History tab)

        # ── FIX: threats and review queue fetched independently ──────────────
        # These query the full DB with no cap — items stay until user acts.
        threats      = get_all_threats_unreviewed(reader)
        review_queue = get_all_pending_review(reader)

    except Exception as e:
        st.error(f"⚠️ DB connection error: {e}"); st.stop()

    recent5 = all_events[:5]
    total   = live_stats.get('total_flows_processed', 0)
    if st.session_state.session_start_flows == 0 or total < st.session_state.session_start_flows:
        st.session_state.session_start_flows = total
    session_flows = max(0, total - st.session_state.session_start_flows)

    atk_cnt = len(threats)
    atk_pct = (atk_cnt / max(len(all_events), 1)) * 100

    # ── FIX: pending count comes directly from the persistent review queue ──
    pending      = len(review_queue)
    review_stats = compute_review_stats(review_queue, history_data)

    pi_device = next((d for d in devices if d['device_id'] == 'rpi-01'), None)
    pi_online = False; pi_sec_ago = 999999
    if pi_device and pi_device.get('last_seen'):
        try:
            ls = datetime.fromisoformat(pi_device['last_seen'])
            pi_sec_ago = (datetime.now() - ls).total_seconds(); pi_online = pi_sec_ago < 30
        except: pass

    def approve_normal_callback(threat_id):
        st.session_state.reader.approve_review(threat_id, 'normal'); st.session_state.active_tab = 'review'
    def approve_attack_callback(threat_id):
        st.session_state.reader.approve_review(threat_id, 'attack'); st.session_state.active_tab = 'review'
    def toggle_show_more_callback():
        st.session_state.show_more_live = not st.session_state.show_more_live

    if st.session_state.auto_refresh: st.session_state.last_refresh = datetime.now()

    st.markdown("""<div class="hero"><h1>🛡️ NETWORK SECURITY OPERATIONS CENTER</h1><p>3-Layer Detection · Zero-Day + Classification + Human Review · 99.92% accuracy</p></div>""", unsafe_allow_html=True)

    col_r1, col_r2, col_r3 = st.columns([3,1,1])
    with col_r1:
        st.markdown(f'<div class="refresh-bar"><span><span class="refresh-dot"></span>LIVE · Last sync: {st.session_state.last_refresh.strftime("%H:%M:%S")}</span><span style="color:#42dcff">{AUTO_REFRESH_SECONDS}s auto-refresh</span></div>', unsafe_allow_html=True)
    with col_r2:
        if st.button("🔄 Refresh", width='stretch', type="primary"): st.session_state.last_refresh = datetime.now()
    with col_r3:
        st.session_state.auto_refresh = st.toggle("Auto", value=st.session_state.auto_refresh)

    c1,c2,c3,c4,c5 = st.columns(5)
    pi_status = "🔴 STOPPED"; pi_color = "#f56565"
    if st.session_state.pi_monitor_enabled and pi_online: pi_status,pi_color = "🟢 LIVE","#48bb78"
    elif st.session_state.pi_monitor_enabled and not pi_online: pi_status,pi_color = "🟡 STARTING","#ecc94b"
    cards = [("SYSTEM","🟢 ONLINE" if total>0 else "🔴 OFFLINE","#42dcff" if total>0 else "#f56565",""),
             ("THIS SESSION",f"{session_flows:,}","#4299e1","flows"),
             ("THREATS",f"{atk_cnt:,}","#f56565" if atk_pct>20 else "#ecc94b" if atk_pct>5 else "#48bb78",f"{atk_pct:.1f}%"),
             ("REVIEW QUEUE",str(pending),"#ed8936","Layer 2"),
             ("RASPBERRY PI",pi_status,pi_color,"")]
    for col,(lbl,val,color,sub) in zip([c1,c2,c3,c4,c5], cards):
        with col:
            st.markdown(f'<div class="stat-card"><div class="stat-label">{lbl}</div><div class="stat-value" style="color:{color}">{val}</div><div class="stat-sub">{sub}</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    t1,t2,t3,t4 = st.columns(4)
    with t1:
        if st.button(f"📡 Live Events ({len(recent5)})", width='stretch', type="primary" if st.session_state.active_tab=='live' else "secondary"):
            st.session_state.active_tab='live'; st.rerun()
    with t2:
        if st.button(f"🔴 Threats ({atk_cnt})", width='stretch', type="primary" if st.session_state.active_tab=='threats' else "secondary"):
            st.session_state.active_tab='threats'; st.rerun()
    with t3:
        if st.button("📂 History", width='stretch', type="primary" if st.session_state.active_tab=='history' else "secondary"):
            st.session_state.active_tab='history'; st.rerun()
    with t4:
        if st.button(f"👤 Review ({pending})", width='stretch', type="primary" if st.session_state.active_tab=='review' else "secondary"):
            st.session_state.active_tab='review'; st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # ── TAB 1: LIVE ───────────────────────────────────────────────────────────
    if st.session_state.active_tab == 'live':
        col_a, col_b = st.columns(2)
        with col_a:
            now = datetime.now(); times, normals, thrt_pts = [], [], []
            for i in range(10,-1,-1):
                t = now - timedelta(minutes=i); times.append(t)
                bucket = [e for e in all_events if abs((datetime.fromisoformat(e['timestamp'])-t).total_seconds())<30]
                t_cnt = sum(1 for e in bucket if is_threat_event(e))
                thrt_pts.append(t_cnt); normals.append(len(bucket)-t_cnt)
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=times,y=normals,name='Normal',fill='tozeroy',line=dict(color='#48bb78',width=2,shape='spline'),fillcolor='rgba(72,187,120,0.2)',mode='lines'))
            fig.add_trace(go.Scatter(x=times,y=thrt_pts,name='Threats',fill='tozeroy',line=dict(color='#f56565',width=2,shape='spline'),fillcolor='rgba(245,101,101,0.2)',mode='lines'))
            fig.update_layout(title=dict(text='Traffic (last 10 min)',font=dict(size=14,color='white')),plot_bgcolor='rgba(0,0,0,0)',paper_bgcolor='rgba(0,0,0,0)',font=dict(color='white',family='Share Tech Mono'),height=220,margin=dict(l=30,r=10,t=40,b=30),xaxis=dict(gridcolor='rgba(255,255,255,0.05)',color='#4a5568'),yaxis=dict(gridcolor='rgba(255,255,255,0.05)',color='#4a5568'),legend=dict(orientation='h',y=1.1,x=0,font=dict(size=11)))
            st.plotly_chart(fig, width='stretch', key="tl_live")
        with col_b:
            THREAT_COLORS = ['#f56565','#ed8936','#ecc94b','#9f7aea','#667eea','#4299e1','#38b2ac','#fc8181']
            session_events = all_events[:session_flows] if session_flows > 0 else all_events
            session_atk_types = Counter(get_classification(e) for e in session_events if is_threat_event(e))
            session_normal_count = max(0, len(session_events) - sum(session_atk_types.values()))
            labels = ['✅ Normal'] + [f'⚠️ {k}' for k in session_atk_types]
            values = [session_normal_count] + list(session_atk_types.values())
            colors = ['#48bb78'] + [THREAT_COLORS[i%len(THREAT_COLORS)] for i in range(len(session_atk_types))]
            if sum(values) > 0:
                fig2 = go.Figure(go.Pie(labels=labels,values=values,hole=0.6,marker=dict(colors=colors,line=dict(color='#0d1117',width=2)),textinfo='label+percent',textfont=dict(size=11,color='white'),hovertemplate='<b>%{label}</b><br>%{value} flows (%{percent})<extra></extra>'))
                fig2.add_annotation(text=f"<b>{session_flows:,}</b><br>session",x=0.5,y=0.5,font=dict(size=16,color='white'),showarrow=False)
                fig2.update_layout(plot_bgcolor='rgba(0,0,0,0)',paper_bgcolor='rgba(0,0,0,0)',font=dict(color='white',family='Share Tech Mono'),height=220,margin=dict(l=0,r=0,t=10,b=0),showlegend=False)
                st.plotly_chart(fig2, width='stretch', key="donut_live")
            else: st.info("Waiting for data...")

        st.markdown('<div class="sec-hdr">🎮 Pi Control</div>', unsafe_allow_html=True)
        with st.container():
            st.markdown('<div class="pi-panel">', unsafe_allow_html=True)
            pc1,pc2 = st.columns([3,1])
            with pc1:
                if pi_device:
                    last_str = f"{int(pi_sec_ago)}s ago" if pi_sec_ago<60 else f"{int(pi_sec_ago)//60}m ago" if pi_sec_ago<3600 else f"{int(pi_sec_ago)//3600}h ago"
                    pi_icon = "🟢" if pi_online else "🔴"
                    st.markdown(f"**{pi_icon} rpi-01** &nbsp;·&nbsp; Last seen: `{last_str}` &nbsp;·&nbsp; IP: `{pi_device.get('ip_address','N/A')}` &nbsp;·&nbsp; Flows: `{pi_device.get('total_flows',0):,}`")
                    if not pi_online and pi_sec_ago < 300:
                        st.markdown(f'<div class="warn-box">⚠️ Connection lost {last_str}</div>', unsafe_allow_html=True)
                else: st.markdown("**🔴 No Pi registered**")
            with pc2:
                if st.session_state.pi_last_state != pi_online: st.session_state.pi_last_state = pi_online
                if st.session_state.pi_monitor_enabled:
                    if st.button("⏹️ STOP", type="secondary", width='stretch'):
                        if send_mqtt("nids/control/rpi-01/stop","stop"):
                            st.session_state.pi_monitor_enabled=False; st.success("✅ STOP sent"); time.sleep(1); st.rerun()
                else:
                    if st.button("▶️ START", type="primary", width='stretch'):
                        if send_mqtt("nids/control/rpi-01/start","start"):
                            st.session_state.pi_monitor_enabled=True; st.success("✅ START sent"); time.sleep(1); st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

        if os.system("pgrep -f mqtt_auto_analyzer.py > /dev/null") != 0:
            st.warning("⚠️ `mqtt_auto_analyzer.py` is NOT running.\n\n```bash\ncd /home/shared/IoT_Project/AI_Anomaly_Detection/realtime_monitor\nnohup python3 mqtt_auto_analyzer.py > mqtt_auto_analyzer.log 2>&1 &\n```")

        events_to_show = all_events if st.session_state.show_more_live else recent5
        st.markdown(f'<div class="sec-hdr">📡 Recent Events ({len(events_to_show)} shown)</div>', unsafe_allow_html=True)
        if all_events:
            for ev in events_to_show: render_event_card(ev, show_ai=True)
            if len(all_events) > 5:
                st.button("📋 Show More" if not st.session_state.show_more_live else "📋 Show Less",
                    key="toggle_show_more_live", width='content', type="secondary", on_click=toggle_show_more_callback)
        else:
            st.markdown('<div class="empty"><div class="empty-icon">✅</div><div class="empty-title">All Clear</div><div class="empty-text">No events yet.</div></div>', unsafe_allow_html=True)

    # ── TAB 2: THREATS ────────────────────────────────────────────────────────
    if st.session_state.active_tab == 'threats':
        if threats:
            st.markdown(f'<div class="sec-hdr">🔴 {len(threats)} Active Threats · Persists until cleared</div>', unsafe_allow_html=True)
            clear_ids = [e.get('id') for e in threats if e.get('id') is not None]
            cbtn1, cbtn2 = st.columns([1,3])
            with cbtn1:
                if st.button("🧹 Clear All Threats", type="secondary", width='stretch'):
                    cleared = clear_threats(reader, clear_ids)
                    st.success(f"Cleared {cleared} threat(s)"); time.sleep(1); st.rerun()
            atk_dist = Counter(get_classification(e) for e in threats)
            fig_bar = go.Figure(go.Bar(x=list(atk_dist.values()),y=list(atk_dist.keys()),orientation='h',marker=dict(color='#f56565',opacity=0.85,line=dict(color='#fc8181',width=1)),text=list(atk_dist.values()),textposition='auto',textfont=dict(color='white',size=12)))
            fig_bar.update_layout(title=dict(text='Attack Type Breakdown',font=dict(size=14,color='white')),plot_bgcolor='rgba(0,0,0,0)',paper_bgcolor='rgba(0,0,0,0)',font=dict(color='white',family='Share Tech Mono'),height=max(200,len(atk_dist)*50),margin=dict(l=120,r=20,t=40,b=20),xaxis=dict(gridcolor='rgba(255,255,255,0.05)',color='#4a5568',title='Count'),yaxis=dict(color='white'))
            st.plotly_chart(fig_bar, width='stretch', key="bar_threats")
            for ev in threats: render_event_card(ev, show_ai=True)
        else:
            st.markdown('<div class="empty"><div class="empty-icon">✅</div><div class="empty-title">No Active Threats</div><div class="empty-text">All threats have been cleared or none detected yet.</div></div>', unsafe_allow_html=True)

    # ── TAB 3: HISTORY ────────────────────────────────────────────────────────
    if st.session_state.active_tab == 'history':
        st.markdown('<div class="sec-hdr">📂 Event History</div>', unsafe_allow_html=True)
        if history_data:
            f1,f2,f3,f4 = st.columns(4)
            all_types = sorted(set(e.get('attack_type','Unknown') for e in history_data))
            all_ips   = sorted(set(e.get('flow_details',{}).get('src_ip','') for e in history_data if e.get('flow_details',{}).get('src_ip','')))
            with f1: date_from = st.date_input("From", value=datetime.now().date()-timedelta(days=7))
            with f2: date_to   = st.date_input("To",   value=datetime.now().date())
            with f3: sel_type  = st.selectbox("Attack Type", ["All"]+all_types)
            with f4: sel_ip    = st.selectbox("Source IP",   ["All"]+all_ips)
            search_q = st.text_input("🔍 Search", placeholder="e.g. 192.168.1.1 or DoS or HTTPS")
            filtered = []
            for e in history_data:
                ts_ok = type_ok = ip_ok = q_ok = True
                try:
                    ev_date = datetime.fromisoformat(e['timestamp']).date()
                    ts_ok = date_from <= ev_date <= date_to
                except: pass
                if sel_type != "All": type_ok = e.get('attack_type','') == sel_type
                if sel_ip   != "All": ip_ok   = e.get('flow_details',{}).get('src_ip','') == sel_ip
                if search_q: q_ok = search_q.lower() in json.dumps(e).lower()
                if ts_ok and type_ok and ip_ok and q_ok: filtered.append(e)
            st.caption(f"Showing **{len(filtered)}** of {len(history_data)} records")
            if filtered:
                p1,p2 = st.columns([1,2])
                with p1: page_size_label = st.selectbox("Rows per page",["200","500","1000","2000","All"],index=0)
                with p2:
                    total_rows = len(filtered); page_size = total_rows if page_size_label=="All" else int(page_size_label)
                    total_pages = max(1,(total_rows+page_size-1)//page_size)
                    page = st.number_input("Page",min_value=1,max_value=total_pages,value=1,step=1)
                start_idx = (page-1)*page_size; end_idx = start_idx+page_size
                rows = []
                for e in filtered[start_idx:end_idx]:
                    fd = e.get('flow_details',{}); css,badge,icon = threat_meta_local(e.get('threat_level',''),e.get('attack_type',''))
                    rows.append({'Time':fmt_ts_full(e.get('timestamp','')),'Type':f"{icon} {e.get('attack_type','Unknown')}",'Threat':e.get('threat_level','—'),'Confidence':f"{e.get('confidence',0):.1f}%",'Src IP':fd.get('src_ip','—'),'Src Port':str(fd.get('src_port','—')),'Dst IP':fd.get('dst_ip','—'),'Dst Port':str(fd.get('dst_port','—')),'Protocol':fd.get('protocol','—'),'L0':'⚠️' if e.get('layer0_flagged') else '✅','L1':'🔴' if e.get('layer1_flagged') else '✅','Reviewed':'✅' if e.get('reviewed') else '—','Decision':e.get('review_decision','—') or '—','Device':e.get('device_id','—')})
                df = pd.DataFrame(rows)
                st.caption(f"Page {page} of {total_pages} · Rows {start_idx+1}–{min(end_idx,total_rows)}")
                st.dataframe(df, width='stretch', hide_index=True, height=min(600,len(df)*36+40))
                st.download_button("📥 Export filtered results (CSV)", data=df.to_csv(index=False), file_name=f"nids_history_{datetime.now().strftime('%Y%m%d_%H%M')}.csv", mime="text/csv")
            else: st.info("No records match the selected filters.")
        else:
            st.markdown('<div class="empty"><div class="empty-icon">📂</div><div class="empty-title">No History Yet</div><div class="empty-text">Events will appear here once the system starts processing traffic.</div></div>', unsafe_allow_html=True)

    # ── TAB 4: HUMAN REVIEW ───────────────────────────────────────────────────
    if st.session_state.active_tab == 'review':
        r_stats = review_stats or {}
        st.markdown(f'<div class="sec-hdr">👤 Layer 2 Human Review Queue · {pending} pending · Persists until reviewed</div>', unsafe_allow_html=True)

        rs1, rs2, rs3 = st.columns(3)
        rs1.metric("Pending",        r_stats.get('pending', 0))
        rs2.metric("Reviewed Today", r_stats.get('reviewed_today', 0))
        rs3.metric("Low Confidence", r_stats.get('low_confidence', 0))

        all_review_ids = [item.get('id') for item in review_queue if item.get('id') is not None]
        if all_review_ids:
            ca1, ca2 = st.columns([1, 3])
            with ca1:
                if st.button("🧹 Clear All Reviews", type="secondary", width='stretch'):
                    try:
                        import sqlite3
                        conn = sqlite3.connect(reader.db_path)
                        now_str = datetime.now().isoformat()
                        placeholders = ",".join(["?"] * len(all_review_ids))
                        conn.execute(
                            f"UPDATE threat_feed SET reviewed=1, review_decision='cleared', review_timestamp=? WHERE id IN ({placeholders})",
                            (now_str, *all_review_ids))
                        conn.commit(); conn.close()
                        st.session_state.review_shown_count = REVIEW_PAGE_SIZE
                        st.session_state.review_skipped = []
                        st.success(f"✅ Cleared {len(all_review_ids)} item(s)")
                    except Exception as e:
                        st.error(f"❌ Clear failed: {e}")
                    time.sleep(1); st.rerun()

        st.caption("Flows stay here until you Confirm Normal, Confirm Attack, or Clear All. They will NOT disappear due to new traffic.")
        st.markdown("<br>", unsafe_allow_html=True)

        display_queue = [item for item in review_queue if item.get('id') not in st.session_state.review_skipped]

        if display_queue:
            shown       = st.session_state.review_shown_count
            total_queue = len(display_queue)
            visible_items = display_queue[:shown]

            st.caption(f"Showing **{len(visible_items)}** of {total_queue} pending items")

            for idx, item in enumerate(visible_items):
                classification = get_classification(item)
                confidence     = item.get('confidence', 0) * 100
                l0 = bool(item.get('layer0_flagged')); l1 = bool(item.get('layer1_flagged'))
                flow_str      = fmt_flow_local(item); fd = item.get('flow_details', {})
                protocol      = fd.get('protocol', '?'); dst_port = fd.get('dst_port', 'N/A')
                src_port      = fd.get('src_port', 'N/A'); bytes_count = fd.get('bytes', 'N/A')
                packets_count = fd.get('packets', 'N/A'); ts = fmt_ts_full(item.get('timestamp',''))
                reason = "🧪 Untrained / Zero‑Day" if is_untrained_classification(classification) else "🔍 Low Confidence (<70%)"
                item_id = item.get('id')
                packet_size_info = ""
                if bytes_count != 'N/A' and packets_count not in ('N/A','0',0):
                    try:
                        avg = int(bytes_count) / int(packets_count)
                        if avg > 1400: packet_size_info = f"• Large packets ({avg:.0f}B avg) — possible exfiltration"
                        elif avg < 100: packet_size_info = f"• Small packets ({avg:.0f}B avg) — possible scanning/C2"
                        else: packet_size_info = f"• Normal packet size ({avg:.0f}B avg)"
                    except: pass
                common_ports = {'80':{'name':'HTTP','risk':'low','desc':'web browsing'},'443':{'name':'HTTPS','risk':'low','desc':'secure web'},'22':{'name':'SSH','risk':'high','desc':'remote access'},'53':{'name':'DNS','risk':'low','desc':'domain lookups'},'3389':{'name':'RDP','risk':'critical','desc':'remote desktop'},'1883':{'name':'MQTT','risk':'medium','desc':'IoT messaging'},'3306':{'name':'MySQL','risk':'critical','desc':'database'},'25':{'name':'SMTP','risk':'medium','desc':'email'},'445':{'name':'SMB','risk':'high','desc':'file sharing'},'8080':{'name':'HTTP-alt','risk':'medium','desc':'web proxy/dev'}}
                if str(dst_port) in common_ports:
                    p = common_ports[str(dst_port)]
                    port_info = f"• Port {dst_port} ({p['name']}) — {p['desc']} — Risk: {p['risk']}"; port_risk = p['risk']
                else:
                    port_info = f"• Port {dst_port} — unusual port — Risk: unknown"; port_risk = "unknown"
                ml_analysis = []
                if l0 and l1: ml_analysis += ["🔴 Both Layer 0 & 1 flagged this","   • L0 (Autoencoder): Anomalous pattern","   • L1 (XGBoost): Potential attack"]
                elif l0 and not l1: ml_analysis += ["🟡 Layer 0 flagged, Layer 1 normal","   • L0: Unusual pattern (zero-day potential)","   • L1: No known signature matched"]
                elif not l0 and l1: ml_analysis += ["🟡 Layer 1 flagged, Layer 0 normal","   • L0: Pattern appeared normal","   • L1: Known attack signature detected"]
                else: ml_analysis += ["✅ Both layers normal — in review due to low confidence"]
                ml_analysis.append(f"   • Confidence: {confidence:.1f}%")
                if is_untrained_classification(classification): ml_analysis.append("   • Untrained/uncertain classification")
                elif confidence < 60: ml_analysis.append("   • VERY LOW confidence — system highly uncertain")
                else: ml_analysis.append("   • MODERATE confidence — needs human verification")

                review_id = f"review_{item_id}_{idx}"
                if 'review_ai_analyses' not in st.session_state: st.session_state.review_ai_analyses = {}
                if 'review_ai_loading'   not in st.session_state: st.session_state.review_ai_loading  = {}
                if review_id not in st.session_state.review_ai_analyses: st.session_state.review_ai_analyses[review_id] = None
                if review_id not in st.session_state.review_ai_loading:  st.session_state.review_ai_loading[review_id]  = False

                st.markdown(f"""
<div class="rev-card">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.8rem;">
    <div><strong style="font-size:1.1rem;color:#ed8936;">Review #{idx+1}</strong>&nbsp;<span class="badge b-review">{reason}</span></div>
    <div style="font-family:'Share Tech Mono',monospace;font-size:0.8rem;color:#4a5568;">{ts}</div>
  </div>
  <div style="background:rgba(0,0,0,0.25);padding:0.7rem;border-radius:8px;margin-bottom:0.8rem;font-family:'Share Tech Mono',monospace;font-size:0.85rem;color:#a0aec0;">{flow_str} &nbsp;·&nbsp; {protocol}</div>
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:0.8rem;margin-bottom:0.8rem;">
    <div style="background:rgba(0,0,0,0.2);padding:0.6rem;border-radius:8px;"><div style="font-size:0.75rem;color:#4a5568;">ML Classification</div><div style="font-weight:700;color:white;">{classification}</div></div>
    <div style="background:rgba(0,0,0,0.2);padding:0.6rem;border-radius:8px;"><div style="font-size:0.75rem;color:#4a5568;">Confidence</div><div style="font-weight:700;color:{'#f56565' if confidence<50 else '#ecc94b' if confidence<70 else '#48bb78'};">{confidence:.1f}%</div></div>
    <div style="background:rgba(0,0,0,0.2);padding:0.6rem;border-radius:8px;"><div style="font-size:0.75rem;color:#4a5568;">Device</div><div style="font-weight:700;color:white;">{item.get('device_id','?')}</div></div>
  </div>
  <div style="background:rgba(0,0,0,0.2);padding:0.8rem;border-radius:8px;margin-bottom:0.8rem;">
    <div style="font-family:'Share Tech Mono',monospace;font-size:0.8rem;color:#667eea;margin-bottom:0.5rem;">🧠 ML MODEL ANALYSIS</div>
    <div style="font-size:0.9rem;color:#e2e8f0;">{"<br>".join(ml_analysis)}</div>
  </div>
  <div style="background:rgba(0,0,0,0.15);padding:0.8rem;border-radius:8px;margin:0.8rem 0;">
    <div style="font-family:'Share Tech Mono',monospace;font-size:0.8rem;color:#4a5568;margin-bottom:0.3rem;">📊 PACKET ANALYSIS</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;font-size:0.85rem;">
      <div><span style="color:#718096;">Data:</span> {bytes_count} bytes</div><div><span style="color:#718096;">Packets:</span> {packets_count}</div>
      <div><span style="color:#718096;">Src Port:</span> {src_port}</div><div><span style="color:#718096;">Dst Port:</span> {dst_port}</div>
    </div>
    <div style="margin-top:0.5rem;font-size:0.85rem;color:#a0aec0;">{packet_size_info}<br>{port_info}</div>
  </div>
""", unsafe_allow_html=True)

                col_ai1, col_ai2 = st.columns([4,1])
                with col_ai2:
                    if not st.session_state.review_ai_analyses[review_id] and not st.session_state.review_ai_loading[review_id]:
                        if st.button("🔍 AI Analyze", key=f"review_ai_{item_id}_{idx}", type="primary", width='stretch'):
                            now_ts = time.time()
                            cooldown = max(st.session_state.ai_cooldown_until-now_ts,GEMINI_MIN_SECONDS_BETWEEN_CALLS-(now_ts-st.session_state.ai_last_request_at))
                            if not gemini_available: st.session_state.review_ai_analyses[review_id] = {'success':False,'error':'Gemini not configured','analysis':'AI unavailable.'}
                            elif cooldown > 0: st.session_state.review_ai_analyses[review_id] = {'success':False,'error':f'Wait {int(cooldown)}s','analysis':'Rate limit.'}
                            else: st.session_state.review_ai_loading[review_id] = True
                            st.rerun()
                    elif st.session_state.review_ai_analyses[review_id]:
                        st.caption("✨ AI complete")
                with col_ai1:
                    if st.session_state.review_ai_loading[review_id]: st.info("⏳ Analyzing...", icon="🤖")
                    elif st.session_state.review_ai_analyses[review_id]:
                        a = st.session_state.review_ai_analyses[review_id]
                        if a.get('success'): render_review_ai_analysis_box(a['analysis'],a.get('assessment','uncertain'),a.get('timestamp',''))
                        else: st.error(f"❌ {a.get('error','Analysis failed')}")

                btn1, btn2, btn3 = st.columns(3)
                with btn1:
                    if st.button("✅ Confirm Normal", key=f"rev_norm_{item_id}_{idx}", width='stretch', type="secondary", on_click=approve_normal_callback, args=(item_id,)): pass
                with btn2:
                    if st.button("🔴 Confirm Attack", key=f"rev_atk_{item_id}_{idx}", width='stretch', type="primary", on_click=approve_attack_callback, args=(item_id,)): pass
                with btn3:
                    if st.button("⏭️ Skip", key=f"rev_skip_{item_id}_{idx}", width='stretch'):
                        if item_id is not None and item_id not in st.session_state.review_skipped:
                            st.session_state.review_skipped.append(item_id)
                        st.info("Skipped"); st.rerun()

                st.markdown("<br>", unsafe_allow_html=True)

                if st.session_state.review_ai_loading[review_id] and not st.session_state.review_ai_analyses[review_id]:
                    with st.spinner("🤖 AI analyzing..."):
                        st.session_state.ai_last_request_at = time.time()
                        flow = item.get('flow_details',{})
                        review_reason = "layer disagreement" if l0 != l1 else "low confidence"
                        try:
                            bytes_val   = int(flow.get('bytes',0) or 0)
                            packets_val = int(flow.get('packets',0) or 0)
                            avg_ps      = bytes_val/packets_val if packets_val>0 else 0
                        except: bytes_val=packets_val=avg_ps=0
                        if avg_ps>1400 and packets_val>10: pp=f"large packets ({avg_ps:.0f}B avg)"
                        elif avg_ps<100 and packets_val>20: pp=f"many small packets ({packets_val} of {avg_ps:.0f}B)"
                        elif packets_val>1000: pp=f"high volume ({packets_val} packets)"
                        else: pp="normal pattern"
                        if l0 and l1: ml_s="Both ML models flagged this"
                        elif l0 and not l1: ml_s="Only L0 flagged (anomaly)"
                        elif not l0 and l1: ml_s="Only L1 flagged (signature)"
                        else: ml_s="Both models normal"
                        prompt = f"""Analyze this packet for HUMAN REVIEW:\nReason: {review_reason} · ML: {ml_s} · Confidence: {confidence:.1f}%\n{flow.get('src_ip','N/A')}:{flow.get('src_port','N/A')} → {flow.get('dst_ip','N/A')}:{flow.get('dst_port','N/A')}\n{bytes_val} bytes in {packets_val} packets · Port {dst_port} (risk: {port_risk}) · Pattern: {pp}\n\nFirst line: "🔴 LIKELY THREAT", "🟢 LIKELY NORMAL", or "🟡 UNCERTAIN"\nThen 4 sentences: why ML conflicted, packet pattern, port assessment, what to look for."""
                        result = analyze_with_gemini_review(item, prompt)
                        if result.get('success'):
                            t = result['analysis'].lower()
                            result['assessment'] = 'likely_threat' if 'likely threat' in t or '🔴' in t else 'likely_normal' if 'likely normal' in t or '🟢' in t else 'uncertain'
                        st.session_state.review_ai_analyses[review_id] = result
                        st.session_state.review_ai_loading[review_id] = False
                        if result.get('rate_limited'): st.session_state.ai_cooldown_until = time.time() + GEMINI_RATE_LIMIT_COOLDOWN_SECONDS
                        st.rerun()

            st.markdown("<br>", unsafe_allow_html=True)
            lb1, lb2, lb3 = st.columns([1, 1, 2])
            with lb1:
                if shown < total_queue:
                    load_n = min(REVIEW_PAGE_SIZE, total_queue - shown)
                    if st.button(f"⬇️ Load {load_n} More", type="secondary", width='stretch'):
                        st.session_state.review_shown_count += REVIEW_PAGE_SIZE; st.rerun()
            with lb2:
                if shown > REVIEW_PAGE_SIZE:
                    if st.button("⬆️ Show Less", type="secondary", width='stretch'):
                        st.session_state.review_shown_count = REVIEW_PAGE_SIZE; st.rerun()
            with lb3:
                if shown < total_queue:
                    st.caption(f"Showing {len(visible_items)} of {total_queue} · {total_queue - shown} more remaining")
                else:
                    st.caption(f"All {total_queue} items shown")

        else:
            if review_queue: st.info("All pending items are skipped in this session.")
            else:
                st.markdown('<div class="empty"><div class="empty-icon">✅</div><div class="empty-title">Queue Empty</div><div class="empty-text">All flows classified with high confidence.</div></div>', unsafe_allow_html=True)


render_live_page()