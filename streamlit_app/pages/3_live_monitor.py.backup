"""
Live Monitor Page - Placeholder for Raspberry Pi integration
"""
import streamlit as st

st.set_page_config(page_title="Live Monitor", page_icon="📡", layout="wide")

st.title("📡 Live Network Monitoring")
st.markdown("Real-time threat detection from edge devices")

st.markdown("---")

st.info("""
🚧 **Coming Soon: Raspberry Pi Edge Integration**

This feature will enable:
- Real-time packet capture from Raspberry Pi
- Live threat detection and alerting
- Distributed monitoring across multiple Pi devices  
- Automatic blocking of malicious IPs
- WebSocket-based live updates

**Status:** Infrastructure ready, awaiting Pi device deployment
""")

st.markdown("### 📋 Planned Features")

col1, col2 = st.columns(2)

with col1:
    st.markdown("""
    **Edge Device Capabilities:**
    - ✅ Packet capture (tcpdump)
    - ✅ Local feature extraction
    - ✅ Batch uploads to server
    - ⏳ Real-time streaming
    - ⏳ Local model inference
    """)

with col2:
    st.markdown("""
    **Server Dashboard:**
    - ⏳ Live flow monitoring
    - ⏳ Alert feed
    - ⏳ Device status tracking
    - ⏳ Threat heatmap
    - ⏳ Auto-response actions
    """)

st.markdown("---")

st.markdown("### 🏗️ Architecture Preview")

st.code('''
Raspberry Pi (Edge)          Dell Server (Hub)
├── tcpdump capture          ├── Receive batches
├── Extract features    ────>├── Run 3-layer analysis
├── Send every 5 sec         ├── Store alerts
└── (Optional) Block IPs     └── Update dashboard
                                     ↓
                                [This Page]
                             Live monitoring UI
''', language='text')

st.markdown("---")

st.success("🎯 **Development Timeline:** Week 2-3 of project (February 12-25)")