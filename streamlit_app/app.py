"""
AI Network Intrusion Detection System - Streamlit UI
Main entry point for the Streamlit application.
"""

import streamlit as st
import sys

# Add project to path
sys.path.insert(0, '/home/shared/IoT_Project/AI_Anomaly_Detection')

st.set_page_config(
    page_title="AI Network IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Keep the root page empty and redirect to the Home page in the multipage app.
st.switch_page("pages/1_home.py")
