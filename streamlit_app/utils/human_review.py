"""
Human Review Interface - Analyst Feedback Component
====================================================

Streamlit component for analysts to review uncertain detections
and provide feedback for model improvement.
"""

import streamlit as st
from datetime import datetime
import json


def render_review_queue(live_data_reader):
    """
    Render the human review queue interface
    
    Args:
        live_data_reader: LiveDataReader instance
    """
    
    st.markdown("### 👤 Human Review Queue")
    
    # Get review statistics
    stats = live_data_reader.get_review_stats()
    
    # Show stats
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Pending Review", stats['pending'], help="Flows awaiting analyst review")
    with col2:
        st.metric("Reviewed Today", stats['reviewed'], help="Flows reviewed in current session")
    with col3:
        st.metric("Total Reviews", stats['total_reviews'], help="All-time review count")
    
    if stats['pending'] == 0:
        st.success("✅ No flows pending review - all detections are high confidence!")
        return
    
    st.markdown("---")
    
    # Get pending flows
    pending_flows = live_data_reader.get_review_queue(limit=20)
    
    if not pending_flows:
        st.info("📭 Review queue is empty")
        return
    
    # Review interface
    st.markdown("""
    <div style='background: #262730; padding: 1rem; border-radius: 8px; margin-bottom: 1rem;'>
        <p style='margin: 0; opacity: 0.8;'>
            <strong>📋 Review Instructions:</strong><br>
            These flows have low confidence (<70%) or layer disagreement. 
            Your feedback helps improve the AI models!
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Display each flow for review
    for idx, flow in enumerate(pending_flows[:10]):  # Show max 10 at a time
        
        with st.expander(
            f"{'🔴' if flow['confidence'] < 30 else '🟡'} Flow #{flow['id']} - {flow['classification']} ({flow['confidence']:.1f}% confidence)",
            expanded=(idx == 0)  # Expand first one
        ):
            
            # Flow details
            col_a, col_b = st.columns(2)
            
            with col_a:
                st.markdown(f"""
                **📅 Detected:** {datetime.fromisoformat(flow['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}  
                **📡 Device:** {flow['device_id']}  
                **🎯 Classification:** {flow['classification']}  
                **📊 Confidence:** {flow['confidence']:.1f}%
                """)
            
            with col_b:
                # Layer results
                layer0 = flow.get('layer0_result', {})
                layer1 = flow.get('layer1_result', {})
                
                st.markdown("**🔍 Detection Layers:**")
                
                if layer0:
                    anomaly_status = "🚨 Anomaly" if layer0.get('is_anomaly') else "✅ Normal"
                    st.markdown(f"- **Layer 0:** {anomaly_status}")
                
                if layer1:
                    st.markdown(f"- **Layer 1:** {layer1.get('classification', 'Unknown')}")
                
                # Show disagreement if exists
                if layer0 and layer1:
                    layer0_says_bad = layer0.get('is_anomaly', False)
                    layer1_says_bad = layer1.get('classification') != 'Normal Traffic'
                    
                    if layer0_says_bad != layer1_says_bad:
                        st.warning("⚠️ **Layer Disagreement** - Needs review!")
            
            # Show some flow features (if available)
            features = flow.get('flow_features', {})
            if features and len(features) > 0:
                with st.expander("📊 Flow Features (Technical Details)"):
                    # Show top 10 interesting features
                    feature_items = list(features.items())[:10]
                    cols = st.columns(2)
                    
                    for i, (key, value) in enumerate(feature_items):
                        col_idx = i % 2
                        with cols[col_idx]:
                            # Format value
                            if isinstance(value, float):
                                value_str = f"{value:.4f}"
                            else:
                                value_str = str(value)
                            st.text(f"{key}: {value_str}")
            
            st.markdown("---")
            st.markdown("**🎯 Your Decision:**")
            
            # Review buttons
            col1, col2, col3, col4 = st.columns([2, 2, 2, 2])
            
            with col1:
                if st.button("✅ Normal Traffic", key=f"normal_{flow['flow_id']}", use_container_width=True):
                    live_data_reader.submit_review(flow['flow_id'], 'normal', 'Analyst verified as normal')
                    st.success("✅ Marked as Normal!")
                    st.rerun()
            
            with col2:
                if st.button("⚠️ Suspicious", key=f"suspicious_{flow['flow_id']}", use_container_width=True):
                    live_data_reader.submit_review(flow['flow_id'], 'suspicious', 'Requires further monitoring')
                    st.warning("⚠️ Marked as Suspicious!")
                    st.rerun()
            
            with col3:
                if st.button("🔴 Attack", key=f"attack_{flow['flow_id']}", use_container_width=True):
                    live_data_reader.submit_review(flow['flow_id'], 'attack', 'Confirmed attack')
                    st.error("🔴 Marked as Attack!")
                    st.rerun()
            
            with col4:
                if st.button("⏭️ Skip", key=f"skip_{flow['flow_id']}", use_container_width=True):
                    st.info("Skipped to next flow")
    
    # Show if there are more
    if len(pending_flows) > 10:
        st.info(f"📋 Showing 10 of {len(pending_flows)} pending reviews. Review these to see more!")


def render_review_stats_widget(live_data_reader):
    """
    Render compact review stats widget for main dashboard
    
    Args:
        live_data_reader: LiveDataReader instance
    """
    stats = live_data_reader.get_review_stats()
    
    if stats['pending'] > 0:
        st.markdown(f"""
        <div style='background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); 
                    padding: 1rem; border-radius: 10px; margin: 1rem 0;
                    box-shadow: 0 4px 15px rgba(243, 156, 18, 0.3);'>
            <div style='display: flex; justify-content: space-between; align-items: center;'>
                <div>
                    <div style='font-size: 0.9rem; opacity: 0.9;'>⏸️ Flows Awaiting Review</div>
                    <div style='font-size: 2rem; font-weight: 700; margin-top: 0.5rem;'>
                        {stats['pending']}
                    </div>
                </div>
                <div style='font-size: 3rem; opacity: 0.7;'>👤</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style='background: linear-gradient(135deg, #2ecc71 0%, #27ae60 100%); 
                    padding: 1rem; border-radius: 10px; margin: 1rem 0;'>
            <div style='display: flex; justify-content: space-between; align-items: center;'>
                <div>
                    <div style='font-size: 0.9rem; opacity: 0.9;'>✅ Review Queue</div>
                    <div style='font-size: 1.5rem; font-weight: 700; margin-top: 0.5rem;'>
                        All Clear
                    </div>
                </div>
                <div style='font-size: 3rem; opacity: 0.7;'>✓</div>
            </div>
        </div>
        """, unsafe_allow_html=True)


def render_review_history_stats(live_data_reader):
    """
    Show review history and analyst contribution stats
    """
    stats = live_data_reader.get_review_stats()
    
    st.markdown("### 📊 Review Activity")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown(f"""
        <div style='text-align: center; padding: 1.5rem; background: #262730; border-radius: 10px;'>
            <div style='font-size: 2.5rem; font-weight: 700; color: #3498db;'>{stats['total_reviews']}</div>
            <div style='opacity: 0.7; margin-top: 0.5rem;'>Total Reviews</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div style='text-align: center; padding: 1.5rem; background: #262730; border-radius: 10px;'>
            <div style='font-size: 2.5rem; font-weight: 700; color: #2ecc71;'>{stats['reviewed']}</div>
            <div style='opacity: 0.7; margin-top: 0.5rem;'>Reviewed</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div style='text-align: center; padding: 1.5rem; background: #262730; border-radius: 10px;'>
            <div style='font-size: 2.5rem; font-weight: 700; color: #f39c12;'>{stats['pending']}</div>
            <div style='opacity: 0.7; margin-top: 0.5rem;'>Pending</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Show impact message
    if stats['total_reviews'] > 0:
        st.success(f"""
        ✨ **Great work!** Your {stats['total_reviews']} reviews have helped improve the AI models.
        The system learns from your feedback to make better predictions!
        """)
    else:
        st.info("💡 **Tip:** Reviewing uncertain detections helps train the AI to be more accurate!")
