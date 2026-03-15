"""
Visualization Utilities for Streamlit App - FIXED VERSION
Handles actual data structure from file_analyzer
"""
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from collections import Counter


def create_attack_distribution_pie(results: list):
    """Create pie chart of attack type distribution"""
    
    attack_types = Counter()
    
    # Handle different possible data structures
    for result in results:
        if isinstance(result, dict):
            # Try different possible keys
            if 'analysis' in result and 'classification' in result['analysis']:
                attack_types[result['analysis']['classification']] += 1
            elif 'classification' in result:
                attack_types[result['classification']] += 1
            elif 'attack_type' in result:
                attack_types[result['attack_type']] += 1
            elif 'label' in result:
                attack_types[result['label']] += 1
            else:
                # Unknown structure - use Normal Traffic as fallback
                attack_types['Normal Traffic'] += 1
        else:
            attack_types['Normal Traffic'] += 1
    
    # Separate normal vs attacks
    colors = ['#2ecc71' if k == 'Normal Traffic' else '#e74c3c' 
              for k in attack_types.keys()]
    
    fig = go.Figure(data=[go.Pie(
        labels=list(attack_types.keys()),
        values=list(attack_types.values()),
        marker=dict(colors=colors),
        textinfo='label+percent',
        hovertemplate='<b>%{label}</b><br>Count: %{value:,}<br>Percentage: %{percent}<extra></extra>'
    )])
    
    fig.update_layout(
        title="Traffic Composition",
        height=400,
        showlegend=True
    )
    
    return fig


def create_threat_level_bar(results: list):
    """Create bar chart of threat levels"""
    
    threat_levels = Counter()
    
    for result in results:
        if isinstance(result, dict):
            # Try different possible keys
            if 'analysis' in result and 'threat_level' in result['analysis']:
                threat_levels[result['analysis']['threat_level']] += 1
            elif 'threat_level' in result:
                threat_levels[result['threat_level']] += 1
            else:
                # Determine threat level based on classification
                classification = None
                if 'analysis' in result and 'classification' in result['analysis']:
                    classification = result['analysis']['classification']
                elif 'classification' in result:
                    classification = result['classification']
                elif 'attack_type' in result:
                    classification = result['attack_type']
                
                if classification and classification != 'Normal Traffic':
                    threat_levels['MEDIUM'] += 1
                else:
                    threat_levels['INFO'] += 1
    
    # Sort by severity
    level_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    sorted_levels = {k: threat_levels.get(k, 0) for k in level_order if k in threat_levels}
    
    colors_map = {
        'CRITICAL': '#e74c3c',
        'HIGH': '#e67e22',
        'MEDIUM': '#f39c12',
        'LOW': '#3498db',
        'INFO': '#95a5a6'
    }
    
    colors = [colors_map.get(k, '#95a5a6') for k in sorted_levels.keys()]
    
    fig = go.Figure(data=[go.Bar(
        x=list(sorted_levels.keys()),
        y=list(sorted_levels.values()),
        marker_color=colors,
        text=list(sorted_levels.values()),
        textposition='auto',
        hovertemplate='<b>%{x}</b><br>Count: %{y:,}<extra></extra>'
    )])
    
    fig.update_layout(
        title="Threat Level Distribution",
        xaxis_title="Threat Level",
        yaxis_title="Number of Flows",
        height=400
    )
    
    return fig


def create_attack_types_bar(results: list, top_n: int = 10):
    """Create bar chart of top attack types"""
    
    attack_types = Counter()
    
    for result in results:
        if isinstance(result, dict):
            classification = None
            
            # Try different possible keys
            if 'analysis' in result and 'classification' in result['analysis']:
                classification = result['analysis']['classification']
            elif 'classification' in result:
                classification = result['classification']
            elif 'attack_type' in result:
                classification = result['attack_type']
            elif 'label' in result:
                classification = result['label']
            
            if classification and classification != 'Normal Traffic':
                attack_types[classification] += 1
    
    # Get top N
    top_attacks = dict(attack_types.most_common(top_n))
    
    if not top_attacks:
        return None
    
    fig = go.Figure(data=[go.Bar(
        x=list(top_attacks.values()),
        y=list(top_attacks.keys()),
        orientation='h',
        marker_color='#e74c3c',
        text=list(top_attacks.values()),
        textposition='auto',
        hovertemplate='<b>%{y}</b><br>Count: %{x:,}<extra></extra>'
    )])
    
    fig.update_layout(
        title=f"Top {top_n} Attack Types Detected",
        xaxis_title="Number of Flows",
        yaxis_title="Attack Type",
        height=400,
        yaxis={'categoryorder': 'total ascending'}
    )
    
    return fig


def create_layer_agreement_chart(results: list):
    """
    Create chart showing Layer 0 vs Layer 1 agreement
    If layer data not available, show simplified classification chart
    """
    
    agreement_counts = {
        'Both Flagged': 0,
        'Layer 0 Only': 0,
        'Layer 1 Only': 0,
        'Both Normal': 0
    }
    
    has_layer_data = False
    
    for result in results:
        if isinstance(result, dict):
            # Check if we have layer data
            if 'layer0' in result and 'layer1' in result:
                has_layer_data = True
                layer0_flag = result['layer0'].get('is_anomaly', False)
                layer1_attack = result['layer1'].get('is_attack', False)
                
                if layer0_flag and layer1_attack:
                    agreement_counts['Both Flagged'] += 1
                elif layer0_flag and not layer1_attack:
                    agreement_counts['Layer 0 Only'] += 1
                elif not layer0_flag and layer1_attack:
                    agreement_counts['Layer 1 Only'] += 1
                else:
                    agreement_counts['Both Normal'] += 1
            else:
                # No layer data - count as normal or attack
                classification = None
                if 'analysis' in result and 'classification' in result['analysis']:
                    classification = result['analysis']['classification']
                elif 'classification' in result:
                    classification = result['classification']
                
                if classification == 'Normal Traffic':
                    agreement_counts['Both Normal'] += 1
                else:
                    agreement_counts['Both Flagged'] += 1
    
    if not has_layer_data:
        # Simplified chart if no layer data
        fig = go.Figure(data=[go.Bar(
            x=['Normal Traffic', 'Attacks Detected'],
            y=[agreement_counts['Both Normal'], agreement_counts['Both Flagged']],
            marker_color=['#2ecc71', '#e74c3c'],
            text=[agreement_counts['Both Normal'], agreement_counts['Both Flagged']],
            textposition='auto',
            hovertemplate='<b>%{x}</b><br>Count: %{y:,}<extra></extra>'
        )])
        
        fig.update_layout(
            title="Classification Results",
            xaxis_title="Category",
            yaxis_title="Number of Flows",
            height=400
        )
    else:
        # Full layer agreement chart
        fig = go.Figure(data=[go.Bar(
            x=list(agreement_counts.keys()),
            y=list(agreement_counts.values()),
            marker_color=['#2ecc71', '#f39c12', '#e67e22', '#3498db'],
            text=list(agreement_counts.values()),
            textposition='auto',
            hovertemplate='<b>%{x}</b><br>Count: %{y:,}<extra></extra>'
        )])
        
        fig.update_layout(
            title="Layer 0 (Zero-Day) vs Layer 1 (Classification) Agreement",
            xaxis_title="Detection Category",
            yaxis_title="Number of Flows",
            height=400
        )
    
    return fig


def create_performance_metrics(performance: dict):
    """Create performance metrics display"""
    
    metrics = {}
    
    # Handle different possible keys
    if 'total_time' in performance:
        metrics['Total Time'] = f"{performance['total_time']:.2f}s"
    
    if 'extraction_time' in performance:
        metrics['Feature Extraction'] = f"{performance['extraction_time']:.2f}s"
    
    if 'preparation_time' in performance:
        metrics['Preparation'] = f"{performance['preparation_time']:.2f}s"
    
    if 'analysis_time' in performance:
        metrics['ML Analysis'] = f"{performance['analysis_time']:.2f}s"
    
    if 'throughput' in performance:
        metrics['Throughput'] = f"{performance['throughput']:,.0f} flows/sec"
    
    # If no performance data, return defaults
    if not metrics:
        metrics = {
            'Status': 'Complete',
            'Performance': 'N/A'
        }
    
    return metrics