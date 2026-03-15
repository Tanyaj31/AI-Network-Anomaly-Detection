"""
Live Data Reader - Wrapper for SharedState
"""
import sys
import os

# Add realtime_monitor to path
project_root = "/home/shared/IoT_Project/AI_Anomaly_Detection"
sys.path.insert(0, os.path.join(project_root, 'realtime_monitor'))

from shared_state import SharedState

# Alias for compatibility
class LiveDataReader(SharedState):
    """Wrapper class that uses SharedState"""
    pass

# For direct import
__all__ = ['LiveDataReader', 'SharedState']
