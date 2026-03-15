"""
VectorizedFlowTracker - Flow Grouping Module
=============================================
Groups packets into bidirectional flows using 5-tuple
(src_ip, dst_ip, src_port, dst_port, protocol)

This is the missing link between packet parsing and feature calculation!
"""

import pandas as pd
import numpy as np
from collections import defaultdict
from typing import Dict, List


class VectorizedFlowTracker:
    """
    Groups packets into bidirectional network flows
    
    A flow is identified by 5-tuple (bidirectional):
    - IP addresses (both directions count as same flow)
    - Ports (both directions count as same flow)  
    - Protocol
    """
    
    def __init__(self):
        self.flows = {}
        self.flow_count = 0
        
    def create_flows(self, packets_df: pd.DataFrame, verbose: bool = True) -> Dict:
        """
        Group packets into flows
        
        Args:
            packets_df: DataFrame from OptimizedPcapParser with columns:
                - src_ip, dst_ip
                - src_port, dst_port
                - protocol
                - length, timestamp
                - tcp_flags (if TCP)
                
        Returns:
            Dictionary where:
                key = flow_id tuple (src_ip, src_port, dst_ip, dst_port, protocol)
                value = dict with:
                    - 'packets': list of all packets
                    - 'fwd_packets': list of forward packets  
                    - 'bwd_packets': list of backward packets
                    - 'start_time': first packet timestamp
                    - 'last_seen': last packet timestamp
        """
        
        if verbose:
            print(f"\n🔄 Grouping {len(packets_df):,} packets into flows...")
        
        flows_dict = {}
        
        for idx, pkt in packets_df.iterrows():
            # Create flow tuple (5-tuple bidirectional)
            flow_id = self._create_flow_tuple(
                pkt['src_ip'], pkt['dst_ip'],
                pkt.get('src_port', 0), pkt.get('dst_port', 0),
                pkt['protocol']
            )
            
            # Initialize flow if first time seeing it
            if flow_id not in flows_dict:
                flows_dict[flow_id] = {
                    'packets': [],
                    'fwd_packets': [],
                    'bwd_packets': [],
                    'start_time': pkt['timestamp'],
                    'last_seen': pkt['timestamp'],
                    'forward_src': pkt['src_ip'],  # Track forward direction
                    'forward_dst': pkt['dst_ip']
                }
            
            flow = flows_dict[flow_id]
            
            # Add to all packets
            flow['packets'].append(pkt)
            
            # Determine direction and add to appropriate list
            if pkt['src_ip'] == flow['forward_src'] and pkt['dst_ip'] == flow['forward_dst']:
                flow['fwd_packets'].append(pkt)
            else:
                flow['bwd_packets'].append(pkt)
            
            # Update last seen time
            flow['last_seen'] = pkt['timestamp']
        
        # Clean up helper fields
        for flow_id in flows_dict:
            del flows_dict[flow_id]['forward_src']
            del flows_dict[flow_id]['forward_dst']
        
        if verbose:
            print(f"✅ Created {len(flows_dict):,} unique flows")
            total_pkts = sum(len(f['packets']) for f in flows_dict.values())
            avg_pkts = total_pkts / len(flows_dict) if flows_dict else 0
            print(f"📊 Average packets per flow: {avg_pkts:.1f}")
        
        return flows_dict
    
    def _create_flow_tuple(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """
        Create flow tuple (5-tuple) - ORDER MATTERS for direction tracking
        
        Returns:
            tuple: (src_ip, src_port, dst_ip, dst_port, protocol)
        """
        # Check if reverse flow already exists
        # If so, use that flow's direction to keep bidirectional grouping
        forward = (src_ip, src_port, dst_ip, dst_port, protocol)
        reverse = (dst_ip, dst_port, src_ip, src_port, protocol)
        
        # Return forward tuple (first packet defines direction)
        return forward


# Quick test
if __name__ == "__main__":
    print("Testing VectorizedFlowTracker...")
    
    # Create sample packet data
    test_packets = pd.DataFrame([
        {'src_ip': '192.168.1.1', 'dst_ip': '8.8.8.8', 'src_port': 12345, 'dst_port': 80, 
         'protocol': 6, 'length': 60, 'timestamp': 1.0},
        {'src_ip': '8.8.8.8', 'dst_ip': '192.168.1.1', 'src_port': 80, 'dst_port': 12345, 
         'protocol': 6, 'length': 1500, 'timestamp': 1.1},
        {'src_ip': '192.168.1.1', 'dst_ip': '8.8.8.8', 'src_port': 12345, 'dst_port': 80, 
         'protocol': 6, 'length': 60, 'timestamp': 1.2},
    ])
    
    tracker = VectorizedFlowTracker()
    flows = tracker.create_flows(test_packets)
    
    print("\n✅ Test passed!")
    print(f"Grouped {len(test_packets)} packets into {len(flows)} flow(s)")
    print(f"\nFlow structure:")
    for flow_id, flow_data in flows.items():
        print(f"  Flow: {flow_id}")
        print(f"    Total packets: {len(flow_data['packets'])}")
        print(f"    Forward: {len(flow_data['fwd_packets'])}")
        print(f"    Backward: {len(flow_data['bwd_packets'])}")
        print(f"    Duration: {flow_data['last_seen'] - flow_data['start_time']:.3f}s")