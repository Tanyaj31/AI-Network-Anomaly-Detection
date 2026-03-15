"""
VectorizedFlowTracker - Flow Grouping Module
=============================================
Groups packets into bidirectional flows using 5-tuple
(src_ip, dst_ip, src_port, dst_port, protocol)
"""

import pandas as pd
import numpy as np
from collections import defaultdict
from typing import Dict, List


class VectorizedFlowTracker:

    def __init__(self):
        self.flows = {}
        self.flow_count = 0

    def create_flows(self, packets_df: pd.DataFrame, verbose: bool = True) -> Dict:
        if verbose:
            print(f"\n🔄 Grouping {len(packets_df):,} packets into flows...")

        flows_dict = {}

        for idx, pkt in packets_df.iterrows():
            flow_id = self._create_flow_tuple(
                pkt['src_ip'], pkt['dst_ip'],
                pkt.get('src_port', 0), pkt.get('dst_port', 0),
                pkt['protocol']
            )

            if flow_id not in flows_dict:
                flows_dict[flow_id] = {
                    'packets': [],
                    'fwd_packets': [],
                    'bwd_packets': [],
                    'start_time': pkt['timestamp'],
                    'last_seen': pkt['timestamp'],
                    'forward_src': pkt['src_ip'],
                    'forward_dst': pkt['dst_ip']
                }

            flow = flows_dict[flow_id]
            flow['packets'].append(pkt)

            if pkt['src_ip'] == flow['forward_src'] and pkt['dst_ip'] == flow['forward_dst']:
                flow['fwd_packets'].append(pkt)
            else:
                flow['bwd_packets'].append(pkt)

            flow['last_seen'] = pkt['timestamp']

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
        forward = (src_ip, src_port, dst_ip, dst_port, protocol)
        reverse = (dst_ip, dst_port, src_ip, src_port, protocol)
        return forward


if __name__ == "__main__":
    print("Testing VectorizedFlowTracker...")
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
    print(f"\n✅ Test passed!")
    print(f"Grouped {len(test_packets)} packets into {len(flows)} flow(s)")
