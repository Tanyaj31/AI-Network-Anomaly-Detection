#!/usr/bin/env python3
"""
MQTT Auto Analyzer - WITH WHITELIST LEARNING
Listens for heartbeat updates and learns from human feedback
"""
import paho.mqtt.client as mqtt
import json
import time
import sys
import os
from datetime import datetime, timedelta
import threading

# Add paths
project_root = "/home/shared/IoT_Project/AI_Anomaly_Detection"
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'layered_ensemble'))
sys.path.insert(0, os.path.join(project_root, 'realtime_monitor'))

from shared_state import SharedState
from production_pipeline import ProductionPipeline

# MQTT Configuration
MQTT_BROKER = "localhost"
MQTT_PORT = 1883

# Initialize components
state_manager = SharedState()
pipeline = None

# Stats
session_stats = {
    'start_time': datetime.now(),
    'total_messages': 0,
    'total_flows': 0,
    'total_attacks': 0,
    'layer0_flagged': 0,
    'whitelisted_flows': 0,
    'errors': 0
}

def init_pipeline():
    """Initialize ML pipeline"""
    global pipeline
    try:
        print("ðŸ”§ Initializing ML pipeline...")
        pipeline = ProductionPipeline()
        
        # CRITICAL: Load all models (Layer 0, Layer 1, scalers, etc.)
        print("ðŸ“¦ Loading models (this may take 10-15 seconds)...")
        pipeline.load_models()
        
        print("âœ… ML pipeline ready")
        print(f"   â€¢ Layer 0 loaded: {pipeline.layer0 is not None}")
        print(f"   â€¢ Layer 1 loaded: {pipeline.layer1 is not None}")
        
        return True
    except Exception as e:
        print(f"âŒ Pipeline initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def check_device_heartbeats():
    """
    Background task - Mark devices offline if no heartbeat for 30s
    """
    def heartbeat_checker():
        print("ðŸ’“ Starting background heartbeat checker (30s timeout)")
        
        while True:
            try:
                devices = state_manager.get_all_devices()
                
                for device in devices:
                    last_seen_str = device.get('last_seen')
                    if last_seen_str:
                        try:
                            last_seen = datetime.fromisoformat(last_seen_str)
                            seconds_ago = (datetime.now() - last_seen).total_seconds()
                            
                            # If no heartbeat for 30 seconds, mark offline
                            if seconds_ago > 30 and device.get('status') == 'online':
                                print(f"\nâš ï¸  Device {device['device_id']} timeout ({seconds_ago:.0f}s)")
                                print(f"   Marking as OFFLINE in database")
                                
                                state_manager.update_device_status(device['device_id'], {
                                    'status': 'offline',
                                    'ip_address': device.get('ip_address'),
                                    'location': device.get('location'),
                                    'total_flows': device.get('total_flows', 0),
                                    'threats_detected': device.get('threats_detected', 0)
                                })
                        except Exception as e:
                            print(f"âŒ Error checking device {device.get('device_id')}: {e}")
                
            except Exception as e:
                print(f"âŒ Heartbeat checker error: {e}")
            
            time.sleep(5)  # Check every 5 seconds
    
    # Start background thread
    thread = threading.Thread(target=heartbeat_checker, daemon=True)
    thread.start()

def extract_flow_details(flow_row):
    """
    Extract network details from a flow for threat feed
    
    Args:
        flow_row: pandas Series or dict with flow features
        
    Returns:
        dict with src_ip, dst_ip, src_port, dst_port, protocol, etc.
    """
    details = {}
    
    # Handle both Series and dict
    if hasattr(flow_row, 'index'):
        # It's a pandas Series
        get_val = lambda col: flow_row[col] if col in flow_row.index else None
    else:
        # It's a dict
        get_val = lambda col: flow_row.get(col)
    
    # Try to extract IP addresses
    possible_src_ip_cols = ['src_ip', 'srcip', 'Source IP', 'source_ip']
    possible_dst_ip_cols = ['dst_ip', 'dstip', 'Destination IP', 'destination_ip']
    
    for col in possible_src_ip_cols:
        val = get_val(col)
        if val is not None:
            details['src_ip'] = str(val)
            break
    
    for col in possible_dst_ip_cols:
        val = get_val(col)
        if val is not None:
            details['dst_ip'] = str(val)
            break
    
    # Try to extract ports
    possible_src_port_cols = ['src_port', 'sport', 'Source Port', 'source_port']
    possible_dst_port_cols = ['dst_port', 'dport', 'Destination Port', 'destination_port']
    
    for col in possible_src_port_cols:
        val = get_val(col)
        if val is not None:
            try:
                details['src_port'] = int(val)
            except:
                details['src_port'] = 0
            break
    
    for col in possible_dst_port_cols:
        val = get_val(col)
        if val is not None:
            try:
                details['dst_port'] = int(val)
            except:
                details['dst_port'] = 0
            break
    
    # Try to extract protocol
    possible_protocol_cols = ['protocol', 'proto', 'Protocol']
    
    for col in possible_protocol_cols:
        val = get_val(col)
        if val is not None:
            # Map protocol numbers to names
            if isinstance(val, (int, float)):
                protocol_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
                details['protocol'] = protocol_map.get(int(val), f'Proto-{int(val)}')
            else:
                details['protocol'] = str(val).upper()
            break
    
    # Try to extract packet/byte counts
    possible_packet_cols = ['total_fwd_packets', 'tot_fwd_pkts', 'packet_count', 'packets', 'Total Fwd Packets']
    possible_byte_cols = ['total_length_of_fwd_packets', 'tot_len_fwd_pkts', 'byte_count', 'bytes', 'Total Length of Fwd Packets']
    
    for col in possible_packet_cols:
        val = get_val(col)
        if val is not None:
            try:
                details['packet_count'] = int(val)
            except:
                details['packet_count'] = 0
            break
    
    for col in possible_byte_cols:
        val = get_val(col)
        if val is not None:
            try:
                details['byte_count'] = int(val)
            except:
                details['byte_count'] = 0
            break
    
    # Set defaults for missing values
    if 'src_ip' not in details:
        details['src_ip'] = 'Unknown'
    if 'dst_ip' not in details:
        details['dst_ip'] = 'Unknown'
    if 'src_port' not in details:
        details['src_port'] = 0
    if 'dst_port' not in details:
        details['dst_port'] = 0
    if 'protocol' not in details:
        details['protocol'] = 'Unknown'
    if 'packet_count' not in details:
        details['packet_count'] = 0
    if 'byte_count' not in details:
        details['byte_count'] = 0
    
    return details

def on_connect(client, userdata, flags, rc, properties=None):
    """MQTT connection callback"""
    if rc == 0:
        print("\n" + "="*60)
        print("ðŸš€ MQTT AUTO ANALYZER - Connected")
        print("="*60)
        print(f"âœ… Broker: {MQTT_BROKER}:{MQTT_PORT}")
        print(f"â° Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60 + "\n")
        
        # Subscribe to data and heartbeat topics
        client.subscribe("nids/+/flows")
        client.subscribe("nids/heartbeat/#")
        
        print("ðŸ“¡ Subscribed to:")
        print("   â€¢ nids/+/flows (network data)")
        print("   â€¢ nids/heartbeat/# (device heartbeats)")
        print()
        
        # Start background heartbeat checker
        check_device_heartbeats()
        
        print("âœ… Ready to process messages")
        print("ðŸŽ“ Whitelist learning enabled\n")
    else:
        print(f"âŒ Connection failed with code: {rc}")

def on_message(client, userdata, msg):
    """
    Handle incoming MQTT messages
    """
    global session_stats
    
    topic = msg.topic
    session_stats['total_messages'] += 1
    
    # ============================================================
    # Handle heartbeat messages
    # ============================================================
    if topic.startswith("nids/heartbeat/"):
        try:
            heartbeat = json.loads(msg.payload.decode())
            device_id = heartbeat.get('device_id', 'unknown')
            status = heartbeat.get('status', 'unknown')
            message = heartbeat.get('message', '')
            
            print(f"\nðŸ’“ HEARTBEAT from {device_id}:")
            print(f"   Status: {status.upper()}")
            if message:
                print(f"   Message: {message}")
            
            # Update device status immediately in database
            state_manager.update_device_status(device_id, {
                'status': status,
                'ip_address': heartbeat.get('ip_address', 'Unknown'),
                'location': heartbeat.get('location', 'Edge Sensor'),
                'total_flows': 0,
                'threats_detected': 0
            })
            
            print(f"   âœ… Database updated: {device_id} -> {status}")
            print()
            return
            
        except Exception as e:
            print(f"âŒ Heartbeat processing error: {e}")
            session_stats['errors'] += 1
            return
    
    # ============================================================
    # Handle regular data messages
    # ============================================================
    if topic.startswith("nids/") and topic.endswith("/flows"):
        try:
            # Parse message
            data = json.loads(msg.payload.decode())
            device_id = data.get('device_id', 'unknown')
            flows = data.get('flows', [])
            num_flows = len(flows)
            
            if num_flows == 0:
                print(f"âš ï¸  Empty message from {device_id}")
                return
            
            print(f"\n{'='*60}")
            print(f"ðŸ“¥ RECEIVED from {device_id}")
            print(f"{'='*60}")
            print(f"â° Time: {datetime.now().strftime('%H:%M:%S')}")
            print(f"ðŸ“¦ Flows: {num_flows}")
            print(f"ðŸ“Š Size: {len(msg.payload):,} bytes")
            
            # Update device status (they're sending data, so they're online)
            state_manager.update_device_status(device_id, {
                'status': 'online',
                'ip_address': data.get('ip_address', 'Unknown'),
                'location': f"Edge Sensor",
                'total_flows': num_flows,
                'threats_detected': 0
            })
            
            # Convert to DataFrame
            import pandas as pd
            flows_df = pd.DataFrame(flows)
            
            # ============================================================
            # ðŸŽ“ WHITELIST CHECK - Human-in-the-loop learning
            # ============================================================
            print(f"ðŸ” Checking whitelist...")
            
            whitelisted_indices = []
            for idx in range(len(flows_df)):
                flow_details = extract_flow_details(flows_df.iloc[idx])
                
                if state_manager.is_whitelisted(flow_details):
                    # This pattern was human-approved as normal — just skip it.
                    # Do NOT call add_threat() here: normal flows don't belong in
                    # the threat feed, and every add_threat() call runs a DELETE
                    # that can wipe legitimate unreviewed threats/review-queue items.
                    whitelisted_indices.append(idx)
            
            # Remove whitelisted flows from batches
            if whitelisted_indices:
                print(f"   âœ… Found {len(whitelisted_indices)} whitelisted patterns")
                
                # Show examples
                for idx in whitelisted_indices[:3]:  # Show first 3
                    fd = extract_flow_details(flows_df.iloc[idx])
                    print(f"      â€¢ {fd.get('src_ip')}:{fd.get('src_port')} â†’ "
                          f"{fd.get('dst_ip')}:{fd.get('dst_port')} ({fd.get('protocol')})")
                
                if len(whitelisted_indices) > 3:
                    print(f"      ... and {len(whitelisted_indices)-3} more")
                
                # Filter DataFrames
                mask = [i for i in range(len(flows_df)) if i not in whitelisted_indices]
                flows_df = flows_df.iloc[mask].reset_index(drop=True)
                
                session_stats['whitelisted_flows'] += len(whitelisted_indices)
                
                print(f"   ðŸ“‹ Analyzing {len(flows_df)} remaining flows with ML")
            
            # If all flows were whitelisted, skip ML
            if len(flows_df) == 0:
                print(f"   âœ… All flows whitelisted - no ML needed!")
                
                # Update session stats
                session_stats['total_flows'] += num_flows
                
                print(f"\nðŸ“Š Batch Results:")
                print(f"   â€¢ Total: {num_flows} flows")
                print(f"   â€¢ Whitelisted: {len(whitelisted_indices)} (100%)")
                print(f"   â€¢ ML analyzed: 0")
                print(f"{'='*60}\n")
                return
            
            # ============================================================
            # ML ANALYSIS for non-whitelisted flows
            # ============================================================
            print(f"âš™ï¸  Running ML analysis on {len(flows_df)} flows...")
            
            # Prepare dataset-specific features
            try:
                from feature_extraction.feature_mappings import FeatureMappings
                from feature_extraction.feature_selector import FeatureSelector
                
                # Initialize feature selector if needed
                if not hasattr(pipeline, '_feature_selector'):
                    mappings = FeatureMappings()
                    pipeline._feature_selector = FeatureSelector(mappings)
                
                feature_selector = pipeline._feature_selector
                
                # Extract features for each dataset
                cicids_batch = feature_selector.extract_batch_for_cicids(flows_df)
                iot_batch = feature_selector.extract_batch_for_iot(flows_df)
                unsw_batch = feature_selector.extract_batch_for_unsw(flows_df)
                
                print(f"   âœ… Features: CICIDS={cicids_batch.shape}, IoT={iot_batch.shape}, UNSW={unsw_batch.shape}")
                
            except Exception as e:
                print(f"   âŒ Feature extraction failed: {e}")
                session_stats['errors'] += 1
                return
            
            # Run through ML pipeline
            results = pipeline.analyze_batch(
                cicids_batch=cicids_batch,
                iot_batch=iot_batch,
                unsw_batch=unsw_batch
            )
            
            # Process results
            attacks = 0
            layer0_flags = 0
            
            for idx, result in enumerate(results):
                # Extract classifications
                classification = result.get('analysis', {}).get('classification', 'Unknown')
                is_attack = classification not in ['Normal Traffic', 'Uncertain - Needs Review']
                layer0_flagged = result.get('layer0', {}).get('is_anomaly', False)
                
                if is_attack:
                    attacks += 1
                if layer0_flagged:
                    layer0_flags += 1
                
                # Extract flow details from original dataframe
                flow_details = {}
                if idx < len(flows_df):
                    flow_row = flows_df.iloc[idx]
                    flow_details = extract_flow_details(flow_row)
                
                # Add to threat feed with flow details
                threat_data = {
                    'device_id': device_id,
                    'attack_type': classification,
                    'threat_level': result.get('analysis', {}).get('threat_level', 'INFO'),
                    'confidence': result.get('analysis', {}).get('confidence', 0),
                    'layer0_flagged': layer0_flagged,
                    'layer1_flagged': is_attack,
                    'flow_details': flow_details
                }
                
                state_manager.add_threat(threat_data)
            
            # Update session stats (include whitelisted flows)
            session_stats['total_flows'] += num_flows
            session_stats['total_attacks'] += attacks
            session_stats['layer0_flagged'] += layer0_flags
            
            # Update system stats
            threat_pct = (session_stats['total_attacks'] / session_stats['total_flows'] * 100) if session_stats['total_flows'] > 0 else 0
            layer0_rate = (session_stats['layer0_flagged'] / session_stats['total_flows'] * 100) if session_stats['total_flows'] > 0 else 0
            
            state_manager.update_system_stats({
                'total_flows_processed': session_stats['total_flows'],
                'total_attacks_detected': session_stats['total_attacks'],
                'threat_level_percent': threat_pct,
                'layer0_flagged_count': session_stats['layer0_flagged'],
                'layer0_flag_rate': layer0_rate
            })
            
            # Print results
            print(f"\nðŸ“Š Batch Results:")
            print(f"   â€¢ Total: {num_flows} flows")
            print(f"   â€¢ Whitelisted: {len(whitelisted_indices)} (skipped ML)")
            print(f"   â€¢ ML analyzed: {len(flows_df)}")
            print(f"   â€¢ Layer 0 flagged: {layer0_flags}")
            print(f"   â€¢ Attacks detected: {attacks}")
            print(f"   â€¢ Normal: {len(flows_df) - attacks}")
            
            print(f"\nðŸ“ˆ Session Totals:")
            print(f"   â€¢ Messages: {session_stats['total_messages']}")
            print(f"   â€¢ Flows: {session_stats['total_flows']:,}")
            print(f"   â€¢ Whitelisted: {session_stats['whitelisted_flows']:,}")
            print(f"   â€¢ Attacks: {session_stats['total_attacks']:,} ({threat_pct:.1f}%)")
            print(f"   â€¢ Layer 0: {session_stats['layer0_flagged']:,} ({layer0_rate:.1f}%)")
            
            uptime = (datetime.now() - session_stats['start_time']).total_seconds()
            print(f"   â€¢ Uptime: {uptime:.0f}s")
            print(f"{'='*60}\n")
            
        except json.JSONDecodeError as e:
            print(f"âŒ Invalid JSON: {e}")
            session_stats['errors'] += 1
        except Exception as e:
            print(f"âŒ Processing error: {e}")
            import traceback
            traceback.print_exc()
            session_stats['errors'] += 1

def on_disconnect(client, userdata, rc, properties=None):
    """MQTT disconnect callback"""
    print(f"\nâš ï¸  Disconnected from broker (code: {rc})")
    if rc != 0:
        print("ðŸ”„ Attempting to reconnect...")

def main():
    """Main function"""
    print("\n" + "="*60)
    print("ðŸš€ MQTT AUTO ANALYZER - WITH WHITELIST LEARNING")
    print("="*60)
    print("Features:")
    print("  â€¢ Instant heartbeat processing")
    print("  â€¢ 30-second timeout detection")
    print("  â€¢ 3-layer ML analysis")
    print("  â€¢ Real-time threat detection")
    print("  â€¢ ðŸŽ“ Human-in-the-loop learning (whitelist)")
    print("="*60 + "\n")
    
    # Initialize ML pipeline
    if not init_pipeline():
        print("âŒ Cannot start without ML pipeline")
        return
    
    # Setup MQTT client
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=f"analyzer-{int(time.time())}")
    except:
        client = mqtt.Client(client_id=f"analyzer-{int(time.time())}")
    
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    
    try:
        print(f"ðŸ”Œ Connecting to {MQTT_BROKER}:{MQTT_PORT}...")
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
        
        print("âœ… Connected successfully")
        print("ðŸ”„ Starting message loop...\n")
        
        # Start MQTT loop (blocks forever)
        client.loop_forever()
        
    except KeyboardInterrupt:
        print("\n\nâ¹ï¸  Shutting down...")
        print(f"\nðŸ“Š Final Stats:")
        print(f"   â€¢ Messages: {session_stats['total_messages']}")
        print(f"   â€¢ Flows: {session_stats['total_flows']:,}")
        print(f"   â€¢ Whitelisted: {session_stats['whitelisted_flows']:,}")
        print(f"   â€¢ Attacks: {session_stats['total_attacks']:,}")
        print(f"   â€¢ Errors: {session_stats['errors']}")
        print("\nâœ… Goodbye!\n")
        
    except Exception as e:
        print(f"\nâŒ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()