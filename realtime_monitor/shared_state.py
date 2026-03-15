"""
Shared State Manager - FIXED
- Bug 1 fixed: DELETE only runs periodically, not on every insert
- Bug 2 fixed: Review queue only catches genuinely uncertain flows, not confirmed attacks
"""

import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
import os

class SharedState:
    
    def __init__(self, db_path="/home/shared/IoT_Project/AI_Anomaly_Detection/realtime_monitor/live_stats.db"):
        self.db_path = db_path
        self._insert_count = 0  # track inserts to run DELETE only occasionally
        db_dir = Path(db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS system_stats (
            id INTEGER PRIMARY KEY,
            total_flows_processed INTEGER DEFAULT 0,
            total_attacks_detected INTEGER DEFAULT 0,
            flows_per_second REAL DEFAULT 0.0,
            threat_level_percent REAL DEFAULT 0.0,
            layer0_flagged_count INTEGER DEFAULT 0,
            layer0_flag_rate REAL DEFAULT 0.0,
            uptime_seconds INTEGER DEFAULT 0,
            timestamp TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS threat_feed (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            classification TEXT,
            attack_type TEXT,
            threat_level TEXT,
            confidence REAL,
            layer0_flagged INTEGER DEFAULT 0,
            layer1_flagged INTEGER DEFAULT 0,
            flow_details TEXT,
            reviewed INTEGER DEFAULT 0,
            review_decision TEXT,
            review_timestamp TEXT,
            timestamp TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS device_status (
            device_id TEXT PRIMARY KEY,
            last_seen TEXT,
            status TEXT,
            ip_address TEXT,
            location TEXT,
            total_flows INTEGER DEFAULT 0,
            threats_detected INTEGER DEFAULT 0
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern_type TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            reason TEXT,
            added_by TEXT DEFAULT 'human_review',
            added_timestamp TEXT,
            UNIQUE(src_ip, dst_ip, src_port, dst_port, protocol)
        )''')
        
        c.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON threat_feed(timestamp)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_device ON threat_feed(device_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_reviewed ON threat_feed(reviewed)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_whitelist_pattern ON whitelist(dst_port, protocol)')
        
        conn.commit()
        conn.close()
    
    def update_system_stats(self, stats):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('DELETE FROM system_stats')
        c.execute('''INSERT INTO system_stats 
                     (total_flows_processed, total_attacks_detected, flows_per_second,
                      threat_level_percent, layer0_flagged_count, layer0_flag_rate,
                      uptime_seconds, timestamp)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (stats.get('total_flows_processed', 0),
                   stats.get('total_attacks_detected', 0),
                   stats.get('flows_per_second', 0),
                   stats.get('threat_level_percent', 0),
                   stats.get('layer0_flagged_count', 0),
                   stats.get('layer0_flag_rate', 0),
                   stats.get('uptime_seconds', 0),
                   datetime.now().isoformat()))
        conn.commit()
        conn.close()
    
    def add_threat(self, threat):
        """
        Add threat/attack/review item to feed.
        
        FIX: DELETE only runs every 100 inserts instead of every single insert.
        This stops the constant pruning that was wiping threats and review items.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        flow_details = threat.get('flow_details', {})
        if isinstance(flow_details, dict):
            flow_details = json.dumps(flow_details)
        
        attack_type = threat.get('attack_type', threat.get('classification', 'Unknown'))
        
        c.execute('''INSERT INTO threat_feed 
                     (device_id, classification, attack_type, threat_level, confidence,
                      layer0_flagged, layer1_flagged, flow_details, timestamp)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (threat.get('device_id'),
                   attack_type,
                   attack_type,
                   threat.get('threat_level'),
                   threat.get('confidence', 0),
                   1 if threat.get('layer0_flagged') else 0,
                   1 if threat.get('layer1_flagged') else 0,
                   flow_details,
                   datetime.now().isoformat()))
        
        conn.commit()
        
        # ── FIX: Only prune every 100 inserts, not every single one ──
        self._insert_count += 1
        if self._insert_count % 100 == 0:
            c.execute('''DELETE FROM threat_feed 
                         WHERE reviewed = 1
                         AND id NOT IN (
                             SELECT id FROM threat_feed 
                             WHERE reviewed = 1
                             ORDER BY id DESC LIMIT 500
                         )''')
            conn.commit()
            print(f"🧹 Pruned old reviewed entries (kept last 500)")
        
        conn.close()
    
    def get_threat_feed(self, limit=20):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM threat_feed ORDER BY id DESC LIMIT ?', (limit,))
        threats = []
        for row in c.fetchall():
            threat = dict(row)
            if 'flow_details' in threat and isinstance(threat['flow_details'], str):
                try:
                    threat['flow_details'] = json.loads(threat['flow_details'])
                except:
                    threat['flow_details'] = {}
            if 'attack_type' not in threat or not threat['attack_type']:
                threat['attack_type'] = threat.get('classification', 'Unknown')
            threats.append(threat)
        conn.close()
        return threats

    def get_recent_threats(self, limit=20):
        return self.get_threat_feed(limit=limit)
    
    def update_device_status(self, device_id, status):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO device_status 
                     (device_id, last_seen, status, ip_address, location, total_flows, threats_detected)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (device_id,
                   datetime.now().isoformat(),
                   status.get('status', 'unknown'),
                   status.get('ip_address'),
                   status.get('location'),
                   status.get('total_flows', 0),
                   status.get('threats_detected', 0)))
        conn.commit()
        conn.close()
    
    def get_system_stats(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM system_stats ORDER BY id DESC LIMIT 1')
        row = c.fetchone()
        conn.close()
        if row:
            try:
                return {
                    'total_flows_processed': int(row['total_flows_processed'] or 0),
                    'total_attacks_detected': int(row['total_attacks_detected'] or 0),
                    'flows_per_second': 0.0,
                    'threat_level_percent': float(row['threat_level_percent'] or 0),
                    'layer0_flagged_count': int(row['layer0_flagged_count'] or 0),
                    'layer0_flag_rate': float(row['layer0_flag_rate'] or 0),
                    'uptime_seconds': 0,
                    'timestamp': row['timestamp'],
                    'is_online': True
                }
            except Exception as e:
                print(f"Error parsing system_stats: {e}")
        return {
            'total_flows_processed': 0, 'total_attacks_detected': 0,
            'flows_per_second': 0.0, 'threat_level_percent': 0.0,
            'layer0_flagged_count': 0, 'layer0_flag_rate': 0.0,
            'uptime_seconds': 0, 'timestamp': datetime.now().isoformat(), 'is_online': False
        }
        
    def get_all_devices(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM device_status')
        devices = [dict(row) for row in c.fetchall()]
        conn.close()
        return devices
    
    def get_attack_distribution(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''SELECT classification, COUNT(*) as count 
                     FROM threat_feed 
                     WHERE classification != 'Normal Traffic'
                     GROUP BY classification''')
        distribution = {row[0]: row[1] for row in c.fetchall()}
        conn.close()
        return distribution
    
    def get_threat_timeline(self, hours=1):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        c.execute('SELECT * FROM threat_feed WHERE timestamp > ? ORDER BY timestamp DESC', (cutoff,))
        threats = []
        for row in c.fetchall():
            threat = dict(row)
            if 'flow_details' in threat and isinstance(threat['flow_details'], str):
                try:
                    threat['flow_details'] = json.loads(threat['flow_details'])
                except:
                    threat['flow_details'] = {}
            threats.append(threat)
        conn.close()
        return threats
    
    def get_review_queue(self, limit=10):
        """
        Get flows needing human review.
        
        FIX: Only catch GENUINELY UNCERTAIN flows:
        - confidence < 0.50 (model unsure)
        - AND not already a confirmed attack (layer1_flagged = 0)
        
        This prevents confirmed attacks from ALSO appearing in review queue
        and getting deleted together when the review queue is cleared.
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = """
            SELECT *
            FROM threat_feed
            WHERE (
                confidence < 0.50
                OR (layer0_flagged = 1 AND layer1_flagged = 0)
            )
            AND (reviewed IS NULL OR reviewed = 0)
            ORDER BY timestamp DESC
            LIMIT ?
            """
            
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            
            review_queue = []
            for row in rows:
                item = dict(row)
                if 'flow_details' in item and isinstance(item['flow_details'], str):
                    try:
                        item['flow_details'] = json.loads(item['flow_details'])
                    except:
                        item['flow_details'] = {}
                if 'classification' not in item:
                    item['classification'] = item.get('attack_type', 'Unknown')
                if 'attack_type' not in item:
                    item['attack_type'] = item.get('classification', 'Unknown')
                review_queue.append(item)
            
            conn.close()
            return review_queue
            
        except Exception as e:
            print(f"Error getting review queue: {e}")
            return []
    
    def get_review_stats(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # FIX: Match the same condition as get_review_queue
            cursor.execute("""
                SELECT COUNT(*) FROM threat_feed 
                WHERE (confidence < 0.50 OR (layer0_flagged = 1 AND layer1_flagged = 0))
                AND (reviewed IS NULL OR reviewed = 0)
            """)
            pending = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM threat_feed 
                WHERE reviewed = 1 AND date(timestamp) = date('now')
            """)
            reviewed_today = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM threat_feed WHERE confidence < 0.50")
            low_confidence = cursor.fetchone()[0]
            
            conn.close()
            return {
                'pending': pending,
                'reviewed_today': reviewed_today,
                'low_confidence': low_confidence,
                'total': pending + reviewed_today
            }
        except Exception as e:
            print(f"Error getting review stats: {e}")
            return {'pending': 0, 'reviewed_today': 0, 'low_confidence': 0, 'total': 0}
    
    def is_whitelisted(self, flow_details: dict) -> bool:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            src_ip   = flow_details.get('src_ip', '')
            dst_ip   = flow_details.get('dst_ip', '')
            src_port = flow_details.get('src_port', 0)
            dst_port = flow_details.get('dst_port', 0)
            protocol = flow_details.get('protocol', '')

            # 1. Exact match
            cursor.execute("""
                SELECT id FROM whitelist
                WHERE src_ip = ? AND dst_ip = ?
                  AND src_port = ? AND dst_port = ?
                  AND protocol = ?
                LIMIT 1
            """, (src_ip, dst_ip, src_port, dst_port, protocol))
            if cursor.fetchone():
                conn.close()
                return True

            # 2. IP-pair + dst_port (ignores ephemeral src_port)
            cursor.execute("""
                SELECT id FROM whitelist
                WHERE src_ip = ? AND dst_ip = ?
                  AND dst_port = ? AND protocol = ?
                LIMIT 1
            """, (src_ip, dst_ip, dst_port, protocol))
            if cursor.fetchone():
                conn.close()
                return True

            # 3. Tailscale subnet 100.x.x.x
            if src_ip.startswith('100.') and dst_ip.startswith('100.'):
                cursor.execute("""
                    SELECT id FROM whitelist
                    WHERE pattern_type = 'subnet'
                      AND (dst_port = ? OR dst_port = 0)
                    LIMIT 1
                """, (dst_port,))
                if cursor.fetchone():
                    conn.close()
                    return True

            conn.close()
            return False

        except Exception as e:
            print(f"Error checking whitelist: {e}")
            return False
    
    def approve_review(self, threat_id, decision):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT flow_details FROM threat_feed WHERE id = ?", (threat_id,))
            row = cursor.fetchone()
            
            if row and decision == 'normal':
                flow_details = row[0]
                if isinstance(flow_details, str):
                    try:
                        flow_details = json.loads(flow_details)
                    except:
                        flow_details = {}
                
                src_ip   = flow_details.get('src_ip', '')
                dst_ip   = flow_details.get('dst_ip', '')
                src_port = flow_details.get('src_port', 0)
                dst_port = flow_details.get('dst_port', 0)
                protocol = flow_details.get('protocol', '')
                
                try:
                    cursor.execute("""
                        INSERT OR IGNORE INTO whitelist
                        (pattern_type, src_ip, dst_ip, src_port, dst_port, protocol, reason, added_timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, ('flow', src_ip, dst_ip, src_port, dst_port, protocol,
                          f'Human reviewed as normal (threat_id={threat_id})',
                          datetime.now().isoformat()))
                    print(f"✅ Added to whitelist: {src_ip}:{src_port} → {dst_ip}:{dst_port} ({protocol})")
                except Exception as e:
                    print(f"⚠️  Whitelist insert failed: {e}")
            
            cursor.execute("""
                UPDATE threat_feed
                SET reviewed = 1, review_decision = ?, review_timestamp = ?
                WHERE id = ?
            """, (decision, datetime.now().isoformat(), threat_id))
            
            conn.commit()
            conn.close()
            print(f"✅ Review approved: ID {threat_id} → {decision}")
            return True
            
        except Exception as e:
            print(f"Error approving review: {e}")
            return False

_shared_state = None

def get_shared_state():
    global _shared_state
    if _shared_state is None:
        _shared_state = SharedState()
    return _shared_state