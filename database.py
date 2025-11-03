"""
Database module for storing network activity and threat logs
"""
import sqlite3
import json

import config


class Database:
    """Database manager for storing threats and network activity"""
    def __init__(self):
        self.db_path = config.DATABASE_PATH
        self.conn = None

    def initialize(self):
        """Initialize database and create tables"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.create_tables()

    def create_tables(self):
        """Create necessary database tables"""
        cursor = self.conn.cursor()

        # Network activity table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                flags TEXT,
                payload TEXT
            )
        ''')

        # Threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT,
                threat_type TEXT NOT NULL,
                threat_score REAL,
                severity TEXT,
                details TEXT,
                intelligence_data TEXT,
                status TEXT DEFAULT 'new'
            )
        ''')

        # Statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_packets INTEGER,
                total_threats INTEGER,
                unique_ips INTEGER,
                data TEXT
            )
        ''')

        self.conn.commit()

    def log_activity(self, packet_data):
        """Log network activity"""
        cursor = self.conn.cursor()

        cursor.execute('''
            INSERT INTO network_activity
            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, flags, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet_data.get('timestamp'),
            packet_data.get('src_ip'),
            packet_data.get('dst_ip'),
            packet_data.get('src_port'),
            packet_data.get('dst_port'),
            packet_data.get('protocol_name'),
            packet_data.get('size'),
            json.dumps(packet_data.get('flags', [])),
            packet_data.get('payload', '')[:1000]  # Limit payload size
        ))

        self.conn.commit()

    def log_threat(self, threat_data):
        """Log detected threat"""
        cursor = self.conn.cursor()

        severity = self.calculate_severity(threat_data.get('threat_score', 0))

        cursor.execute('''
            INSERT INTO threats
            (timestamp, src_ip, dst_ip, threat_type, threat_score, severity, details, intelligence_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            threat_data.get('timestamp'),
            threat_data.get('src_ip'),
            threat_data.get('dst_ip'),
            json.dumps(threat_data.get('threat_type', [])),
            threat_data.get('threat_score'),
            severity,
            json.dumps(threat_data.get('details', [])),
            json.dumps(threat_data.get('intelligence', {}))
        ))

        self.conn.commit()

    def calculate_severity(self, score):
        """Calculate severity from score"""
        if score >= 10:
            return 'CRITICAL'
        elif score >= 7:
            return 'HIGH'
        elif score >= 5:
            return 'MEDIUM'
        else:
            return 'LOW'

    def get_recent_threats(self, limit=50):
        """Get recent threats"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM threats
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))

        return cursor.fetchall()

    def get_threat_statistics(self):
        """Get threat statistics"""
        cursor = self.conn.cursor()

        # Total threats
        cursor.execute('SELECT COUNT(*) FROM threats')
        total = cursor.fetchone()[0]

        # Threats by severity
        cursor.execute('SELECT severity, COUNT(*) FROM threats GROUP BY severity')
        by_severity = dict(cursor.fetchall())

        # Threats by type
        query = 'SELECT threat_type, COUNT(*) FROM threats GROUP BY threat_type LIMIT 10'
        cursor.execute(query)
        by_type = cursor.fetchall()

        # Top attacking IPs
        query = ('SELECT src_ip, COUNT(*) as count FROM threats '
                 'GROUP BY src_ip ORDER BY count DESC LIMIT 10')
        cursor.execute(query)
        top_ips = cursor.fetchall()

        return {
            'total': total,
            'by_severity': by_severity,
            'by_type': by_type,
            'top_ips': top_ips
        }

    def get_activity_statistics(self):
        """Get network activity statistics"""
        cursor = self.conn.cursor()

        # Total packets
        cursor.execute('SELECT COUNT(*) FROM network_activity')
        total_packets = cursor.fetchone()[0]

        # Unique IPs
        cursor.execute('SELECT COUNT(DISTINCT src_ip) FROM network_activity')
        unique_ips = cursor.fetchone()[0]

        # Top protocols
        cursor.execute('SELECT protocol, COUNT(*) FROM network_activity GROUP BY protocol')
        protocols = dict(cursor.fetchall())

        return {
            'total_packets': total_packets,
            'unique_ips': unique_ips,
            'protocols': protocols
        }

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
