"""
Threat detection engine using pattern matching and anomaly detection
"""
import re
import numpy as np
from sklearn.ensemble import IsolationForest
import config

class ThreatDetector:
    """
    Advanced threat detection system using pattern matching,
    machine learning anomaly detection, and behavioral analysis
    """
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.training_data = []
        self.is_trained = False
        self.threat_patterns = {
            'SQL_INJECTION': config.SQL_INJECTION_PATTERNS,
            'XSS': config.XSS_PATTERNS
        }

    def analyze_packet(self, packet_data):
        """
        Analyze a packet for potential threats

        Args:
            packet_data: Dictionary containing packet information

        Returns:
            Dictionary with threat analysis results
        """
        result = {
            'timestamp': packet_data.get('timestamp'),
            'src_ip': packet_data.get('src_ip'),
            'dst_ip': packet_data.get('dst_ip'),
            'is_threat': False,
            'threat_type': [],
            'threat_score': 0.0,
            'details': []
        }

        # Pattern-based detection
        pattern_threats = self.detect_patterns(packet_data)
        if pattern_threats:
            result['is_threat'] = True
            result['threat_type'].extend(pattern_threats)
            result['threat_score'] += len(pattern_threats) * 2.0

        # Port scan detection
        if self.detect_port_scan(packet_data):
            result['is_threat'] = True
            result['threat_type'].append('PORT_SCAN')
            result['threat_score'] += 3.0
            result['details'].append('Multiple port access detected')

        # Suspicious port detection
        if self.detect_suspicious_port(packet_data):
            result['is_threat'] = True
            result['threat_type'].append('SUSPICIOUS_PORT')
            result['threat_score'] += 1.5
            result['details'].append(f"Access to suspicious port: {packet_data.get('dst_port')}")

        # DDoS detection
        if self.detect_ddos(packet_data):
            result['is_threat'] = True
            result['threat_type'].append('DDoS')
            result['threat_score'] += 5.0
            result['details'].append('High packet rate detected')

        # Brute force detection
        if self.detect_brute_force(packet_data):
            result['is_threat'] = True
            result['threat_type'].append('BRUTE_FORCE')
            result['threat_score'] += 4.0
            result['details'].append('Multiple failed connection attempts')

        # Anomaly detection (ML-based)
        if self.is_trained:
            anomaly_score = self.detect_anomaly(packet_data)
            if anomaly_score < 0:  # Anomaly detected
                result['is_threat'] = True
                result['threat_type'].append('ANOMALY')
                result['threat_score'] += abs(anomaly_score) * 2
                result['details'].append('Unusual network behavior detected')

        # Update training data
        self.update_training_data(packet_data)

        # Final threat determination
        result['is_threat'] = result['threat_score'] >= config.THREAT_SCORE_THRESHOLD

        return result

    def detect_patterns(self, packet_data):
        """Detect known attack patterns in payload"""
        threats = []
        payload = packet_data.get('payload', '')

        if not payload:
            return threats

        # Check for SQL injection
        for pattern in self.threat_patterns['SQL_INJECTION']:
            if pattern.lower() in payload.lower():
                threats.append('SQL_INJECTION')
                break

        # Check for XSS
        for pattern in self.threat_patterns['XSS']:
            if pattern.lower() in payload.lower():
                threats.append('XSS')
                break

        # Check for command injection
        if re.search(r'[\|;&`$]', payload):
            cmd_patterns = ['bash', 'sh', 'cmd', 'powershell', 'wget', 'curl']
            if any(cmd in payload.lower() for cmd in cmd_patterns):
                threats.append('COMMAND_INJECTION')

        return threats

    def detect_port_scan(self, packet_data):
        """Detect port scanning activity"""
        # dst_port = packet_data.get('dst_port')  # Unused variable
        flags = packet_data.get('flags', [])

        # SYN scan detection
        if 'SYN' in flags and 'ACK' not in flags:
            return True

        return False

    def detect_suspicious_port(self, packet_data):
        """Check if accessing suspicious ports"""
        dst_port = packet_data.get('dst_port')
        return dst_port in config.SUSPICIOUS_PORTS if dst_port else False

    def detect_ddos(self, packet_data):
        """Detect DDoS attack based on packet rate"""
        packet_rate = packet_data.get('packet_rate', 0)
        return packet_rate > config.DDOS_THRESHOLD

    def detect_brute_force(self, packet_data):
        """Detect brute force attempts"""
        flags = packet_data.get('flags', [])
        dst_port = packet_data.get('dst_port')

        # Multiple RST flags to SSH/RDP/FTP ports indicate failed attempts
        if 'RST' in flags and dst_port in [22, 3389, 21, 23]:
            return True

        return False

    def detect_anomaly(self, packet_data):
        """Use ML to detect anomalies"""
        if not self.is_trained:
            return 0

        features = self.extract_features(packet_data)
        # prediction = self.isolation_forest.predict([features])  # Unused variable
        score = self.isolation_forest.score_samples([features])

        return score[0]

    def extract_features(self, packet_data):
        """Extract numerical features from packet data"""
        return [
            packet_data.get('size', 0),
            packet_data.get('dst_port', 0),
            packet_data.get('src_port', 0),
            len(packet_data.get('payload', '')),
            packet_data.get('packet_rate', 0),
            1 if packet_data.get('protocol_name') == 'TCP' else 0,
            len(packet_data.get('flags', []))
        ]

    def update_training_data(self, packet_data):
        """Update training data and retrain model periodically"""
        features = self.extract_features(packet_data)
        self.training_data.append(features)

        # Train model when we have enough data
        if len(self.training_data) >= 100 and not self.is_trained:
            self.train_model()

        # Retrain periodically
        if len(self.training_data) >= config.TRAINING_DATA_SIZE:
            self.train_model()
            self.training_data = self.training_data[-1000:]  # Keep recent data

    def train_model(self):
        """Train the anomaly detection model"""
        if len(self.training_data) < 10:
            return

        try:
            training_features = np.array(self.training_data)
            self.isolation_forest.fit(training_features)
            self.is_trained = True
        except (ValueError, RuntimeError) as e:
            print(f"Model training error: {e}")
