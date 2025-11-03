"""
Test script to simulate threats and test the detection system
"""
import time
from datetime import datetime
from alert_manager import AlertManager
from threat_detector import ThreatDetector

def test_threat_detector():
    """Test the threat detection system with sample data"""
    detector = ThreatDetector()
    alert_manager = AlertManager()

    print("Testing Threat Detector...")
    print("=" * 70)

    # Test 1: SQL Injection
    print("\n[Test 1] SQL Injection Detection")
    sql_packet = {
        'timestamp': datetime.now().isoformat(),
        'src_ip': '192.168.1.100',
        'dst_ip': '192.168.1.1',
        'dst_port': 80,
        'src_port': 54321,
        'protocol_name': 'TCP',
        'size': 500,
        'flags': ['PSH', 'ACK'],
        'payload': "username=admin' OR '1'='1&password=test",
        'packet_rate': 10
    }

    result = detector.analyze_packet(sql_packet)
    print(f"Result: {result}")
    if result['is_threat']:
        alert_manager.send_alert(result)

    time.sleep(1)

    # Test 2: Port Scan
    print("\n[Test 2] Port Scan Detection")
    scan_packet = {
        'timestamp': datetime.now().isoformat(),
        'src_ip': '10.0.0.50',
        'dst_ip': '192.168.1.1',
        'dst_port': 22,
        'src_port': 12345,
        'protocol_name': 'TCP',
        'size': 60,
        'flags': ['SYN'],
        'payload': '',
        'packet_rate': 5
    }

    result = detector.analyze_packet(scan_packet)
    print(f"Result: {result}")
    if result['is_threat']:
        alert_manager.send_alert(result)

    time.sleep(1)

    # Test 3: DDoS Simulation
    print("\n[Test 3] DDoS Detection")
    ddos_packet = {
        'timestamp': datetime.now().isoformat(),
        'src_ip': '172.16.0.100',
        'dst_ip': '192.168.1.1',
        'dst_port': 80,
        'src_port': 55555,
        'protocol_name': 'TCP',
        'size': 1500,
        'flags': ['ACK'],
        'payload': '',
        'packet_rate': 1500  # High packet rate
    }

    result = detector.analyze_packet(ddos_packet)
    print(f"Result: {result}")
    if result['is_threat']:
        alert_manager.send_alert(result)

    time.sleep(1)

    # Test 4: XSS Attack
    print("\n[Test 4] XSS Detection")
    xss_packet = {
        'timestamp': datetime.now().isoformat(),
        'src_ip': '192.168.1.200',
        'dst_ip': '192.168.1.1',
        'dst_port': 443,
        'src_port': 60000,
        'protocol_name': 'TCP',
        'size': 300,
        'flags': ['PSH', 'ACK'],
        'payload': '<script>alert("XSS")</script>',
        'packet_rate': 3
    }

    result = detector.analyze_packet(xss_packet)
    print(f"Result: {result}")
    if result['is_threat']:
        alert_manager.send_alert(result)

    time.sleep(1)

    # Test 5: Suspicious Port Access
    print("\n[Test 5] Suspicious Port Detection")
    suspicious_packet = {
        'timestamp': datetime.now().isoformat(),
        'src_ip': '203.0.113.42',
        'dst_ip': '192.168.1.1',
        'dst_port': 3389,  # RDP port
        'src_port': 45678,
        'protocol_name': 'TCP',
        'size': 100,
        'flags': ['SYN', 'ACK'],
        'payload': '',
        'packet_rate': 8
    }

    result = detector.analyze_packet(suspicious_packet)
    print(f"Result: {result}")
    if result['is_threat']:
        alert_manager.send_alert(result)

    print("\n" + "=" * 70)
    print("Testing Complete!")
    print("\nAlert Statistics:")
    stats = alert_manager.get_alert_statistics()
    print(f"Total Alerts: {stats['total']}")
    print(f"Critical: {stats['critical']}")
    print(f"High: {stats['high']}")
    print(f"Medium: {stats['medium']}")
    print(f"Low: {stats['low']}")

if __name__ == "__main__":
    test_threat_detector()
