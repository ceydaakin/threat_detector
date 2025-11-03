"""
Configuration file for the Threat Detector system
"""
import os
from dotenv import load_dotenv

load_dotenv()

# Application Settings
APP_NAME = "Cybersecurity Threat Detector"
VERSION = "1.0.0"
DEBUG_MODE = True

# Network Monitoring
NETWORK_INTERFACE = "default"  # Will auto-detect
PACKET_CAPTURE_LIMIT = 100
PACKET_TIMEOUT = 10  # seconds

# Threat Detection Thresholds
ANOMALY_THRESHOLD = 0.7  # 70% confidence for anomaly
THREAT_SCORE_THRESHOLD = 5.0  # Combined threat score threshold
MAX_CONNECTIONS_PER_IP = 100  # connections per minute
MAX_FAILED_ATTEMPTS = 5  # Failed connection attempts

# Threat Intelligence APIs (Free tiers)
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "")

# Database
DATABASE_PATH = "threat_detector.db"

# Dashboard
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 5000

# Alert Settings
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")
ALERT_WEBHOOK = os.getenv("ALERT_WEBHOOK", "")

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = "threat_detector.log"

# Attack Patterns
SUSPICIOUS_PORTS = [22, 23, 3389, 445, 135, 139]  # Common attack targets
DDOS_THRESHOLD = 10000  # packets per minute from a single source
SQL_INJECTION_PATTERNS = [
    "' OR '1'='1",
    "'; DROP TABLE",
    "UNION SELECT",
    "' OR 1=1--",
    "admin'--",
    "' OR 'a'='a"
]
XSS_PATTERNS = [
    "<script>",
    "javascript:",
    "onerror=",
    "onload=",
    "<iframe"
]

# Machine Learning
MODEL_UPDATE_INTERVAL = 3600  # Update model every hour
TRAINING_DATA_SIZE = 10000
