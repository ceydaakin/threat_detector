# 🛡️ Cybersecurity Threat Detector - User Guide

## ✅ Installation Complete!

Your cybersecurity threat detection system is up and running!

## 📊 Web Dashboard

Open in your browser: **http://127.0.0.1:5000**

On the dashboard you can see:

- ✅ Total detected threats
- ✅ Number of critical alerts
- ✅ Total packet count
- ✅ Unique IP addresses
- ✅ Real-time threat list

The dashboard auto-refreshes every 5 seconds.

## 🎯 Features

### 1. **Real-Time Network Monitoring**

- Captures TCP, UDP, ICMP packets
- Port scan detection
- DDoS attack detection
- Connection tracking

### 2. **Threat Detection**

- **SQL Injection** - SQL injection attacks
- **XSS (Cross-Site Scripting)** - Script injection
- **Command Injection** - Command line attacks
- **Port Scanning** - Port scan activities
- **DDoS** - Denial of Service attacks
- **Brute Force** - Brute force attacks
- **Anomaly Detection** - ML-based abnormal behavior detection

### 3. **Free Threat Intelligence**

The system pulls threat data from these free sources:

- **AlienVault OTX** - Malicious IP database
- **Blocklist.de** - SSH attacker list
- **Emerging Threats** - Compromised IPs

### 4. **Alert System**

- Color-coded severity levels (Critical, High, Medium, Low)
- Real-time alerts
- Detailed threat information

## 🔧 Configuration

### API Keys (Optional - For advanced detection)

Edit the `.env` file and add your free API keys:

```env
# AbuseIPDB (Free: https://www.abuseipdb.com/api)
ABUSEIPDB_API_KEY=your_key_here

# VirusTotal (Free: https://www.virustotal.com/gui/my-apikey)
VIRUSTOTAL_API_KEY=your_key_here

# AlienVault OTX (Free: https://otx.alienvault.com/api)
ALIENVAULT_API_KEY=your_key_here
```

### Adjusting Detection Thresholds

You can change the settings in `config.py`:

```python
ANOMALY_THRESHOLD = 0.7  # Anomaly confidence score
THREAT_SCORE_THRESHOLD = 5.0  # Threat score threshold
MAX_CONNECTIONS_PER_IP = 100  # Max connections per minute
DDOS_THRESHOLD = 1000  # Packet limit per second
```

## 🚀 Usage

### 1. Start the System

```powershell
python main.py
```

### 2. Run Tests

Test the system with simulated threats:

```powershell
python test_detector.py
```

### 3. View the Dashboard

In your browser: http://127.0.0.1:5000

### 4. Stop the System

Press `Ctrl+C` in the terminal.

## 📈 Threat Levels

| Level        | Color     | Score Range | Description                      |
| ------------ | --------- | ----------- | -------------------------------- |
| **CRITICAL** | 🔴 Red    | ≥10         | Severe threat - Immediate action |
| **HIGH**     | 🟠 Orange | 7-9.9       | High risk - Investigate quickly  |
| **MEDIUM**   | 🟡 Yellow | 5-6.9       | Medium risk - Monitor            |
| **LOW**      | 🟢 Green  | <5          | Low risk - Informational         |

## 🔍 Example Detected Attacks

### SQL Injection

```
Payload: username=admin' OR '1'='1&password=test
Detection: SQL_INJECTION pattern detected
```

### Port Scan

```
Feature: SYN packets, access to different ports
Detection: PORT_SCAN + SUSPICIOUS_PORT
```

### DDoS

```
Feature: >1000 packets per second
Detection: DDoS attack detected
```

### XSS

```
Payload: <script>alert("XSS")</script>
Detection: XSS pattern detected
```

## 📁 File Structure

```
threat_detector/
├── main.py                    # Main application
├── network_monitor.py         # Network monitoring
├── threat_detector.py         # Threat detection
├── threat_intelligence.py     # Threat intelligence
├── alert_manager.py           # Alert management
├── dashboard.py               # Web dashboard
├── database.py                # Database
├── config.py                  # Configuration
├── test_detector.py           # Test scripts
├── requirements.txt           # Python dependencies
├── threat_detector.db         # SQLite database (auto-created)
└── templates/
    └── dashboard.html         # Dashboard HTML
```

## 💾 Database

The system uses SQLite. Tables:

- **network_activity** - All network activity
- **threats** - Detected threats
- **statistics** - Statistics

To view the database:

```powershell
sqlite3 threat_detector.db
SELECT * FROM threats;
```

## ⚠️ Important Notes

1. **Administrator Privileges**: For full packet capture on Windows, run as administrator:

   ```powershell
   # Open PowerShell as administrator
   python main.py
   ```

2. **Npcap Installation**: For advanced packet capture, install Npcap:

   - https://npcap.com/#download

3. **Firewall**: Your antivirus/firewall may block the application.

4. **Legal Notice**: This tool is for monitoring your own network only. Unauthorized use is illegal.

## 🎓 Learning Resources

### Free Threat Intelligence Sources

- AlienVault OTX: https://otx.alienvault.com
- AbuseIPDB: https://www.abuseipdb.com
- VirusTotal: https://www.virustotal.com
- Blocklist.de: https://www.blocklist.de
- Emerging Threats: https://rules.emergingthreats.net

### About Attack Types

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CVE Database: https://cve.mitre.org/
- NIST Cybersecurity: https://www.nist.gov/cybersecurity

## 🐛 Troubleshooting

### Not capturing packets?

- Check if Npcap/WinPcap is installed
- Run as administrator
- Check firewall settings

### Dashboard not opening?

- Is port 5000 in use?
- `netstat -ano | findstr :5000`

### API not working?

- Check API keys in `.env`
- Check your internet connection

## 🚀 Advanced Usage

### Add Your Own Patterns

Add new patterns to `config.py`:

```python
CUSTOM_PATTERNS = [
    "your_pattern_here",
    "another_pattern"
]
```

### Adjust Thresholds

For more or less sensitive detection:

```python
# More sensitive (more alerts)
THREAT_SCORE_THRESHOLD = 3.0

# Less sensitive (fewer alerts)
THREAT_SCORE_THRESHOLD = 7.0
```

## 📞 Support

For questions:

1. Read the README.md file
2. Run the test script
3. Check the log files

## 🎉 Successfully Installed!

Your system now:
✅ Monitors network traffic
✅ Detects threats
✅ Sends real-time alerts
✅ Visualizes on the web dashboard

**Happy monitoring!** 🛡️
