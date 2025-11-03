# Cybersecurity Threat Detector

A real-time network activity monitoring and threat detection system that analyzes security logs to identify potential attacks before they happen.

## Features

- **Real-time Network Monitoring**: Captures and analyzes network packets
- **Anomaly Detection**: Uses machine learning to detect unusual patterns
- **Threat Intelligence Integration**: Leverages free online threat databases
- **Alert System**: Notifies administrators of potential threats
- **Dashboard**: Visual representation of network activity and threats

## Requirements

- Python 3.8+
- Administrator/Root privileges (for packet capture)
- Internet connection (for threat intelligence updates)

## Installation

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the application:

```bash
python main.py
```

## Components

- `main.py`: Main application entry point
- `network_monitor.py`: Network packet capture and analysis
- `threat_detector.py`: ML-based threat detection engine
- `threat_intelligence.py`: Integration with free threat databases
- `alert_manager.py`: Alert and notification system
- `dashboard.py`: Web-based monitoring dashboard

## Data Sources

- AbuseIPDB (free tier)
- AlienVault OTX
- VirusTotal (free API)
- Local pattern matching and anomaly detection

## Usage

The application runs a local web dashboard on `http://localhost:5000` where you can:

- View real-time network activity
- Monitor detected threats
- Configure alert thresholds
- Export security reports

## Security Note

This tool is for educational and legitimate security monitoring purposes only.
