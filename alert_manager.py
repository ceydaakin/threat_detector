"""
Alert management system for threat notifications
"""
from datetime import datetime

from colorama import Fore, Style

import config


class AlertManager:
    """Alert manager for handling threat notifications"""
    def __init__(self):
        self.alert_history = []
        self.alert_count = 0

    def send_alert(self, threat_data):
        """
        Send alert for detected threat

        Args:
            threat_data: Dictionary containing threat information
        """
        alert = {
            'id': self.alert_count,
            'timestamp': datetime.now().isoformat(),
            'threat_data': threat_data,
            'severity': self.calculate_severity(threat_data),
            'status': 'new'
        }

        self.alert_count += 1
        self.alert_history.append(alert)

        # Display alert
        self.display_alert(alert)

        # Send to external systems if configured
        if config.ALERT_EMAIL:
            self.send_email_alert(alert)

        if config.ALERT_WEBHOOK:
            self.send_webhook_alert(alert)

    def calculate_severity(self, threat_data):
        """Calculate threat severity level"""
        score = threat_data.get('threat_score', 0)

        if score >= 10:
            return 'CRITICAL'
        elif score >= 7:
            return 'HIGH'
        elif score >= 5:
            return 'MEDIUM'
        else:
            return 'LOW'

    def display_alert(self, alert):
        """Display alert in console"""
        severity = alert['severity']
        threat_data = alert['threat_data']

        # Color code based on severity
        if severity == 'CRITICAL':
            color = Fore.RED
        elif severity == 'HIGH':
            color = Fore.YELLOW
        elif severity == 'MEDIUM':
            color = Fore.CYAN
        else:
            color = Fore.WHITE

        print(f"\n{color}{'='*70}")
        print(f"[ALERT #{alert['id']}] Severity: {severity}")
        print(f"Timestamp: {alert['timestamp']}")
        print(f"Source IP: {threat_data.get('src_ip', 'Unknown')}")
        print(f"Threat Type(s): {', '.join(threat_data.get('threat_type', []))}")
        print(f"Threat Score: {threat_data.get('threat_score', 0):.2f}")

        if threat_data.get('details'):
            print(f"Details: {', '.join(threat_data['details'])}")

        intelligence = threat_data.get('intelligence', {})
        if intelligence.get('is_malicious'):
            sources = ', '.join(intelligence.get('sources', []))
            print(f"Threat Intelligence: IP flagged by {sources}")

        print(f"{'='*70}{Style.RESET_ALL}\n")

    def send_email_alert(self, alert):
        """Send email alert (placeholder for actual implementation)"""
        # This would integrate with an email service
        # For now, just log it
        _ = alert  # Placeholder: alert data would be used in actual implementation
        print(f"[*] Email alert would be sent to: {config.ALERT_EMAIL}")

    def send_webhook_alert(self, alert):
        """Send webhook alert (placeholder for actual implementation)"""
        # This would send to a webhook URL (Slack, Discord, etc.)
        _ = alert  # Placeholder: alert data would be used in actual implementation
        print(f"[*] Webhook alert would be sent to: {config.ALERT_WEBHOOK}")

    def get_recent_alerts(self, limit=10):
        """Get recent alerts"""
        return self.alert_history[-limit:]

    def get_alert_statistics(self):
        """Get alert statistics"""
        if not self.alert_history:
            return {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }

        stats = {
            'total': len(self.alert_history),
            'critical': sum(1 for a in self.alert_history if a['severity'] == 'CRITICAL'),
            'high': sum(1 for a in self.alert_history if a['severity'] == 'HIGH'),
            'medium': sum(1 for a in self.alert_history if a['severity'] == 'MEDIUM'),
            'low': sum(1 for a in self.alert_history if a['severity'] == 'LOW')
        }

        return stats
