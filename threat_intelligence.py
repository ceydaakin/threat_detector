"""
Threat intelligence module for querying free online threat databases
"""

from datetime import datetime
from datetime import timedelta
import requests
import config

class ThreatIntelligence:
    """Manages threat intelligence feeds and IP lookups."""
    def __init__(self):
        self.cache = {}
        self.cache_duration = timedelta(hours=24)
        self.malicious_ips = set()
        self.last_update = None

    def update_feeds(self):
        """Update threat intelligence feeds"""
        print("[*] Updating threat intelligence feeds...")

        feeds = {
            "AlienVault OTX": (
                'https://reputation.alienvault.com/reputation.generic',
                lambda line: line.split('#')[0].strip()
            ),
            "Blocklist.de": (
                'https://lists.blocklist.de/lists/ssh.txt',
                None
            ),
            "Emerging Threats": (
                'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
                None
            )
        }
        self._update_from_feeds(feeds)
        self.last_update = datetime.now()
        print("[+] Threat intelligence updated.")
        print(f"    Total malicious IPs: {len(self.malicious_ips)}")

    def check_ip(self, ip_address):
        """
        Check IP against threat intelligence sources

        Args:
            ip_address: IP address to check

        Returns:
            Dictionary with threat intelligence results
        """
        if not ip_address:
            return {'is_malicious': False}

        # Check cache first
        if ip_address in self.cache:
            cache_entry = self.cache[ip_address]
            if datetime.now() - cache_entry['timestamp'] < self.cache_duration:
                return cache_entry['data']

        result = {
            'is_malicious': False,
            'sources': [],
            'reputation_score': 0,
            'last_seen': None,
            'country': None
        }

        # Check local blocklist
        if ip_address in self.malicious_ips:
            result['is_malicious'] = True
            result['sources'].append('Local Blocklist')
            result['reputation_score'] += 5

        # Check AbuseIPDB (if API key provided)
        if config.ABUSEIPDB_API_KEY:
            abuse_result = self.check_abuseipdb(ip_address)
            if abuse_result.get('is_malicious'):
                result['is_malicious'] = True
                result['sources'].append('AbuseIPDB')
                result['reputation_score'] += abuse_result.get('confidence', 0)

        # Check VirusTotal (if API key provided)
        if config.VIRUSTOTAL_API_KEY:
            vt_result = self.check_virustotal(ip_address)
            if vt_result.get('is_malicious'):
                result['is_malicious'] = True
                result['sources'].append('VirusTotal')
                result['reputation_score'] += vt_result.get('positives', 0)

        # Final determination based on the combined score
        result['is_malicious'] = result['reputation_score'] >= config.THREAT_SCORE_THRESHOLD

        # Cache the result
        self.cache[ip_address] = {
            'timestamp': datetime.now(),
            'data': result
        }

        return result

    def check_abuseipdb(self, ip_address):
        """Check IP against AbuseIPDB"""
        if not config.ABUSEIPDB_API_KEY:
            return {'is_malicious': False}

        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': config.ABUSEIPDB_API_KEY
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'
        }

        try:
            response = requests.get(url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json().get('data', {})
                abuse_score = data.get('abuseConfidenceScore', 0)
                return {
                    'is_malicious': abuse_score > 50,
                    'confidence': abuse_score,
                    'country': data.get('countryCode')
                }
        except requests.exceptions.RequestException as e:
            print(f"AbuseIPDB API error: {e}")

        return {'is_malicious': False}

    def check_virustotal(self, ip_address):
        """Check IP against VirusTotal"""
        if not config.VIRUSTOTAL_API_KEY:
            return {'is_malicious': False}

        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
        headers = {
            'x-apikey': config.VIRUSTOTAL_API_KEY
        }

        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)

                return {
                    'is_malicious': (malicious + suspicious) > 0,
                    'positives': malicious + suspicious
                }
        except requests.exceptions.RequestException as e:
            print(f"VirusTotal API error: {e}")

        return {'is_malicious': False}

    def _update_from_feeds(self, feeds):
        """Generic method to update IP lists from multiple feed URLs."""
        for name, (url, parser) in feeds.items():
            self._fetch_and_parse_feed(name, url, parser)

    def _fetch_and_parse_feed(self, feed_name, url, parser_func=None):
        """Fetches and parses a single IP feed."""
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line and not line.startswith('#'):
                        ip = parser_func(line) if parser_func else line.strip()
                        if ip:
                            self.malicious_ips.add(ip)
                print(f"[+] {feed_name} feed updated")
            else:
                print(f"[!] {feed_name} update failed with status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[!] {feed_name} update error: {e}")
