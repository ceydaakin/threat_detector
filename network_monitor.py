"""
Network monitoring module for capturing and analyzing network packets
"""
import time
from collections import defaultdict
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw  # type: ignore # pylint: disable=import-error

import config


class NetworkMonitor:
    """Network monitor for capturing and analyzing packets"""
    def __init__(self):
        self.connection_tracker = defaultdict(list)
        self.packet_count = defaultdict(int)
        self.last_cleanup = time.time()

    def capture_packets(self, count=10, timeout=2):
        """
        Capture network packets

        Args:
            count: Number of packets to capture
            timeout: Timeout in seconds

        Returns:
            List of parsed packet data
        """
        packets_data = []

        try:
            # Capture packets
            packets = sniff(count=count, timeout=timeout, store=True)

            for packet in packets:
                packet_info = self.parse_packet(packet)
                if packet_info:
                    packets_data.append(packet_info)

            # Periodic cleanup of old connections
            if time.time() - self.last_cleanup > 60:
                self.cleanup_old_connections()

        except (OSError, RuntimeError) as e:
            print(f"Packet capture error: {e}")

        return packets_data

    def parse_packet(self, packet):
        """
        Parse packet and extract relevant information

        Args:
            packet: Scapy packet object

        Returns:
            Dictionary with packet information
        """
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'protocol': ip_layer.proto,
            'size': len(packet),
            'flags': [],
            'payload': ''
        }

        # TCP packet
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            packet_info.update({
                'protocol_name': 'TCP',
                'src_port': tcp_layer.sport,
                'dst_port': tcp_layer.dport,
                'flags': self.get_tcp_flags(tcp_layer),
                'seq': tcp_layer.seq,
                'ack': tcp_layer.ack
            })

            # Track connection
            self.track_connection(packet_info['src_ip'], packet_info['dst_port'])

        # UDP packet
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            packet_info.update({
                'protocol_name': 'UDP',
                'src_port': udp_layer.sport,
                'dst_port': udp_layer.dport
            })

        # ICMP packet
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            packet_info.update({
                'protocol_name': 'ICMP',
                'icmp_type': icmp_layer.type,
                'icmp_code': icmp_layer.code
            })

        # DNS packet
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            packet_info['dns_query'] = dns_layer.qd.qname.decode() if dns_layer.qd else ''

        # Extract payload
        if packet.haslayer(Raw):
            try:
                packet_info['payload'] = packet[Raw].load.decode('utf-8', errors='ignore')
            except (UnicodeDecodeError, AttributeError):
                packet_info['payload'] = str(packet[Raw].load)

        # Count packets per IP
        self.packet_count[packet_info['src_ip']] += 1
        packet_info['packet_rate'] = self.packet_count[packet_info['src_ip']]

        return packet_info

    def get_tcp_flags(self, tcp_layer):
        """Extract TCP flags"""
        flags = []
        if tcp_layer.flags.S:
            flags.append('SYN')
        if tcp_layer.flags.A:
            flags.append('ACK')
        if tcp_layer.flags.F:
            flags.append('FIN')
        if tcp_layer.flags.R:
            flags.append('RST')
        if tcp_layer.flags.P:
            flags.append('PSH')
        if tcp_layer.flags.U:
            flags.append('URG')
        return flags

    def track_connection(self, ip, port):
        """Track connections per IP"""
        current_time = time.time()
        self.connection_tracker[ip].append({
            'port': port,
            'time': current_time
        })

    def cleanup_old_connections(self):
        """Remove connections older than 1 minute"""
        current_time = time.time()
        for ip in list(self.connection_tracker.keys()):
            self.connection_tracker[ip] = [
                conn for conn in self.connection_tracker[ip]
                if current_time - conn['time'] < 60
            ]
            if not self.connection_tracker[ip]:
                del self.connection_tracker[ip]

        # Reset packet counts
        self.packet_count.clear()
        self.last_cleanup = current_time

    def get_connection_count(self, ip):
        """Get number of connections from an IP in the last minute"""
        return len(self.connection_tracker.get(ip, []))

    def detect_port_scan(self, ip):
        """Detect if an IP is performing a port scan"""
        connections = self.connection_tracker.get(ip, [])
        unique_ports = len(set(conn['port'] for conn in connections))

        # If accessing more than 10 different ports in a minute, likely a port scan
        return unique_ports > 10

    def detect_ddos(self, ip):
        """Detect potential DDoS from an IP"""
        packet_rate = self.packet_count.get(ip, 0)
        return packet_rate > config.DDOS_THRESHOLD
