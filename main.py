"""
Main entry point for the Cybersecurity Threat Detector
"""
import sys
import threading
import time

from colorama import init, Fore, Style

from alert_manager import AlertManager
import config
from dashboard import Dashboard
from database import Database
from network_monitor import NetworkMonitor
from threat_detector import ThreatDetector
from threat_intelligence import ThreatIntelligence

# Initialize colorama for colored terminal output
init(autoreset=True)


class ThreatDetectorApp:
    """Main application class for the Threat Detector system"""
    def __init__(self):
        self.db = Database()
        self.network_monitor = NetworkMonitor()
        self.threat_detector = ThreatDetector()
        self.threat_intelligence = ThreatIntelligence()
        self.alert_manager = AlertManager()
        self.dashboard = Dashboard(self.db)
        self.running = False

    def print_banner(self):
        """Display application banner"""
        banner = f"""
{Fore.CYAN}{'='*70}
{Fore.GREEN}   _____ _                    _     ____       _            _             
  |_   _| |__  _ __ ___  __ _| |_  |  _ \\ ___| |_ ___  ___| |_ ___  _ __ 
    | | | '_ \\| '__/ _ \\/ _` | __| | | | / _ \\ __/ _ \\/ __| __/ _ \\| '__|
    | | | | | | | |  __/ (_| | |_  | |_| |  __/ ||  __/ (__| || (_) | |   
    |_| |_| |_|_|  \\___|\\__,_|\\__| |____/ \\___|\\__\\___|\\___|\\__\\___/|_|   

{Fore.CYAN}  Version: {config.VERSION}
  Real-time Network Threat Detection & Analysis System
{'='*70}{Style.RESET_ALL}
"""
        print(banner)

    def start(self):
        """Start all components"""
        self.print_banner()
        print(f"{Fore.YELLOW}[*] Initializing Threat Detector System..."
              f"{Style.RESET_ALL}")

        try:
            # Initialize database
            print(f"{Fore.YELLOW}[*] Setting up database...{Style.RESET_ALL}")
            self.db.initialize()

            # Start threat intelligence updates
            print(f"{Fore.YELLOW}[*] Loading threat intelligence feeds..."
                  f"{Style.RESET_ALL}")
            intelligence_thread = threading.Thread(
                target=self.threat_intelligence.update_feeds,
                daemon=True
            )
            intelligence_thread.start()

            # Start network monitoring
            print(f"{Fore.YELLOW}[*] Starting network monitor..."
                  f"{Style.RESET_ALL}")
            monitor_thread = threading.Thread(
                target=self.start_monitoring,
                daemon=True
            )
            monitor_thread.start()

            # Start dashboard
            dashboard_url = f"http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}"
            print(f"{Fore.GREEN}[+] Starting dashboard on {dashboard_url}"
                  f"{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Press Ctrl+C to stop{Style.RESET_ALL}\n")

            self.running = True
            self.dashboard.run()

        except KeyboardInterrupt:
            self.stop()
        except (OSError, RuntimeError, ValueError) as e:
            print(f"{Fore.RED}[!] Error starting application: {e}"
                  f"{Style.RESET_ALL}")
            self.stop()

    def start_monitoring(self):
        """Start the network monitoring and threat detection loop"""
        while self.running:
            try:
                # Capture network packets
                packets = self.network_monitor.capture_packets()

                for packet_data in packets:
                    # Analyze packet for threats
                    threat_result = self.threat_detector.analyze_packet(packet_data)

                    if threat_result['is_threat']:
                        # Check against threat intelligence
                        intel_result = self.threat_intelligence.check_ip(
                            packet_data.get('src_ip', '')
                        )

                        # Combine results
                        threat_result['intelligence'] = intel_result

                        # Store in database
                        self.db.log_threat(threat_result)

                        # Send alert
                        self.alert_manager.send_alert(threat_result)

                        threat_msg = (f"{Fore.RED}[!] THREAT DETECTED: "
                                    f"{threat_result['threat_type']} from "
                                    f"{packet_data.get('src_ip', 'Unknown')}"
                                    f"{Style.RESET_ALL}")
                        print(threat_msg)

                    # Log all activity
                    self.db.log_activity(packet_data)

                time.sleep(0.1)  # Small delay to prevent CPU overload

            except (OSError, RuntimeError, KeyError, ValueError) as e:
                print(f"{Fore.RED}[!] Monitoring error: {e}{Style.RESET_ALL}")
                time.sleep(1)

    def stop(self):
        """Stop all components"""
        print(f"\n{Fore.YELLOW}[*] Shutting down Threat Detector..."
              f"{Style.RESET_ALL}")
        self.running = False
        self.db.close()
        print(f"{Fore.GREEN}[+] Shutdown complete{Style.RESET_ALL}")
        sys.exit(0)


def check_admin_privileges():
    """Check if running with administrator privileges on Windows"""
    if sys.platform == "win32":
        import ctypes  # pylint: disable=import-outside-toplevel
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print(f"{Fore.YELLOW}[!] Warning: Running without administrator "
                  f"privileges.")
            print(f"    Some network monitoring features may be limited."
                  f"{Style.RESET_ALL}\n")


def main():
    """Main function"""
    check_admin_privileges()
    app = ThreatDetectorApp()
    app.start()


if __name__ == "__main__":
    main()
