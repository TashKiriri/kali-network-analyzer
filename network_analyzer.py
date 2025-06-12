#!/usr/bin/env python3
"""
Kali Linux Network Traffic Analyzer
Advanced packet capture and analysis tool for penetration testing and network security analysis.
Designed for Kali Linux environment with enhanced features for security professionals.

Requirements: 
- Kali Linux (scapy is pre-installed)
- Run with sudo privileges
- Network interface in monitor mode (for wireless analysis)

Usage:
    sudo python3 network_analyzer.py -i eth0
    sudo python3 network_analyzer.py -i wlan0 --wireless
    sudo python3 network_analyzer.py -i any -f "port 80 or port 443" --save traffic.json
"""

from scapy.all import *
import argparse
import sys
import json
import threading
import time
from datetime import datetime
from collections import defaultdict, Counter
import signal
import os

class KaliNetworkAnalyzer:
    def __init__(self, interface="eth0", bpf_filter=None, wireless=False, save_file=None):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.wireless = wireless
        self.save_file = save_file
        self.running = True
        self.packets = []
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'protocols': Counter(),
            'src_ips': Counter(),
            'dst_ips': Counter(),
            'ports': Counter(),
            'packet_sizes': [],
            'suspicious_activity': []
        }
        
        # Suspicious patterns
        self.port_scan_threshold = 10
        self.connection_attempts = defaultdict(set)
        
        print(f"[+] Kali Linux Network Analyzer Starting...")
        print(f"[+] Interface: {interface}")
        print(f"[+] Filter: {bpf_filter if bpf_filter else 'None'}")
        print(f"[+] Wireless Mode: {'Enabled' if wireless else 'Disabled'}")
        print("-" * 80)

    def check_permissions(self):
        """Check if running with proper privileges"""
        if os.geteuid() != 0:
            print("[-] Error: This tool requires root privileges")
            print("[!] Run with: sudo python3 network_analyzer.py")
            sys.exit(1)

    def setup_interface(self):
        """Setup network interface for packet capture"""
        try:
            if self.wireless:
                print(f"[+] Setting up wireless interface {self.interface} for monitoring...")
                # Note: In practice, you'd use airmon-ng or similar tools
                print("[!] Ensure interface is in monitor mode using: airmon-ng start wlan0")
            
            # Get available interfaces
            interfaces = get_if_list()
            if self.interface not in interfaces and self.interface != "any":
                print(f"[-] Interface {self.interface} not found")
                print(f"[+] Available interfaces: {', '.join(interfaces)}")
                return False
            return True
        except Exception as e:
            print(f"[-] Interface setup error: {e}")
            return False

    def analyze_packet(self, packet):
        """Detailed packet analysis"""
        try:
            self.stats['total_packets'] += 1
            timestamp = datetime.now()
            
            # Store packet for potential saving
            if self.save_file:
                self.packets.append({
                    'timestamp': timestamp.isoformat(),
                    'summary': packet.summary(),
                    'size': len(packet)
                })

            # Basic packet info
            packet_info = {
                'timestamp': timestamp.strftime("%H:%M:%S.%f")[:-3],
                'size': len(packet),
                'src': None,
                'dst': None,
                'protocol': 'Unknown',
                'details': ''
            }

            self.stats['packet_sizes'].append(len(packet))

            # Layer 2 Analysis (Ethernet/WiFi)
            if Ether in packet:
                packet_info['src_mac'] = packet[Ether].src
                packet_info['dst_mac'] = packet[Ether].dst

            # Layer 3 Analysis (IP)
            if IP in packet:
                packet_info['src'] = packet[IP].src
                packet_info['dst'] = packet[IP].dst
                packet_info['ttl'] = packet[IP].ttl
                
                self.stats['src_ips'][packet[IP].src] += 1
                self.stats['dst_ips'][packet[IP].dst] += 1

                # Layer 4 Analysis (TCP/UDP)
                if TCP in packet:
                    packet_info['protocol'] = 'TCP'
                    packet_info['sport'] = packet[TCP].sport
                    packet_info['dport'] = packet[TCP].dport
                    packet_info['flags'] = str(packet[TCP].flags)
                    packet_info['details'] = f"Flags: {packet[TCP].flags}"
                    
                    self.stats['protocols']['TCP'] += 1
                    self.stats['ports'][packet[TCP].dport] += 1
                    
                    # Check for port scanning
                    self.check_port_scan(packet[IP].src, packet[TCP].dport)
                    
                    # Check for common services
                    service = self.identify_service(packet[TCP].dport)
                    if service:
                        packet_info['service'] = service

                elif UDP in packet:
                    packet_info['protocol'] = 'UDP'
                    packet_info['sport'] = packet[UDP].sport
                    packet_info['dport'] = packet[UDP].dport
                    
                    self.stats['protocols']['UDP'] += 1
                    self.stats['ports'][packet[UDP].dport] += 1
                    
                    service = self.identify_service(packet[UDP].dport)
                    if service:
                        packet_info['service'] = service

                elif ICMP in packet:
                    packet_info['protocol'] = 'ICMP'
                    packet_info['type'] = packet[ICMP].type
                    packet_info['code'] = packet[ICMP].code
                    packet_info['details'] = f"Type: {packet[ICMP].type} Code: {packet[ICMP].code}"
                    
                    self.stats['protocols']['ICMP'] += 1

            # ARP Analysis
            elif ARP in packet:
                packet_info['protocol'] = 'ARP'
                packet_info['src'] = packet[ARP].psrc
                packet_info['dst'] = packet[ARP].pdst
                packet_info['operation'] = 'Request' if packet[ARP].op == 1 else 'Reply'
                packet_info['details'] = f"Operation: {packet_info['operation']}"
                
                self.stats['protocols']['ARP'] += 1

            # WiFi Analysis (if wireless mode)
            if self.wireless and Dot11 in packet:
                self.analyze_wifi_packet(packet, packet_info)

            # Display packet info
            self.display_packet(packet_info)

        except Exception as e:
            print(f"[-] Packet analysis error: {e}")

    def analyze_wifi_packet(self, packet, packet_info):
        """Analyze WiFi-specific packet details"""
        if Dot11 in packet:
            packet_info['wifi_type'] = packet[Dot11].type
            packet_info['wifi_subtype'] = packet[Dot11].subtype
            
            if packet[Dot11].addr1:
                packet_info['addr1'] = packet[Dot11].addr1
            if packet[Dot11].addr2:
                packet_info['addr2'] = packet[Dot11].addr2
            if packet[Dot11].addr3:
                packet_info['addr3'] = packet[Dot11].addr3

            # Check for deauth attacks
            if packet[Dot11].type == 0 and packet[Dot11].subtype == 12:
                self.stats['suspicious_activity'].append({
                    'type': 'Deauth Attack',
                    'timestamp': packet_info['timestamp'],
                    'target': packet_info.get('addr1', 'Unknown')
                })

    def check_port_scan(self, src_ip, dst_port):
        """Detect potential port scanning activity"""
        self.connection_attempts[src_ip].add(dst_port)
        
        if len(self.connection_attempts[src_ip]) > self.port_scan_threshold:
            self.stats['suspicious_activity'].append({
                'type': 'Port Scan',
                'timestamp': datetime.now().strftime("%H:%M:%S"),
                'source': src_ip,
                'ports_scanned': len(self.connection_attempts[src_ip])
            })
            print(f"[!] ALERT: Possible port scan from {src_ip} ({len(self.connection_attempts[src_ip])} ports)")

    def identify_service(self, port):
        """Identify common services by port number"""
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            3389: 'RDP', 5432: 'PostgreSQL', 3306: 'MySQL',
            1433: 'MSSQL', 27017: 'MongoDB', 6379: 'Redis'
        }
        return common_ports.get(port)

    def display_packet(self, info):
        """Display formatted packet information"""
        protocol_color = {
            'TCP': '\033[92m',    # Green
            'UDP': '\033[94m',    # Blue  
            'ICMP': '\033[93m',   # Yellow
            'ARP': '\033[95m',    # Magenta
            'Unknown': '\033[91m' # Red
        }
        
        color = protocol_color.get(info['protocol'], '\033[0m')
        reset = '\033[0m'
        
        output = f"[{info['timestamp']}] {color}{info['protocol']}{reset}"
        
        if info['src'] and info['dst']:
            output += f": {info['src']}"
            if 'sport' in info:
                output += f":{info['sport']}"
            output += f" -> {info['dst']}"
            if 'dport' in info:
                output += f":{info['dport']}"
        
        if 'service' in info:
            output += f" ({info['service']})"
        
        output += f" | Size: {info['size']}"
        
        if info['details']:
            output += f" | {info['details']}"
        
        print(output)

    def display_statistics(self):
        """Display capture statistics"""
        print("\n" + "="*80)
        print(" CAPTURE STATISTICS")
        print("="*80)
        print(f"Total Packets: {self.stats['total_packets']}")
        
        if self.stats['protocols']:
            print("\nProtocol Distribution:")
            for protocol, count in self.stats['protocols'].most_common():
                percentage = (count / self.stats['total_packets']) * 100
                print(f"  {protocol}: {count} ({percentage:.1f}%)")
        
        if self.stats['src_ips']:
            print("\nTop Source IPs:")
            for ip, count in self.stats['src_ips'].most_common(5):
                print(f"  {ip}: {count} packets")
        
        if self.stats['ports']:
            print("\nTop Destination Ports:")
            for port, count in self.stats['ports'].most_common(5):
                service = self.identify_service(port)
                service_str = f" ({service})" if service else ""
                print(f"  {port}{service_str}: {count} packets")
        
        if self.stats['packet_sizes']:
            avg_size = sum(self.stats['packet_sizes']) / len(self.stats['packet_sizes'])
            print(f"\nAverage Packet Size: {avg_size:.1f} bytes")
        
        if self.stats['suspicious_activity']:
            print(f"\n⚠️  SECURITY ALERTS: {len(self.stats['suspicious_activity'])}")
            for alert in self.stats['suspicious_activity'][-5:]:  # Show last 5
                print(f"  [{alert['timestamp']}] {alert['type']}")

    def save_data(self):
        """Save captured data to file"""
        if self.save_file and self.packets:
            try:
                data = {
                    'capture_info': {
                        'interface': self.interface,
                        'filter': self.bpf_filter,
                        'total_packets': len(self.packets)
                    },
                    'statistics': dict(self.stats),
                    'packets': self.packets[-1000:]  # Save last 1000 packets
                }
                
                with open(self.save_file, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
                print(f"\n[+] Data saved to {self.save_file}")
            except Exception as e:
                print(f"[-] Save error: {e}")

    def signal_handler(self, signum, frame):
        """Handle interrupt signal"""
        print(f"\n[+] Stopping capture...")
        self.running = False

    def start_capture(self):
        """Start packet capture"""
        self.check_permissions()
        
        if not self.setup_interface():
            return
        
        # Set up signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        
        try:
            print(f"[+] Starting packet capture on {self.interface}...")
            print("[+] Press Ctrl+C to stop\n")
            
            # Start statistics display thread
            stats_thread = threading.Thread(target=self.periodic_stats)
            stats_thread.daemon = True
            stats_thread.start()
            
            # Start packet capture
            sniff(
                iface=self.interface if self.interface != "any" else None,
                filter=self.bpf_filter,
                prn=self.analyze_packet,
                stop_filter=lambda x: not self.running
            )
            
        except Exception as e:
            print(f"[-] Capture error: {e}")
        finally:
            self.display_statistics()
            self.save_data()

    def periodic_stats(self):
        """Display periodic statistics"""
        while self.running:
            time.sleep(30)  # Update every 30 seconds
            if self.stats['total_packets'] > 0:
                print(f"\n[Stats] Packets: {self.stats['total_packets']} | "
                      f"Protocols: {len(self.stats['protocols'])} | "
                      f"Unique IPs: {len(self.stats['src_ips'])}")

def main():
    parser = argparse.ArgumentParser(description='Kali Linux Network Traffic Analyzer')
    parser.add_argument('-i', '--interface', default='eth0', 
                       help='Network interface to monitor (default: eth0)')
    parser.add_argument('-f', '--filter', 
                       help='BPF filter expression (e.g., "tcp port 80")')
    parser.add_argument('--wireless', action='store_true',
                       help='Enable wireless monitoring features')
    parser.add_argument('--save', metavar='FILE',
                       help='Save capture data to JSON file')
    parser.add_argument('--list-interfaces', action='store_true',
                       help='List available network interfaces')
    
    args = parser.parse_args()
    
    if args.list_interfaces:
        print("Available network interfaces:")
        for iface in get_if_list():
            print(f"  {iface}")
        return
    
    analyzer = KaliNetworkAnalyzer(
        interface=args.interface,
        bpf_filter=args.filter,
        wireless=args.wireless,
        save_file=args.save
    )
    
    analyzer.start_capture()

if __name__ == "__main__":
    main()