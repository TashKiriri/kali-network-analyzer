# Kali Linux Network Traffic Analyzer

A comprehensive network packet capture and analysis tool designed specifically for Kali Linux environments. Perfect for penetration testing, network security analysis, and educational purposes.

## 🚀 Features

### Core Functionality
- **Real-time packet capture** and analysis using Scapy
- **Multi-protocol support**: TCP, UDP, ICMP, ARP
- **Service identification** by port numbers
- **Traffic statistics** and comprehensive reporting
- **BPF filtering** for targeted packet capture

### Security-Focused Features
- **Port scan detection** with configurable thresholds
- **Suspicious activity monitoring** and alerting
- **WiFi packet analysis** with monitor mode support
- **Deauthentication attack detection**
- **Color-coded output** for different protocols

### Advanced Capabilities
- **JSON data export** for further analysis
- **Real-time statistics display**
- **Interface discovery** and selection
- **Wireless monitoring mode**
- **Periodic statistics updates**

## 📋 Requirements

- **Kali Linux** (recommended) or any Linux distribution
- **Python 3.6+**
- **Scapy library** (pre-installed on Kali Linux)
- **Root privileges** for packet capture
- **Network interface** in monitor mode (for wireless analysis)

## 🛠️ Installation

### Quick Install
```bash
# Clone the repository
git clone https://github.com/yourusername/kali-network-analyzer.git
cd kali-network-analyzer

# Make the script executable
chmod +x network_analyzer.py

# Test the installation
python3 network_analyzer.py --list-interfaces
```

### Manual Installation
If Scapy is not installed:
```bash
pip3 install scapy
```

## 🚦 Usage

### Basic Commands

```bash
# List available network interfaces
python3 network_analyzer.py --list-interfaces

# Basic packet capture on ethernet interface
sudo python3 network_analyzer.py -i eth0

# Monitor wireless traffic (requires monitor mode)
sudo python3 network_analyzer.py -i wlan0 --wireless

# Filter specific traffic (HTTP/HTTPS only)
sudo python3 network_analyzer.py -i eth0 -f "port 80 or port 443"

# Save captured data to JSON file
sudo python3 network_analyzer.py -i eth0 --save traffic_capture.json

# Monitor all interfaces
sudo python3 network_analyzer.py -i any
```

### Advanced Filtering Examples

```bash
# Monitor DNS traffic only
sudo python3 network_analyzer.py -i eth0 -f "port 53"

# Monitor traffic to/from specific IP
sudo python3 network_analyzer.py -i eth0 -f "host 192.168.1.1"

# Monitor SSH connections
sudo python3 network_analyzer.py -i eth0 -f "port 22"

# Monitor ICMP traffic (ping, etc.)
sudo python3 network_analyzer.py -i eth0 -f "icmp"
```

## 📊 Output Examples

### Real-time Packet Display
```
[15:30:45.123] TCP: 192.168.1.100:54321 -> 142.250.191.14:443 (HTTPS) | Flags: PA | Size: 1234
[15:30:45.157] UDP: 192.168.1.100:53281 -> 8.8.8.8:53 (DNS) | Size: 74
[15:30:45.189] ICMP: 192.168.1.100 -> 8.8.8.8 | Type: 8 Code: 0 | Size: 84
```

### Statistics Summary
```
================================================================================
 CAPTURE STATISTICS
================================================================================
Total Packets: 1,247

Protocol Distribution:
  TCP: 856 (68.6%)
  UDP: 312 (25.0%)
  ICMP: 79 (6.3%)

Top Source IPs:
  192.168.1.100: 1,089 packets
  8.8.8.8: 98 packets
  142.250.191.14: 60 packets

Top Destination Ports:
  443 (HTTPS): 445 packets
  53 (DNS): 234 packets
  80 (HTTP): 178 packets

Average Packet Size: 387.3 bytes

⚠️  SECURITY ALERTS: 2
  [15:32:15] Port Scan
  [15:33:42] Port Scan
```

## 🔧 Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-i, --interface` | Network interface to monitor | `-i eth0` |
| `-f, --filter` | BPF filter expression | `-f "tcp port 80"` |
| `--wireless` | Enable wireless monitoring features | `--wireless` |
| `--save` | Save capture data to JSON file | `--save capture.json` |
| `--list-interfaces` | List available network interfaces | `--list-interfaces` |

## 🛡️ Security Features

### Port Scan Detection
The tool automatically detects potential port scanning activities:
- Monitors connection attempts from each source IP
- Triggers alerts when threshold exceeded (default: 10 ports)
- Logs suspicious activity with timestamps

### WiFi Security Analysis
When used with wireless interfaces in monitor mode:
- Detects deauthentication attacks
- Monitors beacon frames and probe requests
- Analyzes WiFi management frames

## 📁 File Structure

```
kali-network-analyzer/
├── network_analyzer.py    # Main script
├── README.md             # This file
├── LICENSE              # MIT License
├── requirements.txt     # Python dependencies
├── examples/           # Usage examples
│   ├── basic_usage.md
│   └── advanced_filtering.md
└── docs/              # Additional documentation
    ├── installation.md
    └── troubleshooting.md
```

## 🔍 Troubleshooting

### Permission Issues
```bash
# Error: This tool requires root privileges
sudo python3 network_analyzer.py -i eth0
```

### Interface Not Found
```bash
# List available interfaces first
python3 network_analyzer.py --list-interfaces

# Use the correct interface name
sudo python3 network_analyzer.py -i wlan0
```

### Wireless Monitor Mode
```bash
# Enable monitor mode for wireless interface
sudo airmon-ng start wlan0

# Then use the monitor interface (usually wlan0mon)
sudo python3 network_analyzer.py -i wlan0mon --wireless
```

## ⚖️ Legal and Ethical Use

**IMPORTANT**: This tool is designed for legitimate security testing and network analysis purposes only.

### ✅ Authorized Use Cases:
- Network troubleshooting on your own networks
- Security assessment of systems you own
- Educational purposes in controlled environments
- Penetration testing with proper authorization

### ❌ Prohibited Activities:
- Monitoring networks without explicit permission
- Intercepting private communications
- Any form of unauthorized network access
- Violating privacy laws or regulations

### Legal Disclaimer
Users are solely responsible for ensuring their use of this tool complies with all applicable laws and regulations. The authors assume no liability for misuse of this software.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup
```bash
# Fork the repository
git clone https://github.com/yourusername/kali-network-analyzer.git
cd kali-network-analyzer

# Create a new branch for your feature
git checkout -b feature/your-feature-name

# Make your changes and commit
git commit -am 'Add some feature'

# Push to the branch
git push origin feature/your-feature-name

# Create a Pull Request
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Tasha** - *Initial work* - [YourGitHubUsername](https://github.com/yourusername)

## 🙏 Acknowledgments

- Built with [Scapy](https://scapy.net/) - the powerful Python packet manipulation library
- Inspired by classic network analysis tools like tcpdump and Wireshark
- Thanks to the Kali Linux community for feedback and testing

## 📚 Additional Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [BPF Filter Syntax](https://www.tcpdump.org/manpages/pcap-filter.7.html)
- [Kali Linux Network Tools](https://www.kali.org/tools/)

---

**⭐ If you find this tool useful, please give it a star!**
