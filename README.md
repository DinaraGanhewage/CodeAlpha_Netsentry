<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Flask-3.1-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/Scapy-2.6-2496ED?style=for-the-badge&logo=wireshark&logoColor=white" alt="Scapy">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Status-In%20Development-yellow?style=for-the-badge" alt="Status">
</p>

<h1 align="center">🛡️ NetSentry</h1>
<h3 align="center">Smart Network Packet Analyzer & Security Monitor</h3>

<p align="center">
  A Python-based network monitoring application that captures, analyzes, and visualizes live network traffic through both CLI and a professional web dashboard.
  <br>
  <strong>CodeAlpha Cyber Security Internship — Task 01</strong>
</p>

---

## 📋 Overview

**NetSentry** is a defensive network monitoring and educational tool developed as part of the CodeAlpha Cyber Security Internship. It captures live network traffic using Scapy, analyzes packet metadata, identifies communication protocols, monitors DNS activity, and detects potentially suspicious traffic patterns.

> ⚠️ **Disclaimer:** This tool is for authorized network monitoring and educational purposes only. All detections are labeled as *potential* suspicious activity — not confirmed attacks. Only use on networks you own or have explicit authorization to monitor.

## ✨ Features

### Core Capabilities
- **Real-Time Packet Capture** — Live packet sniffing using Scapy with Npcap on Windows
- **Packet Metadata Analysis** — Extract IPs, MACs, ports, protocols, TTL, TCP flags, and packet direction
- **Protocol Detection** — Identify TCP, UDP, ICMP, ARP with separate transport/application layer tracking
- **DNS Monitoring** — Track DNS queries, query types, and response records with DoH/DoT limitation documentation
- **Threat Detection** — Detect possible port scans, DNS query spikes, and repeated connection attempts
- **Alert Management** — Severity-based alerts (Low/Medium/High) with deduplication to prevent flooding
- **Traffic Statistics** — Protocol distribution, top talkers, top destinations, traffic timeline
- **SQLite Storage** — Efficient batch writes for persistent packet metadata and alert storage
- **CSV & JSON Export** — Export packet data and security alerts for further analysis

### Interfaces
- **CLI Interface** — Live terminal display with colored output for packet monitoring
- **Web Dashboard** — Professional dark-themed dashboard with Chart.js visualizations

## 🏗️ Architecture

```
NetSentry/
│
├── src/                              # Application source code
│   ├── main.py                       # Entry point (CLI + dashboard launcher)
│   ├── capture/                      # Packet capture subsystem
│   │   ├── capture_manager.py        # Capture orchestration & status
│   │   ├── packet_capture.py         # Scapy sniffing in background thread
│   │   └── interface_manager.py      # Network interface discovery
│   ├── analysis/                     # Packet dissection
│   │   ├── packet_analyzer.py        # Header parsing → standardized dict
│   │   ├── protocol_detector.py      # Protocol identification
│   │   └── dns_analyzer.py           # DNS query/response extraction
│   ├── detection/                    # Threat detection
│   │   ├── threat_detector.py        # Detection rules
│   │   └── alert_manager.py          # Alert storage & deduplication
│   ├── monitoring/                   # Traffic statistics
│   │   ├── statistics.py             # Protocol counters, top talkers
│   │   └── traffic_monitor.py        # Time-series data
│   ├── storage/                      # Database layer
│   │   └── database.py              # SQLite batch operations
│   ├── reporting/                    # Export functionality
│   │   └── report_generator.py      # CSV/JSON generation
│   ├── dashboard/                    # Flask web dashboard
│   │   ├── app.py                    # Flask application factory
│   │   ├── api.py                    # REST API endpoints
│   │   ├── templates/                # HTML templates
│   │   └── static/                   # CSS, JavaScript, assets
│   └── utils/                        # Shared utilities
│       ├── config.py                 # Configuration management
│       └── logger.py                 # Centralized logging
│
├── tests/                            # Test suite
├── output/                           # Generated files (DB, exports, logs)
├── screenshots/                      # Dashboard & CLI screenshots
├── config.json                       # User-configurable settings
├── requirements.txt                  # Python dependencies
└── .env.example                      # Environment variable template
```

## 🔧 Prerequisites

- **Python 3.10+**
- **Npcap** — [Download from npcap.com](https://npcap.com/#download) (required for packet capture on Windows)
- **Windows 11** (primary target platform)
- **Administrator privileges** (required for packet capture)

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/Dinara-Gamhewage/NetSentry.git
cd NetSentry

# 2. Create a virtual environment
python -m venv venv
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install Npcap (if not already installed)
# Download from: https://npcap.com/#download
# Run the installer with default settings
```

## 📖 Usage

```bash
# List available network interfaces
python -m src.main --list-interfaces

# Start CLI packet monitor
python -m src.main --interface "Ethernet" --mode cli

# Start web dashboard
python -m src.main --interface "Ethernet" --mode dashboard
# Then open http://127.0.0.1:5000 in your browser

# Capture specific number of packets
python -m src.main --interface "Ethernet" --count 500
```

## 🖥️ Dashboard

The web dashboard provides real-time visualization of network traffic with a professional dark cybersecurity theme.

**Dashboard sections:**
- **Overview** — Total packets, traffic volume, capture status, alert count
- **Live Packet Table** — Real-time packet metadata display
- **Traffic Analytics** — Protocol distribution charts, traffic timeline
- **DNS Monitor** — DNS queries, query types, activity statistics
- **Security Alerts** — Severity-based alert panel
- **Reports** — CSV and JSON export options

> *Screenshots will be added after dashboard implementation.*

## 🔍 Threat Detection Rules

| Rule | Description | Severity |
|------|-------------|----------|
| **Possible Port Scan** | Same source → ≥15 unique ports on target within 60s | HIGH |
| **DNS Query Spike** | Same source sends ≥50 DNS queries within 30s | MEDIUM |
| **Repeated Connections** | Same source → same destination ≥20 times within 30s | MEDIUM |

All thresholds are configurable in `config.json`. Detections are labeled as *potential* indicators for investigation.

## ⚙️ Configuration

Edit `config.json` to customize:
- Capture settings (buffer size, batch size)
- Dashboard settings (host, port, polling interval)
- Detection thresholds (port scan, DNS spike, repeated connections)
- Database and logging paths

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test module
pytest tests/test_packet_analyzer.py -v
```

## 📝 DNS Monitoring Limitations

NetSentry performs passive DNS monitoring by inspecting standard DNS traffic on port 53. The following types of DNS traffic **cannot** be inspected:
- **DNS over HTTPS (DoH)** — DNS queries encrypted within HTTPS connections
- **DNS over TLS (DoT)** — DNS queries encrypted via TLS on port 853

This is a fundamental limitation of passive packet inspection, not a bug.

## 🔒 Security & Ethics

- Only capture traffic on **authorized networks and interfaces**
- **No sensitive payloads** are captured or stored (passwords, credentials, application data)
- Focus is exclusively on **packet metadata** and protocol analysis
- Dashboard is accessible only via **localhost** by default
- All detections are **potential indicators** — not confirmed attacks
- This is a **defensive monitoring and educational tool**

## 🛠️ Technology Stack

| Component | Technology |
|-----------|-----------|
| Packet Capture | Scapy 2.6 + Npcap |
| Backend | Flask 3.1 |
| Database | SQLite (Python built-in) |
| Frontend | HTML5, CSS3, JavaScript, Chart.js |
| CLI | colorama |
| Testing | pytest |
| Language | Python 3.10+ |

## 📅 Development Roadmap

- [x] Project planning and architecture
- [x] Week 1: Packet capture and analysis
- [x] Week 2: Security analysis and storage
- [x] Week 3: Web dashboard
- [x] Week 4: Testing and finalization

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **CodeAlpha** — Cyber Security Internship Program
- **Scapy** — Interactive packet manipulation library
- **Flask** — Lightweight Python web framework
- **Chart.js** — JavaScript charting library

---

<p align="center">
  <strong>Developed by Dinara Gamhewage</strong>
  <br>
  CodeAlpha Cyber Security Internship — Task 01
</p>
