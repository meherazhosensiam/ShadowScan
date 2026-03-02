<p align="center">
  <img src="https://img.shields.io/badge/ShadowScan-v2.0.0-blue?style=for-the-badge&logo=python" alt="ShadowScan Version">
  <img src="https://img.shields.io/badge/Python-3.8%2B-green?style=for-the-badge&logo=python" alt="Python Version">
  <img src="https://img.shields.io/badge/License-Shadow%20Public%20License%20v1.0-purple?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Author-Mahara%20HOSEN%20SIAM-orange?style=for-the-badge" alt="Author">
</p>

<h1 align="center">
  <img src="https://raw.githubusercontent.com/mherasmeherazhosensiamiam/ShadowScan/main/shadowscan-logo.png" alt="ShadowScan Logo" width="600">
  <br>
  🔍 ShadowScan - Advanced Network Port Scanner
</h1>

<p align="center">
  <i>A professional penetration testing tool for network reconnaissance and port scanning</i>
  <br>
  <b>🇫🇷 Navigation France | Multilingual Support</b>
</p>

---

## 📋 Table of Contents

- [📖 About ShadowScan](#-about-shadowscan)
- [✨ Features](#-features)
- [🚀 Installation](#-installation)
- [💻 Usage](#-usage)
- [🔧 Command Line Options](#-command-line-options)
- [📊 Scan Types](#-scan-types)
- [🎨 Output Examples](#-output-examples)
- [📁 Project Structure](#-project-structure)
- [🛡️ Security Considerations](#️-security-considerations)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)
- [👤 Author](#-author)
- [⭐ Star History](#-star-history)

---

## 📖 About ShadowScan

**ShadowScan** is an advanced, feature-rich network port scanner designed for penetration testers, cybersecurity professionals, and network administrators. Built with Python, it provides comprehensive network reconnaissance capabilities with an intuitive interface featuring **French navigation support** (Navigation France).

ShadowScan enables security professionals to discover open ports, identify running services, grab banners, and assess network exposure efficiently. The tool employs multi-threading for high-performance scanning and provides detailed, color-coded output for easy interpretation of results.

### 🎯 Key Highlights

| Feature | Description |
|---------|-------------|
| **Multi-threaded Scanning** | Utilize multiple threads for lightning-fast port scanning |
| **Service Detection** | Automatically identify services running on open ports |
| **Banner Grabbing** | Capture service banners for fingerprinting |
| **French Navigation** | Intuitive menu system with French language support |
| **Export Options** | Save results in JSON or plain text formats |
| **Color-coded Output** | Easy-to-read terminal output with semantic colors |

---

## ✨ Features

### 🔍 Core Scanning Capabilities

- **Quick Scan**: Rapidly scan the most common 24 ports used in enterprise environments
- **Full Scan**: Comprehensive scan of all 65,535 TCP ports
- **Custom Scan**: Define specific port ranges or individual ports to scan
- **Service Detection**: Identify services and applications running on discovered ports
- **Banner Grabbing**: Extract service banners for detailed fingerprinting and version detection

### 🎨 User Interface

- **Interactive Mode**: User-friendly menu-driven interface with French navigation
- **Command Line Mode**: Full-featured CLI for automation and scripting
- **Color-coded Results**: Visual distinction between secure, common, and potentially vulnerable ports
- **Progress Indicators**: Real-time feedback during scanning operations

### 📊 Output & Reporting

- **JSON Export**: Structured output for integration with other tools
- **Text Export**: Human-readable reports for documentation
- **Verbose Mode**: Detailed output including banner information
- **Summary Reports**: Consolidated view of all discovered services

### ⚡ Performance Features

- **Configurable Threading**: Adjust thread count based on system resources
- **Timeout Control**: Fine-tune connection timeouts for different network conditions
- **Efficient Port Handling**: Optimized algorithms for rapid port enumeration

---

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/meherazhosensiam/ShadowScan.git

# Navigate to the directory
cd ShadowScan

# Install dependencies
pip install -r requirements.txt

# Make the script executable (Linux/macOS)
chmod +x shadowscan.py
```

### Manual Installation

```bash
# Install colorama for colored output (optional but recommended)
pip install colorama
```

### Verify Installation

```bash
# Run ShadowScan with version flag
python shadowscan.py --version

# Or run interactive mode
python shadowscan.py -i
```

---

## 💻 Usage

### Interactive Mode (Recommended for Beginners)

```bash
python shadowscan.py -i
```

This launches the interactive menu with French navigation:

```
╔═══════════════════════════════════════════════════════════════════╗
║  🇫🇷 Bienvenue dans ShadowScan - Navigation France              ║
╠═══════════════════════════════════════════════════════════════════╣
║  [1] Analyse rapide (Quick Scan)     [2] Analyse complète      ║
║  [3] Capture de bannière           [4] Ports personnalisés   ║
║  [5] Détection de services         [6] Analyse UDP           ║
║  [7] Exporter les résultats        [8] Paramètres            ║
║  [9] À propos                     [0] Quitter               ║
╚═══════════════════════════════════════════════════════════════════╝
```

### Command Line Examples

#### Quick Scan (Common Ports)
```bash
python shadowscan.py -t 192.168.1.1
```

#### Full Port Scan
```bash
python shadowscan.py -t example.com --full
```

#### Custom Port Range
```bash
python shadowscan.py -t 10.0.0.1 -p 1-1000
```

#### Specific Ports
```bash
python shadowscan.py -t 192.168.1.1 -p 22,80,443,8080
```

#### Banner Grabbing Enabled
```bash
python shadowscan.py -t 192.168.1.1 -b -v
```

#### Export Results
```bash
python shadowscan.py -t 192.168.1.1 -e results.json
```

---

## 🔧 Command Line Options

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-t` | `--target` | Target IP address or hostname |
| `-p` | `--ports` | Port range (e.g., 1-1000) or comma-separated list |
| `--full` | | Perform full port scan (1-65535) |
| `--quick` | | Quick scan on common ports (default) |
| `-b` | `--banner` | Enable banner grabbing |
| `-th` | `--threads` | Number of threads (default: 100) |
| `-to` | `--timeout` | Connection timeout in seconds (default: 1.0) |
| `-v` | `--verbose` | Enable verbose output |
| `-e` | `--export` | Export results to file |
| `-i` | `--interactive` | Run in interactive mode |
| | `--version` | Show version information |

---

## 📊 Scan Types

### 1. Quick Scan
Scans the 24 most common ports used in enterprise environments:
- FTP (21), SSH (22), Telnet (23), SMTP (25)
- DNS (53), HTTP (80), POP3 (110), RPC (135)
- NetBIOS (139), IMAP (143), HTTPS (443), SMB (445)
- And more...

### 2. Full Scan
Comprehensive scan of all 65,535 TCP ports. Recommended for thorough security assessments.

### 3. Custom Scan
Scan specific ports or ranges based on your requirements.

### 4. Service Detection
Identify services running on open ports with banner grabbing for detailed fingerprinting.

---

## 🎨 Output Examples

### Standard Output

```
════════════════════════════════════════════════════════════════════
   ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗ ██████╗ ███████╗
   ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝ ██╔════╝
   ███████╗██║   ██║██║  ██║█████╗  ██╔██╗ ██║██║  ███╗█████╗  
   ╚════██║██║   ██║██║  ██║██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  
   ███████║╚██████╔╝██████╔╝███████╗██║ ╚████║╚██████╔╝███████╗
   ╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
════════════════════════════════════════════════════════════════════

[*] Starting ShadowScan against: 192.168.1.1 (192.168.1.1)
[*] Scan started at: 2024-01-15 14:30:00
[*] Scanning 24 ports with 100 threads
────────────────────────────────────────────────────────────────────

[+] Port    22/tcp  OPEN    SSH (Secure Shell)
[+] Port    80/tcp  OPEN    HTTP (HyperText Transfer Protocol)
[+] Port   443/tcp  OPEN    HTTPS (HTTP Secure)
[+] Port  3306/tcp  OPEN    MySQL

────────────────────────────────────────────────────────────────────
[✓] Scan Complete!
[*] Target: 192.168.1.1
[*] Open Ports: 4
[*] Scan Duration: 0.52 seconds
[*] Finished: 2024-01-15 14:30:01
════════════════════════════════════════════════════════════════════
```

### JSON Export Format

```json
{
    "tool": "ShadowScan",
    "version": "2.0.0",
    "author": "Maheraz HOSEN SIAM",
    "target": "192.168.1.1",
    "scan_date": "2024-01-15 14:30:00",
    "duration": "0:00:00.520000",
    "total_open_ports": 4,
    "open_ports": [
        {
            "port": 22,
            "state": "open",
            "service": "SSH (Secure Shelzl)",
            "banner": "SSH-2.0-OpenSSH_8.9"
        },
        {
            "port": 80,
            "state": "open",
            "service": "HTTP (HyperText Transfer Protocol)",
            "banner": null
        }
    ]
}
```

---

## 📁 Project Structure

```
ShadowScan/
├── shadowscan.py          # Main scanner script
├── README.md              # Documentation (this file)
├── requirements.txt       # Python dependencies
├── LICENSE                # Shadow Public License v1.0
├── CONTRIBUTING.md        # Contribution guidelines
├── .gitignore            # Git ignore patterns
└── assets/
    └── shadowscan-logo.png
```

---

## 🛡️ Security Considerations

### ⚠️ Important Notice

**ShadowScan is designed for authorized security testing only.** Before using this tool, ensure you have:

1. **Explicit Permission**: Written authorization from the system owner
2. **Legal Compliance**: Understanding of local and international laws
3. **Professional Responsibility**: Use for defensive security purposes only

### Legal Disclaimer

The author, **Mahara HOSEN SIAM**, is not responsible for any misuse or damage caused by this tool. This software is provided for educational and authorized penetration testing purposes only. Users are solely responsible for ensuring they have proper authorization before scanning any networks or systems.

### Best Practices

- Always obtain written permission before scanning
- Use the `--timeout` option to avoid network congestion
- Start with quick scans before attempting full port scans
- Document all scanning activities for compliance

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help improve the project for everyone

---

## 📜 License

This project is licensed under the **Shadow Public License v1.0** - see the [LICENSE](LICENSE) file for details.

### License Summary

- ✅ Free for personal and educational use
- ✅ Free for authorized penetration testing
- ✅ Modifications allowed with attribution
- ❌ Commercial use requires written permission
- ❌ Malicious use strictly prohibited

---

## 👤 Author

<div align="center">

### **Mahara HOSEN SIAM**

*Cybersecurity Learner & Future Penetration Tester*

[![GitHub](https://img.shields.io/badge/GitHub-mharasiam-181717?style=for-the-badge&logo=github)](https://github.com/mharasiam)
[![Twitter](https://img.shields.io/badge/Twitter-@mharasiam-1DA1F2?style=for-the-badge&logo=twitter)](https://twitter.com/mharasiam)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Mahara%20HOSEN%20SIAM-0A66C2?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/mharasiam)

</div>

---

## ⭐ Star History

If you find ShadowScan useful, please consider giving it a ⭐ star on GitHub!

[![Star History Chart](https://api.star-history.com/svg?repos=mharasiam/ShadowScan&type=Date)](https://star-history.com/#mharasiam/ShadowScan&Date)

---

<p align="center">
  <b>ShadowScan</b> - Illuminating Network Security, One Port at a Time
  <br>
  <i>Made with ❤️ by Mahara HOSEN SIAM</i>
</p>
