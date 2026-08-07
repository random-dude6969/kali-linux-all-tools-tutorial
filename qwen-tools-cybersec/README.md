# QwenSec Recon Suite

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Version](https://img.shields.io/badge/Version-1.0.0-orange.svg)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)

**Professional Cybersecurity Intelligence & Reconnaissance Tool**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Examples](#examples) • [API](#api) • [Contributing](#contributing)

</div>

---

## 📋 Overview

**QwenSec Recon Suite** is an advanced, multi-threaded reconnaissance and information gathering framework designed for professional penetration testers, security researchers, and cybersecurity professionals. It provides comprehensive target analysis with automated reporting capabilities.

### 🔥 Key Features

- **🌐 Multi-threaded Subdomain Enumeration** - Fast brute-force subdomain discovery
- **🔌 Port Scanning with Service Detection** - Identify open ports and running services
- **🛠️ Technology Stack Fingerprinting** - Detect web frameworks, servers, and technologies
- **🔒 SSL/TLS Certificate Analysis** - Extract and analyze certificate information
- **📋 DNS Record Enumeration** - Comprehensive DNS record discovery (A, AAAA, MX, NS, TXT, CNAME, SOA)
- **📊 Automated Report Generation** - Export results in JSON, HTML, or Markdown formats
- **⚡ High Performance** - Configurable threading for optimal speed
- **🎨 Colored Output** - Professional terminal output with color coding
- **🔄 Error Handling** - Robust retry logic and graceful degradation
- **📝 Verbose Logging** - Detailed logging for debugging and auditing

---

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Quick Install

```bash
# Clone the repository
git clone <repository-url>
cd qwen-tools-cybersec

# Install dependencies
pip install -r requirements.txt
```

### Manual Dependency Installation

```bash
pip install requests dnspython colorama tqdm
```

### Optional Dependencies

For enhanced functionality:

```bash
# For advanced port scanning
pip install python-nmap

# Note: Requires nmap installed on system
# Ubuntu/Debian: sudo apt-get install nmap
# macOS: brew install nmap
```

---

## 💻 Usage

### Basic Usage

```bash
# Simple scan
python src/qwen_recon.py -t example.com

# Scan with verbose output
python src/qwen_recon.py -t example.com --verbose

# Scan with custom thread count
python src/qwen_recon.py -t example.com --threads 50
```

### Advanced Usage

```bash
# Generate HTML report
python src/qwen_recon.py -t example.com -o report.html --format html

# Generate Markdown report
python src/qwen_recon.py -t example.com -o report.md --format markdown

# Generate JSON report
python src/qwen_recon.py -t example.com -o report.json --format json

# Skip specific scans
python src/qwen_recon.py -t example.com --no-subdomains --no-ports

# Custom timeout
python src/qwen_recon.py -t example.com --timeout 10 --verbose
```

### Command Line Options

```
usage: qwen_recon.py [-h] -t TARGET [--threads THREADS] [--timeout TIMEOUT] 
                     [-v] [-o OUTPUT] [-f {json,html,markdown}] 
                     [--no-subdomains] [--no-ports] [--no-web]

QwenSec Recon Suite - Professional Cybersecurity Intelligence Tool

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target domain or IP address
  --threads THREADS     Number of concurrent threads (default: 10)
  --timeout TIMEOUT     Timeout in seconds (default: 5)
  -v, --verbose         Enable verbose output
  -o OUTPUT, --output OUTPUT
                        Output file path
  -f {json,html,markdown}, --format {json,html,markdown}
                        Output format (default: json)
  --no-subdomains       Skip subdomain enumeration
  --no-ports            Skip port scanning
  --no-web              Skip web fingerprinting

Examples:
  qwen_recon.py -t example.com
  qwen_recon.py --target example.com --threads 50 --verbose
  qwen_recon.py -t example.com -o report.html --format html
  qwen_recon.py -t example.com --json > output.json
```

---

## 📸 Examples

### Example 1: Basic Reconnaissance

```bash
$ python src/qwen_recon.py -t google.com --verbose

    ╔═══════════════════════════════════════════════════════════╗
    ║           QwenSec Recon Suite v1.0.0                      ║
    ║     Professional Cybersecurity Intelligence Tool          ║
    ║                                                           ║
    ║  ⚠️  WARNING: Use only on systems you have permission    ║
    ║      to test. Unauthorized scanning is illegal.           ║
    ╚═══════════════════════════════════════════════════════════╝

[12:34:56] [INFO] 🚀 Starting QwenSec Recon Suite scan for google.com
[12:34:56] [INFO] Enumerating DNS records
[12:34:57] [SUCCESS] Found 4 A records
[12:34:57] [SUCCESS] DNS enumeration complete
[12:34:57] [INFO] Starting subdomain enumeration for google.com
[12:34:58] [SUCCESS] Found: www.google.com
[12:34:58] [SUCCESS] Found: mail.google.com
[12:34:59] [SUCCESS] Subdomain enumeration complete. Found 2 subdomains
...
[12:35:30] [SUCCESS] ✅ Scan completed in 34.52 seconds
```

### Example 2: Generate HTML Report

```bash
$ python src/qwen_recon.py -t example.com -o scan_report.html --format html --verbose

[12:40:00] [SUCCESS] Report saved to: scan_report.html
```

The generated HTML report includes:
- Professional styling with responsive design
- Interactive tables for port information
- Color-coded sections for easy reading
- Complete scan metadata

### Example 3: Programmatic Usage

```python
from src.qwen_recon import QwenReconScanner

# Initialize scanner
scanner = QwenReconScanner(
    target='example.com',
    threads=20,
    timeout=5,
    verbose=True
)

# Run scan
results = scanner.run_full_scan()

# Generate report
report = scanner.generate_report(output_format='json')
print(report)

# Access specific results
print(f"Subdomains found: {results.subdomains}")
print(f"Open ports: {results.open_ports}")
print(f"Technologies: {results.technologies}")
```

---

## 🏗️ Architecture

### Project Structure

```
qwen-tools-cybersec/
├── src/
│   ├── qwen_recon.py          # Main reconnaissance tool
│   └── __init__.py
├── config/                     # Configuration files
├── logs/                       # Scan logs and output
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

### Core Components

1. **QwenReconScanner** - Main scanner class orchestrating all reconnaissance activities
2. **ColorLogger** - Professional colored logging utility
3. **ScanResult** - Data class for structured result storage
4. **Report Generators** - Multiple format exporters (JSON, HTML, Markdown)

### Scan Modules

- **DNS Enumerator** - Queries DNS records using dnspython or socket fallback
- **Subdomain Scanner** - Multi-threaded brute-force subdomain discovery
- **Port Scanner** - TCP connect scan with service detection
- **Web Fingerprinter** - HTTP header and content analysis
- **SSL Analyzer** - Certificate extraction and validation

---

## 📊 Output Formats

### JSON Format

Structured data ideal for programmatic processing:

```json
{
  "target": "example.com",
  "timestamp": "2024-01-15T12:34:56.789012",
  "subdomains": ["www.example.com", "mail.example.com"],
  "open_ports": [
    {"port": 80, "state": "open", "service": "HTTP"},
    {"port": 443, "state": "open", "service": "HTTPS"}
  ],
  "technologies": ["Nginx", "jQuery", "Bootstrap"],
  "ssl_info": {...},
  "dns_records": {...},
  "errors": []
}
```

### HTML Format

Professional, styled report suitable for presentations and client deliverables.

### Markdown Format

Clean, readable format perfect for documentation and GitHub integration.

---

## ⚙️ Configuration

### Threading

Adjust thread count based on your network and target:

- **Low (5-10 threads)**: Conservative, stealthy scanning
- **Medium (10-20 threads)**: Balanced speed and reliability (default)
- **High (50+ threads)**: Fast scanning for authorized engagements

### Timeout

Configure timeout values for slow networks:

- Default: 5 seconds
- Slow networks: 10-15 seconds
- Fast networks: 2-3 seconds

---

## 🔒 Legal Disclaimer

**IMPORTANT**: This tool is designed for legitimate security testing and educational purposes only.

- ✅ Use only on systems you own or have explicit written permission to test
- ✅ Comply with all applicable laws and regulations
- ✅ Follow responsible disclosure practices
- ❌ Never use for unauthorized access or malicious activities

**Unauthorized scanning of computer systems without permission is illegal and may result in criminal prosecution.**

---

## 🤝 Contributing

We welcome contributions from the security community!

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Standards

- Follow PEP 8 style guidelines
- Include docstrings for all functions and classes
- Add type hints where appropriate
- Write meaningful commit messages
- Test thoroughly before submitting

---

## 📝 Changelog

### Version 1.0.0 (Initial Release)

- ✅ Multi-threaded subdomain enumeration
- ✅ Port scanning with service detection
- ✅ Technology fingerprinting
- ✅ SSL/TLS certificate analysis
- ✅ DNS record enumeration
- ✅ JSON, HTML, and Markdown report generation
- ✅ Colored terminal output
- ✅ Verbose logging mode
- ✅ Graceful error handling
- ✅ Configurable threading and timeouts

---

## 📧 Support

For issues, questions, or suggestions:

- 🐛 **Bug Reports**: Submit via GitHub Issues
- 💡 **Feature Requests**: Open an issue with the "enhancement" label
- 📧 **Contact**: Qwen Security Team

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🙏 Acknowledgments

- Built with ❤️ by the Qwen Security Team
- Inspired by industry-standard reconnaissance tools
- Thanks to the open-source security community

---

<div align="center">

**QwenSec Recon Suite v1.0.0**

*Professional Cybersecurity Intelligence Tool*

Made with 🐍 Python | Licensed under MIT

</div>
