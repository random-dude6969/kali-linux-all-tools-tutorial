# QwenSec Core - Professional Cybersecurity Reconnaissance Suite

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Version](https://img.shields.io/badge/Version-2.0-orange.svg)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)

**Enterprise-grade reconnaissance tool for security professionals**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Architecture](#architecture) • [Examples](#examples)

</div>

---

## 🚀 Overview

**QwenSec Core** is a high-performance, asynchronous cybersecurity reconnaissance suite designed for professional penetration testers and security engineers. Built with modern Python async/await patterns, it delivers blazing-fast subdomain enumeration, port scanning, technology fingerprinting, and comprehensive reporting.

### Key Capabilities

- 🔍 **Multi-threaded Subdomain Enumeration** - Discovers hidden subdomains using permutation engines and common wordlists
- 🔌 **Intelligent Port Scanning** - Scans 1000+ ports with service detection and banner grabbing
- 🎯 **Technology Fingerprinting** - Identifies CMS, frameworks, servers, and analytics tools (Wappalyzer-like)
- 🔒 **SSL/TLS Analysis** - Extracts certificate information and detects misconfigurations
- 📊 **Professional Reporting** - Generates beautiful Markdown, JSON, and HTML reports
- ⚡ **Async Performance** - Handles hundreds of concurrent requests with configurable rate limiting
- 🎨 **Rich Terminal UI** - Beautiful progress bars, tables, and colored output (optional)

---

## ✨ Features

### Advanced Reconnaissance Engine

| Feature | Description |
|---------|-------------|
| **Subdomain Discovery** | Common wordlist + permutation patterns + brute-force |
| **Port Scanning** | TCP connect scan with service detection (1-1024 + common ports) |
| **Tech Detection** | Identifies 20+ technologies (WordPress, React, Nginx, Cloudflare, etc.) |
| **SSL Analysis** | Certificate extraction, validity checks, issuer information |
| **HTTP Fingerprinting** | Status codes, headers, titles, response times |
| **DNS Enumeration** | A, AAAA, MX, TXT, NS record discovery |

### Enterprise-Ready Architecture

- ✅ **Type Hinting** - Full type annotations for IDE support and code quality
- ✅ **Data Classes** - Structured data models for clean, maintainable code
- ✅ **Async/Await** - Non-blocking I/O for maximum performance
- ✅ **Configurable** - YAML/JSON configuration support
- ✅ **Error Handling** - Graceful degradation on network failures
- ✅ **Logging** - Structured logging with multiple levels
- ✅ **CLI & API** - Use as command-line tool or import as library

---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Quick Install

```bash
cd qwen-tools-cybersec
pip install -r requirements.txt
```

### Optional: Rich Library for Beautiful Output

```bash
pip install rich
```

---

## 🎯 Usage

### Basic Scan

```bash
python qwen_core.py -t example.com
```

### Advanced Options

```bash
python qwen_core.py -t example.com --threads 100 -o report.md
python qwen_core.py -t example.com -o report.json --format json
python qwen_core.py -t example.com -v
```

### CLI Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--target` | `-t` | Target domain (required) | - |
| `--output` | `-o` | Output file path | stdout |
| `--format` | `-f` | Output format (markdown/json) | markdown |
| `--threads` | - | Max concurrent requests | 50 |
| `--verbose` | `-v` | Debug logging | False |

---

## 📋 Example Output

```
╭──────────────────────────────────────────────╮
│  Starting QwenSec Core Scan                  │
│  Target: example.com                         │
╰──────────────────────────────────────────────╯

🔍 Enumerating subdomains... [████████] 100%
🔌 Scanning ports... [████████] 100%

# QwenSec Core Report
- Subdomains Found: 12
- Open Ports: 5
- Duration: 8.45s
```

---

## 🔒 Legal Disclaimer

**For authorized security testing only.** Only scan systems you own or have written permission to test.

---

<div align="center">

**QwenSec Core v2.0** • Made with ❤️ by QwenSec Team

</div>
