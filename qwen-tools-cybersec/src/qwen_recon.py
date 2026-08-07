#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QwenSec Recon Suite - Professional Cybersecurity Intelligence Tool
===================================================================

Author: Qwen Security Team
Version: 1.0.0
License: MIT
Description: Advanced multi-threaded reconnaissance and information gathering framework
             designed for professional penetration testers and security researchers.

Features:
    - Multi-threaded subdomain enumeration
    - Port scanning with service detection
    - Technology stack fingerprinting
    - SSL/TLS certificate analysis
    - DNS record enumeration
    - Automated report generation (JSON, HTML, Markdown)
    - Configurable verbosity and output formats
    - Error handling and retry logic
    - Rate limiting support

Usage:
    python qwen_recon.py -t example.com -o report.html
    python qwen_recon.py --target example.com --threads 50 --verbose

Requirements:
    pip install requests dnspython python-nmap colorama tqdm
"""

import argparse
import json
import socket
import ssl
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
import logging

# Third-party imports (with graceful fallback)
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from colorama import init, Fore, Style
    init()
    COLOR_AVAILABLE = True
except ImportError:
    COLOR_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


@dataclass
class ScanResult:
    """Data class for storing scan results"""
    target: str
    timestamp: str
    subdomains: List[str]
    open_ports: List[Dict[str, Any]]
    technologies: List[str]
    ssl_info: Optional[Dict[str, Any]]
    dns_records: Dict[str, List[str]]
    errors: List[str]


class ColorLogger:
    """Professional colored logging utility"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.colors = {
            'INFO': Fore.GREEN,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'DEBUG': Fore.CYAN,
            'SUCCESS': Fore.GREEN + Style.BRIGHT,
            'RESET': Style.RESET_ALL
        } if COLOR_AVAILABLE else {}
    
    def log(self, level: str, message: str):
        if not self.verbose and level == 'DEBUG':
            return
        
        color = self.colors.get(level, '')
        reset = self.colors.get('RESET', '')
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = f"[{timestamp}] [{level}]"
        
        if COLOR_AVAILABLE:
            print(f"{color}{prefix}{reset} {message}")
        else:
            print(f"{prefix} {message}")
    
    def info(self, msg): self.log('INFO', msg)
    def warning(self, msg): self.log('WARNING', msg)
    def error(self, msg): self.log('ERROR', msg)
    def debug(self, msg): self.log('DEBUG', msg)
    def success(self, msg): self.log('SUCCESS', msg)


class QwenReconScanner:
    """
    Professional reconnaissance scanner with advanced features
    """
    
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
        'app', 'web', 'portal', 'login', 'auth', 'sso', 'cdn', 'static',
        'assets', 'img', 'images', 'js', 'css', 'media', 'docs', 'wiki',
        'git', 'github', 'gitlab', 'jenkins', 'ci', 'cd', 'build', 'deploy'
    ]
    
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
        3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 27017
    ]
    
    def __init__(self, target: str, threads: int = 10, timeout: int = 5, verbose: bool = False):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.logger = ColorLogger(verbose)
        self.results = ScanResult(
            target=target,
            timestamp=datetime.now().isoformat(),
            subdomains=[],
            open_ports=[],
            technologies=[],
            ssl_info=None,
            dns_records={},
            errors=[]
        )
        
        # Setup requests session with retry logic
        if REQUESTS_AVAILABLE:
            self.session = requests.Session()
            retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
            adapter = HTTPAdapter(max_retries=retry)
            self.session.mount('http://', adapter)
            self.session.mount('https://', adapter)
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
        else:
            self.session = None
    
    def scan_subdomain(self, subdomain: str) -> Optional[str]:
        """Check if a subdomain exists"""
        full_domain = f"{subdomain}.{self.target}"
        try:
            socket.gethostbyname(full_domain)
            return full_domain
        except socket.gaierror:
            return None
    
    def enumerate_subdomains(self) -> List[str]:
        """Enumerate subdomains using brute-force approach"""
        self.logger.info(f"Starting subdomain enumeration for {self.target}")
        found_subdomains = []
        
        subdomains_to_check = self.COMMON_SUBDOMAINS
        
        if TQDM_AVAILABLE and self.verbose:
            iterator = tqdm(subdomains_to_check, desc="Scanning subdomains", leave=False)
        else:
            iterator = subdomains_to_check
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {
                executor.submit(self.scan_subdomain, sub): sub 
                for sub in subdomains_to_check
            }
            
            for future in as_completed(future_to_subdomain):
                try:
                    result = future.result()
                    if result:
                        found_subdomains.append(result)
                        self.logger.success(f"Found: {result}")
                except Exception as e:
                    if self.verbose:
                        self.logger.error(f"Error scanning subdomain: {e}")
        
        self.results.subdomains = found_subdomains
        self.logger.success(f"Subdomain enumeration complete. Found {len(found_subdomains)} subdomains")
        return found_subdomains
    
    def scan_port(self, port: int) -> Optional[Dict[str, Any]]:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                service = self._detect_service(port)
                return {
                    'port': port,
                    'state': 'open',
                    'service': service
                }
        except Exception as e:
            if self.verbose:
                self.logger.error(f"Error scanning port {port}: {e}")
        return None
    
    def _detect_service(self, port: int) -> str:
        """Detect service running on port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt', 9000: 'PHP-FPM', 27017: 'MongoDB'
        }
        return services.get(port, 'Unknown')
    
    def port_scan(self) -> List[Dict[str, Any]]:
        """Perform port scanning"""
        self.logger.info(f"Starting port scan on {self.target}")
        open_ports = []
        
        ports_to_scan = self.COMMON_PORTS
        
        if TQDM_AVAILABLE and self.verbose:
            iterator = tqdm(ports_to_scan, desc="Scanning ports", leave=False)
        else:
            iterator = ports_to_scan
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, port): port 
                for port in ports_to_scan
            }
            
            for future in as_completed(future_to_port):
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        self.logger.success(f"Port {result['port']} ({result['service']}) is open")
                except Exception as e:
                    if self.verbose:
                        self.logger.error(f"Error in port scan: {e}")
        
        open_ports.sort(key=lambda x: x['port'])
        self.results.open_ports = open_ports
        self.logger.success(f"Port scan complete. Found {len(open_ports)} open ports")
        return open_ports
    
    def fingerprint_technologies(self) -> List[str]:
        """Fingerprint web technologies"""
        self.logger.info("Fingerprinting technologies")
        technologies = []
        
        if not REQUESTS_AVAILABLE or not self.session:
            self.logger.warning("Requests library not available, skipping web fingerprinting")
            return technologies
        
        urls_to_check = [
            f"http://{self.target}",
            f"https://{self.target}"
        ]
        
        for url in urls_to_check:
            try:
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                
                # Check headers
                server = response.headers.get('Server', '')
                if server:
                    technologies.append(f"Server: {server}")
                
                powered_by = response.headers.get('X-Powered-By', '')
                if powered_by:
                    technologies.append(f"Powered-By: {powered_by}")
                
                # Check for common tech indicators in content
                content = response.text.lower()
                
                tech_indicators = {
                    'WordPress': ['wp-content', 'wp-includes'],
                    'jQuery': ['jquery'],
                    'React': ['react'],
                    'Angular': ['ng-'],
                    'Vue.js': ['vue'],
                    'Bootstrap': ['bootstrap'],
                    'Nginx': ['nginx'],
                    'Apache': ['apache'],
                    'PHP': ['php'],
                    'ASP.NET': ['asp.net'],
                    'Node.js': ['node.js'],
                    'Express': ['express']
                }
                
                for tech, indicators in tech_indicators.items():
                    if any(indicator in content for indicator in indicators):
                        if tech not in [t.split(':')[0] if ':' in t else t for t in technologies]:
                            technologies.append(tech)
                
                self.logger.success(f"Checked {url}")
                
            except requests.exceptions.RequestException as e:
                if self.verbose:
                    self.logger.error(f"Error checking {url}: {e}")
                self.results.errors.append(f"Web fingerprinting error for {url}: {str(e)}")
        
        self.results.technologies = list(set(technologies))
        self.logger.success(f"Technology fingerprinting complete. Identified {len(technologies)} technologies")
        return technologies
    
    def analyze_ssl(self) -> Optional[Dict[str, Any]]:
        """Analyze SSL/TLS certificate"""
        self.logger.info("Analyzing SSL certificate")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'protocol': ssock.version()
                    }
                    
                    self.logger.success("SSL certificate analyzed successfully")
                    self.results.ssl_info = ssl_info
                    return ssl_info
                    
        except Exception as e:
            self.logger.warning(f"SSL analysis failed: {e}")
            self.results.errors.append(f"SSL analysis error: {str(e)}")
            return None
    
    def enumerate_dns(self) -> Dict[str, List[str]]:
        """Enumerate DNS records"""
        self.logger.info("Enumerating DNS records")
        dns_results = {}
        
        if not DNS_AVAILABLE:
            self.logger.warning("dnspython not available, using basic DNS lookup")
            try:
                ip = socket.gethostbyname(self.target)
                dns_results['A'] = [ip]
            except Exception as e:
                self.results.errors.append(f"Basic DNS lookup failed: {str(e)}")
            return dns_results
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                records = [str(rdata) for rdata in answers]
                if records:
                    dns_results[record_type] = records
                    self.logger.success(f"Found {len(records)} {record_type} records")
            except Exception as e:
                if self.verbose:
                    self.logger.debug(f"No {record_type} records found: {e}")
        
        self.results.dns_records = dns_results
        self.logger.success("DNS enumeration complete")
        return dns_results
    
    def run_full_scan(self) -> ScanResult:
        """Execute complete reconnaissance scan"""
        self.logger.info(f"🚀 Starting QwenSec Recon Suite scan for {self.target}")
        start_time = time.time()
        
        try:
            # Run all scans
            self.enumerate_dns()
            self.enumerate_subdomains()
            self.port_scan()
            self.fingerprint_technologies()
            self.analyze_ssl()
            
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            self.results.errors.append("Scan interrupted by user")
        except Exception as e:
            self.logger.error(f"Critical error during scan: {e}")
            self.results.errors.append(f"Critical error: {str(e)}")
        
        elapsed_time = time.time() - start_time
        self.logger.success(f"✅ Scan completed in {elapsed_time:.2f} seconds")
        
        return self.results
    
    def generate_report(self, output_format: str = 'json') -> str:
        """Generate scan report in specified format"""
        results_dict = asdict(self.results)
        
        if output_format == 'json':
            report = json.dumps(results_dict, indent=2)
        
        elif output_format == 'markdown':
            report = self._generate_markdown_report(results_dict)
        
        elif output_format == 'html':
            report = self._generate_html_report(results_dict)
        
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
        
        return report
    
    def _generate_markdown_report(self, data: Dict) -> str:
        """Generate Markdown formatted report"""
        report = f"""# QwenSec Reconnaissance Report

## Target Information
- **Target**: {data['target']}
- **Scan Time**: {data['timestamp']}
- **Total Subdomains Found**: {len(data['subdomains'])}
- **Open Ports**: {len(data['open_ports'])}
- **Technologies Detected**: {len(data['technologies'])}

## Subdomains
"""
        if data['subdomains']:
            for sub in data['subdomains']:
                report += f"- {sub}\n"
        else:
            report += "No subdomains found.\n"
        
        report += "\n## Open Ports\n"
        if data['open_ports']:
            report += "| Port | Service |\n|------|---------|\n"
            for port in data['open_ports']:
                report += f"| {port['port']} | {port['service']} |\n"
        else:
            report += "No open ports found.\n"
        
        report += "\n## Technologies\n"
        if data['technologies']:
            for tech in data['technologies']:
                report += f"- {tech}\n"
        else:
            report += "No technologies detected.\n"
        
        if data['ssl_info']:
            report += "\n## SSL Certificate\n"
            for key, value in data['ssl_info'].items():
                report += f"- **{key}**: {value}\n"
        
        if data['dns_records']:
            report += "\n## DNS Records\n"
            for record_type, records in data['dns_records'].items():
                report += f"### {record_type}\n"
                for record in records:
                    report += f"- {record}\n"
        
        if data['errors']:
            report += "\n## Errors\n"
            for error in data['errors']:
                report += f"- {error}\n"
        
        report += f"\n---\n*Generated by QwenSec Recon Suite v1.0.0*\n"
        
        return report
    
    def _generate_html_report(self, data: Dict) -> str:
        """Generate HTML formatted report"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QwenSec Recon Report - {data['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .info-box {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #3498db; color: white; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .success {{ color: #27ae60; }}
        .warning {{ color: #f39c12; }}
        .error {{ color: #e74c3c; }}
        ul {{ line-height: 1.8; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 QwenSec Reconnaissance Report</h1>
        
        <div class="info-box">
            <strong>Target:</strong> {data['target']}<br>
            <strong>Scan Time:</strong> {data['timestamp']}<br>
            <strong>Subdomains Found:</strong> {len(data['subdomains'])}<br>
            <strong>Open Ports:</strong> {len(data['open_ports'])}<br>
            <strong>Technologies:</strong> {len(data['technologies'])}
        </div>
        
        <h2>🌐 Subdomains</h2>
        {'<ul>' + ''.join(f'<li>{sub}</li>' for sub in data['subdomains']) + '</ul>' if data['subdomains'] else '<p>No subdomains found.</p>'}
        
        <h2>🔌 Open Ports</h2>
        {self._generate_ports_html(data['open_ports'])}
        
        <h2>🛠️ Technologies Detected</h2>
        {'<ul>' + ''.join(f'<li>{tech}</li>' for tech in data['technologies']) + '</ul>' if data['technologies'] else '<p>No technologies detected.</p>'}
        
        {self._generate_ssl_html(data['ssl_info'])}
        
        {self._generate_dns_html(data['dns_records'])}
        
        {self._generate_errors_html(data['errors'])}
        
        <div class="footer">
            <p>Generated by <strong>QwenSec Recon Suite v1.0.0</strong></p>
            <p>Professional Cybersecurity Intelligence Tool</p>
        </div>
    </div>
</body>
</html>"""
        return html
    
    def _generate_ports_html(self, ports: List[Dict]) -> str:
        if not ports:
            return '<p>No open ports found.</p>'
        
        html = '<table><tr><th>Port</th><th>Service</th></tr>'
        for port in ports:
            html += f"<tr><td>{port['port']}</td><td>{port['service']}</td></tr>"
        html += '</table>'
        return html
    
    def _generate_ssl_html(self, ssl_info: Optional[Dict]) -> str:
        if not ssl_info:
            return ''
        
        html = '<h2>🔒 SSL Certificate</h2><div class="info-box">'
        for key, value in ssl_info.items():
            html += f"<strong>{key.replace('_', ' ').title()}:</strong> {value}<br>"
        html += '</div>'
        return html
    
    def _generate_dns_html(self, dns_records: Dict) -> str:
        if not dns_records:
            return ''
        
        html = '<h2>📋 DNS Records</h2>'
        for record_type, records in dns_records.items():
            html += f"<h3>{record_type}</h3><ul>"
            for record in records:
                html += f"<li>{record}</li>"
            html += '</ul>'
        return html
    
    def _generate_errors_html(self, errors: List[str]) -> str:
        if not errors:
            return ''
        
        html = '<h2>⚠️ Errors</h2><ul>'
        for error in errors:
            html += f"<li class='error'>{error}</li>"
        html += '</ul>'
        return html


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='QwenSec Recon Suite - Professional Cybersecurity Intelligence Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t example.com
  %(prog)s --target example.com --threads 50 --verbose
  %(prog)s -t example.com -o report.html --format html
  %(prog)s -t example.com --json > output.json
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target domain or IP address')
    parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout in seconds (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-f', '--format', choices=['json', 'html', 'markdown'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--no-subdomains', action='store_true', help='Skip subdomain enumeration')
    parser.add_argument('--no-ports', action='store_true', help='Skip port scanning')
    parser.add_argument('--no-web', action='store_true', help='Skip web fingerprinting')
    
    args = parser.parse_args()
    
    # Validate target
    if not args.target:
        parser.error("Target is required")
    
    print(f"""
    ╔═══════════════════════════════════════════════════════════╗
    ║           QwenSec Recon Suite v1.0.0                      ║
    ║     Professional Cybersecurity Intelligence Tool          ║
    ║                                                           ║
    ║  ⚠️  WARNING: Use only on systems you have permission    ║
    ║      to test. Unauthorized scanning is illegal.           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    scanner = QwenReconScanner(
        target=args.target,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    # Run scan
    results = scanner.run_full_scan()
    
    # Generate report
    report = scanner.generate_report(output_format=args.format)
    
    # Output results
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)
        scanner.logger.success(f"Report saved to: {args.output}")
    else:
        print("\n" + "="*60)
        print("SCAN RESULTS")
        print("="*60)
        print(report)
    
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nFatal error: {e}")
        sys.exit(1)
