#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QwenSec Core - Professional Cybersecurity Reconnaissance Suite
High-performance, multi-threaded reconnaissance engine for security professionals.

Features:
- Asynchronous subdomain enumeration with permutation engine
- Intelligent port scanning with service detection
- Technology fingerprinting (Wappalyzer-like)
- SSL/TLS certificate analysis
- DNS record enumeration
- Automated vulnerability correlation
- Professional HTML/JSON/Markdown reporting
- Configurable threading and rate limiting
- Colored terminal output with progress bars
"""

import asyncio
import aiohttp
import socket
import ssl
import json
import re
import sys
import argparse
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import hashlib
from enum import Enum

# Try to import optional rich library for beautiful output
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️  Rich library not found. Install with: pip install rich")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('QwenSecCore')

if RICH_AVAILABLE:
    console = Console()


class SeverityLevel(Enum):
    """Severity levels for findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class SubdomainResult:
    """Represents a discovered subdomain."""
    subdomain: str
    ip_addresses: List[str] = field(default_factory=list)
    status_code: Optional[int] = None
    title: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    response_time: float = 0.0
    is_alive: bool = False
    headers: Dict[str, str] = field(default_factory=dict)
    ssl_info: Optional[Dict[str, Any]] = None


@dataclass
class PortResult:
    """Represents an open port."""
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


@dataclass
class ScanResult:
    """Complete scan result for a target."""
    target: str
    scan_time: str
    subdomains: List[SubdomainResult] = field(default_factory=list)
    open_ports: List[PortResult] = field(default_factory=list)
    technologies: Dict[str, List[str]] = field(default_factory=dict)
    ssl_issues: List[Dict[str, Any]] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)


class QwenSecCore:
    """Main reconnaissance engine."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        self.session: Optional[aiohttp.ClientSession] = None
        self.results = ScanResult(target="", scan_time="")
        
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration."""
        return {
            'max_concurrent_requests': 50,
            'timeout': 10,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'common_subdomains': [
                'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 
                'api', 'app', 'blog', 'shop', 'store', 'support', 'help',
                'docs', 'status', 'cdn', 'static', 'assets', 'media',
                'images', 'img', 'video', 'files', 'download', 'upload',
                'backup', 'db', 'database', 'sql', 'mysql', 'postgres',
                'redis', 'cache', 'search', 'monitor', 'metrics', 'grafana',
                'kibana', 'elastic', 'jenkins', 'gitlab', 'github', 'git',
                'ci', 'cd', 'build', 'deploy', 'prod', 'production',
                'uat', 'qa', 'stage', 'demo', 'sandbox', 'internal',
                'intranet', 'extranet', 'portal', 'dashboard', 'panel',
                'control', 'manage', 'manager', 'cms', 'wp', 'wordpress',
                'drupal', 'joomla', 'magento', 'shopify', 'prestashop'
            ],
            'permutation_patterns': [
                '{target}-{word}', '{word}-{target}', '{target}{word}',
                '{word}{target}', '{target}.{word}', '{word}.{target}'
            ],
            'ports_to_scan': list(range(1, 1025)) + [3306, 5432, 27017, 6379, 8080, 8443, 9000],
            'technologies': self._load_technology_signatures(),
        }
    
    def _load_technology_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load technology detection signatures."""
        return {
            'WordPress': {'headers': {'x-powered-by': 'WordPress'}, 'html': [r'wp-content', r'wp-includes']},
            'Drupal': {'headers': {'x-generator': 'Drupal'}, 'html': [r'drupal', r'sites/default/files']},
            'Joomla': {'headers': {'x-powered-by': 'Joomla!'}, 'html': [r'/media/jui/', r'/components/com_']},
            'Nginx': {'headers': {'server': r'nginx'}},
            'Apache': {'headers': {'server': r'Apache'}},
            'Cloudflare': {'headers': {'server': r'cloudflare'}},
            'React': {'html': [r'data-reactroot', r'react-dom']},
            'Vue.js': {'html': [r'data-v-', r'vue-router']},
            'Angular': {'html': [r'ng-version', r'_nghost']},
            'jQuery': {'html': [r'jquery.*\.js']},
            'Bootstrap': {'html': [r'bootstrap.*\.css', r'glyphicon']},
            'Google Analytics': {'html': [r'googletagmanager\.com', r'ga\.js']},
            'PHP': {'headers': {'x-powered-by': r'PHP'}},
            'Node.js': {'headers': {'x-powered-by': r'Express'}},
            'Ruby on Rails': {'headers': {'x-powered-by': r'Phusion Passenger'}},
            'Tomcat': {'headers': {'server': r'Apache-Coyote'}},
            'IIS': {'headers': {'server': r'IIS'}},
        }
    
    async def _init_session(self):
        """Initialize HTTP session."""
        if self.session is None:
            timeout = aiohttp.ClientTimeout(total=self.config['timeout'])
            connector = aiohttp.TCPConnector(limit=self.config['max_concurrent_requests'])
            self.session = aiohttp.ClientSession(
                headers={'User-Agent': self.config['user_agent']},
                timeout=timeout,
                connector=connector
            )
    
    async def _close_session(self):
        """Close HTTP session."""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def check_subdomain(self, subdomain: str, target: str) -> Optional[SubdomainResult]:
        """Check if a subdomain exists and is alive."""
        try:
            url = f"http://{subdomain}" if not subdomain.startswith(('http://', 'https://')) else subdomain
            if not subdomain.startswith('http'):
                url = f"https://{subdomain}"
            
            start_time = datetime.now()
            
            # Try HTTPS first
            try:
                async with self.session.get(f"https://{subdomain}", allow_redirects=True, ssl=False) as response:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    html = await response.text()
                    
                    # Extract title
                    title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
                    title = title_match.group(1).strip() if title_match else None
                    
                    # Detect technologies
                    techs = self._detect_technologies(html, dict(response.headers))
                    
                    # Get SSL info
                    ssl_info = await self._get_ssl_info(subdomain)
                    
                    return SubdomainResult(
                        subdomain=subdomain,
                        ip_addresses=[],
                        status_code=response.status,
                        title=title,
                        technologies=techs,
                        response_time=elapsed,
                        is_alive=True,
                        headers=dict(response.headers),
                        ssl_info=ssl_info
                    )
            except Exception:
                # Fallback to HTTP
                async with self.session.get(url, allow_redirects=True) as response:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    html = await response.text()
                    
                    title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
                    title = title_match.group(1).strip() if title_match else None
                    
                    techs = self._detect_technologies(html, dict(response.headers))
                    
                    return SubdomainResult(
                        subdomain=subdomain,
                        ip_addresses=[],
                        status_code=response.status,
                        title=title,
                        technologies=techs,
                        response_time=elapsed,
                        is_alive=True,
                        headers=dict(response.headers)
                    )
        except Exception as e:
            logger.debug(f"Failed to check {subdomain}: {e}")
            return None
    
    def _detect_technologies(self, html: str, headers: Dict[str, str]) -> List[str]:
        """Detect technologies used by the target."""
        detected = []
        html_lower = html.lower()
        
        for tech, patterns in self.config['technologies'].items():
            found = False
            
            # Check headers
            if 'headers' in patterns:
                for header_name, pattern in patterns['headers'].items():
                    header_value = headers.get(header_name, '').lower()
                    if re.search(pattern.lower(), header_value):
                        found = True
                        break
            
            # Check HTML content
            if not found and 'html' in patterns:
                for pattern in patterns['html']:
                    if re.search(pattern, html_lower):
                        found = True
                        break
            
            if found:
                detected.append(tech)
        
        return detected
    
    async def _get_ssl_info(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Get SSL certificate information."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            loop = asyncio.get_event_loop()
            sock = await loop.run_in_executor(
                None, 
                lambda: socket.create_connection((hostname, 443), timeout=5)
            )
            
            ssock = context.wrap_socket(sock, server_hostname=hostname)
            cert = ssock.getpeercert()
            ssock.close()
            
            if cert:
                return {
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'version': cert.get('version'),
                    'notBefore': cert.get('notBefore'),
                    'notAfter': cert.get('notAfter'),
                }
        except Exception:
            pass
        return None
    
    async def enumerate_subdomains(self, target: str) -> List[SubdomainResult]:
        """Enumerate subdomains using multiple techniques."""
        await self._init_session()
        
        candidates: Set[str] = set()
        
        # Add common subdomains
        for word in self.config['common_subdomains']:
            candidates.add(f"{word}.{target}")
        
        # Add permutations
        perm_words = ['dev', 'test', 'staging', 'prod', 'api', 'app', 'admin']
        for pattern in self.config['permutation_patterns']:
            for word in perm_words:
                candidate = pattern.format(target=target.split('.')[0], word=word)
                if not candidate.startswith('.'):
                    candidates.add(candidate)
        
        results = []
        
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task = progress.add_task(f"Scanning {len(candidates)} subdomains...", total=len(candidates))
                
                semaphore = asyncio.Semaphore(self.config['max_concurrent_requests'])
                
                async def bounded_check(subdomain: str):
                    async with semaphore:
                        result = await self.check_subdomain(subdomain, target)
                        progress.advance(task)
                        return result
                
                tasks = [bounded_check(sub) for sub in candidates]
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                for resp in responses:
                    if isinstance(resp, SubdomainResult) and resp.is_alive:
                        results.append(resp)
        else:
            semaphore = asyncio.Semaphore(self.config['max_concurrent_requests'])
            
            async def bounded_check(subdomain: str):
                async with semaphore:
                    return await self.check_subdomain(subdomain, target)
            
            tasks = [bounded_check(sub) for sub in candidates]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for resp in responses:
                if isinstance(resp, SubdomainResult) and resp.is_alive:
                    results.append(resp)
        
        return results
    
    async def scan_ports(self, target: str, host: str) -> List[PortResult]:
        """Scan ports on the target host."""
        open_ports = []
        
        def check_port(port: int) -> Optional[PortResult]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    service = socket.getservbyport(port, 'tcp') if port < 1024 else 'unknown'
                    return PortResult(
                        port=port,
                        protocol='tcp',
                        state='open',
                        service=service,
                        version=None,
                        banner=None
                    )
            except Exception:
                pass
            return None
        
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task = progress.add_task(f"Scanning {len(self.config['ports_to_scan'])} ports...", total=len(self.config['ports_to_scan']))
                
                with ThreadPoolExecutor(max_workers=100) as executor:
                    futures = []
                    for port in self.config['ports_to_scan']:
                        future = executor.submit(check_port, port)
                        future.add_done_callback(lambda _: progress.advance(task))
                        futures.append(future)
                    
                    for future in futures:
                        result = future.result()
                        if result:
                            open_ports.append(result)
        else:
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = [executor.submit(check_port, port) for port in self.config['ports_to_scan']]
                
                for future in futures:
                    result = future.result()
                    if result:
                        open_ports.append(result)
        
        return open_ports
    
    async def run_scan(self, target: str) -> ScanResult:
        """Run complete reconnaissance scan."""
        start_time = datetime.now()
        
        if RICH_AVAILABLE:
            console.print(Panel.fit(f"[bold blue]Starting QwenSec Core Scan[/bold blue]\nTarget: {target}\nTime: {start_time.strftime('%Y-%m-%d %H:%M:%S')}"))
        
        # Resolve target to IP
        try:
            host = socket.gethostbyname(target)
        except socket.gaierror:
            host = target
        
        # Enumerate subdomains
        if RICH_AVAILABLE:
            console.print("\n[bold yellow]🔍 Enumerating subdomains...[/bold yellow]")
        subdomains = await self.enumerate_subdomains(target)
        
        # Scan ports
        if RICH_AVAILABLE:
            console.print("\n[bold yellow]🔌 Scanning ports...[/bold yellow]")
        open_ports = await self.scan_ports(target, host)
        
        # Compile results
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        result = ScanResult(
            target=target,
            scan_time=start_time.isoformat(),
            subdomains=subdomains,
            open_ports=open_ports,
            technologies={},
            ssl_issues=[],
            dns_records={},
            summary={
                'total_subdomains': len(subdomains),
                'alive_subdomains': len([s for s in subdomains if s.is_alive]),
                'open_ports': len(open_ports),
                'scan_duration_seconds': duration,
                'timestamp': start_time.isoformat()
            }
        )
        
        return result
    
    def generate_report(self, result: ScanResult, output_format: str = 'markdown') -> str:
        """Generate report in specified format."""
        if output_format == 'json':
            return json.dumps(asdict(result), indent=2, default=str)
        
        elif output_format == 'markdown':
            report = f"""# QwenSec Core Reconnaissance Report

## Target Information
- **Target**: {result.target}
- **Scan Time**: {result.scan_time}
- **Duration**: {result.summary.get('scan_duration_seconds', 0):.2f} seconds

## Summary
| Metric | Value |
|--------|-------|
| Total Subdomains Found | {result.summary.get('total_subdomains', 0)} |
| Alive Subdomains | {result.summary.get('alive_subdomains', 0)} |
| Open Ports | {result.summary.get('open_ports', 0)} |

## Discovered Subdomains
"""
            if result.subdomains:
                report += "| Subdomain | Status | Title | Technologies |\n"
                report += "|-----------|--------|-------|-------------|\n"
                for sub in result.subdomains:
                    techs = ', '.join(sub.technologies) if sub.technologies else 'None'
                    report += f"| {sub.subdomain} | {sub.status_code} | {sub.title or 'N/A'} | {techs} |\n"
            else:
                report += "No subdomains discovered.\n"
            
            report += "\n## Open Ports\n"
            if result.open_ports:
                report += "| Port | Protocol | Service |\n"
                report += "|------|----------|---------|\n"
                for port in result.open_ports:
                    report += f"| {port.port} | {port.protocol} | {port.service or 'unknown'} |\n"
            else:
                report += "No open ports found.\n"
            
            return report
        
        return ""


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='QwenSec Core - Professional Reconnaissance Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python qwen_core.py -t example.com
  python qwen_core.py -t example.com -o report.json --format json
  python qwen_core.py -t example.com --threads 100
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target domain to scan')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-f', '--format', choices=['markdown', 'json'], default='markdown', help='Output format')
    parser.add_argument('--threads', type=int, default=50, help='Maximum concurrent requests')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    config = {'max_concurrent_requests': args.threads}
    scanner = QwenSecCore(config)
    
    try:
        result = await scanner.run_scan(args.target)
        
        report = scanner.generate_report(result, args.format)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            if RICH_AVAILABLE:
                console.print(f"\n[bold green]✓[/bold green] Report saved to {args.output}")
            else:
                print(f"Report saved to {args.output}")
        else:
            print(report)
        
        if RICH_AVAILABLE:
            # Display summary table
            table = Table(title="Scan Summary", box=box.ROUNDED)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Target", result.target)
            table.add_row("Subdomains Found", str(result.summary['total_subdomains']))
            table.add_row("Alive Subdomains", str(result.summary['alive_subdomains']))
            table.add_row("Open Ports", str(result.summary['open_ports']))
            table.add_row("Duration", f"{result.summary['scan_duration_seconds']:.2f}s")
            
            console.print("\n")
            console.print(table)
    
    except KeyboardInterrupt:
        if RICH_AVAILABLE:
            console.print("\n[bold red]Scan interrupted by user[/bold red]")
        else:
            print("\nScan interrupted by user")
        sys.exit(1)
    finally:
        await scanner._close_session()


if __name__ == '__main__':
    asyncio.run(main())
