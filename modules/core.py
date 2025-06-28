"""
Core WCD-Raptor functionality
"""

import os
import json
import csv
import hashlib
import time
from pathlib import Path
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Optional, Tuple

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel

from .cdn_detector import CDNDetector
from .payload_generator import PayloadGenerator
from .response_analyzer import ResponseAnalyzer
from .url_filter import URLFilter
from .cookie_handler import CookieHandler
from .origin_exploiter import OriginExploiter

console = Console()

class WCDRaptor:
    def __init__(self, output_dir='output', threads=5, timeout=10, verbose=False, 
                 headless=False, race_condition=False, user_agent='WCD-Raptor/1.0',
                 exploit_mode=False, origin_timeout=15, exploit_depth='basic'):
        self.output_dir = Path(output_dir)
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.headless = headless
        self.race_condition = race_condition
        self.user_agent = user_agent
        
        # Add exploit mode parameters
        self.exploit_mode = exploit_mode
        self.origin_timeout = origin_timeout
        self.exploit_depth = exploit_depth
        
        # Initialize components
        self.cdn_detector = CDNDetector()
        self.payload_generator = PayloadGenerator()
        self.response_analyzer = ResponseAnalyzer()
        self.url_filter = URLFilter()
        self.cookie_handler = CookieHandler()
        
        # Initialize Origin Exploitation Engine
        if exploit_mode:
            self.origin_exploiter = OriginExploiter(
                timeout=origin_timeout,
                verbose=verbose,
                depth=exploit_depth
            )
        
        # Statistics
        self.stats = {
            'targets_scanned': 0,
            'urls_tested': 0,
            'vulnerabilities_found': 0,
            'cacheable_urls': 0,
            'start_time': time.time(),
            'origin_ips_found': 0,
            'origin_vulnerabilities': 0,
            'csrf_tokens_found': 0,
            'admin_panels_found': 0,
            'api_leaks_found': 0
        }
        
        # Results storage
        self.results = []
        
        # Create output directory
        self.output_dir.mkdir(exist_ok=True)
    
    def load_cookies(self, cookie_file: str):
        """Load cookies from file"""
        try:
            self.cookie_handler.load_cookies(cookie_file)
            if not self.headless:
                console.print(f"[green]Loaded cookies from {cookie_file}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to load cookies: {str(e)}[/red]")
    
    def scan_target(self, target: str):
        """Scan a single target"""
        self.stats['targets_scanned'] += 1
        
        if not self.headless:
            console.print(f"\n[bold blue]Scanning target: {target}[/bold blue]")
        
        # Parse target
        parsed = urlparse(target)
        domain = parsed.netloc
        
        # Create target directory
        target_dir = self.output_dir / domain
        target_dir.mkdir(exist_ok=True)
        
        # Step 1: CDN Detection
        cdn_info = self._detect_cdn(target, target_dir)
        
        # Step 2: URL Discovery and Filtering
        urls = self._discover_and_filter_urls([target], target_dir)
        
        # Step 3: WCD Testing
        vulnerabilities = self._test_wcd_vulnerabilities(urls, target_dir)
        
        # Step 4: Origin Exploitation (if enabled)
        origin_results = []
        if self.exploit_mode:
            origin_results = self._exploit_origin_ips(target, target_dir)
        
        # Step 4: Generate Reports
        self._generate_reports(target, vulnerabilities, target_dir, origin_results)
        
        return vulnerabilities
    
    def scan_url_file(self, url_file: str):
        """Scan URLs from file"""
        try:
            with open(url_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            if not self.headless:
                console.print(f"[green]Loaded {len(urls)} URLs from {url_file}[/green]")
            
            # Group URLs by domain
            domain_urls = {}
            for url in urls:
                parsed = urlparse(url)
                domain = parsed.netloc
                if domain not in domain_urls:
                    domain_urls[domain] = []
                domain_urls[domain].append(url)
            
            # Scan each domain
            all_vulnerabilities = []
            for domain, domain_url_list in domain_urls.items():
                self.stats['targets_scanned'] += 1
                
                if not self.headless:
                    console.print(f"\n[bold blue]Scanning domain: {domain}[/bold blue]")
                
                # Create target directory
                target_dir = self.output_dir / domain
                target_dir.mkdir(exist_ok=True)
                
                # Save raw URLs
                with open(target_dir / 'raw_urls.txt', 'w') as f:
                    for url in domain_url_list:
                        f.write(f"{url}\n")
                
                # CDN Detection (use first URL)
                cdn_info = self._detect_cdn(domain_url_list[0], target_dir)
                
                # URL Filtering
                filtered_urls = self._discover_and_filter_urls(domain_url_list, target_dir)
                
                # WCD Testing
                vulnerabilities = self._test_wcd_vulnerabilities(filtered_urls, target_dir)
                all_vulnerabilities.extend(vulnerabilities)
                
                # Generate Reports
                self._generate_reports(domain, vulnerabilities, target_dir)
            
            return all_vulnerabilities
            
        except Exception as e:
            console.print(f"[red]Error reading URL file: {str(e)}[/red]")
            return []
    
    def _detect_cdn(self, target: str, target_dir: Path) -> Dict:
        """Detect CDN and reverse proxy"""
        if not self.headless:
            console.print("[yellow]Detecting CDN/Reverse Proxy...[/yellow]")
        
        cdn_info = self.cdn_detector.detect(target, timeout=self.timeout)
        
        # Save CDN info
        with open(target_dir / 'cdn_info.txt', 'w') as f:
            f.write(f"Target: {target}\n")
            f.write(f"CDN Detected: {cdn_info.get('cdn_name', 'Unknown')}\n")
            f.write(f"Server: {cdn_info.get('server', 'Unknown')}\n")
            f.write(f"Cache Headers: {json.dumps(cdn_info.get('cache_headers', {}), indent=2)}\n")
            f.write(f"Detection Headers: {json.dumps(cdn_info.get('detection_headers', {}), indent=2)}\n")
        
        if not self.headless:
            if cdn_info.get('cdn_name'):
                console.print(f"[green]CDN Detected: {cdn_info['cdn_name']}[/green]")
            else:
                console.print("[yellow]No CDN detected[/yellow]")
        
        return cdn_info
    
    def _discover_and_filter_urls(self, urls: List[str], target_dir: Path) -> List[str]:
        """Filter URLs for cacheable endpoints"""
        if not self.headless:
            console.print("[yellow]Filtering cacheable URLs...[/yellow]")
        
        cacheable_urls = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            disable=self.headless
        ) as progress:
            task = progress.add_task("Filtering URLs...", total=len(urls))
            
            for url in urls:
                try:
                    is_cacheable = self.url_filter.is_potentially_cacheable(
                        url, timeout=self.timeout, user_agent=self.user_agent
                    )
                    if is_cacheable:
                        cacheable_urls.append(url)
                        self.stats['cacheable_urls'] += 1
                except Exception as e:
                    if self.verbose:
                        console.print(f"[red]Error filtering {url}: {str(e)}[/red]")
                
                progress.update(task, advance=1)
        
        # Save cacheable URLs
        with open(target_dir / 'cacheable_urls.txt', 'w') as f:
            for url in cacheable_urls:
                f.write(f"{url}\n")
        
        if not self.headless:
            console.print(f"[green]Found {len(cacheable_urls)} potentially cacheable URLs[/green]")
        
        return cacheable_urls
    
    def _test_wcd_vulnerabilities(self, urls: List[str], target_dir: Path) -> List[Dict]:
        """Test for WCD vulnerabilities"""
        if not urls:
            return []
        
        if not self.headless:
            console.print("[yellow]Testing WCD vulnerabilities...[/yellow]")
        
        vulnerabilities = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            disable=self.headless
        ) as progress:
            task = progress.add_task("Testing vulnerabilities...", total=len(urls))
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_url = {}
                
                for url in urls:
                    payloads = self.payload_generator.generate_payloads(url)
                    for payload in payloads:
                        future = executor.submit(self._test_single_payload, url, payload)
                        future_to_url[future] = (url, payload)
                
                for future in as_completed(future_to_url):
                    url, payload = future_to_url[future]
                    try:
                        result = future.result()
                        if result and result.get('vulnerable'):
                            vulnerabilities.append(result)
                            self.stats['vulnerabilities_found'] += 1
                        self.stats['urls_tested'] += 1
                    except Exception as e:
                        if self.verbose:
                            console.print(f"[red]Error testing {url}: {str(e)}[/red]")
                    
                    progress.update(task, advance=1)
        
        return vulnerabilities
    
    def _test_single_payload(self, original_url: str, payload: Dict) -> Optional[Dict]:
        """Test a single WCD payload"""
        try:
            # Create HTTP client
            client = httpx.Client(
                timeout=self.timeout,
                headers={'User-Agent': self.user_agent},
                cookies=self.cookie_handler.get_cookies(),
                follow_redirects=True
            )
            
            # Test original URL
            original_response = client.get(original_url)
            
            # Test payload URL
            payload_url = payload['url']
            payload_response = client.get(payload_url, headers=payload.get('headers', {}))
            
            # Analyze responses
            analysis = self.response_analyzer.analyze_responses(
                original_response, payload_response, original_url, payload_url
            )
            
            if analysis['vulnerable']:
                return {
                    'original_url': original_url,
                    'payload_url': payload_url,
                    'payload_type': payload['type'],
                    'vulnerable': True,
                    'confidence': analysis['confidence'],
                    'evidence': analysis['evidence'],
                    'original_status': original_response.status_code,
                    'payload_status': payload_response.status_code,
                    'cache_headers': analysis.get('cache_headers', {}),
                    'timestamp': time.time()
                }
            
            client.close()
            return None
            
        except Exception as e:
            if self.verbose:
                console.print(f"[red]Error testing payload: {str(e)}[/red]")
            return None
    
    def _exploit_origin_ips(self, target: str, target_dir: Path) -> List[Dict]:
        """Exploit discovered origin IPs"""
        if not self.headless:
            console.print("[bold red]🔥 Starting Origin Exploitation Engine (OEE)...[/bold red]")
        
        # Discover origin IPs
        origin_ips = self.origin_exploiter.discover_origin_ips(target)
        self.stats['origin_ips_found'] = len(origin_ips)
        
        if not origin_ips:
            if not self.headless:
                console.print("[yellow]No origin IPs discovered[/yellow]")
            return []
        
        if not self.headless:
            console.print(f"[green]Found {len(origin_ips)} origin IP(s): {', '.join(origin_ips)}[/green]")
        
        # Save discovered IPs
        with open(target_dir / 'origin_ips.txt', 'w') as f:
            for ip in origin_ips:
                f.write(f"{ip}\n")
        
        # Exploit each origin IP
        all_exploits = []
        for origin_ip in origin_ips:
            if not self.headless:
                console.print(f"[yellow]🎯 Exploiting origin IP: {origin_ip}[/yellow]")
            
            exploits = self.origin_exploiter.exploit_origin(target, origin_ip)
            all_exploits.extend(exploits)
            
            # Update statistics
            for exploit in exploits:
                if exploit['type'] == 'csrf_token':
                    self.stats['csrf_tokens_found'] += 1
                elif exploit['type'] == 'admin_panel':
                    self.stats['admin_panels_found'] += 1
                elif exploit['type'] == 'api_leak':
                    self.stats['api_leaks_found'] += 1
                self.stats['origin_vulnerabilities'] += 1
        
        # Save origin exploitation results
        with open(target_dir / 'origin_exploits.json', 'w') as f:
            json.dump(all_exploits, f, indent=2)
        
        if not self.headless and all_exploits:
            self._print_origin_exploits(all_exploits)
        
        return all_exploits
    
    def _print_origin_exploits(self, exploits: List[Dict]):
        """Print origin exploitation results"""
        table = Table(title="🔥 Origin Exploitation Results")
        table.add_column("Origin IP", style="cyan")
        table.add_column("Exploit Type", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Evidence", style="green")
        
        severity_colors = {
            'critical': 'bold red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'green'
        }
        
        for exploit in exploits:
            severity_color = severity_colors.get(exploit['severity'], 'white')
            table.add_row(
                exploit['origin_ip'],
                exploit['type'],
                f"[{severity_color}]{exploit['severity'].upper()}[/{severity_color}]",
                exploit['evidence'][:50] + "..." if len(exploit['evidence']) > 50 else exploit['evidence']
            )
        
        console.print(table)
    
    def _generate_reports(self, target: str, vulnerabilities: List[Dict], target_dir: Path, origin_results: List[Dict] = None):
        """Generate JSON and CSV reports"""
        # JSON Report
        json_report = {
            'target': target,
            'scan_time': time.time(),
            'vulnerabilities_count': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
        
        # Add origin results to JSON report
        if origin_results:
            json_report['origin_exploits'] = origin_results
            json_report['origin_exploits_count'] = len(origin_results)
        
        with open(target_dir / 'results.json', 'w') as f:
            json.dump(json_report, f, indent=2)
        
        # CSV Report
        if vulnerabilities:
            with open(target_dir / 'results.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'original_url', 'payload_url', 'payload_type', 'confidence',
                    'original_status', 'payload_status', 'evidence'
                ])
                writer.writeheader()
                for vuln in vulnerabilities:
                    writer.writerow({
                        'original_url': vuln['original_url'],
                        'payload_url': vuln['payload_url'],
                        'payload_type': vuln['payload_type'],
                        'confidence': vuln['confidence'],
                        'original_status': vuln['original_status'],
                        'payload_status': vuln['payload_status'],
                        'evidence': vuln['evidence']
                    })
        
        # Console output
        if not self.headless and vulnerabilities:
            self._print_vulnerabilities(vulnerabilities)
    
    def _print_vulnerabilities(self, vulnerabilities: List[Dict]):
        """Print vulnerabilities to console"""
        table = Table(title="WCD Vulnerabilities Found")
        table.add_column("Original URL", style="cyan")
        table.add_column("Payload Type", style="yellow")
        table.add_column("Confidence", style="green")
        table.add_column("Evidence", style="red")
        
        for vuln in vulnerabilities:
            table.add_row(
                vuln['original_url'][:50] + "..." if len(vuln['original_url']) > 50 else vuln['original_url'],
                vuln['payload_type'],
                vuln['confidence'],
                vuln['evidence'][:30] + "..." if len(vuln['evidence']) > 30 else vuln['evidence']
            )
        
        console.print(table)
    
    def print_summary(self):
        """Print scan summary"""
        elapsed_time = time.time() - self.stats['start_time']
        
        summary_table = Table(title="Scan Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Targets Scanned", str(self.stats['targets_scanned']))
        summary_table.add_row("URLs Tested", str(self.stats['urls_tested']))
        summary_table.add_row("Cacheable URLs Found", str(self.stats['cacheable_urls']))
        summary_table.add_row("Vulnerabilities Found", str(self.stats['vulnerabilities_found']))
        
        # Add origin exploitation stats if enabled
        if hasattr(self, 'exploit_mode') and self.exploit_mode:
            summary_table.add_row("Origin IPs Found", str(self.stats['origin_ips_found']))
            summary_table.add_row("Origin Vulnerabilities", str(self.stats['origin_vulnerabilities']))
            summary_table.add_row("CSRF Tokens Found", str(self.stats['csrf_tokens_found']))
            summary_table.add_row("Admin Panels Found", str(self.stats['admin_panels_found']))
            summary_table.add_row("API Leaks Found", str(self.stats['api_leaks_found']))
        
        summary_table.add_row("Scan Time", f"{elapsed_time:.2f} seconds")
        
        console.print("\n")
        console.print(summary_table)
        console.print(f"\n[bold green]Results saved to: {self.output_dir}[/bold green]")
