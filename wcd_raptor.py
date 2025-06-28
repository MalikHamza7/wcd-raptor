#!/usr/bin/env python3
"""
WCD-Raptor - Web Cache Deception Detection Tool
Developed By: Hamza Iqbal
License: MIT
"""

import argparse
import sys
import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

from modules.core import WCDRaptor
from modules.utils import setup_logging, validate_target
from modules.banner import print_banner

console = Console()

def main():
    parser = argparse.ArgumentParser(
        description="WCD-Raptor - Web Cache Deception Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 wcd_raptor.py --target https://example.com
  python3 wcd_raptor.py --url-file urls.txt --cookie-file session.txt
  python3 wcd_raptor.py --target https://example.com --verbose --threads 10
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--target', '-t', help='Single target domain/URL')
    input_group.add_argument('--url-file', '-f', help='File containing list of URLs')
    
    # Optional parameters
    parser.add_argument('--cookie-file', '-c', help='Cookie file (Netscape or JSON format)')
    parser.add_argument('--output-dir', '-o', default='output', help='Output directory (default: output)')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--headless', action='store_true', help='Minimal output for pipelines')
    parser.add_argument('--race-condition', action='store_true', help='Enable race condition testing')
    parser.add_argument('--user-agent', default='WCD-Raptor/1.0', help='Custom User-Agent')
    parser.add_argument('--exploit', action='store_true', help='Enable Origin Exploitation Engine (OEE)')
    parser.add_argument('--origin-timeout', type=int, default=15, help='Origin IP request timeout (default: 15)')
    parser.add_argument('--exploit-depth', choices=['basic', 'deep'], default='basic', help='Exploitation depth level')
    
    args = parser.parse_args()
    
    # Print banner unless in headless mode
    if not args.headless:
        print_banner()
    
    # Setup logging
    setup_logging(args.verbose)
    
    try:
        # Initialize WCD-Raptor
        raptor = WCDRaptor(
            output_dir=args.output_dir,
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose,
            headless=args.headless,
            race_condition=args.race_condition,
            user_agent=args.user_agent,
            exploit_mode=args.exploit,
            origin_timeout=args.origin_timeout,
            exploit_depth=args.exploit_depth
        )
        
        # Load cookies if provided
        if args.cookie_file:
            raptor.load_cookies(args.cookie_file)
        
        # Process targets
        if args.target:
            if validate_target(args.target):
                raptor.scan_target(args.target)
            else:
                console.print("[red]Invalid target URL provided[/red]")
                sys.exit(1)
        elif args.url_file:
            if os.path.exists(args.url_file):
                raptor.scan_url_file(args.url_file)
            else:
                console.print(f"[red]URL file not found: {args.url_file}[/red]")
                sys.exit(1)
        
        # Print summary
        if not args.headless:
            raptor.print_summary()
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
