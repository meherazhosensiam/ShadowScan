#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowScan - Main Entry Point
Author: Meheraz HOSEN SIAM
Description: Advanced Network Port Scanner
"""

import sys
import argparse

from .utils.output import OutputFormatter
from .scanners.tcp_scan import TCPScanner, quick_tcp_scan, full_tcp_scan
from .scanners.syn_scan import SYNScanner, quick_syn_scan
from .scanners.udp_scan import UDPScanner, quick_udp_scan
from .fingerprint.os_detect import OSFingerprinter
from .fingerprint.banner_db import BannerDatabase

__version__ = "2.0.0"
__author__ = "Meheraz HOSEN SIAM"


def interactive_mode():
    """Interactive menu-driven interface"""
    OutputFormatter.print_banner()
    
    scanner = None
    
    while True:
        OutputFormatter.print_menu()
        choice = input(f"\n{OutputFormatter.Fore.GREEN}ShadowScan>{OutputFormatter.Style.RESET_ALL} ").strip()
        
        if choice == '0' or choice.lower() == 'exit':
            OutputFormatter.print_info("Thank you for using ShadowScan! Au revoir!")
            break
        
        elif choice == '1':
            # TCP Quick Scan
            target = input("Enter target IP/hostname: ").strip()
            if not target:
                OutputFormatter.print_error("Target required")
                continue
            OutputFormatter.print_info(f"Running TCP Quick Scan on {target}...")
            scanner = quick_tcp_scan(target)
            if scanner.scan():
                scanner.print_summary()
        
        elif choice == '2':
            # TCP Full Scan
            target = input("Enter target IP/hostname: ").strip()
            if not target:
                OutputFormatter.print_error("Target required")
                continue
            OutputFormatter.print_info(f"Running TCP Full Scan on {target}...")
            OutputFormatter.print_warning("This may take a while...")
            scanner = full_tcp_scan(target)
            if scanner.scan():
                scanner.print_summary()
        
        elif choice == '3':
            # SYN Scan
            target = input("Enter target IP/hostname: ").strip()
            if not target:
                OutputFormatter.print_error("Target required")
                continue
            OutputFormatter.print_info(f"Running SYN Scan on {target}...")
            OutputFormatter.print_warning("SYN scan requires root privileges")
            scanner = quick_syn_scan(target)
            if scanner.scan():
                scanner.print_summary()
        
        elif choice == '4':
            # UDP Scan
            target = input("Enter target IP/hostname: ").strip()
            if not target:
                OutputFormatter.print_error("Target required")
                continue
            OutputFormatter.print_info(f"Running UDP Scan on {target}...")
            scanner = quick_udp_scan(target)
            if scanner.scan():
                scanner.print_summary()
        
        elif choice == '5':
            # Custom Ports
            target = input("Enter target IP/hostname: ").strip()
            if not target:
                OutputFormatter.print_error("Target required")
                continue
            ports_str = input("Enter ports (e.g., 22,80,443 or 1-1000): ").strip()
            if not ports_str:
                OutputFormatter.print_error("Ports required")
                continue
            
            from .utils.network import NetworkUtils
            ports = NetworkUtils.parse_port_range(ports_str)
            
            OutputFormatter.print_info(f"Running Custom TCP Scan on {len(ports)} ports...")
            scanner = TCPScanner(target, ports, banner_grab=True)
            if scanner.scan():
                scanner.print_summary()
        
        elif choice == '6':
            # Banner Grab
            target = input("Enter target IP/hostname: ").strip()
            port = int(input("Enter port: ").strip() or "80")
            
            OutputFormatter.print_info(f"Grabbing banner from {target}:{port}...")
            scanner = TCPScanner(target, [port], banner_grab=True, verbose=True)
            if scanner.scan():
                if scanner.results:
                    banner = scanner.results[0].get('banner')
                    if banner:
                        db = BannerDatabase()
                        db.print_analysis(banner)
                    else:
                        OutputFormatter.print_warning("No banner received")
                scanner.print_summary()
        
        elif choice == '7':
            # OS Fingerprint
            target = input("Enter target IP/hostname: ").strip()
            if not target:
                OutputFormatter.print_error("Target required")
                continue
            
            OutputFormatter.print_info(f"OS Fingerprinting {target}...")
            fp = OSFingerprinter(target)
            fp.fingerprint()
            fp.print_results()
        
        elif choice == '8':
            # Export Results
            if not scanner or not scanner.results:
                OutputFormatter.print_warning("No scan results to export. Run a scan first.")
                continue
            
            filename = input("Enter filename (e.g., results.json): ").strip()
            if not filename:
                filename = "shadowscan_results.json"
            
            format_type = 'json' if filename.endswith('.json') else 'txt'
            scanner.export_results(filename, format_type)
        
        elif choice == '9':
            # About
            print(f"""
{OutputFormatter.Fore.CYAN}{'═' * 60}
{OutputFormatter.Fore.MAGENTA}  ABOUT SHADOWSCAN v{__version__}
{OutputFormatter.Fore.CYAN}{'═' * 60}
{OutputFormatter.Fore.WHITE}
  ShadowScan is an advanced network port scanner designed
  for penetration testers and cybersecurity professionals.
  
  Features:
  {OutputFormatter.Fore.GREEN}●{OutputFormatter.Fore.WHITE} TCP Connect Scan - Full handshake scanning
  {OutputFormatter.Fore.GREEN}●{OutputFormatter.Fore.WHITE} SYN Scan - Stealth half-open scanning
  {OutputFormatter.Fore.GREEN}●{OutputFormatter.Fore.WHITE} UDP Scan - Connectionless scanning
  {OutputFormatter.Fore.GREEN}●{OutputFormatter.Fore.WHITE} OS Fingerprinting - Remote OS detection
  {OutputFormatter.Fore.GREEN}●{OutputFormatter.Fore.WHITE} Banner Analysis - Service identification
  {OutputFormatter.Fore.GREEN}●{OutputFormatter.Fore.WHITE} Modular Architecture - Extensible design
  
{OutputFormatter.Fore.CYAN}  Scan Types:
  {OutputFormatter.Fore.YELLOW}  • TCP Connect{OutputFormatter.Fore.WHITE} - Most reliable, easily detected
  {OutputFormatter.Fore.YELLOW}  • SYN Scan{OutputFormatter.Fore.WHITE} - Faster, stealthier (requires root)
  {OutputFormatter.Fore.YELLOW}  • UDP Scan{OutputFormatter.Fore.WHITE} - For UDP services
  
{OutputFormatter.Fore.CYAN}  Author: {OutputFormatter.Fore.YELLOW}Meheraz HOSEN SIAM
{OutputFormatter.Fore.CYAN}  Role: {OutputFormatter.Fore.YELLOW}Cybersecurity Learner & Future Penetration Tester
{OutputFormatter.Fore.CYAN}  License: {OutputFormatter.Fore.YELLOW}Shadow Public License v1.0
{OutputFormatter.Fore.CYAN}{'═' * 60}{OutputFormatter.Style.RESET_ALL}
""")
        
        else:
            OutputFormatter.print_error(f"Invalid option: {choice}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description=f'ShadowScan v{__version__} - Advanced Network Port Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  %(prog)s -t 192.168.1.1                    # TCP quick scan
  %(prog)s -t example.com --tcp --full       # TCP full scan
  %(prog)s -t 10.0.0.1 --syn                 # SYN scan (requires root)
  %(prog)s -t 192.168.1.1 --udp              # UDP scan
  %(prog)s -t 192.168.1.1 -p 22,80,443       # Custom ports
  %(prog)s -t 192.168.1.1 --os-fingerprint   # OS detection
  %(prog)s -i                                # Interactive mode

Scan Types:
  TCP Connect  - Full TCP handshake, most reliable
  SYN Scan     - Half-open scan, requires root privileges
  UDP Scan     - UDP port scanning

Author: {__author__}
License: Shadow Public License v1.0
        """
    )
    
    parser.add_argument('-t', '--target', type=str, help='Target IP or hostname')
    parser.add_argument('-p', '--ports', type=str, help='Port range or comma-separated list')
    
    # Scan types
    scan_group = parser.add_mutually_exclusive_group()
    scan_group.add_argument('--tcp', action='store_true', help='TCP connect scan (default)')
    scan_group.add_argument('--syn', action='store_true', help='SYN scan (requires root)')
    scan_group.add_argument('--udp', action='store_true', help='UDP scan')
    
    parser.add_argument('--full', action='store_true', help='Full port scan (1-65535)')
    parser.add_argument('--quick', action='store_true', help='Quick scan (common ports)')
    parser.add_argument('-b', '--banner', action='store_true', help='Enable banner grabbing')
    parser.add_argument('--os-fingerprint', action='store_true', help='OS fingerprinting')
    parser.add_argument('-th', '--threads', type=int, default=100, help='Thread count (default: 100)')
    parser.add_argument('-to', '--timeout', type=float, default=1.0, help='Timeout in seconds')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-e', '--export', type=str, help='Export results to file')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode')
    parser.add_argument('--version', action='version', version=f'ShadowScan v{__version__}')
    
    args = parser.parse_args()
    
    # Interactive mode
    if args.interactive or len(sys.argv) == 1:
        interactive_mode()
        return
    
    # Validate target
    if not args.target:
        parser.print_help()
        OutputFormatter.print_error("Target is required. Use -t or --target")
        sys.exit(1)
    
    OutputFormatter.print_banner()
    
    # Determine scan type and create scanner
    if args.syn:
        if args.full:
            scanner = SYNScanner(args.target, list(range(1, 65536)), args.threads, args.timeout)
        elif args.quick or not args.ports:
            scanner = quick_syn_scan(args.target, args.threads)
        else:
            from .utils.network import NetworkUtils
            ports = NetworkUtils.parse_port_range(args.ports)
            scanner = SYNScanner(args.target, ports, args.threads, args.timeout)
    
    elif args.udp:
        if args.full:
            scanner = UDPScanner(args.target, list(range(1, 65536)), args.threads, args.timeout)
        elif args.quick or not args.ports:
            scanner = quick_udp_scan(args.target, args.threads)
        else:
            from .utils.network import NetworkUtils
            ports = NetworkUtils.parse_port_range(args.ports)
            scanner = UDPScanner(args.target, ports, args.threads, args.timeout)
    
    else:  # TCP (default)
        if args.full:
            scanner = full_tcp_scan(args.target, args.threads)
        elif args.quick or not args.ports:
            scanner = quick_tcp_scan(args.target, args.threads)
        else:
            from .utils.network import NetworkUtils
            ports = NetworkUtils.parse_port_range(args.ports)
            scanner = TCPScanner(args.target, ports, args.threads, args.timeout, 
                                args.verbose, args.banner)
    
    # Configure scanner
    scanner.verbose = args.verbose
    
    # Run scan
    try:
        success = scanner.scan()
        
        if success:
            scanner.print_summary()
            
            # OS Fingerprinting
            if args.os_fingerprint:
                open_ports = [r['port'] for r in scanner.results if r.get('state') == 'open']
                fp = OSFingerprinter(args.target, args.timeout)
                fp.fingerprint(open_ports)
                fp.print_results()
            
            # Export results
            if args.export:
                format_type = 'json' if args.export.endswith('.json') else 'txt'
                scanner.export_results(args.export, format_type)
    
    except KeyboardInterrupt:
        OutputFormatter.print_warning("\nScan cancelled by user")
        OutputFormatter.print_info("Thank you for using ShadowScan!")
        sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        OutputFormatter.print_warning("\nShadowScan terminated by user")
        sys.exit(0)
